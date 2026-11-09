//! Attested forwarding of `KubeTEE` chat and image requests.
//!
//! Each upstream connection to `llm.kubetee.ai` is attested before use and
//! renewed every 10 minutes. On a new TLS 1.3 connection the proxy fetches a
//! quote bound to a fresh nonce and verifies it: a `kubetee.attestation.v1`
//! keyset naming this connection's serving key and unexpired, `report_data`
//! equal to the v1 statement binding of that keyset and the nonce, Intel
//! DCAP chain and an `UpToDate` TCB, a TDX report with debug off, the event
//! log replaying to RTMR0-3, and the serving certificate's key signing the
//! nonce. A response without the v1 binding fails closed. Requests are sent
//! only on attested connections, one at a time per connection, and never
//! after the keyset's deadline.

pub mod binding;
pub mod evidence;
mod model_snapshot;
pub mod pool;

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use axum::body::{Body, Bytes};
use axum::http::header::{AUTHORIZATION, HOST};
use axum::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use chrono::{DateTime, Utc};
use dcap_qvl::collateral::CollateralClient;
use dcap_qvl::policy::QuoteClaims;
use http_body_util::{BodyExt as _, Limited};
use hyper::body::Incoming;
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use tokio::time::{timeout, Instant};
use tokio_rustls::TlsConnector;

use crate::model_bindings::{self, RegistrySnapshot, SnapshotCache};
use crate::tee_evidence;
use crate::upstream_proxy::{self, retry_attestation, strip_hop_by_hop, UpstreamConnection};
use evidence::{AttestationPayload, Measurements};
use model_snapshot::{EndpointKind, KubeteeModelBindings};
use pool::{Lease, Limits, Pool};

pub use crate::upstream_proxy::ATTESTATION_ATTEMPTS;

/// The name the proxy's logs and error bodies use.
pub const PROVIDER: &str = "KubeTEE";
/// Where the proxy listens; Envoy's `kubetee_verify_proxy` cluster points here.
pub const BIND_ADDR: &str = "127.0.0.1:8084";
/// The only upstream host.
pub const HOST_NAME: &str = "llm.kubetee.ai";
/// Header carrying the upstream model id Envoy selected for this request.
pub const SELECTOR_HEADER: &str = "x-gm-upstream-model";
const SESSION_ID_HEADER: &str = "x-gm-session-id";
const LITELLM_SESSION_ID_HEADER: &str = "x-litellm-session-id";
pub const CHAT_COMPLETIONS: &str = "/v1/chat/completions";
pub const IMAGES_GENERATIONS: &str = "/v1/images/generations";
pub const MODELS: &str = "/v1/models";

/// Header families the supplier sets that are removed in both directions.
const SUPPLIER_HEADER_PREFIXES: [&str; 2] = ["x-kubetee-", "x-litellm-"];
const BODY_LIMIT: usize = 2 * 1024 * 1024;
/// The largest inference request body the proxy reads.
const REQUEST_LIMIT: usize = 32 * 1024 * 1024;
/// How long a pooled connection may take to accept its next request.
const READY_TIMEOUT: Duration = Duration::from_secs(1);
/// Envoy's route timeout: a non-streaming completion sends its headers
/// only when it is done.
const INFERENCE_TIMEOUT: Duration = Duration::from_secs(1800);

/// Verifies a quote's Intel signature chain.
#[async_trait]
pub trait QuoteChain: Send + Sync {
    /// The claims of `quote`, its signature chain verified against Intel
    /// collateral, and the Unix time it was verified at. That time is read
    /// after the collateral is fetched and also bounds the appraisal.
    ///
    /// # Errors
    ///
    /// Returns an error when collateral cannot be fetched, the clock cannot
    /// be read, or the signature chain does not verify.
    async fn verify(&self, quote: &[u8]) -> Result<(QuoteClaims, u64)>;
}

struct Pccs(CollateralClient);

#[async_trait]
impl QuoteChain for Pccs {
    async fn verify(&self, quote: &[u8]) -> Result<(QuoteClaims, u64)> {
        let collateral = tee_evidence::fetch_collateral(&self.0, quote).await?;
        let now = tee_evidence::unix_now()?;
        Ok((
            tee_evidence::verify_signature_chain(quote, collateral, now)?,
            now,
        ))
    }
}

/// What a successful attestation of one connection found.
#[derive(Clone, Debug)]
pub struct Attestation {
    pub pod: String,
    pub peer: SocketAddr,
    pub measurements: Measurements,
    /// UTC deadline of the served keyset; the connection is not used after it.
    pub keyset_not_after: DateTime<Utc>,
}

#[derive(Clone)]
pub struct KubeteeVerifier {
    tls: TlsConnector,
    address: Option<SocketAddr>,
    quote_chain: Arc<dyn QuoteChain>,
    nonce: fn() -> [u8; 32],
    limits: Limits,
    pool: Arc<Pool>,
    model_snapshot: RegistrySnapshot<KubeteeModelBindings>,
}

impl fmt::Debug for KubeteeVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubeteeVerifier")
            .finish_non_exhaustive()
    }
}

impl KubeteeVerifier {
    /// Build the verifier: TLS 1.3 only, `WebPKI` roots, HTTP/1.1, and Intel
    /// collateral from Phala's PCCS unless `PCCS_URL` overrides it.
    ///
    /// # Errors
    ///
    /// Returns an error when the collateral client cannot be built.
    pub fn new() -> Result<Self> {
        let network = std::env::var("GM_NETWORK").context("missing measured GM_NETWORK")?;
        let registry_origin = model_bindings::registry_url_for_network(&network)
            .ok_or_else(|| anyhow::anyhow!("GM_NETWORK must be exactly mainnet or testnet"))?;
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let model_snapshot = RegistrySnapshot::new(
            model_bindings::registry_http_client()
                .map_err(anyhow::Error::msg)
                .context("build fixed KubeTEE registry client")?,
            format!("{registry_origin}{}", model_snapshot::PATH),
            network,
            SnapshotCache::default(),
            model_snapshot::parse_model_snapshot,
            "KubeTEE",
        );
        Ok(Self::with_parts(
            roots,
            None,
            Arc::new(Pccs(tee_evidence::collateral_client()?)),
            tee_evidence::random_nonce,
            Limits::default(),
            model_snapshot,
        ))
    }

    fn with_parts(
        roots: RootCertStore,
        address: Option<SocketAddr>,
        quote_chain: Arc<dyn QuoteChain>,
        nonce: fn() -> [u8; 32],
        limits: Limits,
        model_snapshot: RegistrySnapshot<KubeteeModelBindings>,
    ) -> Self {
        let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            tls: TlsConnector::from(Arc::new(config)),
            address,
            quote_chain,
            nonce,
            limits,
            pool: Arc::new(Pool::new(limits.pool_limits())),
            model_snapshot,
        }
    }

    /// Refresh the registry snapshot and require `model` to be listed.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot provide a valid current
    /// snapshot or the model is not present in it.
    pub async fn check_model_binding(&self, model: &str) -> Result<(), &'static str> {
        self.model_snapshot.refresh().await?;
        let snapshot = self
            .model_snapshot
            .current()
            .await
            .ok_or("KubeTEE model bindings are unavailable or stale")?;
        snapshot
            .models
            .contains_key(model)
            .then_some(())
            .ok_or("model is not in the current KubeTEE model bindings")
    }

    pub fn start_model_bindings_refresh(&self) {
        self.model_snapshot.start();
    }

    #[cfg(test)]
    async fn refresh_bindings(&self) -> Result<(), &'static str> {
        self.model_snapshot.refresh().await
    }

    async fn current_snapshot_for_request(
        &self,
        request: RequestDescriptor,
    ) -> Result<Option<String>> {
        let Some(snapshot) = self.model_snapshot.fresh().await else {
            return Ok(None);
        };
        validate_request_parts(
            &request.method,
            &request.path,
            &request.selectors,
            &snapshot,
        )
        .map(Some)
    }

    /// Attest one new connection, sending no inference, and close it.
    ///
    /// # Errors
    ///
    /// Returns an error when every attempt to connect and attest fails.
    pub async fn preflight(&self) -> Result<Attestation> {
        let (connection, attestation, _) = self.connect_and_attest().await?;
        drop(connection.sender);
        upstream_proxy::finish_connection(PROVIDER, connection.driver).await?;
        Ok(attestation)
    }

    /// Send `request` on an attested connection: an idle pooled one, or a
    /// new one once its attestation verifies.
    ///
    /// # Errors
    ///
    /// Returns an error for a request outside the current registry snapshot,
    /// or for any attestation or upstream failure. A request is never sent on
    /// a connection whose attestation failed, and never sent twice.
    pub async fn forward(&self, request: Request<Body>) -> Result<Response<Body>> {
        let Some(selector) = self
            .current_snapshot_for_request(request_descriptor(&request))
            .await?
        else {
            return Ok(bindings_unavailable_response());
        };
        let request = timeout(
            self.limits.request_read_timeout,
            require_body_model(request, &selector),
        )
        .await
        .context("reading the KubeTEE request timed out")??;
        // Reading the body and attesting a connection can outlive the snapshot
        // that admitted the request. Recheck after each wait.
        if self
            .current_snapshot_for_request(request_descriptor(&request))
            .await?
            .is_none()
        {
            return Ok(bindings_unavailable_response());
        }
        let mut connection = self.checkout().await?;
        if self
            .current_snapshot_for_request(request_descriptor(&request))
            .await?
            .is_none()
        {
            return Ok(bindings_unavailable_response());
        }
        ensure!(
            self.pool.usable(&connection),
            "KubeTEE connection expired or closed before inference"
        );
        let upstream = upstream_request(request)?;
        connection.requests += 1;
        let response =
            match timeout(INFERENCE_TIMEOUT, connection.sender.send_request(upstream)).await {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => {
                    connection.retire();
                    return Err(error).context("send KubeTEE inference on an attested connection");
                }
                Err(_) => {
                    connection.retire();
                    bail!("KubeTEE inference timed out");
                }
            };
        let (mut parts, body) = response.into_parts();
        strip_supplier_headers(&mut parts.headers);
        strip_hop_by_hop(&mut parts.headers);
        let body = Lease::new(
            Body::new(pool::SupplierBody(body)),
            connection,
            Arc::clone(&self.pool),
        );
        Ok(Response::from_parts(parts, Body::new(body)))
    }

    /// The upstream model list, narrowed to the current registry snapshot,
    /// fetched on an attested connection.
    ///
    /// # Errors
    ///
    /// Returns an error when no attested connection is available or the list
    /// cannot be read.
    pub async fn models(&self, request: Request<Body>) -> Result<Response<Body>> {
        if !self.model_snapshot.is_fresh().await {
            return Ok(bindings_unavailable_response());
        }
        let mut upstream = Request::builder()
            .method(Method::GET)
            .uri(MODELS)
            .header(HOST, HOST_NAME);
        if let Some(authorization) = request.headers().get(AUTHORIZATION) {
            upstream = upstream.header(AUTHORIZATION, authorization);
        }
        let upstream = upstream
            .body(Body::empty())
            .context("build KubeTEE model list request")?;
        let mut connection = self.checkout().await?;
        connection.requests += 1;
        let result = timeout(self.limits.fetch_timeout, async {
            let response = connection
                .sender
                .send_request(upstream)
                .await
                .context("send KubeTEE model list request")?;
            let (mut parts, body) = response.into_parts();
            let body = read_body(body).await?;
            strip_supplier_headers(&mut parts.headers);
            strip_hop_by_hop(&mut parts.headers);
            if parts.status != StatusCode::OK {
                return Ok(Response::from_parts(parts, Body::from(body)));
            }
            let list: Value = serde_json::from_slice(&body).context("decode KubeTEE model list")?;
            let Some(snapshot) = self.model_snapshot.fresh().await else {
                return Ok(bindings_unavailable_response());
            };
            read_models(parts, &list, &snapshot)
        })
        .await
        .context("KubeTEE model list fetch timed out")
        .and_then(|result| result);
        if result.is_ok() {
            self.pool.give_back(connection);
        } else {
            connection.retire();
        }
        result
    }

    /// How many idle attested connections are pooled.
    #[must_use]
    pub fn idle_connections(&self) -> usize {
        self.pool.idle()
    }

    /// A pooled connection ready for its next request, or a newly attested
    /// one when none is.
    async fn checkout(&self) -> Result<pool::Attested> {
        while let Some(mut connection) = self.pool.take() {
            let ready = timeout(READY_TIMEOUT, connection.sender.ready()).await;
            if matches!(ready, Ok(Ok(()))) && self.pool.usable(&connection) {
                return Ok(connection);
            }
            connection.retire();
        }
        let (connection, attestation, attested_at) = self.connect_and_attest().await?;
        let connection = pool::Attested {
            sender: connection.sender,
            driver: connection.driver,
            attested_at,
            idle_since: None,
            expires_at: Some(attestation.keyset_not_after),
            requests: 0,
        };
        // Fresh connections need the same final check as pooled ones: the
        // keyset may have expired while attestation was being completed.
        if !self.pool.usable(&connection) {
            connection.retire();
            bail!("KubeTEE connection expired or closed before its first request");
        }
        Ok(connection)
    }

    async fn connect_and_attest(&self) -> Result<(UpstreamConnection, Attestation, Instant)> {
        let mut attempt = 0;
        retry_attestation(PROVIDER, || {
            let current = attempt;
            attempt += 1;
            self.connect_and_attest_once(current)
        })
        .await
    }

    async fn connect_and_attest_once(
        &self,
        attempt: usize,
    ) -> Result<(UpstreamConnection, Attestation, Instant)> {
        let mut connection =
            upstream_proxy::connect(&self.tls, PROVIDER, HOST_NAME, self.address, attempt).await?;
        match self.attest(&mut connection).await {
            Ok((attestation, attested_at)) => Ok((connection, attestation, attested_at)),
            Err(error) => {
                connection.driver.abort();
                Err(error).with_context(|| format!("attest {HOST_NAME} via {}", connection.peer))
            }
        }
    }

    async fn attest(&self, connection: &mut UpstreamConnection) -> Result<(Attestation, Instant)> {
        let attested_at = Instant::now();
        let nonce = hex::encode((self.nonce)());
        let uri: Uri = format!("/v1/attestation?nonce={nonce}")
            .parse()
            .context("build KubeTEE attestation URI")?;
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(HOST, HOST_NAME)
            .body(Body::empty())
            .context("build KubeTEE attestation request")?;
        let body = timeout(self.limits.fetch_timeout, async {
            let response = connection
                .sender
                .send_request(request)
                .await
                .context("send KubeTEE attestation request")?;
            ensure!(
                response.status() == StatusCode::OK,
                "KubeTEE attestation endpoint returned {}",
                response.status()
            );
            read_body(response.into_body()).await
        })
        .await
        .context("KubeTEE attestation fetch timed out")??;
        // Keyset deadlines use UTC wall time throughout their lifetime.
        // QuoteChain's time is only the quote appraisal clock (historical in
        // offline fixtures), not a clock for live connection reuse.
        let binding =
            evidence::BindingGuard::run(&body, &nonce, connection.leaf.as_ref(), Utc::now())
                .context("kubetee.attestation.v1 binding")?;
        let payload: AttestationPayload =
            serde_json::from_slice(&body).context("decode KubeTEE attestation response")?;
        let quote =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &payload.quote)
                .context("decode KubeTEE quote")?;
        let (claims, now) = self.quote_chain.verify(&quote).await?;
        let measurements = evidence::verify_attestation(
            &payload,
            &nonce,
            connection.leaf.as_ref(),
            &claims,
            now,
            &binding.report_data,
        )?;
        binding.ensure_current(Utc::now())?;
        evidence::log_attested(&payload.pod, &measurements);
        Ok((
            Attestation {
                pod: payload.pod,
                peer: connection.peer,
                measurements,
                keyset_not_after: binding.not_after,
            },
            attested_at,
        ))
    }
}

fn bindings_unavailable_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"error":"KubeTEE model bindings are unavailable or stale"}"#,
        ))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

async fn read_body(body: Incoming) -> Result<Bytes> {
    Ok(Limited::new(body, BODY_LIMIT)
        .collect()
        .await
        .map_err(|error| anyhow::anyhow!("read KubeTEE response: {error}"))?
        .to_bytes())
}

fn read_models(
    mut parts: axum::http::response::Parts,
    list: &Value,
    snapshot: &KubeteeModelBindings,
) -> Result<Response<Body>> {
    let served = serde_json::to_vec(&served_models(list, snapshot)).context("encode model list")?;
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    Ok(Response::from_parts(parts, Body::from(served)))
}

/// The upstream model list narrowed to ids in the current registry snapshot.
fn served_models(list: &Value, bindings: &KubeteeModelBindings) -> Value {
    let data = list
        .get("data")
        .and_then(Value::as_array)
        .map(|models| {
            models
                .iter()
                .filter(|model| {
                    model
                        .get("id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| bindings.models.contains_key(id))
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    serde_json::json!({"object": "list", "data": data})
}

/// Validate the method, endpoint, selector count, and endpoint-kind binding.
#[cfg(test)]
fn validate_request(request: &Request<Body>, bindings: &KubeteeModelBindings) -> Result<String> {
    let request = request_descriptor(request);
    validate_request_parts(&request.method, &request.path, &request.selectors, bindings)
}

struct RequestDescriptor {
    method: Method,
    path: String,
    selectors: Vec<HeaderValue>,
}

fn request_descriptor(request: &Request<Body>) -> RequestDescriptor {
    RequestDescriptor {
        method: request.method().clone(),
        path: request.uri().path().to_owned(),
        selectors: request
            .headers()
            .get_all(SELECTOR_HEADER)
            .iter()
            .cloned()
            .collect(),
    }
}

fn validate_request_parts(
    method: &Method,
    path: &str,
    selectors: &[HeaderValue],
    bindings: &KubeteeModelBindings,
) -> Result<String> {
    let endpoint = EndpointKind::for_path(path).context("KubeTEE route is not supported")?;
    ensure!(
        method == Method::POST,
        "KubeTEE inference requires POST, not {method} {path}"
    );
    let [selector] = selectors else {
        bail!("KubeTEE request needs exactly one model selector");
    };
    let selector = selector
        .to_str()
        .context("KubeTEE model selector is not ASCII")?;
    let bound_endpoint = bindings
        .models
        .get(selector)
        .context("unsupported KubeTEE model selector")?;
    ensure!(
        *bound_endpoint == endpoint,
        "KubeTEE model selector is not admitted for this endpoint"
    );
    Ok(selector.to_owned())
}

/// Read the request body and require its model to match the selected route.
async fn require_body_model(request: Request<Body>, selector: &str) -> Result<Request<Body>> {
    #[derive(serde::Deserialize)]
    struct ChatModel {
        model: String,
    }
    let (parts, body) = request.into_parts();
    let body = Limited::new(body, REQUEST_LIMIT)
        .collect()
        .await
        .map_err(|error| anyhow::anyhow!("read KubeTEE request: {error}"))?
        .to_bytes();
    // Serde's derived struct deserializer also accepts positional arrays.
    ensure!(
        body.trim_ascii_start().starts_with(b"{"),
        "KubeTEE request must be a JSON object"
    );
    let chat: ChatModel = serde_json::from_slice(&body).context("KubeTEE request has no model")?;
    ensure!(
        chat.model == selector,
        "KubeTEE request names a model other than its selector"
    );
    Ok(Request::from_parts(parts, Body::from(body)))
}

fn upstream_request(mut request: Request<Body>) -> Result<Request<Body>> {
    let session_id = (request.uri().path() == CHAT_COMPLETIONS)
        .then(|| request_session_id(&request))
        .flatten();
    let headers = request.headers_mut();
    headers.remove(SELECTOR_HEADER);
    strip_supplier_headers(headers);
    headers.remove(SESSION_ID_HEADER);
    if let Some(session_id) = session_id {
        headers.insert(LITELLM_SESSION_ID_HEADER, session_id);
    }
    strip_hop_by_hop(headers);
    headers.insert(HOST, HeaderValue::from_static(HOST_NAME));
    let mut request = request.map(|body| Body::new(pool::SupplierBody(body)));
    let path = request
        .uri()
        .path_and_query()
        .map_or(CHAT_COMPLETIONS, axum::http::uri::PathAndQuery::as_str);
    *request.uri_mut() = path.parse().context("encode KubeTEE upstream URI")?;
    Ok(request)
}

fn request_session_id(request: &Request<Body>) -> Option<HeaderValue> {
    let mut values = request.headers().get_all(SESSION_ID_HEADER).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let bytes = value.as_bytes();
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f'))
    {
        return None;
    }
    Some(value.clone())
}

/// Remove every `x-kubetee-*` and `x-litellm-*` header.
pub(crate) fn strip_supplier_headers(headers: &mut HeaderMap) {
    let names = headers
        .keys()
        .filter(|name| {
            SUPPLIER_HEADER_PREFIXES
                .iter()
                .any(|prefix| name.as_str().starts_with(prefix))
        })
        .cloned()
        .collect::<Vec<_>>();
    for name in names {
        headers.remove(name);
    }
}

/// The 502 the `KubeTEE` proxy answers with when it refuses a request.
#[must_use]
pub fn error_response(error: &anyhow::Error) -> Response<Body> {
    upstream_proxy::error_response(PROVIDER, error)
}

#[cfg(test)]
mod tests;
