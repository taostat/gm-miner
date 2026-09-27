//! Attested forwarding of `KubeTEE` chat completions.
//!
//! Each upstream connection to `llm.kubetee.ai` is attested before use and
//! renewed every 10 minutes. On a new TLS 1.3 connection the proxy fetches a
//! quote bound to a fresh nonce and verifies it: Intel DCAP chain and an
//! `UpToDate` TCB, a TDX report with debug off, `report_data = SHA-512(nonce)`,
//! the event log replaying to RTMR0-3, and the serving certificate's key
//! signing the nonce. Chat requests are then sent on attested connections
//! only, one at a time per connection.

pub mod evidence;
pub mod pool;

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use axum::body::{Body, Bytes};
use axum::http::header::{AUTHORIZATION, HOST};
use axum::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use dcap_qvl::collateral::CollateralClient;
use dcap_qvl::QuoteCollateralV3;
use http_body_util::{BodyExt as _, Limited};
use hyper::body::Incoming;
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::tee_evidence;
use crate::upstream_proxy::{self, retry_attestation, strip_hop_by_hop, UpstreamConnection};
use evidence::{AttestationPayload, Measurements};
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
pub const CHAT_COMPLETIONS: &str = "/v1/chat/completions";
pub const MODELS: &str = "/v1/models";

/// Every `KubeTEE` chat model gm sources, by the upstream id its route
/// names (`kubetee/<id>` in `docs/sourcing.md`).
pub const TARGETS: [&str; 6] = [
    "z-ai/glm-5.2",
    "z-ai/glm-5.3",
    "z-ai/glm-5.3-flash",
    "deepseek/deepseek-v4.1-flash",
    "ornith/ornith-1.5-397b",
    "xiaomi/mimo-v2.6-pro",
];

/// Header families the supplier sets that are removed in both directions.
/// Image models the direct `/v1/images/generations` route serves. They are
/// listed in model discovery; chat for them is refused.
pub const IMAGE_MODELS: [&str; 1] = ["black-forest-labs/flux.2-klein-4b"];

const SUPPLIER_HEADER_PREFIXES: [&str; 2] = ["x-kubetee-", "x-litellm-"];
const BODY_LIMIT: usize = 2 * 1024 * 1024;
/// How long a pooled connection may take to accept its next request.
const READY_TIMEOUT: Duration = Duration::from_secs(1);
/// Envoy's route timeout: a non-streaming completion sends its headers
/// only when it is done.
const INFERENCE_TIMEOUT: Duration = Duration::from_secs(1800);

/// Where quote collateral and the current time come from.
#[async_trait]
pub trait Collateral: Send + Sync {
    /// Fetch the Intel collateral that appraises `quote`.
    async fn fetch(&self, quote: &[u8]) -> Result<QuoteCollateralV3>;
    /// Seconds since the Unix epoch at which collateral must be valid.
    ///
    /// # Errors
    ///
    /// Returns an error when the clock cannot be read.
    fn now(&self) -> Result<u64>;
}

struct Pccs(CollateralClient);

#[async_trait]
impl Collateral for Pccs {
    async fn fetch(&self, quote: &[u8]) -> Result<QuoteCollateralV3> {
        tee_evidence::fetch_collateral(&self.0, quote).await
    }

    fn now(&self) -> Result<u64> {
        tee_evidence::unix_now()
    }
}

/// What a successful attestation of one connection found.
#[derive(Clone, Debug)]
pub struct Attestation {
    pub pod: String,
    pub peer: SocketAddr,
    pub measurements: Measurements,
}

#[derive(Clone)]
pub struct KubeteeVerifier {
    tls: TlsConnector,
    address: Option<SocketAddr>,
    collateral: Arc<dyn Collateral>,
    nonce: fn() -> [u8; 32],
    pool: Arc<Pool>,
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
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Ok(Self::with_parts(
            roots,
            None,
            Arc::new(Pccs(tee_evidence::collateral_client()?)),
            tee_evidence::random_nonce,
            Limits::default(),
        ))
    }

    fn with_parts(
        roots: RootCertStore,
        address: Option<SocketAddr>,
        collateral: Arc<dyn Collateral>,
        nonce: fn() -> [u8; 32],
        limits: Limits,
    ) -> Self {
        let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            tls: TlsConnector::from(Arc::new(config)),
            address,
            collateral,
            nonce,
            pool: Arc::new(Pool::new(limits)),
        }
    }

    /// Attest one new connection, sending no inference, and close it.
    ///
    /// # Errors
    ///
    /// Returns an error when every attempt to connect and attest fails.
    pub async fn preflight(&self) -> Result<Attestation> {
        let (connection, attestation) = self.connect_and_attest().await?;
        drop(connection.sender);
        upstream_proxy::finish_connection(PROVIDER, connection.driver).await?;
        Ok(attestation)
    }

    /// Send `request` on an attested connection: an idle pooled one, or a
    /// new one once its attestation verifies.
    ///
    /// # Errors
    ///
    /// Returns an error for a request outside the target list, or for any
    /// attestation or upstream failure. A request is never sent on a
    /// connection whose attestation failed, and never sent twice.
    pub async fn forward(&self, request: Request<Body>) -> Result<Response<Body>> {
        validate_request(&request)?;
        let mut connection = self.checkout().await?;
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
        let body = Lease::new(body, connection, Arc::clone(&self.pool));
        Ok(Response::from_parts(parts, Body::new(body)))
    }

    /// The upstream model list, narrowed to [`TARGETS`] and [`IMAGE_MODELS`], fetched on an
    /// attested connection.
    ///
    /// # Errors
    ///
    /// Returns an error when no attested connection is available or the list
    /// cannot be read.
    pub async fn models(&self, request: Request<Body>) -> Result<Response<Body>> {
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
        let result = timeout(
            self.pool.limits().fetch_timeout,
            read_models(&mut connection.sender, upstream),
        )
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
        let (connection, _) = self.connect_and_attest().await?;
        Ok(pool::Attested {
            sender: connection.sender,
            driver: connection.driver,
            attested_at: Instant::now(),
            requests: 0,
        })
    }

    async fn connect_and_attest(&self) -> Result<(UpstreamConnection, Attestation)> {
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
    ) -> Result<(UpstreamConnection, Attestation)> {
        let mut connection =
            upstream_proxy::connect(&self.tls, PROVIDER, HOST_NAME, self.address, attempt).await?;
        match self.attest(&mut connection).await {
            Ok(attestation) => Ok((connection, attestation)),
            Err(error) => {
                connection.driver.abort();
                Err(error).with_context(|| format!("attest {HOST_NAME} via {}", connection.peer))
            }
        }
    }

    async fn attest(&self, connection: &mut UpstreamConnection) -> Result<Attestation> {
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
        let body = timeout(self.pool.limits().fetch_timeout, async {
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
        let payload: AttestationPayload =
            serde_json::from_slice(&body).context("decode KubeTEE attestation response")?;
        let quote =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &payload.quote)
                .context("decode KubeTEE quote")?;
        let collateral = self.collateral.fetch(&quote).await?;
        let now = self.collateral.now()?;
        let claims = tee_evidence::verify_signature_chain(&quote, collateral, now)?;
        let measurements =
            evidence::verify_attestation(&payload, &nonce, connection.leaf.as_ref(), &claims, now)?;
        evidence::log_attested(&payload.pod, &measurements);
        Ok(Attestation {
            pod: payload.pod,
            peer: connection.peer,
            measurements,
        })
    }
}

async fn read_body(body: Incoming) -> Result<Bytes> {
    Ok(Limited::new(body, BODY_LIMIT)
        .collect()
        .await
        .map_err(|error| anyhow::anyhow!("read KubeTEE response: {error}"))?
        .to_bytes())
}

async fn read_models(
    sender: &mut hyper::client::conn::http1::SendRequest<Body>,
    request: Request<Body>,
) -> Result<Response<Body>> {
    let response = sender
        .send_request(request)
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
    let served = serde_json::to_vec(&served_targets(&list)).context("encode model list")?;
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    Ok(Response::from_parts(parts, Body::from(served)))
}

/// The upstream model list with every entry outside [`TARGETS`] and
/// [`IMAGE_MODELS`] removed.
#[must_use]
pub fn served_targets(list: &Value) -> Value {
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
                        .is_some_and(|id| TARGETS.contains(&id) || IMAGE_MODELS.contains(&id))
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    serde_json::json!({"object": "list", "data": data})
}

/// Refuse anything but a chat completion for a target model. Runs before
/// any connection is used or opened.
fn validate_request(request: &Request<Body>) -> Result<&'static str> {
    ensure!(
        request.method() == Method::POST && request.uri().path() == CHAT_COMPLETIONS,
        "KubeTEE is served only at POST {CHAT_COMPLETIONS}, not {} {}",
        request.method(),
        request.uri().path()
    );
    let mut selectors = request.headers().get_all(SELECTOR_HEADER).iter();
    let (Some(selector), None) = (selectors.next(), selectors.next()) else {
        bail!("KubeTEE request needs exactly one model selector");
    };
    let selector = selector
        .to_str()
        .context("KubeTEE model selector is not ASCII")?;
    TARGETS
        .into_iter()
        .find(|target| *target == selector)
        .context("unsupported KubeTEE model selector")
}

fn upstream_request(mut request: Request<Body>) -> Result<Request<Body>> {
    let headers = request.headers_mut();
    headers.remove(SELECTOR_HEADER);
    strip_supplier_headers(headers);
    strip_hop_by_hop(headers);
    headers.insert(HOST, HeaderValue::from_static(HOST_NAME));
    let mut request = request.map(|body| Body::new(body.map_frame(pool::strip_supplier_trailers)));
    let path = request
        .uri()
        .path_and_query()
        .map_or(CHAT_COMPLETIONS, axum::http::uri::PathAndQuery::as_str);
    *request.uri_mut() = path.parse().context("encode KubeTEE upstream URI")?;
    Ok(request)
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
