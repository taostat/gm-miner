//! Fixed Bedrock Mantle Messages adapter for registry-authorized Anthropic models.
//!
//! The inbound Anthropic request is parsed into a bounded, duplicate-aware
//! JSON value. Only the reviewed Messages fields and client-executed custom
//! tool protocol are accepted. The adapter then builds a fresh request to the
//! fixed Mantle hostname and path, replacing only the request model selector.
//! The raw AWS response identity is checked before its model field is rewritten
//! to the canonical registry model and before any response bytes are released.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::State,
    http::{
        header::{ACCEPT, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE},
        HeaderMap, HeaderValue, Method, Request, Response, StatusCode,
    },
    routing::any,
    Router,
};
use futures_util::{stream, StreamExt};
use reqwest::{redirect::Policy, Client};
use rustls::{ClientConfig, RootCertStore};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use tokio::{net::TcpListener, sync::RwLock, time::MissedTickBehavior};
use tracing::info;

pub const BEDROCK_MANTLE_FEATURE: &str = "bedrock-mantle-model-bindings-v1";
pub const BEDROCK_MANTLE_BIND_ADDR: &str = "127.0.0.1:8085";
pub const BEDROCK_MANTLE_HOST: &str = "bedrock-mantle.us-east-1.api.aws";
pub const BEDROCK_MANTLE_PATH: &str = "/anthropic/v1/messages";
pub const ANTHROPIC_VERSION: &str = "2023-06-01";
pub const EXECUTION_POLICY_HEADER: &str = "x-gm-execution-policy";
pub const EXACT_CANONICAL_NO_REPLAY_POLICY: &str = "exact-canonical-no-replay-v1";
pub const MODEL_BINDING_REVISION_HEADER: &str = "x-gm-model-binding-revision";

const BEDROCK_MANTLE_URL: &str = "https://bedrock-mantle.us-east-1.api.aws/anthropic/v1/messages";
const BEDROCK_BINDINGS_PATH: &str = "/model-bindings/bedrock";
const MAX_REQUEST_BODY: usize = 20 * 1024 * 1024;
const MAX_RESPONSE_BODY: usize = 32 * 1024 * 1024;
const MAX_STREAM_PREAMBLE: usize = 64 * 1024;
/// One in-body SSE frame. A thinking block's closing signature frame grows with
/// the thinking (about 75 KB at 32k thinking tokens); 4 MiB leaves wide headroom.
const MAX_STREAM_FRAME: usize = 4 * 1024 * 1024;
const MAX_BINDINGS_BODY: usize = 1024 * 1024;
const MAX_MODEL_BINDINGS: usize = 1024;
const MAX_MODEL_ID_BYTES: usize = 256;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const BINDINGS_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const BINDINGS_FRESHNESS_TTL: Duration = Duration::from_secs(120);
/// Protocol-safe integer bound only. Model output ceilings belong to the
/// provider/catalog; this bound does not drive allocation in the adapter.
const MAX_TOKEN_FIELD_VALUE: u64 = u32::MAX as u64;
const MAX_MESSAGES: usize = 16_384;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModelBinding {
    provider: String,
    model: String,
    upstream_model: String,
    response_model: String,
    revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BindingsSnapshot {
    network: String,
    revision: u64,
    bindings: BTreeMap<String, ModelBinding>,
}

#[derive(Debug, Clone)]
struct CachedBindings {
    snapshot: BindingsSnapshot,
    fetched_at: Instant,
}

#[derive(Debug, Default)]
struct BindingCache {
    current: Option<CachedBindings>,
    /// Retained across removals so a model cannot be re-added with an old or
    /// reused row revision during this runtime's lifetime.
    highest_binding: BTreeMap<String, ModelBinding>,
}

impl BindingCache {
    #[cfg(test)]
    fn with_snapshot(snapshot: BindingsSnapshot, fetched_at: Instant) -> Self {
        let highest_binding = snapshot.bindings.clone();
        Self {
            current: Some(CachedBindings {
                snapshot,
                fetched_at,
            }),
            highest_binding,
        }
    }

    fn apply(&mut self, snapshot: BindingsSnapshot, now: Instant) -> Result<(), &'static str> {
        if let Some(current) = &self.current {
            if snapshot.revision < current.snapshot.revision {
                return Err("registry binding snapshot revision moved backwards");
            }
            if snapshot.revision == current.snapshot.revision {
                if snapshot != current.snapshot {
                    return Err("registry changed binding payload without advancing revision");
                }
                self.current = Some(CachedBindings {
                    snapshot,
                    fetched_at: now,
                });
                return Ok(());
            }

            for (model, previous) in &self.highest_binding {
                let Some(next) = snapshot.bindings.get(model) else {
                    continue;
                };
                if next.revision < previous.revision {
                    return Err("model binding revision moved backwards");
                }
                if next.revision == previous.revision && next != previous {
                    return Err("model binding changed without advancing its revision");
                }
                if !current.snapshot.bindings.contains_key(model)
                    && next.revision <= previous.revision
                {
                    return Err("removed model binding was re-added without a new revision");
                }
            }
        }

        for (model, binding) in &snapshot.bindings {
            self.highest_binding.insert(model.clone(), binding.clone());
        }
        self.current = Some(CachedBindings {
            snapshot,
            fetched_at: now,
        });
        Ok(())
    }

    fn current_binding(
        &self,
        model: &str,
        expected_revision: u64,
        now: Instant,
    ) -> Result<ModelBinding, Reject> {
        let cached = self
            .current
            .as_ref()
            .filter(|cached| {
                now.saturating_duration_since(cached.fetched_at) <= BINDINGS_FRESHNESS_TTL
            })
            .ok_or(Reject::BindingsUnavailable)?;
        let binding = cached
            .snapshot
            .bindings
            .get(model)
            .ok_or(Reject::UnsupportedModel)?;
        if binding.revision != expected_revision {
            return Err(Reject::BindingRevision);
        }
        Ok(binding.clone())
    }
}

#[derive(Clone)]
pub struct BedrockMantleState {
    client: Client,
    authorization: HeaderValue,
    registry_network: String,
    registry_url: String,
    bindings: Arc<RwLock<BindingCache>>,
    #[cfg(test)]
    test_upstream_url: Option<String>,
}

impl BedrockMantleState {
    /// Construct the production transport from the one configured Bedrock API
    /// key. No endpoint, proxy, CA, redirect, region, or AWS account override
    /// is accepted from the process environment.
    ///
    /// # Errors
    ///
    /// Returns an error when the qualified region or key is missing or invalid,
    /// or when the fixed TLS client cannot be initialized.
    pub fn from_environment() -> Result<Self, &'static str> {
        let network = std::env::var("GM_NETWORK").map_err(|_| "missing measured GM_NETWORK")?;
        let registry_url = registry_url_for_network(&network)
            .ok_or("GM_NETWORK must be exactly mainnet or testnet")?;
        let region = std::env::var("BEDROCK_REGION").map_err(|_| "missing Bedrock region")?;
        if region != "us-east-1" {
            return Err("Bedrock Mantle is qualified only in us-east-1");
        }
        let key = std::env::var("BEDROCK_API_KEY").map_err(|_| "missing Bedrock API key")?;
        if key.is_empty() || key.contains(';') {
            return Err("Bedrock API key must be one non-empty value");
        }
        let authorization = HeaderValue::from_str(&format!("Bearer {key}"))
            .map_err(|_| "Bedrock API key is not a valid HTTP credential")?;

        let client = production_http_client()?;

        Ok(Self {
            client,
            authorization,
            registry_network: network,
            registry_url: format!("{registry_url}{BEDROCK_BINDINGS_PATH}"),
            bindings: Arc::new(RwLock::new(BindingCache::default())),
            #[cfg(test)]
            test_upstream_url: None,
        })
    }

    #[cfg(test)]
    #[expect(
        clippy::expect_used,
        reason = "test setup uses a fixed local client and credential"
    )]
    fn for_test(url: &str, authorization: &str) -> Self {
        let client = Client::builder()
            .no_proxy()
            .http1_only()
            .pool_max_idle_per_host(0)
            .retry(reqwest::retry::never())
            .redirect(Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .expect("test HTTP client");
        Self {
            client,
            authorization: HeaderValue::from_str(authorization).expect("test credential"),
            registry_network: "mainnet".to_owned(),
            registry_url: format!("https://registry.saygm.com{BEDROCK_BINDINGS_PATH}"),
            bindings: Arc::new(RwLock::new(BindingCache::with_snapshot(
                test_bindings_payload(),
                Instant::now(),
            ))),
            test_upstream_url: Some(url.to_owned()),
        }
    }

    #[cfg(test)]
    fn with_test_registry_url(mut self, url: &str) -> Self {
        self.registry_url = url.to_owned();
        self
    }

    async fn refresh_bindings(&self) -> Result<(), &'static str> {
        let response = self
            .client
            .get(&self.registry_url)
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|_| "fixed registry binding fetch failed")?;
        if response.status() != StatusCode::OK {
            return Err("fixed registry binding fetch returned a non-200 status");
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err("fixed registry binding response is not JSON");
        }
        let body = read_bounded_registry_body(response).await?;
        let snapshot = parse_bindings_payload(&body, &self.registry_network)?;
        self.bindings.write().await.apply(snapshot, Instant::now())
    }
}

/// Return the only registry origins permitted by the measured network literal.
fn registry_url_for_network(network: &str) -> Option<&'static str> {
    match network {
        "mainnet" => Some("https://registry.saygm.com"),
        "testnet" => Some("https://test-registry.saygm.com"),
        _ => None,
    }
}

#[cfg(test)]
const TEST_MODEL_A: &str = "test-model-a";
#[cfg(test)]
const TEST_SELECTOR_A: &str = "anthropic.test-model-a-v1";
#[cfg(test)]
const TEST_RESPONSE_MODEL_A: &str = "test-model-a-provider-echo";
#[cfg(test)]
const TEST_MODEL_REVISION_A: u64 = 7;

#[cfg(test)]
fn test_bindings_payload() -> BindingsSnapshot {
    let binding = ModelBinding {
        provider: "anthropic".to_owned(),
        model: TEST_MODEL_A.to_owned(),
        upstream_model: TEST_SELECTOR_A.to_owned(),
        response_model: TEST_RESPONSE_MODEL_A.to_owned(),
        revision: TEST_MODEL_REVISION_A,
    };
    BindingsSnapshot {
        network: "mainnet".to_owned(),
        revision: 10,
        bindings: BTreeMap::from([(TEST_MODEL_A.to_owned(), binding)]),
    }
}

async fn read_bounded_registry_body(response: reqwest::Response) -> Result<Vec<u8>, &'static str> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BINDINGS_BODY as u64)
    {
        return Err("registry binding response exceeds the size limit");
    }
    let mut body = Vec::new();
    let mut source = response.bytes_stream();
    while let Some(chunk) = source.next().await {
        let chunk = chunk.map_err(|_| "registry binding response body failed")?;
        if body.len().saturating_add(chunk.len()) > MAX_BINDINGS_BODY {
            return Err("registry binding response exceeds the size limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn parse_bindings_payload(
    bytes: &[u8],
    expected_network: &str,
) -> Result<BindingsSnapshot, &'static str> {
    let value =
        parse_unique_json(bytes).map_err(|_| "registry binding response is invalid JSON")?;
    let object = value
        .as_object()
        .filter(|object| {
            object_has_only_keys(
                object,
                &["schema_version", "network", "revision", "bindings"],
            )
        })
        .ok_or("registry binding response has an invalid envelope")?;
    if object.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("registry binding schema version is unsupported");
    }
    let network = object
        .get("network")
        .and_then(Value::as_str)
        .ok_or("registry binding response has no network")?;
    if network != expected_network {
        return Err("registry binding response is for a different network");
    }
    let revision = object
        .get("revision")
        .and_then(Value::as_u64)
        .filter(|revision| *revision <= MAX_SAFE_INTEGER)
        .ok_or("registry binding response has an invalid revision")?;
    let rows = object
        .get("bindings")
        .and_then(Value::as_array)
        .filter(|rows| rows.len() <= MAX_MODEL_BINDINGS)
        .ok_or("registry binding response has an invalid binding list")?;

    let mut bindings = BTreeMap::new();
    for row in rows {
        let row = row
            .as_object()
            .filter(|row| {
                object_has_only_keys(
                    row,
                    &[
                        "provider",
                        "model",
                        "upstream_model",
                        "response_model",
                        "revision",
                    ],
                )
            })
            .ok_or("registry model binding has an invalid shape")?;
        let provider = row
            .get("provider")
            .and_then(Value::as_str)
            .filter(|provider| *provider == "anthropic")
            .ok_or("registry model binding has an invalid provider")?;
        let model = row
            .get("model")
            .and_then(Value::as_str)
            .filter(|model| valid_model_id(model))
            .ok_or("registry model binding has an invalid canonical model")?;
        let upstream_model = row
            .get("upstream_model")
            .and_then(Value::as_str)
            .filter(|selector| valid_bedrock_selector(selector))
            .ok_or("registry model binding has an invalid Bedrock selector")?;
        let response_model = row
            .get("response_model")
            .and_then(Value::as_str)
            .filter(|model| valid_model_id(model))
            .ok_or("registry model binding has an invalid response identity")?;
        let binding_revision = row
            .get("revision")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0 && *value <= MAX_SAFE_INTEGER && *value <= revision)
            .ok_or("registry model binding has an invalid revision")?;

        let binding = ModelBinding {
            provider: provider.to_owned(),
            model: model.to_owned(),
            upstream_model: upstream_model.to_owned(),
            response_model: response_model.to_owned(),
            revision: binding_revision,
        };
        if bindings.insert(model.to_owned(), binding).is_some() {
            return Err("registry model bindings contain a duplicate canonical model");
        }
    }

    Ok(BindingsSnapshot {
        network: network.to_owned(),
        revision,
        bindings,
    })
}

fn object_has_only_keys(object: &Map<String, Value>, allowed: &[&str]) -> bool {
    object.keys().all(|key| allowed.contains(&key.as_str()))
        && allowed.iter().all(|key| object.contains_key(*key))
}

fn valid_model_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MODEL_ID_BYTES
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

fn valid_bedrock_selector(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("anthropic.") else {
        return false;
    };
    !suffix.is_empty()
        && value.len() <= MAX_MODEL_ID_BYTES
        && suffix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

/// Build the fixed production transport with an explicit TLS crypto provider.
/// Other workspace dependencies can enable multiple rustls providers, so
/// relying on rustls process-wide auto-selection can panic at startup.
fn production_http_client() -> Result<Client, &'static str> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| "failed to configure fixed Bedrock TLS versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();

    // Messages inference is billable. Use one HTTP/1.1 request per new
    // connection, disable reqwest's protocol retry policy, and avoid
    // pooled-connection cancellation retries.
    Client::builder()
        .no_proxy()
        .https_only(true)
        .http1_only()
        .pool_max_idle_per_host(0)
        .retry(reqwest::retry::never())
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30 * 60))
        .user_agent("gm-bedrock-mantle-adapter/1")
        .use_preconfigured_tls(tls)
        .build()
        .map_err(|_| "failed to initialize fixed Bedrock Mantle transport")
}

#[derive(Clone)]
struct AppState(BedrockMantleState);

/// Bind and serve the private loopback adapter used by Envoy.
///
/// # Errors
///
/// Returns an error if the server stops with an I/O failure.
pub async fn serve(listener: TcpListener, state: BedrockMantleState) -> Result<(), &'static str> {
    let refresh_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(BINDINGS_REFRESH_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if let Err(error) = refresh_state.refresh_bindings().await {
                tracing::warn!(error, "Bedrock model bindings refresh was rejected");
            }
        }
    });
    let app = Router::new()
        .route("/v1/messages", any(handle_request))
        .with_state(AppState(state));
    info!(
        bind = BEDROCK_MANTLE_BIND_ADDR,
        "Bedrock Mantle adapter ready"
    );
    axum::serve(listener, app)
        .await
        .map_err(|_| "Bedrock Mantle adapter stopped")
}

async fn handle_request(State(state): State<AppState>, request: Request<Body>) -> Response<Body> {
    match forward_request(state.0, request).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reject {
    Method,
    Path,
    Header,
    BodyTooLarge,
    InvalidBody,
    UnsupportedModel,
    BindingRevision,
    BindingsUnavailable,
    Upstream,
    UpstreamTransport,
    UpstreamHttp(u16),
    ModelIdentityMismatch,
}

impl Reject {
    // Fixed categories only: never log provider bodies, model strings, headers,
    // credentials, or request content. Public error bodies remain unchanged.
    fn upstream_diagnostic(self) -> Option<(&'static str, Option<u16>)> {
        match self {
            Self::Upstream => Some(("upstream_response_invalid", None)),
            Self::UpstreamTransport => Some(("upstream_transport_failed", None)),
            Self::UpstreamHttp(status) => Some(("upstream_http_rejected", Some(status))),
            Self::ModelIdentityMismatch => Some(("model_identity_mismatch", None)),
            _ => None,
        }
    }

    fn into_response(self) -> Response<Body> {
        if let Some((reason, upstream_status)) = self.upstream_diagnostic() {
            tracing::warn!(reason, upstream_status, "Bedrock Mantle request rejected");
        }
        let (status, error_type, message) = match self {
            Self::Method => (
                StatusCode::METHOD_NOT_ALLOWED,
                "invalid_request_error",
                "Bedrock Messages requires POST",
            ),
            Self::Path => (
                StatusCode::NOT_FOUND,
                "invalid_request_error",
                "Bedrock Messages path or query is not allowed",
            ),
            Self::Header => (
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "Bedrock Messages headers are invalid",
            ),
            Self::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request_error",
                "Bedrock Messages body exceeds the adapter limit",
            ),
            Self::InvalidBody => (
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "Bedrock Messages body is not supported",
            ),
            Self::UnsupportedModel => (
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "Bedrock model is not currently approved",
            ),
            Self::BindingRevision => (
                StatusCode::CONFLICT,
                "invalid_request_error",
                "Bedrock model binding revision is stale or invalid",
            ),
            Self::BindingsUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "api_error",
                "Bedrock model bindings are unavailable or stale",
            ),
            Self::Upstream
            | Self::UpstreamTransport
            | Self::UpstreamHttp(_)
            | Self::ModelIdentityMismatch => (
                StatusCode::BAD_GATEWAY,
                "api_error",
                "Bedrock Mantle request failed",
            ),
        };
        let body = format!("{{\"error\":{{\"type\":\"{error_type}\",\"message\":\"{message}\"}}}}");
        response(status, "application/json", Body::from(body))
    }
}

async fn forward_request(
    state: BedrockMantleState,
    request: Request<Body>,
) -> Result<Response<Body>, Reject> {
    if request.method() != Method::POST {
        return Err(Reject::Method);
    }
    if request
        .uri()
        .path_and_query()
        .map(axum::http::uri::PathAndQuery::as_str)
        != Some("/v1/messages")
    {
        return Err(Reject::Path);
    }
    let requested_binding_revision = validate_inbound_headers(request.headers())?;

    let bytes = to_bytes(request.into_body(), MAX_REQUEST_BODY)
        .await
        .map_err(|_| Reject::BodyTooLarge)?;
    let (mut request_body, stream_response) = prepare_request_body(&bytes)?;
    let model = request_body
        .get("model")
        .and_then(Value::as_str)
        .ok_or(Reject::InvalidBody)?
        .to_owned();
    let accept = if stream_response {
        "text/event-stream"
    } else {
        "application/json"
    };
    let url = upstream_url({
        #[cfg(test)]
        {
            state.test_upstream_url.as_deref()
        }
        #[cfg(not(test))]
        {
            None
        }
    });
    // This read happens after caller body collection and validation. Keep the
    // read lock through the synchronous model rewrite and request build, then
    // start the provider request immediately; a refresh cannot interleave
    // between the current binding check and request construction.
    let cache = state.bindings.read().await;
    let binding = cache.current_binding(&model, requested_binding_revision, Instant::now())?;
    request_body
        .as_object_mut()
        .ok_or(Reject::InvalidBody)?
        .insert(
            "model".to_owned(),
            Value::String(binding.upstream_model.clone()),
        );
    let upstream_body = serde_json::to_vec(&request_body).map_err(|_| Reject::InvalidBody)?;
    let upstream_request = state
        .client
        .post(url)
        .header(AUTHORIZATION, state.authorization.clone())
        .header("anthropic-version", ANTHROPIC_VERSION)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, accept)
        .body(upstream_body)
        .build()
        .map_err(|_| Reject::Upstream)?;
    drop(cache);
    let upstream = state
        .client
        .execute(upstream_request)
        .await
        .map_err(|_| Reject::UpstreamTransport)?;

    finish_upstream_response(upstream, &binding, stream_response).await
}

async fn finish_upstream_response(
    upstream: reqwest::Response,
    binding: &ModelBinding,
    stream_response: bool,
) -> Result<Response<Body>, Reject> {
    if upstream.status() != StatusCode::OK {
        return Err(Reject::UpstreamHttp(upstream.status().as_u16()));
    }
    if stream_response {
        let content_type = upstream
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
        {
            return Err(Reject::Upstream);
        }
        let source = upstream
            .bytes_stream()
            .map(|result| {
                result.map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "upstream stream interrupted",
                    )
                })
            })
            .boxed();
        let (preamble, source) =
            validate_stream_identity(source, &binding.response_model, &binding.model).await?;
        let first = stream::once(async move { Ok::<Bytes, io::Error>(preamble) });
        let body = Body::from_stream(guard_stream(first.chain(source).boxed()));
        Ok(response_with_binding_revision(
            StatusCode::OK,
            "text/event-stream",
            body,
            binding.revision,
        ))
    } else {
        let content_type = upstream
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(Reject::Upstream);
        }
        let body = read_bounded_response(upstream).await?;
        let body = canonicalize_response_identity(&body, &binding.response_model, &binding.model)?;
        Ok(response_with_binding_revision(
            StatusCode::OK,
            "application/json",
            Body::from(body),
            binding.revision,
        ))
    }
}

fn validate_inbound_headers(headers: &HeaderMap) -> Result<u64, Reject> {
    let mut execution_policies = headers.get_all(EXECUTION_POLICY_HEADER).iter();
    if execution_policies
        .next()
        .and_then(|value| value.to_str().ok())
        != Some(EXACT_CANONICAL_NO_REPLAY_POLICY)
        || execution_policies.next().is_some()
    {
        return Err(Reject::Header);
    }

    if headers.contains_key("anthropic-workspace-id")
        || headers.contains_key("anthropic-beta")
        || headers.contains_key(CONTENT_ENCODING)
    {
        return Err(Reject::Header);
    }
    if headers.keys().any(|name| {
        name.as_str().starts_with("x-amzn-bedrock-")
            || (name.as_str().starts_with("anthropic-") && name.as_str() != "anthropic-version")
    }) {
        return Err(Reject::Header);
    }

    let content_types = headers.get_all(CONTENT_TYPE).iter().collect::<Vec<_>>();
    if content_types.len() != 1
        || content_types[0]
            .to_str()
            .ok()
            .is_none_or(|value| !value.eq_ignore_ascii_case("application/json"))
    {
        return Err(Reject::Header);
    }
    let versions = headers
        .get_all("anthropic-version")
        .iter()
        .collect::<Vec<_>>();
    if versions.len() != 1
        || versions[0]
            .to_str()
            .ok()
            .is_none_or(|value| value != ANTHROPIC_VERSION)
    {
        return Err(Reject::Header);
    }
    let revisions = headers
        .get_all(MODEL_BINDING_REVISION_HEADER)
        .iter()
        .collect::<Vec<_>>();
    if revisions.len() != 1 {
        return Err(Reject::Header);
    }
    let revision = revisions[0]
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|revision| *revision > 0)
        .ok_or(Reject::Header)?;
    if revisions[0].as_bytes() != revision.to_string().as_bytes() {
        return Err(Reject::Header);
    }
    Ok(revision)
}

fn prepare_request_body(bytes: &[u8]) -> Result<(Value, bool), Reject> {
    let mut value = parse_unique_json(bytes).map_err(|_| Reject::InvalidBody)?;
    let object = value.as_object_mut().ok_or(Reject::InvalidBody)?;
    let allowed = [
        "model",
        "max_tokens",
        "messages",
        "system",
        "stop_sequences",
        "temperature",
        "top_p",
        "top_k",
        "stream",
        "tools",
        "tool_choice",
        "thinking",
        "output_config",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if object.keys().any(|key| !allowed.contains(key.as_str())) {
        return Err(Reject::InvalidBody);
    }

    let model = object
        .get("model")
        .and_then(Value::as_str)
        .ok_or(Reject::InvalidBody)?;
    if !valid_model_id(model) {
        return Err(Reject::InvalidBody);
    }
    let max_tokens = object
        .get("max_tokens")
        .and_then(Value::as_u64)
        .filter(|value| (1..=MAX_TOKEN_FIELD_VALUE).contains(value))
        .ok_or(Reject::InvalidBody)?;
    let _ = max_tokens;
    let messages = object
        .get("messages")
        .and_then(Value::as_array)
        .filter(|messages| !messages.is_empty() && messages.len() <= MAX_MESSAGES)
        .ok_or(Reject::InvalidBody)?;
    for message in messages {
        validate_message(message)?;
    }
    if let Some(system) = object.get("system") {
        validate_text_content(system)?;
    }
    let stream_response = match object.get("stream") {
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(Reject::InvalidBody),
        None => false,
    };
    if let Some(Value::Array(stops)) = object.get("stop_sequences") {
        if stops.len() > 64 || stops.iter().any(|value| value.as_str().is_none()) {
            return Err(Reject::InvalidBody);
        }
    } else if object.contains_key("stop_sequences") {
        return Err(Reject::InvalidBody);
    }
    if let Some(value) = object.get("temperature") {
        if !valid_unit_float(value) {
            return Err(Reject::InvalidBody);
        }
    }
    if let Some(value) = object.get("top_p") {
        if !valid_unit_float(value) {
            return Err(Reject::InvalidBody);
        }
    }
    if let Some(value) = object.get("top_k") {
        if value.as_u64().is_none_or(|value| value > 500) {
            return Err(Reject::InvalidBody);
        }
    }
    if let Some(value) = object.get("tools") {
        validate_tools(value)?;
    }
    if let Some(value) = object.get("tool_choice") {
        validate_tool_choice(value)?;
    }
    if let Some(value) = object.get("thinking") {
        validate_thinking(value)?;
    }
    if let Some(value) = object.get("output_config") {
        validate_output_config(value)?;
    }
    Ok((value, stream_response))
}

fn valid_unit_float(value: &Value) -> bool {
    value
        .as_number()
        .and_then(Number::as_f64)
        .is_some_and(|value| value.is_finite() && (0.0..=1.0).contains(&value))
}

fn validate_message(value: &Value) -> Result<(), Reject> {
    let object = value.as_object().ok_or(Reject::InvalidBody)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "role" | "content"))
    {
        return Err(Reject::InvalidBody);
    }
    if !matches!(
        object.get("role").and_then(Value::as_str),
        Some("user" | "assistant")
    ) {
        return Err(Reject::InvalidBody);
    }
    let content = object.get("content").ok_or(Reject::InvalidBody)?;
    validate_content(content, true)
}

fn validate_text_content(value: &Value) -> Result<(), Reject> {
    match value {
        Value::String(_) => Ok(()),
        Value::Array(blocks) => {
            for block in blocks {
                validate_block(block, false)?;
            }
            Ok(())
        }
        _ => Err(Reject::InvalidBody),
    }
}

fn validate_content(value: &Value, allow_tool_blocks: bool) -> Result<(), Reject> {
    match value {
        Value::String(_) => Ok(()),
        Value::Array(blocks) => {
            for block in blocks {
                validate_block(block, allow_tool_blocks)?;
            }
            Ok(())
        }
        _ => Err(Reject::InvalidBody),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the complete closed content-block allowlist stays together for audit"
)]
fn validate_block(value: &Value, allow_tool_blocks: bool) -> Result<(), Reject> {
    let object = value.as_object().ok_or(Reject::InvalidBody)?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(Reject::InvalidBody)?;
    match kind {
        "text" => {
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "type" | "text" | "cache_control"))
                || object.get("text").and_then(Value::as_str).is_none()
            {
                return Err(Reject::InvalidBody);
            }
            validate_cache_control(object.get("cache_control"))
        }
        "image" => {
            if !allow_tool_blocks
                || object
                    .keys()
                    .any(|key| !matches!(key.as_str(), "type" | "source" | "cache_control"))
            {
                return Err(Reject::InvalidBody);
            }
            validate_cache_control(object.get("cache_control"))?;
            validate_inline_source(
                object.get("source").ok_or(Reject::InvalidBody)?,
                &["image/jpeg", "image/png", "image/gif", "image/webp"],
            )
        }
        "document" => {
            if !allow_tool_blocks
                || object.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "type" | "source" | "title" | "context" | "cache_control"
                    )
                })
            {
                return Err(Reject::InvalidBody);
            }
            for key in ["title", "context"] {
                if object
                    .get(key)
                    .is_some_and(|value| value.as_str().is_none())
                {
                    return Err(Reject::InvalidBody);
                }
            }
            validate_cache_control(object.get("cache_control"))?;
            validate_inline_source(
                object.get("source").ok_or(Reject::InvalidBody)?,
                &["application/pdf"],
            )
        }
        "tool_use" if allow_tool_blocks => {
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "type" | "id" | "name" | "input"))
                || object.get("id").and_then(Value::as_str).is_none()
                || object.get("name").and_then(Value::as_str).is_none()
                || object.get("input").is_none()
            {
                return Err(Reject::InvalidBody);
            }
            Ok(())
        }
        "tool_result" if allow_tool_blocks => {
            if object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "type" | "tool_use_id" | "content" | "is_error" | "cache_control"
                )
            }) || object.get("tool_use_id").and_then(Value::as_str).is_none()
                || object
                    .get("is_error")
                    .is_some_and(|value| value.as_bool().is_none())
            {
                return Err(Reject::InvalidBody);
            }
            validate_cache_control(object.get("cache_control"))?;
            if let Some(content) = object.get("content") {
                validate_content(content, true)?;
            }
            Ok(())
        }
        "thinking" if allow_tool_blocks => {
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "type" | "thinking" | "signature"))
                || object.get("thinking").and_then(Value::as_str).is_none()
                || object.get("signature").and_then(Value::as_str).is_none()
            {
                return Err(Reject::InvalidBody);
            }
            Ok(())
        }
        "redacted_thinking" if allow_tool_blocks => {
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "type" | "data"))
                || object.get("data").and_then(Value::as_str).is_none()
            {
                return Err(Reject::InvalidBody);
            }
            Ok(())
        }
        _ => Err(Reject::InvalidBody),
    }
}

fn validate_inline_source(value: &Value, allowed_media_types: &[&str]) -> Result<(), Reject> {
    let source = value.as_object().ok_or(Reject::InvalidBody)?;
    if source
        .keys()
        .any(|key| !matches!(key.as_str(), "type" | "media_type" | "data"))
        || source.get("type").and_then(Value::as_str) != Some("base64")
        || source
            .get("media_type")
            .and_then(Value::as_str)
            .is_none_or(|media| !allowed_media_types.contains(&media))
        || source.get("data").and_then(Value::as_str).is_none()
    {
        return Err(Reject::InvalidBody);
    }
    Ok(())
}

fn validate_cache_control(value: Option<&Value>) -> Result<(), Reject> {
    let Some(value) = value else {
        return Ok(());
    };
    let object = value.as_object().ok_or(Reject::InvalidBody)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "type" | "ttl"))
        || object.get("type").and_then(Value::as_str) != Some("ephemeral")
        || object
            .get("ttl")
            .is_some_and(|ttl| !matches!(ttl.as_str(), Some("5m" | "1h")))
    {
        return Err(Reject::InvalidBody);
    }
    Ok(())
}

fn validate_tools(value: &Value) -> Result<(), Reject> {
    let tools = value.as_array().ok_or(Reject::InvalidBody)?;
    if tools.len() > 128 {
        return Err(Reject::InvalidBody);
    }
    for tool in tools {
        let object = tool.as_object().ok_or(Reject::InvalidBody)?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "type" | "name" | "description" | "input_schema" | "cache_control" | "strict"
            )
        }) || object
            .get("type")
            .is_some_and(|value| value.as_str() != Some("custom"))
            || object
                .get("name")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || object
                .get("input_schema")
                .and_then(Value::as_object)
                .is_none()
            || object
                .get("description")
                .is_some_and(|value| value.as_str().is_none())
            || object
                .get("strict")
                .is_some_and(|value| value.as_bool().is_none())
        {
            return Err(Reject::InvalidBody);
        }
        validate_cache_control(object.get("cache_control"))?;
    }
    Ok(())
}

fn validate_tool_choice(value: &Value) -> Result<(), Reject> {
    let object = value.as_object().ok_or(Reject::InvalidBody)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "type" | "name" | "disable_parallel_tool_use"))
        || !matches!(
            object.get("type").and_then(Value::as_str),
            Some("auto" | "any" | "tool" | "none")
        )
        || object
            .get("name")
            .is_some_and(|value| value.as_str().is_none())
        || object
            .get("disable_parallel_tool_use")
            .is_some_and(|value| value.as_bool().is_none())
    {
        return Err(Reject::InvalidBody);
    }
    if object.get("type").and_then(Value::as_str) == Some("tool")
        && object.get("name").and_then(Value::as_str).is_none()
    {
        return Err(Reject::InvalidBody);
    }
    Ok(())
}

fn validate_thinking(value: &Value) -> Result<(), Reject> {
    let object = value.as_object().ok_or(Reject::InvalidBody)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "type" | "budget_tokens" | "effort"))
        || !matches!(
            object.get("type").and_then(Value::as_str),
            Some("enabled" | "adaptive" | "disabled")
        )
        || object.get("budget_tokens").is_some_and(|value| {
            value
                .as_u64()
                .is_none_or(|value| value == 0 || value > MAX_TOKEN_FIELD_VALUE)
        })
        || object
            .get("effort")
            .is_some_and(|value| !matches!(value.as_str(), Some("low" | "medium" | "high" | "max")))
    {
        return Err(Reject::InvalidBody);
    }
    Ok(())
}

fn validate_output_config(value: &Value) -> Result<(), Reject> {
    let object = value.as_object().ok_or(Reject::InvalidBody)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "effort" | "format"))
        || object
            .get("effort")
            .is_some_and(|value| !matches!(value.as_str(), Some("low" | "medium" | "high" | "max")))
    {
        return Err(Reject::InvalidBody);
    }
    if let Some(format) = object.get("format") {
        let format = format.as_object().ok_or(Reject::InvalidBody)?;
        if format
            .keys()
            .any(|key| !matches!(key.as_str(), "type" | "schema"))
            || format.get("type").and_then(Value::as_str) != Some("json_schema")
            || format.get("schema").and_then(Value::as_object).is_none()
        {
            return Err(Reject::InvalidBody);
        }
    }
    Ok(())
}

async fn read_bounded_response(response: reqwest::Response) -> Result<Vec<u8>, Reject> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| Reject::UpstreamTransport)?;
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BODY {
            return Err(Reject::Upstream);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn canonicalize_response_identity(
    bytes: &[u8],
    expected_raw_model: &str,
    canonical_model: &str,
) -> Result<Vec<u8>, Reject> {
    let mut value = parse_unique_json(bytes).map_err(|_| Reject::Upstream)?;
    let object = value.as_object_mut().ok_or(Reject::Upstream)?;
    let raw_model = object
        .get("model")
        .and_then(Value::as_str)
        .ok_or(Reject::Upstream)?;
    if raw_model != expected_raw_model {
        return Err(Reject::ModelIdentityMismatch);
    }
    object.insert(
        "model".to_owned(),
        Value::String(canonical_model.to_owned()),
    );
    serde_json::to_vec(&value).map_err(|_| Reject::Upstream)
}

type BoxBodyStream = futures_util::stream::BoxStream<'static, Result<Bytes, io::Error>>;

async fn validate_stream_identity(
    mut source: BoxBodyStream,
    expected_raw_model: &str,
    canonical_model: &str,
) -> Result<(Bytes, BoxBodyStream), Reject> {
    let mut buffer = Vec::new();
    let mut scanned = 0usize;
    let mut preamble_bytes = 0usize;
    loop {
        let Some(next) = source.next().await else {
            return Err(Reject::Upstream);
        };
        let chunk = next.map_err(|_| Reject::UpstreamTransport)?;
        buffer.extend_from_slice(&chunk);
        loop {
            let Some((frame_end, separator_end)) = find_sse_frame(&buffer[scanned..]) else {
                if buffer.len().saturating_sub(scanned) > MAX_STREAM_PREAMBLE
                    || preamble_bytes.saturating_add(buffer.len().saturating_sub(scanned))
                        > MAX_STREAM_PREAMBLE
                {
                    return Err(Reject::Upstream);
                }
                break;
            };
            let frame_start = scanned;
            let frame_end = scanned + frame_end;
            let after_frame = scanned + separator_end;
            let frame = &buffer[frame_start..frame_end];
            preamble_bytes = preamble_bytes.saturating_add(after_frame - frame_start);
            if preamble_bytes > MAX_STREAM_PREAMBLE {
                return Err(Reject::Upstream);
            }
            match parse_sse_preamble_frame(frame, expected_raw_model, canonical_model)? {
                StreamPreambleEvent::Empty | StreamPreambleEvent::Ping => {
                    scanned = after_frame;
                }
                StreamPreambleEvent::MessageStart(canonical_frame) => {
                    let capacity = buffer
                        .len()
                        .saturating_sub(after_frame - frame_start)
                        .saturating_add(canonical_frame.len());
                    let mut preamble = Vec::with_capacity(capacity);
                    preamble.extend_from_slice(&buffer[..frame_start]);
                    preamble.extend_from_slice(&canonical_frame);
                    preamble.extend_from_slice(&buffer[after_frame..]);
                    return Ok((Bytes::from(preamble), source));
                }
                StreamPreambleEvent::Other => return Err(Reject::Upstream),
            }
        }
        if buffer.len().saturating_sub(scanned) > MAX_STREAM_PREAMBLE {
            return Err(Reject::Upstream);
        }
        if scanned > 0 && scanned >= buffer.len() / 2 {
            buffer.drain(..scanned);
            scanned = 0;
        }
    }
}

/// Preserve the AWS event bytes while requiring a well-formed terminal event.
/// The stream is deliberately not retried: an interrupted response becomes a
/// body error after the already validated message-start event.
fn guard_stream(source: BoxBodyStream) -> BoxBodyStream {
    let guarded = stream::unfold(
        (source, Vec::new(), 0usize, false, false, false),
        |(mut source, mut pending, mut total, mut started, mut terminal, failed)| async move {
            if failed {
                return None;
            }
            match source.next().await {
                Some(Ok(chunk)) => {
                    total = total.saturating_add(chunk.len());
                    let early_end = if total > MAX_RESPONSE_BODY {
                        Some(StreamEnd::ResponseBodyLimit)
                    } else if terminal && !chunk.is_empty() {
                        Some(StreamEnd::DataAfterTerminal)
                    } else {
                        None
                    };
                    if let Some(end) = early_end {
                        return Some((
                            Err(end.into_error()),
                            (source, pending, total, started, terminal, true),
                        ));
                    }
                    // `pending` holds no separator yet, so scan only the new
                    // bytes (less a separator's overlap): a frame near the bound
                    // must not be rescanned on every chunk.
                    let scanned = pending.len().saturating_sub(3);
                    pending.extend_from_slice(&chunk);
                    let mut consumed = 0usize;
                    while let Some((frame_end, separator_end)) =
                        find_sse_frame(&pending[consumed.max(scanned)..])
                    {
                        let base = consumed.max(scanned);
                        let start = consumed;
                        let frame_end = base + frame_end;
                        let after_frame = base + separator_end;
                        if frame_end - start > MAX_STREAM_FRAME {
                            return Some((
                                Err(StreamEnd::FrameLimit.into_error()),
                                (source, pending, total, started, terminal, true),
                            ));
                        }
                        match parse_stream_event(&pending[start..frame_end]) {
                            Ok(StreamEvent::Empty | StreamEvent::Ping) if !terminal => {}
                            Ok(StreamEvent::MessageStart) if !started && !terminal => {
                                started = true;
                            }
                            Ok(StreamEvent::MessageStop | StreamEvent::Error)
                                if started && !terminal =>
                            {
                                terminal = true;
                            }
                            Ok(StreamEvent::Other) if started && !terminal => {}
                            _ => {
                                return Some((
                                    Err(StreamEnd::InvalidEvent.into_error()),
                                    (source, pending, total, started, terminal, true),
                                ));
                            }
                        }
                        consumed = after_frame;
                        if terminal && consumed < pending.len() {
                            return Some((
                                Err(StreamEnd::DataAfterTerminal.into_error()),
                                (source, pending, total, started, terminal, true),
                            ));
                        }
                    }
                    if pending.len().saturating_sub(consumed) > MAX_STREAM_FRAME {
                        return Some((
                            Err(StreamEnd::FrameLimit.into_error()),
                            (source, pending, total, started, terminal, true),
                        ));
                    }
                    if consumed > 0 {
                        pending.drain(..consumed);
                    }
                    Some((
                        Ok(chunk),
                        (source, pending, total, started, terminal, false),
                    ))
                }
                Some(Err(_)) => Some((
                    Err(StreamEnd::UpstreamInterrupted.into_error()),
                    (source, pending, total, started, terminal, true),
                )),
                None if terminal && pending.is_empty() => None,
                None => Some((
                    Err(StreamEnd::MissingTerminal.into_error()),
                    (source, pending, total, started, terminal, true),
                )),
            }
        },
    );
    guarded.boxed()
}

/// Why [`guard_stream`] ended a response body early. Logged by name only:
/// no event bytes or sizes from the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamEnd {
    ResponseBodyLimit,
    DataAfterTerminal,
    InvalidEvent,
    FrameLimit,
    MissingTerminal,
    UpstreamInterrupted,
}

impl StreamEnd {
    fn reason(self) -> &'static str {
        match self {
            Self::ResponseBodyLimit => "response_body_limit",
            Self::DataAfterTerminal => "data_after_terminal",
            Self::InvalidEvent => "invalid_event",
            Self::FrameLimit => "frame_limit",
            Self::MissingTerminal => "missing_terminal",
            Self::UpstreamInterrupted => "upstream_interrupted",
        }
    }

    fn into_error(self) -> io::Error {
        tracing::warn!(reason = self.reason(), "Bedrock Mantle stream ended early");
        let (kind, message) = match self {
            Self::ResponseBodyLimit | Self::InvalidEvent => (
                io::ErrorKind::InvalidData,
                "invalid Bedrock Mantle event stream",
            ),
            Self::DataAfterTerminal => (
                io::ErrorKind::InvalidData,
                "data follows terminal Bedrock Mantle event",
            ),
            Self::FrameLimit => (
                io::ErrorKind::InvalidData,
                "oversized Bedrock Mantle event frame",
            ),
            Self::MissingTerminal => (
                io::ErrorKind::UnexpectedEof,
                "Bedrock Mantle event stream ended without a terminal event",
            ),
            Self::UpstreamInterrupted => (
                io::ErrorKind::ConnectionReset,
                "upstream stream interrupted",
            ),
        };
        io::Error::new(kind, message)
    }
}

enum StreamEvent {
    Empty,
    Ping,
    MessageStart,
    MessageStop,
    Error,
    Other,
}

fn parse_stream_event(frame: &[u8]) -> Result<StreamEvent, Reject> {
    let text = std::str::from_utf8(frame).map_err(|_| Reject::Upstream)?;
    let mut event = None;
    let mut data: Option<Vec<u8>> = None;
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        if let Some(value) = line.strip_prefix("event:") {
            if event.replace(value.trim_start()).is_some() {
                return Err(Reject::Upstream);
            }
        } else if let Some(value) = line.strip_prefix("data:") {
            if data.is_some() {
                return Err(Reject::Upstream);
            }
            data = Some(value.trim_start().as_bytes().to_vec());
        } else {
            return Err(Reject::Upstream);
        }
    }
    let Some(event) = event else {
        return if data.is_none() {
            Ok(StreamEvent::Empty)
        } else {
            Err(Reject::Upstream)
        };
    };
    if event == "ping" {
        if let Some(data) = data {
            if !data.is_empty()
                && parse_unique_json(&data)
                    .ok()
                    .and_then(|value| value.get("type").and_then(Value::as_str).map(str::to_owned))
                    .as_deref()
                    != Some("ping")
            {
                return Err(Reject::Upstream);
            }
        }
        return Ok(StreamEvent::Ping);
    }
    let data = data
        .filter(|data| !data.is_empty())
        .ok_or(Reject::Upstream)?;
    let value = parse_unique_json(&data).map_err(|_| Reject::Upstream)?;
    if value.get("type").and_then(Value::as_str) != Some(event) {
        return Err(Reject::Upstream);
    }
    match event {
        "message_start" => Ok(StreamEvent::MessageStart),
        "message_stop" => Ok(StreamEvent::MessageStop),
        "error" => Ok(StreamEvent::Error),
        "content_block_start" | "content_block_delta" | "content_block_stop" | "message_delta" => {
            Ok(StreamEvent::Other)
        }
        _ => Err(Reject::Upstream),
    }
}

enum StreamPreambleEvent {
    Empty,
    Ping,
    MessageStart(Vec<u8>),
    Other,
}

fn parse_sse_preamble_frame(
    frame: &[u8],
    expected_raw_model: &str,
    canonical_model: &str,
) -> Result<StreamPreambleEvent, Reject> {
    let text = std::str::from_utf8(frame).map_err(|_| Reject::Upstream)?;
    let mut event = None;
    let mut data = Vec::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        if let Some(value) = line.strip_prefix("event:") {
            if event.is_some() {
                return Err(Reject::Upstream);
            }
            event = Some(value.trim_start());
        } else if let Some(value) = line.strip_prefix("data:") {
            if !data.is_empty() {
                return Err(Reject::Upstream);
            }
            data.extend_from_slice(value.trim_start().as_bytes());
        } else {
            return Err(Reject::Upstream);
        }
    }
    let Some(event) = event else {
        return if data.is_empty() {
            Ok(StreamPreambleEvent::Empty)
        } else {
            Err(Reject::Upstream)
        };
    };
    if event == "ping" {
        if !data.is_empty() {
            let ping = parse_unique_json(&data).map_err(|_| Reject::Upstream)?;
            if ping.get("type").and_then(Value::as_str) != Some("ping") {
                return Err(Reject::Upstream);
            }
        }
        return Ok(StreamPreambleEvent::Ping);
    }
    if event != "message_start" || data.is_empty() {
        return Ok(StreamPreambleEvent::Other);
    }
    let mut value = parse_unique_json(&data).map_err(|_| Reject::Upstream)?;
    if value.get("type").and_then(Value::as_str) != Some("message_start") {
        return Err(Reject::Upstream);
    }
    let message = value
        .get_mut("message")
        .and_then(Value::as_object_mut)
        .ok_or(Reject::Upstream)?;
    let raw_model = message
        .get("model")
        .and_then(Value::as_str)
        .ok_or(Reject::Upstream)?;
    if raw_model != expected_raw_model {
        return Err(Reject::ModelIdentityMismatch);
    }
    message.insert(
        "model".to_owned(),
        Value::String(canonical_model.to_owned()),
    );
    let data = serde_json::to_string(&value).map_err(|_| Reject::Upstream)?;
    Ok(StreamPreambleEvent::MessageStart(
        format!("event: message_start\ndata: {data}\n\n").into_bytes(),
    ))
}

fn find_sse_frame(bytes: &[u8]) -> Option<(usize, usize)> {
    let lf = bytes.windows(2).position(|window| window == b"\n\n");
    let crlf = bytes.windows(4).position(|window| window == b"\r\n\r\n");
    match (lf, crlf) {
        (Some(lf), Some(crlf)) if crlf < lf => Some((crlf, crlf + 4)),
        (Some(lf), _) => Some((lf, lf + 2)),
        (None, Some(crlf)) => Some((crlf, crlf + 4)),
        (None, None) => None,
    }
}

fn parse_unique_json(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    Ok(value)
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("invalid number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            let value = map.next_value::<UniqueValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

fn response(status: StatusCode, content_type: &'static str, body: Body) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .body(body)
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn response_with_binding_revision(
    status: StatusCode,
    content_type: &'static str,
    body: Body,
    revision: u64,
) -> Response<Body> {
    let mut response = response(status, content_type, body);
    if let Ok(value) = HeaderValue::from_str(&revision.to_string()) {
        response
            .headers_mut()
            .insert(MODEL_BINDING_REVISION_HEADER, value);
    }
    response
}

fn upstream_url(test_override: Option<&str>) -> &str {
    test_override.unwrap_or(BEDROCK_MANTLE_URL)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions use known-valid fixtures"
)]
mod tests {
    use super::*;
    use axum::{
        body::to_bytes,
        routing::{get, post},
    };
    use serde_json::json;
    use tokio::task::JoinHandle;

    const VALID_BODY: &str = r#"{"model":"test-model-a","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}"#;

    #[test]
    fn production_transport_initializes_with_explicit_crypto_provider() {
        assert!(production_http_client().is_ok());
    }

    #[test]
    fn request_model_is_validated_and_left_for_registry_binding_rewrite() {
        let (value, streaming) = prepare_request_body(VALID_BODY.as_bytes()).expect("body");
        assert_eq!(value["model"], TEST_MODEL_A);
        assert_eq!(value["messages"][0]["content"], "hello");
        assert!(!streaming);
        for model in ["anthropic/test-model-a", "bad model"] {
            let body = VALID_BODY.replace(TEST_MODEL_A, model);
            assert_eq!(
                prepare_request_body(body.as_bytes()),
                Err(Reject::InvalidBody)
            );
        }
        let selector_looking_canonical = VALID_BODY.replace(TEST_MODEL_A, "anthropic.test-model-a");
        assert!(prepare_request_body(selector_looking_canonical.as_bytes()).is_ok());
    }

    #[test]
    fn token_fields_use_protocol_integer_bounds_not_current_model_limits() {
        let body = VALID_BODY.replace("\"max_tokens\":32", "\"max_tokens\":128001");
        assert!(prepare_request_body(body.as_bytes()).is_ok());
        let largest = VALID_BODY.replace("\"max_tokens\":32", "\"max_tokens\":4294967295");
        assert!(prepare_request_body(largest.as_bytes()).is_ok());
        for invalid in [
            VALID_BODY.replace("\"max_tokens\":32", "\"max_tokens\":4294967296"),
            VALID_BODY.replace("\"max_tokens\":32", "\"max_tokens\":32.5"),
            VALID_BODY.replace("\"max_tokens\":32", "\"max_tokens\":-1"),
        ] {
            assert_eq!(
                prepare_request_body(invalid.as_bytes()),
                Err(Reject::InvalidBody)
            );
        }
    }

    #[test]
    fn parser_rejects_duplicate_selectors_and_nested_duplicate_fields() {
        let duplicate_model = br#"{"model":"test-model-a","model":"test-model-b","max_tokens":32,"messages":[{"role":"user","content":"x"}]}"#;
        assert_eq!(
            prepare_request_body(duplicate_model),
            Err(Reject::InvalidBody)
        );
        let duplicate_nested = br#"{"model":"test-model-a","max_tokens":32,"messages":[{"role":"user","content":[{"type":"text","text":"a","text":"b"}]}]}"#;
        assert_eq!(
            prepare_request_body(duplicate_nested),
            Err(Reject::InvalidBody)
        );
    }

    #[test]
    fn registry_binding_parser_enforces_the_shared_snapshot_contract() {
        let valid = r#"{"schema_version":1,"network":"mainnet","revision":9,"bindings":[{"provider":"anthropic","model":"future-model:2027","upstream_model":"anthropic.future-model-2027-v1","response_model":"future-model-provider-echo","revision":4}]}"#;
        let snapshot = parse_bindings_payload(valid.as_bytes(), "mainnet").expect("valid snapshot");
        assert_eq!(snapshot.revision, 9);
        assert_eq!(snapshot.bindings["future-model:2027"].revision, 4);
        for invalid in [
            valid.replace("\"revision\":9", "\"revision\":9,\"revision\":9"),
            valid.replace(
                "\"model\":\"future-model:2027\"",
                "\"model\":\"future-model:2027\",\"model\":\"other\"",
            ),
            valid.replace("\"revision\":4", "\"revision\":10"),
            valid.replace("\"revision\":9", "\"revision\":9007199254740992"),
            valid.replace("\"model\":\"future-model:2027\"", "\"model\":\"bad/model\""),
            valid.replace("\"provider\":\"anthropic\"", "\"provider\":\"openai\""),
            valid.replace(
                "\"response_model\":\"future-model-provider-echo\"",
                "\"response_model\":\"future-model-provider-echo\",\"custom\":true",
            ),
            valid.replace("\"network\":\"mainnet\"", "\"network\":\"testnet\""),
        ] {
            assert!(parse_bindings_payload(invalid.as_bytes(), "mainnet").is_err());
        }
        let wrong_selector = valid.replace(
            "anthropic.future-model-2027-v1",
            "arn:aws:bedrock:us-east-1:123456789012:custom-model/foo",
        );
        assert!(parse_bindings_payload(wrong_selector.as_bytes(), "mainnet").is_err());
        let fractional_revision = valid.replace("\"revision\":9", "\"revision\":9.0");
        assert!(parse_bindings_payload(fractional_revision.as_bytes(), "mainnet").is_err());
        let overlong_model = valid.replace(
            "future-model:2027",
            &format!("m{}", "x".repeat(MAX_MODEL_ID_BYTES)),
        );
        assert!(parse_bindings_payload(overlong_model.as_bytes(), "mainnet").is_err());

        let rows = (0..=MAX_MODEL_BINDINGS)
            .map(|index| {
                json!({
                    "provider": "anthropic",
                    "model": format!("future-model-{index}"),
                    "upstream_model": format!("anthropic.system-{index}"),
                    "response_model": format!("raw-echo-{index}"),
                    "revision": 1,
                })
            })
            .collect::<Vec<_>>();
        let too_many = serde_json::to_vec(&json!({
            "schema_version": 1,
            "network": "mainnet",
            "revision": 1,
            "bindings": rows,
        }))
        .expect("test JSON");
        assert!(parse_bindings_payload(&too_many, "mainnet").is_err());

        let aliases = r#"{"schema_version":1,"network":"mainnet","revision":9,"bindings":[{"provider":"anthropic","model":"future-model-one","upstream_model":"anthropic.shared-system-id","response_model":"shared-provider-echo","revision":4},{"provider":"anthropic","model":"future-model-two","upstream_model":"anthropic.shared-system-id","response_model":"shared-provider-echo","revision":5}]}"#;
        assert_eq!(
            parse_bindings_payload(aliases.as_bytes(), "mainnet")
                .expect("aliases may share raw selector and response echo")
                .bindings
                .len(),
            2
        );
    }

    #[test]
    fn binding_cache_requires_monotonic_snapshots_and_bounded_freshness() {
        let now = Instant::now();
        let snapshot = test_bindings_payload();
        let mut cache = BindingCache::with_snapshot(snapshot.clone(), now);
        assert!(cache
            .current_binding(
                TEST_MODEL_A,
                TEST_MODEL_REVISION_A,
                now + BINDINGS_FRESHNESS_TTL
            )
            .is_ok());
        assert_eq!(
            cache.current_binding(
                TEST_MODEL_A,
                TEST_MODEL_REVISION_A,
                now + BINDINGS_FRESHNESS_TTL + Duration::from_millis(1),
            ),
            Err(Reject::BindingsUnavailable)
        );

        let refreshed_at = (now + BINDINGS_FRESHNESS_TTL)
            .checked_sub(Duration::from_secs(1))
            .expect("test instant is safely in the future");
        cache
            .apply(snapshot.clone(), refreshed_at)
            .expect("same payload refresh");
        assert!(cache
            .current_binding(
                TEST_MODEL_A,
                TEST_MODEL_REVISION_A,
                refreshed_at + BINDINGS_FRESHNESS_TTL,
            )
            .is_ok());

        let lower = BindingsSnapshot {
            revision: snapshot.revision - 1,
            ..snapshot.clone()
        };
        assert!(cache
            .apply(lower, refreshed_at + Duration::from_secs(1))
            .is_err());
        let changed_same_revision = BindingsSnapshot {
            bindings: BTreeMap::new(),
            ..snapshot.clone()
        };
        assert!(cache
            .apply(changed_same_revision, refreshed_at + Duration::from_secs(1))
            .is_err());
        assert_eq!(
            cache.current_binding(
                TEST_MODEL_A,
                TEST_MODEL_REVISION_A,
                refreshed_at + BINDINGS_FRESHNESS_TTL + Duration::from_millis(1),
            ),
            Err(Reject::BindingsUnavailable),
            "rejected refreshes must not renew binding freshness"
        );
    }

    #[test]
    fn binding_rows_cannot_roll_back_change_in_place_or_return_after_revocation() {
        let now = Instant::now();
        let original = test_bindings_payload();
        let mut cache = BindingCache::with_snapshot(original.clone(), now);

        let rollback = BindingsSnapshot {
            revision: original.revision + 1,
            bindings: BTreeMap::from([(
                TEST_MODEL_A.to_owned(),
                ModelBinding {
                    revision: TEST_MODEL_REVISION_A - 1,
                    ..original.bindings[TEST_MODEL_A].clone()
                },
            )]),
            ..original.clone()
        };
        assert!(cache.apply(rollback, now + Duration::from_secs(1)).is_err());

        let equivocation = BindingsSnapshot {
            revision: original.revision + 1,
            bindings: BTreeMap::from([(
                TEST_MODEL_A.to_owned(),
                ModelBinding {
                    upstream_model: "anthropic.changed-without-row-revision".to_owned(),
                    ..original.bindings[TEST_MODEL_A].clone()
                },
            )]),
            ..original.clone()
        };
        assert!(cache
            .apply(equivocation, now + Duration::from_secs(1))
            .is_err());

        let revoked = BindingsSnapshot {
            revision: original.revision + 1,
            bindings: BTreeMap::new(),
            ..original.clone()
        };
        cache
            .apply(revoked, now + Duration::from_secs(1))
            .expect("advance snapshot to revoke row");
        let stale_readd = BindingsSnapshot {
            revision: original.revision + 2,
            ..original.clone()
        };
        assert!(cache
            .apply(stale_readd, now + Duration::from_secs(2))
            .is_err());

        let valid_readd = BindingsSnapshot {
            revision: original.revision + 2,
            bindings: BTreeMap::from([(
                TEST_MODEL_A.to_owned(),
                ModelBinding {
                    revision: TEST_MODEL_REVISION_A + 1,
                    ..original.bindings[TEST_MODEL_A].clone()
                },
            )]),
            ..original
        };
        cache
            .apply(valid_readd, now + Duration::from_secs(2))
            .expect("re-add row only with a higher row revision");
    }

    #[test]
    fn rejects_cloudtrail_selector_type_confusion_and_unknown_capture_fields() {
        for field in [
            r#""stream":"false""#,
            r#""max_tokens":"32""#,
            r#""metadata":{"user_id":"buyer"}"#,
            r#""mcp_servers":[]"#,
            r#""container":{"id":"remote"}"#,
            r#""unknown_feature":true"#,
        ] {
            let body = format!(
                r#"{{"model":"{TEST_MODEL_A}","max_tokens":32,"messages":[{{"role":"user","content":"hello"}}],{field}}}"#
            );
            assert_eq!(
                prepare_request_body(body.as_bytes()),
                Err(Reject::InvalidBody),
                "{field}"
            );
        }
    }

    #[test]
    fn preserves_client_side_tool_workflows_and_inline_media_semantically() {
        let value = json!({
            "model": TEST_MODEL_A,
            "max_tokens": 1024,
            "stream": true,
            "system": [{ "type": "text", "text": "follow the tool schema", "cache_control": { "type": "ephemeral", "ttl": "5m" } }],
            "tools": [{
                "name": "lookup_order",
                "description": "Read order data",
                "input_schema": { "type": "object", "properties": { "id": { "type": "string" } }, "required": ["id"] }
            }],
            "tool_choice": { "type": "auto" },
            "messages": [
                { "role": "user", "content": [{ "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "aGVsbG8=" } }] },
                { "role": "assistant", "content": [{ "type": "tool_use", "id": "toolu_1", "name": "lookup_order", "input": { "id": "42" } }] },
                { "role": "user", "content": [{ "type": "tool_result", "tool_use_id": "toolu_1", "content": "order found" }] },
                { "role": "assistant", "content": [{ "type": "text", "text": "done" }] }
            ]
        });
        let bytes = serde_json::to_vec(&value).expect("json");
        let (rewritten, stream) = prepare_request_body(&bytes).expect("tool workflow");
        assert_eq!(rewritten["model"], TEST_MODEL_A);
        assert_eq!(rewritten["messages"], value["messages"]);
        assert_eq!(rewritten["tools"], value["tools"]);
        assert_eq!(rewritten["system"], value["system"]);
        assert!(stream);
    }

    #[test]
    fn rejects_server_side_tools_and_external_or_file_media() {
        let bodies = [
            r#"{"type":"web_search_20250305","name":"search","input_schema":{"type":"object"}}"#,
            r#"{"type":"mcp_toolset","mcp_servers":[]}"#,
        ];
        for tool in bodies {
            let body = format!("{{\"model\":\"{TEST_MODEL_A}\",\"max_tokens\":32,\"tools\":[{tool}],\"messages\":[{{\"role\":\"user\",\"content\":\"x\"}}]}}" );
            assert_eq!(
                prepare_request_body(body.as_bytes()),
                Err(Reject::InvalidBody)
            );
        }
        for source in [
            r#"{"type":"url","url":"https://example.invalid/prompt.pdf"}"#,
            r#"{"type":"file_id","file_id":"file_123"}"#,
        ] {
            let body = format!("{{\"model\":\"{TEST_MODEL_A}\",\"max_tokens\":32,\"messages\":[{{\"role\":\"user\",\"content\":[{{\"type\":\"image\",\"source\":{source}}}]}}]}}" );
            assert_eq!(
                prepare_request_body(body.as_bytes()),
                Err(Reject::InvalidBody)
            );
        }
    }

    #[test]
    fn identity_mismatch_is_distinct_from_malformed_upstream() {
        let wrong = canonicalize_response_identity(
            br#"{"model":"different-model"}"#,
            TEST_RESPONSE_MODEL_A,
            TEST_MODEL_A,
        )
        .expect_err("wrong identity");
        let malformed =
            canonicalize_response_identity(b"not json", TEST_RESPONSE_MODEL_A, TEST_MODEL_A)
                .expect_err("malformed JSON");
        assert_ne!(
            wrong, malformed,
            "identity rejection must be diagnostically distinct"
        );
    }

    #[tokio::test]
    async fn diagnostics_preserve_content_free_public_errors() {
        for (failure, reason, status) in [
            (Reject::Upstream, "upstream_response_invalid", None),
            (Reject::UpstreamTransport, "upstream_transport_failed", None),
            (
                Reject::UpstreamHttp(403),
                "upstream_http_rejected",
                Some(403),
            ),
            (
                Reject::ModelIdentityMismatch,
                "model_identity_mismatch",
                None,
            ),
        ] {
            assert_eq!(failure.upstream_diagnostic(), Some((reason, status)));
            let response = failure.into_response();
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            let body = to_bytes(response.into_body(), 4096)
                .await
                .expect("error body");
            assert_eq!(
                body.as_ref(),
                br#"{"error":{"type":"api_error","message":"Bedrock Mantle request failed"}}"#
            );
        }
        assert_eq!(Reject::InvalidBody.upstream_diagnostic(), None);
        assert_eq!(
            canonicalize_response_identity(
                br#"{"content":[]}"#,
                TEST_RESPONSE_MODEL_A,
                TEST_MODEL_A
            ),
            Err(Reject::Upstream)
        );
    }

    #[tokio::test]
    async fn interrupted_response_bodies_are_transport_failures() {
        let failed = || {
            stream::iter([Err::<Bytes, io::Error>(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "private transport details",
            ))])
        };
        let response = reqwest::Response::from(
            Response::builder()
                .status(200)
                .body(reqwest::Body::wrap_stream(failed()))
                .expect("HTTP response"),
        );
        assert_eq!(
            read_bounded_response(response).await,
            Err(Reject::UpstreamTransport)
        );
        assert!(matches!(
            validate_stream_identity(failed().boxed(), TEST_RESPONSE_MODEL_A, TEST_MODEL_A).await,
            Err(Reject::UpstreamTransport)
        ));
    }

    #[tokio::test]
    async fn upstream_http_rejection_is_not_an_identity_mismatch() {
        let binding = test_bindings_payload().bindings[TEST_MODEL_A].clone();
        let upstream = reqwest::Response::from(
            Response::builder()
                .status(403)
                .body("private provider error details")
                .expect("HTTP response"),
        );
        let failure = finish_upstream_response(upstream, &binding, false)
            .await
            .expect_err("upstream rejection");
        assert_eq!(failure, Reject::UpstreamHttp(403));
    }

    #[test]
    fn response_identity_is_checked_raw_then_canonicalized() {
        let correct = br#"{"id":"msg_1","type":"message","model":"test-model-a-provider-echo","content":[],"stop_reason":"end_turn"}"#;
        let canonical =
            canonicalize_response_identity(correct, TEST_RESPONSE_MODEL_A, TEST_MODEL_A)
                .expect("identity");
        let value: Value = serde_json::from_slice(&canonical).expect("canonical JSON");
        assert_eq!(value["model"], TEST_MODEL_A);
        let wrong = br#"{"model":"test-model-a-v2"}"#;
        assert_eq!(
            canonicalize_response_identity(wrong, TEST_RESPONSE_MODEL_A, TEST_MODEL_A),
            Err(Reject::ModelIdentityMismatch)
        );
        let duplicate = br#"{"model":"test-model-a-provider-echo","model":"test-model-a-v2"}"#;
        assert_eq!(
            canonicalize_response_identity(duplicate, TEST_RESPONSE_MODEL_A, TEST_MODEL_A),
            Err(Reject::Upstream)
        );
    }

    #[tokio::test]
    async fn stream_is_not_released_before_the_identity_event() {
        let wrong = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"test-model-a-v2\"}}\n\n";
        let chunks = stream::iter([Ok(Bytes::copy_from_slice(wrong))]).boxed();
        assert!(matches!(
            validate_stream_identity(chunks, TEST_RESPONSE_MODEL_A, TEST_MODEL_A).await,
            Err(Reject::ModelIdentityMismatch)
        ));
        let duplicate = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"test-model-a-provider-echo\",\"model\":\"test-model-a-v2\"}}\n\n";
        let chunks = stream::iter([Ok(Bytes::copy_from_slice(duplicate))]).boxed();
        assert!(
            validate_stream_identity(chunks, TEST_RESPONSE_MODEL_A, TEST_MODEL_A)
                .await
                .is_err()
        );
        let correct = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"test-model-a-provider-echo\"}}\n\n";
        let chunks = stream::iter([Ok(Bytes::copy_from_slice(correct))]).boxed();
        let (preamble, mut rest) =
            validate_stream_identity(chunks, TEST_RESPONSE_MODEL_A, TEST_MODEL_A)
                .await
                .expect("stream identity");
        let canonical = std::str::from_utf8(&preamble).expect("UTF-8 preamble");
        assert!(canonical.contains(TEST_MODEL_A));
        assert!(!canonical.contains(TEST_RESPONSE_MODEL_A));
        assert!(rest.next().await.is_none());
    }

    #[tokio::test]
    async fn guarded_stream_requires_a_terminal_event_and_preserves_valid_bytes() {
        let valid = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"test-model-a\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
        );
        let chunks = stream::iter([Ok(Bytes::from_static(valid.as_bytes()))]).boxed();
        let collected = guard_stream(chunks).collect::<Vec<_>>().await;
        assert_eq!(collected.len(), 1);
        assert_eq!(
            collected[0].as_ref().expect("valid stream").as_ref(),
            valid.as_bytes()
        );

        let unterminated = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"test-model-a\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\"}\n\n"
        );
        let chunks = stream::iter([Ok(Bytes::from_static(unterminated.as_bytes()))]).boxed();
        let collected = guard_stream(chunks).collect::<Vec<_>>().await;
        assert_eq!(collected.len(), 2);
        assert!(collected[0].is_ok());
        assert_eq!(
            collected[1]
                .as_ref()
                .expect_err("missing terminal must fail")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    fn signature_delta_frame(signature_bytes: usize) -> Vec<u8> {
        let mut frame = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"".to_vec();
        frame.resize(frame.len() + signature_bytes, b'A');
        frame.extend_from_slice(b"\"}}\n\n");
        frame
    }

    fn stream_with_frame(frame: &[u8]) -> Vec<u8> {
        let mut body = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"test-model-a\"}}\n\n".to_vec();
        body.extend_from_slice(frame);
        body.extend_from_slice(b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
        body
    }

    fn in_chunks(body: &[u8], chunk_bytes: usize) -> BoxBodyStream {
        let chunks: Vec<Result<Bytes, io::Error>> = body
            .chunks(chunk_bytes)
            .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
            .collect();
        stream::iter(chunks).boxed()
    }

    #[tokio::test]
    async fn guarded_stream_passes_a_signature_frame_larger_than_the_preamble_bound() {
        // A long thinking block ends in one signature frame; at 32k thinking
        // tokens it is about 75 KB, so it arrives split across many reads.
        let body = stream_with_frame(&signature_delta_frame(MAX_STREAM_PREAMBLE + 32 * 1024));
        let collected = guard_stream(in_chunks(&body, 8 * 1024))
            .collect::<Vec<_>>()
            .await;
        let mut forwarded = Vec::new();
        for chunk in collected {
            forwarded.extend_from_slice(&chunk.expect("large frame must pass"));
        }
        assert_eq!(forwarded, body);
    }

    #[tokio::test]
    async fn guarded_stream_finds_separators_split_across_any_chunk_boundary() {
        // Mixed LF and CRLF separators, so each lands across a boundary at
        // some chunk size; a frame left unparsed would end the stream early.
        let body = concat!(
            "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"test-model-a\"}}\r\n\r\n",
            "event: ping\ndata: {\"type\":\"ping\"}\n\n",
            "event: content_block_delta\r\ndata: {\"type\":\"content_block_delta\"}\r\n\r\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
        )
        .as_bytes();
        for chunk_bytes in 1..=7 {
            let mut forwarded = Vec::new();
            for chunk in guard_stream(in_chunks(body, chunk_bytes))
                .collect::<Vec<_>>()
                .await
            {
                forwarded.extend_from_slice(&chunk.expect("valid stream must pass"));
            }
            assert_eq!(forwarded, body, "chunk size {chunk_bytes}");
        }
    }

    /// A signature frame whose event bytes, separator excluded, are `length`.
    fn frame_of_length(length: usize) -> Vec<u8> {
        let overhead = signature_delta_frame(0).len() - b"\n\n".len();
        let frame = signature_delta_frame(length - overhead);
        assert_eq!(frame.len() - 2, length);
        frame
    }

    async fn guard_result(body: &[u8], chunk_bytes: usize) -> Result<Vec<u8>, io::Error> {
        let mut forwarded = Vec::new();
        for chunk in guard_stream(in_chunks(body, chunk_bytes))
            .collect::<Vec<_>>()
            .await
        {
            forwarded.extend_from_slice(&chunk?);
        }
        Ok(forwarded)
    }

    #[tokio::test]
    async fn guarded_stream_applies_the_frame_bound_to_complete_frames() {
        let over = stream_with_frame(&frame_of_length(MAX_STREAM_FRAME + 1));
        for chunk_bytes in [over.len(), 8 * 1024] {
            let error = guard_result(&over, chunk_bytes)
                .await
                .expect_err("a frame over the bound must fail");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{chunk_bytes}");
            assert_eq!(
                error.to_string(),
                "oversized Bedrock Mantle event frame",
                "{chunk_bytes}"
            );
        }
        let at_bound = stream_with_frame(&frame_of_length(MAX_STREAM_FRAME));
        assert_eq!(
            guard_result(&at_bound, at_bound.len())
                .await
                .expect("a frame at the bound must pass"),
            at_bound
        );
    }

    #[tokio::test]
    async fn guarded_stream_holds_exactly_the_frame_bound_of_a_partial_frame() {
        let body = stream_with_frame(&frame_of_length(MAX_STREAM_FRAME));
        let frame_start = body
            .windows(2)
            .position(|window| window == b"\n\n")
            .expect("message_start separator")
            + 2;
        let at_bound = frame_start + MAX_STREAM_FRAME;
        for (split, passes) in [(at_bound, true), (at_bound + 1, false)] {
            let chunks = stream::iter([
                Ok(Bytes::copy_from_slice(&body[..split])),
                Ok(Bytes::copy_from_slice(&body[split..])),
            ])
            .boxed();
            let collected = guard_stream(chunks).collect::<Vec<_>>().await;
            assert_eq!(
                collected.iter().all(Result::is_ok),
                passes,
                "{} buffered bytes",
                split - frame_start
            );
        }
    }

    fn padded_ping(frame_bytes: usize) -> Vec<u8> {
        let mut frame = b"event: ping\ndata: {\"type\":\"ping\",\"pad\":\"".to_vec();
        let closing = b"\"}\n\n";
        frame.resize(frame_bytes - closing.len(), b'A');
        frame.extend_from_slice(closing);
        frame
    }

    /// A valid stream of exactly `total` bytes, padded with ping frames.
    fn stream_of_length(total: usize) -> Vec<u8> {
        let mut padding = Vec::new();
        let mut remaining = total - stream_with_frame(&[]).len();
        while remaining > 0 {
            let frame = remaining.min(1024 * 1024);
            let frame = if remaining - frame < 64 {
                remaining
            } else {
                frame
            };
            padding.extend(padded_ping(frame));
            remaining -= frame;
        }
        stream_with_frame(&padding)
    }

    #[tokio::test]
    async fn guarded_stream_holds_exactly_the_response_body_bound() {
        for (total, passes) in [(MAX_RESPONSE_BODY, true), (MAX_RESPONSE_BODY + 1, false)] {
            let body = stream_of_length(total);
            assert_eq!(body.len(), total);
            let collected = guard_stream(in_chunks(&body, 1024 * 1024))
                .collect::<Vec<_>>()
                .await;
            assert_eq!(collected.iter().all(Result::is_ok), passes, "{total} bytes");
        }
    }

    #[tokio::test]
    async fn guarded_stream_enforces_event_order() {
        let start = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"test-model-a\"}}\n\n";
        let delta = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\"}\n\n";
        let stop = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        for (body, valid) in [
            (format!("{start}{delta}{stop}"), true),
            (format!("{start}{start}{stop}"), false),
            (format!("{delta}{start}{stop}"), false),
            (stop.to_owned(), false),
        ] {
            let chunks = stream::iter([Ok(Bytes::from(body.clone()))]).boxed();
            let collected = guard_stream(chunks).collect::<Vec<_>>().await;
            assert_eq!(collected.iter().all(Result::is_ok), valid, "{body}");
        }
        let after_stop =
            stream::iter([Ok(Bytes::from(format!("{start}{stop}"))), Ok(Bytes::new())]).boxed();
        assert!(guard_stream(after_stop)
            .collect::<Vec<_>>()
            .await
            .iter()
            .all(Result::is_ok));
    }

    #[tokio::test]
    async fn guarded_stream_rejects_a_frame_over_the_frame_bound() {
        // Exceed the bound by more than a chunk, so the partial frame crosses
        // it before the frame can complete.
        let body = stream_with_frame(&signature_delta_frame(MAX_STREAM_FRAME + 16 * 1024));
        let collected = guard_stream(in_chunks(&body, 8 * 1024))
            .collect::<Vec<_>>()
            .await;
        let error = collected
            .last()
            .expect("stream output")
            .as_ref()
            .expect_err("an oversized frame must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(collected.iter().filter(|chunk| chunk.is_err()).count(), 1);
    }

    thread_local! {
        static THREAD_LOG: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    /// Writes into the calling thread's buffer. A `#[tokio::test]` runs on
    /// its own thread, so each test reads only what it logged.
    struct ThreadLog;

    impl io::Write for ThreadLog {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            THREAD_LOG.with(|log| log.borrow_mut().extend_from_slice(bytes));
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A process-wide subscriber: a scoped default races callsite interest
    /// caching against parallel tests that log under no subscriber.
    fn install_thread_log() {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            let subscriber = tracing_subscriber::fmt()
                .with_writer(|| ThreadLog)
                .with_ansi(false)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("no other global subscriber in this test binary");
        });
    }

    async fn guard_log(body: &[u8]) -> String {
        install_thread_log();
        THREAD_LOG.with(|log| log.borrow_mut().clear());
        let _ = guard_stream(in_chunks(body, 8 * 1024))
            .collect::<Vec<_>>()
            .await;
        let bytes = THREAD_LOG.with(|log| std::mem::take(&mut *log.borrow_mut()));
        String::from_utf8(bytes).expect("UTF-8 log")
    }

    #[tokio::test]
    async fn guarded_stream_logs_the_rule_that_ended_it_without_content() {
        let oversized = stream_with_frame(&signature_delta_frame(MAX_STREAM_FRAME + 16 * 1024));
        let log = guard_log(&oversized).await;
        assert!(log.contains("reason=\"frame_limit\""), "log: {log}");
        assert!(!log.contains("AAAA"), "log carries stream bytes: {log}");

        let unknown = stream_with_frame(b"event: unknown\ndata: {\"type\":\"unknown\"}\n\n");
        let log = guard_log(&unknown).await;
        assert!(log.contains("reason=\"invalid_event\""), "log: {log}");
        assert!(!log.contains("unknown"), "log carries stream bytes: {log}");

        let mut after_terminal = stream_with_frame(&[]);
        after_terminal.extend_from_slice(b"event: ping\ndata: {\"type\":\"ping\"}\n\n");
        let log = guard_log(&after_terminal).await;
        assert!(log.contains("reason=\"data_after_terminal\""), "log: {log}");

        let valid = stream_with_frame(&signature_delta_frame(16));
        assert_eq!(guard_log(&valid).await, "");
    }

    #[tokio::test]
    async fn stream_identity_rejects_a_preamble_over_its_bound() {
        let mut ping = b"event: ping\ndata: {\"type\":\"ping\",\"pad\":\"".to_vec();
        ping.resize(ping.len() + MAX_STREAM_PREAMBLE, b'A');
        ping.extend_from_slice(b"\"}\n\n");
        let body = stream_with_frame(&[]);
        let mut oversized = ping;
        oversized.extend_from_slice(&body);
        assert!(matches!(
            validate_stream_identity(
                in_chunks(&oversized, 8 * 1024),
                TEST_RESPONSE_MODEL_A,
                TEST_MODEL_A
            )
            .await,
            Err(Reject::Upstream)
        ));
    }

    #[tokio::test]
    async fn guarded_stream_rejects_data_after_terminal_and_interrupted_transport() {
        let after_terminal = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"test-model-a\"}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            "event: ping\ndata: {\"type\":\"ping\"}\n\n"
        );
        let chunks = stream::iter([Ok(Bytes::from_static(after_terminal.as_bytes()))]).boxed();
        let collected = guard_stream(chunks).collect::<Vec<_>>().await;
        assert_eq!(collected.len(), 1);
        assert_eq!(
            collected[0]
                .as_ref()
                .expect_err("data after terminal must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );

        let interrupted = stream::iter([
            Ok(Bytes::from_static(b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"test-model-a\"}}\n\n")),
            Err(io::Error::new(io::ErrorKind::ConnectionReset, "test interruption")),
        ]).boxed();
        let collected = guard_stream(interrupted).collect::<Vec<_>>().await;
        assert_eq!(collected.len(), 2);
        assert_eq!(
            collected[1]
                .as_ref()
                .expect_err("interrupted stream must fail")
                .kind(),
            io::ErrorKind::ConnectionReset
        );
    }

    #[tokio::test]
    async fn local_proxy_rejects_query_path_and_workspace_before_upstream() {
        let (state, calls) = test_state().await;
        let response = handle_request(
            State(AppState(state.clone())),
            request("/v1/messages?workspace=attacker", VALID_BODY),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let mut workspace = request("/v1/messages", VALID_BODY);
        workspace
            .headers_mut()
            .insert("anthropic-workspace-id", HeaderValue::from_static("other"));
        let response = handle_request(State(AppState(state)), workspace).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn execution_and_binding_revision_headers_must_be_single_and_exact() {
        let (state, calls) = test_state().await;
        let cases = [
            ("missing", {
                let mut request = request("/v1/messages", VALID_BODY);
                request.headers_mut().remove(EXECUTION_POLICY_HEADER);
                request
            }),
            ("duplicate", {
                let mut request = request("/v1/messages", VALID_BODY);
                request.headers_mut().append(
                    EXECUTION_POLICY_HEADER,
                    HeaderValue::from_static(EXACT_CANONICAL_NO_REPLAY_POLICY),
                );
                request
            }),
            ("wrong value", {
                let mut request = request("/v1/messages", VALID_BODY);
                request
                    .headers_mut()
                    .insert(EXECUTION_POLICY_HEADER, HeaderValue::from_static("true"));
                request
            }),
            ("missing binding revision", {
                let mut request = request("/v1/messages", VALID_BODY);
                request.headers_mut().remove(MODEL_BINDING_REVISION_HEADER);
                request
            }),
            ("duplicate binding revision", {
                let mut request = request("/v1/messages", VALID_BODY);
                request
                    .headers_mut()
                    .append(MODEL_BINDING_REVISION_HEADER, HeaderValue::from_static("8"));
                request
            }),
            ("noncanonical binding revision", {
                let mut request = request("/v1/messages", VALID_BODY);
                request.headers_mut().insert(
                    MODEL_BINDING_REVISION_HEADER,
                    HeaderValue::from_static("07"),
                );
                request
            }),
        ];
        for (label, request) in cases {
            let response = handle_request(State(AppState(state.clone())), request).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{label}");
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn stale_model_binding_revision_is_rejected_before_upstream_dispatch() {
        let (state, calls) = test_state().await;
        let mut request = request("/v1/messages", VALID_BODY);
        request
            .headers_mut()
            .insert(MODEL_BINDING_REVISION_HEADER, HeaderValue::from_static("8"));
        let response = handle_request(State(AppState(state)), request).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn expired_binding_snapshot_fails_closed_before_upstream_dispatch() {
        let (state, calls) = test_state().await;
        {
            let mut cache = state.bindings.write().await;
            let current = cache.current.as_mut().expect("test snapshot");
            current.fetched_at = Instant::now()
                .checked_sub(BINDINGS_FRESHNESS_TTL)
                .and_then(|fetched_at| fetched_at.checked_sub(Duration::from_secs(1)))
                .expect("test expiry instant is safely in the past");
        }
        let response =
            handle_request(State(AppState(state)), request("/v1/messages", VALID_BODY)).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn binding_changes_during_body_collection_reject_before_dispatch() {
        for change in ["revision", "removal", "expiry"] {
            let (state, calls) = test_state().await;
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            let body = Body::from_stream(stream::once(async move {
                started_tx.send(()).expect("signal body collection");
                release_rx.await.expect("release body collection");
                Ok::<_, io::Error>(Bytes::from_static(VALID_BODY.as_bytes()))
            }));
            let request = request("/v1/messages", VALID_BODY).map(|_| body);
            let request_state = state.clone();
            let pending = tokio::spawn(async move {
                handle_request(State(AppState(request_state)), request).await
            });
            started_rx.await.expect("body collection started");
            {
                let mut cache = state.bindings.write().await;
                if change == "expiry" {
                    cache.current.as_mut().expect("test snapshot").fetched_at = Instant::now()
                        .checked_sub(BINDINGS_FRESHNESS_TTL + Duration::from_secs(1))
                        .expect("expiry instant");
                } else {
                    let mut snapshot = test_bindings_payload();
                    snapshot.revision += 1;
                    if change == "removal" {
                        snapshot.bindings.clear();
                    } else {
                        snapshot
                            .bindings
                            .get_mut(TEST_MODEL_A)
                            .expect("test row")
                            .revision += 1;
                    }
                    cache
                        .apply(snapshot, Instant::now())
                        .expect("updated snapshot");
                }
            }
            release_tx.send(()).expect("release request body");
            let response = pending.await.expect("request completes");
            let expected = match change {
                "revision" => StatusCode::CONFLICT,
                "removal" => StatusCode::BAD_REQUEST,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            assert_eq!(response.status(), expected, "{change}");
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::Relaxed),
                0,
                "{change}"
            );
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the same running adapter acceptance scenario keeps its state transitions auditable together"
    )]
    async fn one_running_adapter_installs_future_bindings_rewrites_both_response_modes_and_revokes()
    {
        const MODEL_B: &str = "future-model-2027-01";
        const SELECTOR_B: &str = "anthropic.future-model-2027-01-v1";
        const ECHO_B: &str = "future-model-2027-01-provider-echo";
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let upstream_calls = calls.clone();
        let upstream_app = Router::new().route(
            "/anthropic/v1/messages",
            post(move |request: Request<Body>| {
                let upstream_calls = upstream_calls.clone();
                async move {
                    upstream_calls.fetch_add(1, Ordering::Relaxed);
                    let body = to_bytes(request.into_body(), MAX_REQUEST_BODY)
                        .await
                        .expect("upstream request body");
                    let request: Value = serde_json::from_slice(&body).expect("request json");
                    let selector = request["model"].as_str().expect("model selector");
                    let (expected_selector, raw_model) = if selector == TEST_SELECTOR_A {
                        (TEST_SELECTOR_A, TEST_RESPONSE_MODEL_A)
                    } else {
                        (SELECTOR_B, ECHO_B)
                    };
                    assert_eq!(selector, expected_selector);
                    if request["stream"] == true {
                        let message_start = json!({
                            "type": "message_start",
                            "message": {"model": raw_model},
                        });
                        let message_delta = json!({
                            "type": "message_delta",
                            "delta": {"stop_reason": "end_turn"},
                        });
                        let message_stop = json!({"type": "message_stop"});
                        let body = format!(
                            "event: message_start\ndata: {message_start}\n\nevent: message_delta\ndata: {message_delta}\n\nevent: message_stop\ndata: {message_stop}\n\n"
                        );
                        ([(CONTENT_TYPE, "text/event-stream")], body)
                    } else {
                        (
                            [(CONTENT_TYPE, "application/json")],
                            json!({"model": raw_model}).to_string(),
                        )
                    }
                }
            }),
        );
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener");
        let upstream_addr = upstream_listener.local_addr().expect("upstream address");
        let upstream_task = tokio::spawn(async move {
            axum::serve(upstream_listener, upstream_app)
                .await
                .expect("upstream");
        });

        let initial = test_bindings_payload();
        let state = BedrockMantleState::for_test(
            &format!("http://{upstream_addr}/anthropic/v1/messages"),
            "Bearer configured-only",
        );
        let binding_b = ModelBinding {
            provider: "anthropic".to_owned(),
            model: MODEL_B.to_owned(),
            upstream_model: SELECTOR_B.to_owned(),
            response_model: ECHO_B.to_owned(),
            revision: 11,
        };
        let added_snapshot = BindingsSnapshot {
            network: "mainnet".to_owned(),
            revision: 11,
            bindings: BTreeMap::from([
                (
                    TEST_MODEL_A.to_owned(),
                    initial.bindings[TEST_MODEL_A].clone(),
                ),
                (MODEL_B.to_owned(), binding_b.clone()),
            ]),
        };

        let snapshot_body = Arc::new(RwLock::new(snapshot_json(&initial)));
        let registry_body = snapshot_body.clone();
        let registry_app = Router::new().route(
            "/model-bindings/bedrock",
            get(move || {
                let registry_body = registry_body.clone();
                async move {
                    let body = registry_body.read().await.clone();
                    ([(CONTENT_TYPE, "application/json")], body)
                }
            }),
        );
        let registry_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("registry listener");
        let registry_addr = registry_listener.local_addr().expect("registry address");
        let registry_task = tokio::spawn(async move {
            axum::serve(registry_listener, registry_app)
                .await
                .expect("registry");
        });
        let state =
            state.with_test_registry_url(&format!("http://{registry_addr}/model-bindings/bedrock"));
        state
            .refresh_bindings()
            .await
            .expect("install initial model binding");

        let adapter_app = Router::new()
            .route("/v1/messages", any(handle_request))
            .with_state(AppState(state.clone()));
        let adapter_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("adapter listener");
        let adapter_addr = adapter_listener.local_addr().expect("adapter address");
        let adapter_task = tokio::spawn(async move {
            axum::serve(adapter_listener, adapter_app)
                .await
                .expect("adapter");
        });
        let adapter_url = format!("http://{adapter_addr}/v1/messages");
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("adapter test client");

        let denied_before_refresh = format!(
            r#"{{"model":"{MODEL_B}","max_tokens":32,"messages":[{{"role":"user","content":"future"}}]}}"#
        );
        let response = test_adapter_request(&client, &adapter_url, VALID_BODY, "7").await;
        assert_eq!(response.status(), StatusCode::OK);
        let response =
            test_adapter_request(&client, &adapter_url, &denied_before_refresh, "11").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        *snapshot_body.write().await = snapshot_json(&added_snapshot);
        state
            .refresh_bindings()
            .await
            .expect("install future model binding into running adapter");

        let request_b = |streaming: bool, revision: &'static str| {
            let body = if streaming {
                denied_before_refresh
                    .replace("\"max_tokens\":32,", "\"max_tokens\":32,\"stream\":true,")
            } else {
                denied_before_refresh.clone()
            };
            (body, revision)
        };

        let (body, revision) = request_b(false, "11");
        let response = test_adapter_request(&client, &adapter_url, &body, revision).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(MODEL_BINDING_REVISION_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("11")
        );
        let body = response.bytes().await.expect("buffered body");
        let value: Value = serde_json::from_slice(&body).expect("canonical body");
        assert_eq!(value["model"], MODEL_B);

        let (body, revision) = request_b(true, "11");
        let response = test_adapter_request(&client, &adapter_url, &body, revision).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.bytes().await.expect("stream body");
        let text = std::str::from_utf8(&body).expect("SSE body");
        assert!(text.contains(MODEL_B));
        assert!(!text.contains(ECHO_B));
        assert_eq!(calls.load(Ordering::Relaxed), 3);

        let revoked_snapshot = BindingsSnapshot {
            network: "mainnet".to_owned(),
            revision: 12,
            bindings: BTreeMap::from([(
                TEST_MODEL_A.to_owned(),
                initial.bindings[TEST_MODEL_A].clone(),
            )]),
        };
        *snapshot_body.write().await = snapshot_json(&revoked_snapshot);
        state.refresh_bindings().await.expect("revoke future model");
        let (body, revision) = request_b(false, "11");
        let response = test_adapter_request(&client, &adapter_url, &body, revision).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let readded_snapshot = BindingsSnapshot {
            network: "mainnet".to_owned(),
            revision: 13,
            bindings: BTreeMap::from([
                (
                    TEST_MODEL_A.to_owned(),
                    initial.bindings[TEST_MODEL_A].clone(),
                ),
                (
                    MODEL_B.to_owned(),
                    ModelBinding {
                        revision: 13,
                        ..binding_b
                    },
                ),
            ]),
        };
        *snapshot_body.write().await = snapshot_json(&readded_snapshot);
        state.refresh_bindings().await.expect("new row revision");
        let (body, revision) = request_b(false, "11");
        let response = test_adapter_request(&client, &adapter_url, &body, revision).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(calls.load(Ordering::Relaxed), 3);

        adapter_task.abort();
        registry_task.abort();
        upstream_task.abort();
    }

    async fn test_adapter_request(
        client: &Client,
        url: &str,
        body: &str,
        revision: &str,
    ) -> reqwest::Response {
        client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header(EXECUTION_POLICY_HEADER, EXACT_CANONICAL_NO_REPLAY_POLICY)
            .header(MODEL_BINDING_REVISION_HEADER, revision)
            .body(body.to_owned())
            .send()
            .await
            .expect("adapter response")
    }

    fn snapshot_json(snapshot: &BindingsSnapshot) -> Vec<u8> {
        let bindings = snapshot
            .bindings
            .values()
            .map(|binding| {
                json!({
                    "provider": binding.provider,
                    "model": binding.model,
                    "upstream_model": binding.upstream_model,
                    "response_model": binding.response_model,
                    "revision": binding.revision,
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "network": snapshot.network,
            "revision": snapshot.revision,
            "bindings": bindings,
        }))
        .expect("snapshot JSON")
    }

    #[tokio::test]
    async fn failed_upstream_dispatch_is_attempted_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let attempts = std::sync::Arc::new(AtomicUsize::new(0));
        let recorded = attempts.clone();
        let accept_task = tokio::spawn(async move {
            if listener.accept().await.is_ok() {
                recorded.fetch_add(1, Ordering::Relaxed);
            }
            if tokio::time::timeout(Duration::from_millis(250), listener.accept())
                .await
                .is_ok()
            {
                recorded.fetch_add(1, Ordering::Relaxed);
            }
        });
        let url = format!("http://{address}/anthropic/v1/messages");
        let state = BedrockMantleState::for_test(&url, "Bearer configured-only");
        let response =
            handle_request(State(AppState(state)), request("/v1/messages", VALID_BODY)).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        accept_task.await.expect("accept task");
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn proxy_sends_only_fixed_headers_and_rewrites_only_model() {
        let received = std::sync::Arc::new(std::sync::Mutex::new(None));
        let capture = received.clone();
        let upstream_app = Router::new().route(
            "/anthropic/v1/messages",
            post(move |request: Request<Body>| {
                let capture = capture.clone();
                async move {
                    let headers = request.headers().clone();
                    let body = to_bytes(request.into_body(), MAX_REQUEST_BODY)
                        .await
                        .expect("body");
                    *capture.lock().expect("capture") = Some((headers, body.to_vec()));
                    (
                        [(CONTENT_TYPE, "application/json")],
                        r#"{"model":"test-model-a-provider-echo","id":"msg_1"}"#,
                    )
                }
            }),
        );
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let upstream_addr = upstream_listener.local_addr().expect("address");
        let upstream_task: JoinHandle<()> = tokio::spawn(async move {
            axum::serve(upstream_listener, upstream_app)
                .await
                .expect("upstream");
        });
        let url = format!("http://{upstream_addr}/anthropic/v1/messages");
        let state = BedrockMantleState::for_test(&url, "Bearer configured-only");
        let mut request = request("/v1/messages", VALID_BODY);
        request.headers_mut().insert(
            "authorization",
            HeaderValue::from_static("Bearer buyer-secret"),
        );
        request
            .headers_mut()
            .insert("x-private", HeaderValue::from_static("must-not-forward"));
        let response = handle_request(State(AppState(state)), request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(MODEL_BINDING_REVISION_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("7")
        );
        let raw = to_bytes(response.into_body(), MAX_RESPONSE_BODY)
            .await
            .expect("response body");
        let canonical: Value = serde_json::from_slice(&raw).expect("canonical JSON");
        assert_eq!(canonical["model"], TEST_MODEL_A);
        let (headers, sent) = received
            .lock()
            .expect("capture")
            .take()
            .expect("upstream request");
        let value: Value = serde_json::from_slice(&sent).expect("sent json");
        assert_eq!(value["model"], TEST_SELECTOR_A);
        assert_eq!(
            headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer configured-only")
        );
        assert_eq!(
            headers
                .get("anthropic-version")
                .and_then(|value| value.to_str().ok()),
            Some(ANTHROPIC_VERSION)
        );
        assert!(headers.get("x-private").is_none());
        assert!(headers.get(EXECUTION_POLICY_HEADER).is_none());
        upstream_task.abort();
    }

    fn request(uri: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header(EXECUTION_POLICY_HEADER, EXACT_CANONICAL_NO_REPLAY_POLICY)
            .header(
                MODEL_BINDING_REVISION_HEADER,
                TEST_MODEL_REVISION_A.to_string(),
            )
            .body(Body::from(body.to_owned()))
            .expect("request")
    }

    async fn test_state() -> (
        BedrockMantleState,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = count.clone();
        let upstream_app = Router::new().route(
            "/anthropic/v1/messages",
            post(move || {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    (
                        [(CONTENT_TYPE, "application/json")],
                        r#"{"model":"test-model-a-provider-echo"}"#,
                    )
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            axum::serve(listener, upstream_app).await.expect("upstream");
        });
        let state = BedrockMantleState::for_test(
            &format!("http://{address}/anthropic/v1/messages"),
            "Bearer configured-only",
        );
        (state, count)
    }
}
