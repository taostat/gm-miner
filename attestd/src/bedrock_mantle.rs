//! Fixed Bedrock Mantle Messages adapter for registry-authorized Anthropic models.
//!
//! The inbound Anthropic request is parsed into a bounded, duplicate-aware
//! JSON value. The adapter rewrites only the bound request model and leaves all
//! other body fields for Bedrock to validate. It builds a fresh request to the
//! fixed Mantle hostname and path.
//! The raw AWS response identity is checked before its model field is rewritten
//! to the canonical registry model and before any response bytes are released.

use std::{
    collections::BTreeMap,
    io,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::State,
    http::{
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER},
        HeaderMap, HeaderValue, Method, Request, Response, StatusCode,
    },
    routing::any,
    Router,
};
use futures_util::{stream, StreamExt};
use reqwest::{redirect::Policy, Client};
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Map, Value};

use tokio::net::TcpListener;
#[cfg(test)]
use tokio::sync::{watch, RwLock};
use tracing::info;

#[cfg(test)]
use crate::model_bindings::RefreshStatus as BindingRefreshStatus;
use crate::model_bindings::{self, RegistryCache, RegistrySnapshot, SnapshotCache};
#[cfg(test)]
use crate::model_bindings::{
    next_delay, FRESHNESS_TTL as BINDINGS_FRESHNESS_TTL,
    ON_DEMAND_MIN_INTERVAL as BINDINGS_ON_DEMAND_MIN_INTERVAL,
};
use crate::strict_json::parse_unique_json;

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
const MAX_ANTHROPIC_BETA_HEADER_BYTES: usize = 1024;
const MAX_RESPONSE_BODY: usize = 32 * 1024 * 1024;
const MAX_STREAM_PREAMBLE: usize = 64 * 1024;
/// One in-body SSE frame. A thinking block's closing signature frame grows with
/// the thinking (about 75 KB at 32k thinking tokens); 4 MiB leaves wide headroom.
const MAX_STREAM_FRAME: usize = 4 * 1024 * 1024;
const MAX_ERROR_BODY: usize = 64 * 1024;
const ERROR_BODY_WAIT: Duration = Duration::from_secs(5);
const PROMPT_TOO_LONG: &[u8] = b"prompt is too long";
const MAX_MODEL_BINDINGS: usize = 1024;
const MAX_MODEL_ID_BYTES: usize = 256;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
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

#[derive(Debug, Default)]
struct BindingCache {
    snapshots: SnapshotCache<BindingsSnapshot>,
    /// Retained across removals so a model cannot be re-added with an old or
    /// reused row revision during this runtime's lifetime.
    highest_binding: BTreeMap<String, ModelBinding>,
}

impl BindingCache {
    #[cfg(test)]
    fn with_snapshot(snapshot: BindingsSnapshot, fetched_at: Instant) -> Self {
        let highest_binding = snapshot.bindings.clone();
        let mut snapshots = SnapshotCache::default();
        snapshots.publish(snapshot, fetched_at);
        Self {
            snapshots,
            highest_binding,
        }
    }

    fn apply(&mut self, snapshot: BindingsSnapshot, now: Instant) -> Result<(), &'static str> {
        if let Some(current) = self.snapshots.current() {
            if snapshot.revision < current.revision {
                return Err("registry binding snapshot revision moved backwards");
            }
            if snapshot.revision == current.revision {
                if snapshot != *current {
                    return Err("registry changed binding payload without advancing revision");
                }
                self.snapshots.publish(snapshot, now);
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
                if !current.bindings.contains_key(model) && next.revision <= previous.revision {
                    return Err("removed model binding was re-added without a new revision");
                }
            }
        }

        for (model, binding) in &snapshot.bindings {
            self.highest_binding.insert(model.clone(), binding.clone());
        }
        self.snapshots.publish(snapshot, now);
        Ok(())
    }

    fn current_binding(&self, model: &str, expected_revision: u64, now: Instant) -> BindingLookup {
        let Some(snapshot) = self.snapshots.current() else {
            return BindingLookup::Refresh(Reject::BindingsUnavailable);
        };
        let binding = snapshot.bindings.get(model);
        if binding.is_some_and(|binding| expected_revision < binding.revision) {
            return BindingLookup::Behind;
        }
        if !self.snapshots.is_fresh(now) {
            return BindingLookup::Refresh(Reject::BindingsUnavailable);
        }
        let Some(binding) = binding else {
            return BindingLookup::Refresh(Reject::UnsupportedModel);
        };
        if binding.revision != expected_revision {
            return BindingLookup::Refresh(Reject::BindingRevision);
        }
        BindingLookup::Ready(binding.clone())
    }
}

impl RegistryCache<BindingsSnapshot> for BindingCache {
    fn publish(
        &mut self,
        snapshot: BindingsSnapshot,
        fetched_at: Instant,
    ) -> Result<(), &'static str> {
        self.apply(snapshot, fetched_at)
    }

    fn current_cached(&self) -> Option<&model_bindings::CachedSnapshot<BindingsSnapshot>> {
        self.snapshots.current_cached()
    }
}

enum BindingLookup {
    Ready(ModelBinding),
    Behind,
    Refresh(Reject),
}

impl BindingLookup {
    #[cfg(test)]
    fn into_result(self) -> Result<ModelBinding, Reject> {
        match self {
            Self::Ready(binding) => Ok(binding),
            Self::Behind => Err(Reject::BindingRevision),
            Self::Refresh(reject) => Err(reject),
        }
    }
}

#[derive(Clone)]
pub struct BedrockMantleState {
    client: Client,
    authorization: HeaderValue,
    registry: RegistrySnapshot<BindingsSnapshot, BindingCache>,
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
        let registry_url = model_bindings::registry_url_for_network(&network)
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
        let registry = RegistrySnapshot::new(
            model_bindings::registry_http_client()?,
            format!("{registry_url}{BEDROCK_BINDINGS_PATH}"),
            network,
            BindingCache::default(),
            parse_bindings_payload,
            "Bedrock",
        );

        Ok(Self {
            client,
            authorization,
            registry,
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
        let registry = RegistrySnapshot::new(
            client.clone(),
            format!("https://registry.saygm.com{BEDROCK_BINDINGS_PATH}"),
            "mainnet".to_owned(),
            BindingCache::with_snapshot(test_bindings_payload(), Instant::now()),
            parse_bindings_payload,
            "Bedrock",
        );
        Self {
            client,
            authorization: HeaderValue::from_str(authorization).expect("test credential"),
            registry,
            test_upstream_url: Some(url.to_owned()),
        }
    }

    #[cfg(test)]
    fn with_test_registry_url(mut self, url: &str) -> Self {
        self.registry = self.registry.with_url(url);
        self
    }

    #[cfg(test)]
    async fn refresh_bindings(&self) -> Result<(), &'static str> {
        self.registry.refresh().await
    }

    async fn wait_for_binding_refresh(&self) {
        self.registry.wait_for_refresh().await;
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

fn parse_bindings_payload(
    bytes: &[u8],
    expected_network: &str,
) -> Result<BindingsSnapshot, &'static str> {
    let object = model_bindings::parse_envelope(
        bytes,
        expected_network,
        &["schema_version", "network", "revision", "bindings"],
    )?;
    let network = object
        .get("network")
        .and_then(Value::as_str)
        .ok_or("registry binding response has no network")?;
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
                model_bindings::object_has_exact_keys(
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
            .filter(|model| model_bindings::valid_model_id(model, &[]))
            .ok_or("registry model binding has an invalid canonical model")?;
        let upstream_model = row
            .get("upstream_model")
            .and_then(Value::as_str)
            .filter(|selector| valid_bedrock_selector(selector))
            .ok_or("registry model binding has an invalid Bedrock selector")?;
        let response_model = row
            .get("response_model")
            .and_then(Value::as_str)
            .filter(|model| model_bindings::valid_model_id(model, &[]))
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
    state.registry.start();
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
    UpstreamThrottled { retry_after_secs: Option<u32> },
    UpstreamUnauthorized,
    UpstreamForbidden,
    UpstreamInvalidRequest { prompt_too_long: bool },
    UpstreamTooLarge,
    ModelIdentityMismatch,
}

impl Reject {
    // Fixed categories only: never log provider bodies, model strings, headers,
    // credentials, or request content.
    fn upstream_diagnostic(self) -> Option<(&'static str, Option<u16>)> {
        match self {
            Self::Upstream => Some(("upstream_response_invalid", None)),
            Self::UpstreamTransport => Some(("upstream_transport_failed", None)),
            Self::UpstreamHttp(status) => Some(("upstream_http_rejected", Some(status))),
            Self::UpstreamThrottled { .. } => Some(("upstream_http_rejected", Some(429))),
            Self::UpstreamUnauthorized => Some(("upstream_http_rejected", Some(401))),
            Self::UpstreamForbidden => Some(("upstream_http_rejected", Some(403))),
            Self::UpstreamInvalidRequest { .. } => Some(("upstream_http_rejected", Some(400))),
            Self::UpstreamTooLarge => Some(("upstream_http_rejected", Some(413))),
            Self::ModelIdentityMismatch => Some(("model_identity_mismatch", None)),
            _ => None,
        }
    }

    // Public bodies are fixed strings, never provider text: an AWS error can
    // name the account, role or ARN behind the worker's credential. The gm
    // gateway reads the 401/403 bodies' `invalid_api_key` as a provider-account
    // failure on any status; no other body here may carry a drain phrase.
    fn public_error(self) -> (StatusCode, &'static str, &'static str) {
        match self {
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
                "Bedrock Messages body is invalid",
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
            Self::UpstreamThrottled { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_error",
                "Bedrock Mantle throttled the request",
            ),
            Self::UpstreamUnauthorized => (
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                "Bedrock Mantle rejected the worker credential (invalid_api_key)",
            ),
            Self::UpstreamForbidden => (
                StatusCode::FORBIDDEN,
                "permission_error",
                "Bedrock Mantle denied the worker credential access (invalid_api_key)",
            ),
            Self::UpstreamInvalidRequest {
                prompt_too_long: true,
            } => (
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "Bedrock Mantle rejected the request: prompt is too long",
            ),
            Self::UpstreamInvalidRequest {
                prompt_too_long: false,
            } => (
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "Bedrock Mantle rejected the request as invalid",
            ),
            Self::UpstreamTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "Bedrock Mantle rejected the request size",
            ),
            Self::Upstream
            | Self::UpstreamTransport
            | Self::UpstreamHttp(_)
            | Self::ModelIdentityMismatch => (
                StatusCode::BAD_GATEWAY,
                "api_error",
                "Bedrock Mantle request failed",
            ),
        }
    }

    fn into_response(self) -> Response<Body> {
        if let Some((reason, upstream_status)) = self.upstream_diagnostic() {
            tracing::warn!(reason, upstream_status, "Bedrock Mantle request rejected");
        }
        let (status, error_type, message) = self.public_error();
        let body = format!("{{\"error\":{{\"type\":\"{error_type}\",\"message\":\"{message}\"}}}}");
        let mut response = response(status, "application/json", Body::from(body));
        if let Self::UpstreamThrottled {
            retry_after_secs: Some(seconds),
        } = self
        {
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
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
    let (requested_binding_revision, anthropic_beta) = validate_inbound_headers(request.headers())?;

    let bytes = to_bytes(request.into_body(), MAX_REQUEST_BODY)
        .await
        .map_err(|_| Reject::BodyTooLarge)?;
    let PreparedRequestBody {
        mut fields,
        model,
        stream_response,
    } = prepare_request_body(&bytes)?;
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
    let mut config = BindingRequestConfig {
        model: &model,
        revision: requested_binding_revision,
        fields: &mut fields,
        client: &state.client,
        url,
        authorization: &state.authorization,
        anthropic_beta: anthropic_beta.as_ref(),
        accept,
    };
    let mut prepared = state
        .registry
        .with_cache(|cache, now| prepare_binding_request(cache, &mut config, now))
        .await?;
    if matches!(&prepared, PreparedBindingRequest::Refresh(_)) {
        state.wait_for_binding_refresh().await;
        prepared = state
            .registry
            .with_cache(|cache, now| prepare_binding_request(cache, &mut config, now))
            .await?;
    }
    let (binding, upstream_request) = match prepared {
        PreparedBindingRequest::Ready(binding, request) => (binding, *request),
        PreparedBindingRequest::Refresh(reject) => return Err(reject),
    };
    let upstream = state
        .client
        .execute(upstream_request)
        .await
        .map_err(|_| Reject::UpstreamTransport)?;

    finish_upstream_response(upstream, &binding, stream_response).await
}

struct BindingRequestConfig<'a> {
    model: &'a str,
    revision: u64,
    fields: &'a mut Map<String, Value>,
    client: &'a Client,
    url: &'a str,
    authorization: &'a HeaderValue,
    anthropic_beta: Option<&'a HeaderValue>,
    accept: &'a str,
}

enum PreparedBindingRequest {
    Refresh(Reject),
    Ready(ModelBinding, Box<reqwest::Request>),
}

fn prepare_binding_request(
    cache: &BindingCache,
    config: &mut BindingRequestConfig<'_>,
    now: Instant,
) -> Result<PreparedBindingRequest, Reject> {
    let binding = match cache.current_binding(config.model, config.revision, now) {
        BindingLookup::Ready(binding) => binding,
        BindingLookup::Behind => return Err(Reject::BindingRevision),
        BindingLookup::Refresh(reject) => return Ok(PreparedBindingRequest::Refresh(reject)),
    };
    config.fields.insert(
        "model".to_owned(),
        Value::String(binding.upstream_model.clone()),
    );
    let body = serde_json::to_vec(config.fields).map_err(|_| Reject::InvalidBody)?;
    let mut request = config
        .client
        .post(config.url)
        .header(AUTHORIZATION, config.authorization.clone())
        .header("anthropic-version", ANTHROPIC_VERSION)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, config.accept);
    if let Some(value) = config.anthropic_beta {
        request = request.header("anthropic-beta", value.clone());
    }
    let request = request.body(body).build().map_err(|_| Reject::Upstream)?;
    Ok(PreparedBindingRequest::Ready(binding, Box::new(request)))
}

async fn finish_upstream_response(
    upstream: reqwest::Response,
    binding: &ModelBinding,
    stream_response: bool,
) -> Result<Response<Body>, Reject> {
    if upstream.status() != StatusCode::OK {
        return Err(upstream_rejection(upstream).await);
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
        if !model_bindings::is_json_content_type(upstream.headers()) {
            return Err(Reject::Upstream);
        }
        let body = model_bindings::read_bounded_body(upstream, MAX_RESPONSE_BODY)
            .await
            .map_err(map_bounded_body_error)?;
        let body = canonicalize_response_identity(&body, &binding.response_model, &binding.model)?;
        Ok(response_with_binding_revision(
            StatusCode::OK,
            "application/json",
            Body::from(body),
            binding.revision,
        ))
    }
}

async fn upstream_rejection(upstream: reqwest::Response) -> Reject {
    match upstream.status() {
        StatusCode::TOO_MANY_REQUESTS => Reject::UpstreamThrottled {
            retry_after_secs: retry_after_secs(upstream.headers()),
        },
        StatusCode::UNAUTHORIZED => Reject::UpstreamUnauthorized,
        StatusCode::FORBIDDEN => Reject::UpstreamForbidden,
        StatusCode::BAD_REQUEST => Reject::UpstreamInvalidRequest {
            prompt_too_long: tokio::time::timeout(
                ERROR_BODY_WAIT,
                model_bindings::read_bounded_body(upstream, MAX_ERROR_BODY),
            )
            .await
            .is_ok_and(|body| body.is_ok_and(|body| signals_prompt_too_long(&body))),
        },
        StatusCode::PAYLOAD_TOO_LARGE => Reject::UpstreamTooLarge,
        status => Reject::UpstreamHttp(status.as_u16()),
    }
}

fn map_bounded_body_error(error: model_bindings::BoundedBodyError) -> Reject {
    match error {
        model_bindings::BoundedBodyError::Read => Reject::UpstreamTransport,
        model_bindings::BoundedBodyError::TooLarge => Reject::Upstream,
    }
}

/// Only the delay-seconds form is relayed; an HTTP-date or garbage value is
/// dropped rather than replaced with a guess.
fn retry_after_secs(headers: &HeaderMap) -> Option<u32> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

// Anthropic's context-window refusal; the gm gateway reroutes a 400 carrying
// this phrase to a wider-window route when its capability retry is enabled.
fn signals_prompt_too_long(body: &[u8]) -> bool {
    body.to_ascii_lowercase()
        .windows(PROMPT_TOO_LONG.len())
        .any(|window| window == PROMPT_TOO_LONG)
}

fn validate_inbound_headers(headers: &HeaderMap) -> Result<(u64, Option<HeaderValue>), Reject> {
    let mut execution_policies = headers.get_all(EXECUTION_POLICY_HEADER).iter();
    if execution_policies
        .next()
        .and_then(|value| value.to_str().ok())
        != Some(EXACT_CANONICAL_NO_REPLAY_POLICY)
        || execution_policies.next().is_some()
    {
        return Err(Reject::Header);
    }

    let content_types = headers.get_all(CONTENT_TYPE).iter().collect::<Vec<_>>();
    if content_types.len() != 1
        || !model_bindings::is_json_content_type(headers)
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
    let anthropic_beta = validate_anthropic_beta_header(headers)?;
    Ok((revision, anthropic_beta))
}

fn validate_anthropic_beta_header(headers: &HeaderMap) -> Result<Option<HeaderValue>, Reject> {
    let mut values = headers.get_all("anthropic-beta").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Reject::Header);
    }

    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_ANTHROPIC_BETA_HEADER_BYTES
        || bytes.iter().any(|byte| !(0x20..=0x7e).contains(byte))
    {
        return Err(Reject::Header);
    }
    for item in bytes.split(|byte| *byte == b',') {
        let Some(start) = item.iter().position(|byte| *byte != b' ') else {
            return Err(Reject::Header);
        };
        let Some(end) = item.iter().rposition(|byte| *byte != b' ') else {
            return Err(Reject::Header);
        };
        if !item[start..=end].iter().copied().all(is_http_token_byte) {
            return Err(Reject::Header);
        }
    }
    Ok(Some(value.clone()))
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[derive(Debug, PartialEq)]
struct PreparedRequestBody {
    fields: Map<String, Value>,
    model: String,
    stream_response: bool,
}

fn prepare_request_body(bytes: &[u8]) -> Result<PreparedRequestBody, Reject> {
    let value = parse_unique_json(bytes).map_err(|_| Reject::InvalidBody)?;
    let Value::Object(fields) = value else {
        return Err(Reject::InvalidBody);
    };
    let model = fields
        .get("model")
        .and_then(Value::as_str)
        .ok_or(Reject::InvalidBody)?
        .to_owned();
    if !model_bindings::valid_model_id(&model, &[]) {
        return Err(Reject::InvalidBody);
    }
    let stream_response = match fields.get("stream") {
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(Reject::InvalidBody),
        None => false,
    };
    Ok(PreparedRequestBody {
        fields,
        model,
        stream_response,
    })
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
                StreamPreambleEvent::Other => scanned = after_frame,
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
            }
        }
        if buffer.len().saturating_sub(scanned) > MAX_STREAM_PREAMBLE {
            return Err(Reject::Upstream);
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
                            Ok(StreamEvent::Empty | StreamEvent::Ping | StreamEvent::Unknown)
                                if !terminal => {}
                            Ok(StreamEvent::MessageStart(_)) if !started && !terminal => {
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
    MessageStart(Value),
    MessageStop,
    Error,
    Other,
    Unknown,
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
    if event.is_empty() || value.get("type").and_then(Value::as_str) != Some(event) {
        return Err(Reject::Upstream);
    }
    match event {
        "message_start" => Ok(StreamEvent::MessageStart(value)),
        "message_stop" => Ok(StreamEvent::MessageStop),
        "error" => Ok(StreamEvent::Error),
        "content_block_start" | "content_block_delta" | "content_block_stop" | "message_delta" => {
            Ok(StreamEvent::Other)
        }
        _ => Ok(StreamEvent::Unknown),
    }
}

enum StreamPreambleEvent {
    MessageStart(Vec<u8>),
    Other,
}

fn parse_sse_preamble_frame(
    frame: &[u8],
    expected_raw_model: &str,
    canonical_model: &str,
) -> Result<StreamPreambleEvent, Reject> {
    let mut value = match parse_stream_event(frame)? {
        StreamEvent::MessageStart(value) => value,
        StreamEvent::Empty | StreamEvent::Ping | StreamEvent::Unknown => {
            return Ok(StreamPreambleEvent::Other);
        }
        _ => return Err(Reject::Upstream),
    };
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
    use crate::gateway_contract::signals_drain;
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
        let prepared = prepare_request_body(VALID_BODY.as_bytes()).expect("body");
        assert_eq!(prepared.model, TEST_MODEL_A);
        assert_eq!(prepared.fields["messages"][0]["content"], "hello");
        assert!(!prepared.stream_response);
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
    fn request_parser_rejects_invalid_json_and_ambiguous_route_controls() {
        for invalid in [
            "not json",
            "[]",
            "{}",
            r#"{"max_tokens":32}"#,
            r#"{"model":"bad/model"}"#,
            r#"{"model":"test-model-a","stream":"true"}"#,
            r#"{"model":"test-model-a","model":"test-model-b"}"#,
        ] {
            assert_eq!(
                prepare_request_body(invalid.as_bytes()),
                Err(Reject::InvalidBody),
                "{invalid}"
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
            .into_result()
            .is_ok());
        assert_eq!(
            cache
                .current_binding(
                    TEST_MODEL_A,
                    TEST_MODEL_REVISION_A,
                    now + BINDINGS_FRESHNESS_TTL + Duration::from_millis(1),
                )
                .into_result(),
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
            .into_result()
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
        assert!(
            cache
                .current_binding(
                    TEST_MODEL_A,
                    TEST_MODEL_REVISION_A,
                    refreshed_at + BINDINGS_FRESHNESS_TTL,
                )
                .into_result()
                .is_ok(),
            "rejected refreshes must leave the last successful binding usable through its TTL"
        );
        assert_eq!(
            cache
                .current_binding(
                    TEST_MODEL_A,
                    TEST_MODEL_REVISION_A,
                    refreshed_at + BINDINGS_FRESHNESS_TTL + Duration::from_millis(1),
                )
                .into_result(),
            Err(Reject::BindingsUnavailable),
            "rejected refreshes must not renew binding freshness"
        );
    }

    #[test]
    fn binding_refresh_backoff_grows_caps_and_resets_after_success() {
        let expected = [3, 6, 12, 24, 35, 35, 35];
        for (consecutive_failures, seconds) in (1_u32..=7).zip(expected) {
            assert_eq!(
                next_delay(consecutive_failures, 0.0),
                Duration::from_secs(seconds),
            );
        }
        assert_eq!(
            next_delay(5, 1.0),
            Duration::from_secs(43) + Duration::from_millis(750),
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
    fn prepares_client_side_tool_workflows_and_inline_media_unchanged() {
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
        let prepared = prepare_request_body(&bytes).expect("tool workflow");
        assert_eq!(Value::Object(prepared.fields), value);
        assert!(prepared.stream_response);
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
                Reject::UpstreamHttp(503),
                "upstream_http_rejected",
                Some(503),
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
        let invalid_body = Reject::InvalidBody.into_response();
        assert_eq!(invalid_body.status(), StatusCode::BAD_REQUEST);
        let invalid_body = to_bytes(invalid_body.into_body(), 4096)
            .await
            .expect("invalid-body response");
        assert_eq!(
            invalid_body.as_ref(),
            br#"{"error":{"type":"invalid_request_error","message":"Bedrock Messages body is invalid"}}"#
        );
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
            model_bindings::read_bounded_body(response, MAX_RESPONSE_BODY)
                .await
                .map_err(map_bounded_body_error),
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
                .status(503)
                .body("private provider error details")
                .expect("HTTP response"),
        );
        let failure = finish_upstream_response(upstream, &binding, false)
            .await
            .expect_err("upstream rejection");
        assert_eq!(failure, Reject::UpstreamHttp(503));
    }

    struct Relayed {
        status: StatusCode,
        retry_after: Option<String>,
        error_type: String,
        body: String,
    }

    async fn relay_upstream_error(
        status: u16,
        headers: &[(&'static str, &'static str)],
        body: &'static str,
        streaming: bool,
    ) -> Relayed {
        let headers = headers.to_vec();
        let upstream_app = Router::new().route(
            "/anthropic/v1/messages",
            post(move || async move {
                let mut response = Response::builder()
                    .status(status)
                    .header(CONTENT_TYPE, "application/json");
                for (name, value) in headers {
                    response = response.header(name, value);
                }
                response.body(Body::from(body)).expect("upstream response")
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let upstream_task: JoinHandle<()> = tokio::spawn(async move {
            axum::serve(listener, upstream_app).await.expect("upstream");
        });
        let state = BedrockMantleState::for_test(
            &format!("http://{address}/anthropic/v1/messages"),
            "Bearer configured-only",
        );
        let request_body = if streaming {
            VALID_BODY.replace("\"max_tokens\"", "\"stream\":true,\"max_tokens\"")
        } else {
            VALID_BODY.to_owned()
        };
        let response = handle_request(
            State(AppState(state)),
            request("/v1/messages", &request_body),
        )
        .await;
        upstream_task.abort();
        let status = response.status();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .map(|value| value.to_str().expect("ASCII Retry-After").to_owned());
        let raw = to_bytes(response.into_body(), 4096)
            .await
            .expect("error body");
        let value: Value = serde_json::from_slice(&raw).expect("JSON error body");
        Relayed {
            status,
            retry_after,
            error_type: value["error"]["type"].as_str().expect("type").to_owned(),
            body: String::from_utf8(raw.to_vec()).expect("UTF-8 body"),
        }
    }

    #[tokio::test]
    async fn upstream_throttle_is_relayed_as_a_429_with_only_a_numeric_provider_hint() {
        for (headers, expected_hint, streaming) in [
            (&[("retry-after", "7")][..], Some("7"), false),
            (&[("retry-after", "7")][..], Some("7"), true),
            (&[][..], None, false),
            (
                &[("retry-after", "Wed, 21 Oct 2015 07:28:00 GMT")][..],
                None,
                false,
            ),
            (&[("retry-after", "-3")][..], None, false),
            (
                &[("x-amzn-errortype", "ThrottlingException")][..],
                None,
                false,
            ),
        ] {
            let relayed = relay_upstream_error(
                429,
                headers,
                r#"{"message":"Too many requests for account 123456789012"}"#,
                streaming,
            )
            .await;
            assert_eq!(relayed.status, StatusCode::TOO_MANY_REQUESTS, "{headers:?}");
            assert_eq!(relayed.retry_after.as_deref(), expected_hint, "{headers:?}");
            assert_eq!(relayed.error_type, "rate_limit_error");
            assert!(!relayed.body.contains("123456789012"));
        }
    }

    #[tokio::test]
    async fn upstream_credential_failures_keep_their_status_and_read_as_an_account_failure() {
        let aws_denial = r#"{"message":"User: arn:aws:iam::123456789012:user/miner is not authorized to perform: bedrock:InvokeModel"}"#;
        for (status, expected, error_type) in [
            (401, StatusCode::UNAUTHORIZED, "authentication_error"),
            (403, StatusCode::FORBIDDEN, "permission_error"),
        ] {
            let relayed = relay_upstream_error(status, &[], aws_denial, false).await;
            assert_eq!(relayed.status, expected);
            assert_eq!(relayed.error_type, error_type);
            assert!(relayed.body.contains("invalid_api_key"));
            assert!(!relayed.body.contains("arn:aws"));
            assert!(!relayed.body.contains("123456789012"));
            assert_eq!(relayed.retry_after, None);
        }
    }

    #[tokio::test]
    async fn upstream_request_errors_stay_buyer_errors_without_provider_text() {
        let too_long = r#"{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 250000 tokens > 200000 maximum"}}"#;
        let relayed = relay_upstream_error(400, &[], too_long, false).await;
        assert_eq!(relayed.status, StatusCode::BAD_REQUEST);
        assert_eq!(relayed.error_type, "invalid_request_error");
        assert!(relayed.body.contains("prompt is too long"));
        assert!(!relayed.body.contains("250000"));

        let invalid = r#"{"message":"messages.0.content: field required"}"#;
        let relayed = relay_upstream_error(400, &[], invalid, false).await;
        assert_eq!(relayed.status, StatusCode::BAD_REQUEST);
        assert_eq!(relayed.error_type, "invalid_request_error");
        assert!(!relayed.body.contains("prompt is too long"));
        assert!(!relayed.body.contains("field required"));

        let relayed = relay_upstream_error(413, &[], "{}", false).await;
        assert_eq!(relayed.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(relayed.error_type, "request_too_large");
    }

    #[tokio::test]
    async fn upstream_server_and_worker_side_failures_stay_502() {
        for status in [404, 408, 424, 500, 503, 529] {
            let relayed = relay_upstream_error(
                status,
                &[("retry-after", "7")],
                r#"{"message":"private provider details"}"#,
                false,
            )
            .await;
            assert_eq!(relayed.status, StatusCode::BAD_GATEWAY, "{status}");
            assert_eq!(relayed.error_type, "api_error");
            assert_eq!(relayed.retry_after, None, "{status}");
            assert!(!relayed.body.contains("private provider details"));
        }
    }

    #[tokio::test]
    async fn public_bodies_honour_the_gateway_drain_and_saturation_contract() {
        let credential = [Reject::UpstreamUnauthorized, Reject::UpstreamForbidden];
        let every_other = [
            Reject::Method,
            Reject::Path,
            Reject::Header,
            Reject::BodyTooLarge,
            Reject::InvalidBody,
            Reject::UnsupportedModel,
            Reject::BindingRevision,
            Reject::BindingsUnavailable,
            Reject::Upstream,
            Reject::UpstreamTransport,
            Reject::UpstreamHttp(503),
            Reject::UpstreamThrottled {
                retry_after_secs: Some(7),
            },
            Reject::UpstreamInvalidRequest {
                prompt_too_long: true,
            },
            Reject::UpstreamInvalidRequest {
                prompt_too_long: false,
            },
            Reject::UpstreamTooLarge,
            Reject::ModelIdentityMismatch,
        ];
        let body = |failure: Reject| async move {
            let raw = to_bytes(failure.into_response().into_body(), 4096)
                .await
                .expect("error body");
            String::from_utf8(raw.to_vec()).expect("UTF-8 body")
        };
        for failure in credential {
            let text = body(failure).await;
            assert!(signals_drain(&text), "{failure:?}");
        }
        for failure in every_other {
            let text = body(failure).await;
            assert!(!signals_drain(&text), "{failure:?}");
            assert!(!text.contains("miner saturated"), "{failure:?}");
        }
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

        let future_events = concat!(
            "event: future_event\ndata: {\"type\":\"future_event\",\"extra\":true}\n\n",
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"test-model-a-provider-echo\",\"future_field\":true}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"future_content_block\",\"future_field\":true}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"future_delta\",\"future_field\":true}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
        );
        let (preamble, rest) = validate_stream_identity(
            in_chunks(future_events.as_bytes(), 9),
            TEST_RESPONSE_MODEL_A,
            TEST_MODEL_A,
        )
        .await
        .expect("unknown events pass after the raw model identity is verified");
        let chunks = stream::once(async move { Ok::<Bytes, io::Error>(preamble) })
            .chain(rest)
            .boxed();
        let collected = guard_stream(chunks).collect::<Vec<_>>().await;
        let mut forwarded = Vec::new();
        for chunk in collected {
            forwarded.extend_from_slice(chunk.expect("valid future event stream").as_ref());
        }
        let forwarded = String::from_utf8(forwarded).expect("UTF-8 stream");
        assert!(forwarded.contains("event: future_event\n"));
        assert!(forwarded.contains("\"future_field\":true"));
        assert!(forwarded.contains("future_content_block"));
        assert!(forwarded.contains("future_delta"));
        assert!(forwarded.contains(TEST_MODEL_A));
        assert!(!forwarded.contains(TEST_RESPONSE_MODEL_A));
    }

    #[tokio::test(start_paused = true)]
    async fn stream_identity_rejects_known_events_before_start_without_waiting() {
        for event in [
            "error",
            "message_stop",
            "content_block_start",
            "content_block_delta",
            "content_block_stop",
            "message_delta",
        ] {
            let frame = format!("event: {event}\ndata: {{\"type\":\"{event}\"}}\n\n");
            let source = stream::iter([Ok(Bytes::from(frame))])
                .chain(stream::pending())
                .boxed();
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                validate_stream_identity(source, TEST_RESPONSE_MODEL_A, TEST_MODEL_A),
            )
            .await;
            assert!(matches!(result, Ok(Err(Reject::Upstream))), "{event}");
        }
    }

    #[tokio::test]
    async fn stream_identity_rejects_malformed_preamble_before_valid_start() {
        let start = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"test-model-a-provider-echo\"}}\n\n";
        for frame in [
            "event: future_event\ndata: not-json\n\n",
            "event: future_event\ndata: {\"type\":\"other_event\"}\n\n",
            "event: future_event\ndata: {\"type\":\"future_event\",\"type\":\"future_event\"}\n\n",
            "event: future_event\n\n",
            "event: message_start\ndata:\n\n",
            "data:\n\n",
        ] {
            let source = stream::iter([
                Ok(Bytes::copy_from_slice(frame.as_bytes())),
                Ok(Bytes::from_static(start)),
            ])
            .boxed();
            assert!(
                matches!(
                    validate_stream_identity(source, TEST_RESPONSE_MODEL_A, TEST_MODEL_A).await,
                    Err(Reject::Upstream)
                ),
                "{frame}"
            );
        }
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
        assert_eq!(guard_log(&unknown).await, "");

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
    async fn local_proxy_rejects_query_path_and_ignores_unforwarded_workspace_header() {
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
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn unbound_models_and_oversized_requests_are_rejected_before_dispatch() {
        let (state, calls) = test_state().await;
        let registry_snapshot = test_bindings_payload();
        let registry = MockBindingRegistry::start(&registry_snapshot, false).await;
        let state = registry.attach(state);
        let unbound = VALID_BODY.replace(TEST_MODEL_A, "unbound-model");
        let response = handle_request(
            State(AppState(state.clone())),
            request("/v1/messages", &unbound),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let oversized = request("/v1/messages", VALID_BODY)
            .map(|_| Body::from(vec![b' '; MAX_REQUEST_BODY + 1]));
        let response = handle_request(State(AppState(state)), oversized).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(registry.calls(), 1);
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
            ("empty beta token", {
                let mut request = request("/v1/messages", VALID_BODY);
                request.headers_mut().insert(
                    "anthropic-beta",
                    HeaderValue::from_static("future-feature,,interleaved-thinking-2025-05-14"),
                );
                request
            }),
            ("invalid beta token", {
                let mut request = request("/v1/messages", VALID_BODY);
                request
                    .headers_mut()
                    .insert("anthropic-beta", HeaderValue::from_static("future feature"));
                request
            }),
            ("duplicate beta header", {
                let mut request = request("/v1/messages", VALID_BODY);
                request
                    .headers_mut()
                    .insert("anthropic-beta", HeaderValue::from_static("future-feature"));
                request.headers_mut().append(
                    "anthropic-beta",
                    HeaderValue::from_static("another-feature"),
                );
                request
            }),
            ("non-visible beta byte", {
                let mut request = request("/v1/messages", VALID_BODY);
                request.headers_mut().insert(
                    "anthropic-beta",
                    HeaderValue::from_bytes(b"future-\xff").expect("opaque header byte"),
                );
                request
            }),
            ("overlong beta header", {
                let mut request = request("/v1/messages", VALID_BODY);
                let value = format!("future-{}", "x".repeat(MAX_ANTHROPIC_BETA_HEADER_BYTES));
                request.headers_mut().insert(
                    "anthropic-beta",
                    HeaderValue::from_str(&value).expect("long ASCII header"),
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
    async fn lower_model_binding_revision_is_rejected_without_refresh() {
        for expired in [false, true] {
            let (state, upstream_calls) = test_state().await;
            if expired {
                expire_bindings(&state).await;
            }
            let registry = MockBindingRegistry::start(&test_bindings_payload(), false).await;
            let state = registry.attach(state);
            let request = request_with_revision("/v1/messages", VALID_BODY, "6");
            let response = handle_request(State(AppState(state)), request).await;

            assert_eq!(response.status(), StatusCode::CONFLICT, "expired={expired}");
            assert_eq!(registry.calls(), 0, "expired={expired}");
            assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::Relaxed), 0);
        }
    }

    #[tokio::test]
    async fn request_without_a_snapshot_joins_the_initial_refresh() {
        let (state, upstream_calls) = test_state().await;
        *state.registry.cache_for_test().write().await = BindingCache::default();
        let registry = MockBindingRegistry::start(&test_bindings_payload(), true).await;
        let state = registry.attach(state);
        let response = handle_request(State(AppState(state)), request("/v1/messages", VALID_BODY));
        tokio::pin!(response);
        assert!(futures_util::poll!(&mut response).is_pending());
        registry.wait_for_call().await;
        assert!(futures_util::poll!(&mut response).is_pending());
        registry.release(1);

        assert_eq!(response.await.status(), StatusCode::OK);
        assert_eq!(registry.calls(), 1);
        assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn newer_model_binding_revision_refreshes_before_dispatch() {
        let (state, upstream_calls) = test_state().await;
        let registry_snapshot = snapshot_with_model_revision(TEST_MODEL_REVISION_A + 1);
        let registry = MockBindingRegistry::start(&registry_snapshot, false).await;
        let state = registry.attach(state);
        let request = request_with_revision("/v1/messages", VALID_BODY, "8");

        let response = handle_request(State(AppState(state)), request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(registry.calls(), 1);
        assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn request_joins_one_startable_refresh_and_is_served() {
        let (state, upstream_calls) = test_state().await;
        let registry_snapshot = snapshot_with_model_revision(TEST_MODEL_REVISION_A + 1);
        let registry = MockBindingRegistry::start(&registry_snapshot, true).await;
        let state = registry.attach(state);
        let response = tokio::spawn(handle_request(
            State(AppState(state)),
            request_with_revision("/v1/messages", VALID_BODY, "8"),
        ));

        registry.wait_for_call().await;
        tokio::task::yield_now().await;
        assert!(
            !response.is_finished(),
            "request waits for the in-flight fetch"
        );
        assert_eq!(registry.calls(), 1);
        registry.release(1);

        assert_eq!(response.await.expect("request").status(), StatusCode::OK);
        assert_eq!(
            registry.calls(),
            1,
            "request must wait for exactly one fetch"
        );
        assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn refreshed_binding_revision_must_match_exactly() {
        for (row_revision, label) in [
            (TEST_MODEL_REVISION_A, "registry remains behind"),
            (TEST_MODEL_REVISION_A + 2, "registry advances past request"),
        ] {
            let (state, upstream_calls) = test_state().await;
            let registry_snapshot = if row_revision == TEST_MODEL_REVISION_A {
                test_bindings_payload()
            } else {
                snapshot_with_model_revision(row_revision)
            };
            let registry = MockBindingRegistry::start(&registry_snapshot, false).await;
            let state = registry.attach(state);
            let request = request_with_revision("/v1/messages", VALID_BODY, "8");

            let response = handle_request(State(AppState(state)), request).await;

            assert_eq!(response.status(), StatusCode::CONFLICT, "{label}");
            assert_eq!(registry.calls(), 1, "{label}");
            assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::Relaxed), 0);
        }
    }

    #[tokio::test]
    async fn concurrent_newer_revisions_share_one_refresh() {
        let (state, upstream_calls) = test_state().await;
        let registry_snapshot = snapshot_with_model_revision(TEST_MODEL_REVISION_A + 1);
        let registry = MockBindingRegistry::start(&registry_snapshot, true).await;
        let state = registry.attach(state);
        let requests = (0..8)
            .map(|_| {
                let state = state.clone();
                tokio::spawn(async move {
                    let mut request = request("/v1/messages", VALID_BODY);
                    request
                        .headers_mut()
                        .insert(MODEL_BINDING_REVISION_HEADER, HeaderValue::from_static("8"));
                    handle_request(State(AppState(state)), request).await
                })
            })
            .collect::<Vec<_>>();

        registry.wait_for_call().await;
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(registry.calls(), 1);
        registry.release(8);
        for request in requests {
            assert_eq!(
                request.await.expect("concurrent request").status(),
                StatusCode::OK
            );
        }
        assert_eq!(registry.calls(), 1);
        assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::Relaxed), 8);
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_waiter_rechecks_after_its_fetch_even_if_another_fetch_completed() {
        let clock_guard = paused_clock_guard();
        let (state, upstream_calls) = test_state().await;
        let registry = MockBindingRegistry::start(&test_bindings_payload(), true).await;
        let state = registry.attach(state);
        let mut status = state.registry.status_for_test();
        let observed = status.borrow_and_update().generation();
        let delayed = handle_request(
            State(AppState(state.clone())),
            request_with_revision("/v1/messages", VALID_BODY, "8"),
        );
        tokio::pin!(delayed);
        assert!(futures_util::poll!(&mut delayed).is_pending());
        registry.wait_for_call().await;
        registry.release(1);
        let _ = wait_for_generation(&mut status, observed).await;

        // Leave this request unpolled while another caller completes a refresh.
        tokio::time::advance(BINDINGS_ON_DEMAND_MIN_INTERVAL).await;
        let next = tokio::spawn(handle_request(
            State(AppState(state)),
            request_with_revision("/v1/messages", VALID_BODY, "8"),
        ));
        registry.wait_for_call().await;
        registry.release(1);
        assert_eq!(
            next.await.expect("second request").status(),
            StatusCode::CONFLICT
        );

        let polled = futures_util::poll!(&mut delayed);
        assert!(
            matches!(polled, std::task::Poll::Ready(ref response) if response.status() == StatusCode::CONFLICT),
            "a completed fetch must release its waiter even after later completions"
        );
        assert_eq!(registry.calls(), 2);
        assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::Relaxed), 0);
        clock_guard.abort();
    }

    #[tokio::test]
    async fn cancelled_request_does_not_cancel_the_shared_refresh() {
        let (state, upstream_calls) = test_state().await;
        let snapshot = snapshot_with_model_revision(TEST_MODEL_REVISION_A + 1);
        let registry = MockBindingRegistry::start(&snapshot, true).await;
        let state = registry.attach(state);
        let mut first = request("/v1/messages", VALID_BODY);
        first
            .headers_mut()
            .insert(MODEL_BINDING_REVISION_HEADER, HeaderValue::from_static("8"));
        let first_state = state.clone();
        let cancelled = tokio::spawn(handle_request(State(AppState(first_state)), first));
        registry.wait_for_call().await;
        cancelled.abort();
        assert!(cancelled
            .await
            .expect_err("cancelled request")
            .is_cancelled());

        let mut second = request("/v1/messages", VALID_BODY);
        second
            .headers_mut()
            .insert(MODEL_BINDING_REVISION_HEADER, HeaderValue::from_static("8"));
        let response = handle_request(State(AppState(state)), second);
        tokio::pin!(response);
        assert!(futures_util::poll!(&mut response).is_pending());
        registry.release(1);

        assert_eq!(response.await.status(), StatusCode::OK);
        assert_eq!(registry.calls(), 1);
        assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_refreshes_obey_backoff_and_reset_after_recovery() {
        let (state, _) = test_state().await;
        let registry = MockBindingRegistry::start(&invalid_bindings_payload(), false).await;
        let state = registry.attach(state);
        let mut status = state.registry.status_for_test();
        let mut observed = status.borrow_and_update().generation();
        state.registry.start();

        registry.wait_for_call().await;
        observed = wait_for_generation(&mut status, observed).await;
        assert_eq!(registry.calls(), 1);
        let first_minimum = next_delay(1, 0.0);
        let first_maximum = next_delay(1, 1.0);
        tokio::time::advance(first_minimum.saturating_sub(Duration::from_millis(1))).await;
        tokio::task::yield_now().await;
        assert_eq!(registry.calls(), 1);
        tokio::time::advance(
            first_maximum
                .saturating_sub(first_minimum)
                .saturating_add(Duration::from_millis(1)),
        )
        .await;
        registry.wait_for_call().await;
        observed = wait_for_generation(&mut status, observed).await;
        assert_eq!(registry.calls(), 2);

        *registry.body.write().await = snapshot_json(&test_bindings_payload());
        let second_minimum = next_delay(2, 0.0);
        let second_maximum = next_delay(2, 1.0);
        tokio::time::advance(second_minimum.saturating_sub(Duration::from_millis(1))).await;
        tokio::task::yield_now().await;
        assert_eq!(registry.calls(), 2);
        tokio::time::advance(
            second_maximum
                .saturating_sub(second_minimum)
                .saturating_add(Duration::from_millis(1)),
        )
        .await;
        registry.wait_for_call().await;
        observed = wait_for_generation(&mut status, observed).await;
        assert_eq!(registry.calls(), 3);

        tokio::time::advance(Duration::from_secs(59)).await;
        tokio::task::yield_now().await;
        assert_eq!(registry.calls(), 3);
        tokio::time::advance(Duration::from_secs(2)).await;
        registry.wait_for_call().await;
        let _ = wait_for_generation(&mut status, observed).await;
        assert_eq!(registry.calls(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_initial_refresh_retries_after_backoff_without_dispatch() {
        let (state, upstream_calls) = test_state().await;
        *state.registry.cache_for_test().write().await = BindingCache::default();
        let registry = MockBindingRegistry::start(&invalid_bindings_payload(), false).await;
        let state = registry.attach(state);
        let mut status = state.registry.status_for_test();
        let mut observed = status.borrow_and_update().generation();

        let response = tokio::spawn(handle_request(
            State(AppState(state.clone())),
            request("/v1/messages", VALID_BODY),
        ));
        registry.wait_for_call().await;
        let response = response.await.expect("initial request");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        observed = wait_for_generation(&mut status, observed).await;
        assert_eq!(registry.calls(), 1);
        assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::Relaxed), 0);

        let minimum = next_delay(1, 0.0);
        let maximum = next_delay(1, 1.0);
        tokio::time::advance(minimum.saturating_sub(Duration::from_millis(1))).await;
        tokio::task::yield_now().await;
        assert_eq!(registry.calls(), 1);
        tokio::time::advance(
            maximum
                .saturating_sub(minimum)
                .saturating_add(Duration::from_millis(1)),
        )
        .await;
        registry.wait_for_call().await;
        let _ = wait_for_generation(&mut status, observed).await;
        assert_eq!(registry.calls(), 2);
        assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn on_demand_refresh_waits_out_minimum_gap_and_serves_new_revision() {
        let clock_guard = paused_clock_guard();
        let (state, upstream_calls) = test_state().await;
        let registry = MockBindingRegistry::start(&test_bindings_payload(), false).await;
        let state = registry.attach(state);
        let first = handle_request(
            State(AppState(state.clone())),
            request_with_revision("/v1/messages", VALID_BODY, "8"),
        );
        assert_eq!(first.await.status(), StatusCode::CONFLICT);
        assert_eq!(registry.calls(), 1);

        let newer_snapshot = snapshot_with_model_revision(TEST_MODEL_REVISION_A + 1);
        *registry.body.write().await = snapshot_json(&newer_snapshot);
        let second = handle_request(
            State(AppState(state)),
            request_with_revision("/v1/messages", VALID_BODY, "8"),
        );
        tokio::pin!(second);
        assert!(futures_util::poll!(&mut second).is_pending());
        tokio::time::advance(
            BINDINGS_ON_DEMAND_MIN_INTERVAL.saturating_sub(Duration::from_millis(1)),
        )
        .await;
        tokio::task::yield_now().await;
        assert_eq!(registry.calls(), 1);
        assert!(futures_util::poll!(&mut second).is_pending());

        tokio::time::advance(Duration::from_millis(1)).await;
        registry.wait_for_call().await;
        let response = second.await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(registry.calls(), 2);
        assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        clock_guard.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn newer_revision_rejects_immediately_during_failure_backoff() {
        let clock_guard = paused_clock_guard();
        for (kind, expected_status, expired, model, revision) in [
            (
                "newer revision",
                StatusCode::CONFLICT,
                false,
                TEST_MODEL_A,
                "8",
            ),
            (
                "unknown model",
                StatusCode::BAD_REQUEST,
                false,
                "unknown-model",
                "7",
            ),
            (
                "expired snapshot",
                StatusCode::SERVICE_UNAVAILABLE,
                true,
                TEST_MODEL_A,
                "7",
            ),
        ] {
            let (state, upstream_calls) = test_state().await;
            if expired {
                expire_bindings(&state).await;
            }
            let registry = MockBindingRegistry::start(&invalid_bindings_payload(), false).await;
            let state = registry.attach(state);
            let body = VALID_BODY.replace(TEST_MODEL_A, model);
            let first = handle_request(
                State(AppState(state.clone())),
                request_with_revision("/v1/messages", &body, revision),
            );
            assert_eq!(first.await.status(), expected_status, "{kind}");
            assert_eq!(registry.calls(), 1, "{kind}");

            let second = handle_request(
                State(AppState(state)),
                request_with_revision("/v1/messages", &body, revision),
            );
            tokio::pin!(second);
            let polled = futures_util::poll!(&mut second);
            assert!(polled.is_ready(), "{kind} must reject immediately");
            let response = match polled {
                std::task::Poll::Ready(response) => Some(response),
                std::task::Poll::Pending => None,
            }
            .expect("an immediately rejected request must be ready");
            assert_eq!(response.status(), expected_status, "{kind}");
            assert_eq!(registry.calls(), 1, "{kind} must not start another fetch");
            assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::Relaxed), 0);
        }
        clock_guard.abort();
    }

    #[tokio::test]
    async fn newly_approved_unknown_model_refreshes_before_dispatch() {
        const MODEL_B: &str = "future-model-2027-01";
        const SELECTOR_B: &str = "anthropic.future-model-2027-01-v1";
        const ECHO_B: &str = "future-model-2027-01-provider-echo";

        let (state, upstream_calls) = test_state_with_response(ECHO_B).await;
        let mut registry_snapshot = test_bindings_payload();
        registry_snapshot.revision += 1;
        registry_snapshot.bindings.insert(
            MODEL_B.to_owned(),
            ModelBinding {
                provider: "anthropic".to_owned(),
                model: MODEL_B.to_owned(),
                upstream_model: SELECTOR_B.to_owned(),
                response_model: ECHO_B.to_owned(),
                revision: 11,
            },
        );
        let registry = MockBindingRegistry::start(&registry_snapshot, false).await;
        let state = registry.attach(state);
        let body = VALID_BODY.replace(TEST_MODEL_A, MODEL_B);
        let mut request = request("/v1/messages", &body);
        request.headers_mut().insert(
            MODEL_BINDING_REVISION_HEADER,
            HeaderValue::from_static("11"),
        );

        let response = handle_request(State(AppState(state)), request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(registry.calls(), 1);
        assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        let body = to_bytes(response.into_body(), 4096)
            .await
            .expect("response body");
        let value: Value = serde_json::from_slice(&body).expect("JSON response");
        assert_eq!(value["model"], MODEL_B);
    }

    #[tokio::test]
    async fn expired_binding_snapshot_fails_closed_before_upstream_dispatch() {
        let (state, calls) = test_state().await;
        expire_bindings(&state).await;
        let registry = MockBindingRegistry::start(&invalid_bindings_payload(), false).await;
        let state = registry.attach(state);
        let response =
            handle_request(State(AppState(state)), request("/v1/messages", VALID_BODY)).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(registry.calls(), 1);
    }

    #[tokio::test]
    async fn failed_on_demand_refresh_does_not_restore_expired_bindings() {
        let (state, upstream_calls) = test_state().await;
        expire_bindings(&state).await;
        let registry = MockBindingRegistry::start(&invalid_bindings_payload(), false).await;
        let state = registry.attach(state);
        let request = request_with_revision("/v1/messages", VALID_BODY, "8");

        let response = handle_request(State(AppState(state)), request).await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(registry.calls(), 1);
        assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn binding_changes_during_body_collection_reject_before_dispatch() {
        for change in ["revision", "removal", "expiry"] {
            let (state, calls) = test_state().await;
            let mut revoked = test_bindings_payload();
            revoked.revision += 1;
            revoked.bindings.clear();
            let registry_snapshot = if change == "expiry" {
                invalid_bindings_payload()
            } else {
                revoked
            };
            let registry = MockBindingRegistry::start(&registry_snapshot, false).await;
            let state = registry.attach(state);
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
                let cache_arc = state.registry.cache_for_test();
                let mut cache = cache_arc.write().await;
                if change == "expiry" {
                    cache.snapshots.age(
                        Instant::now(),
                        BINDINGS_FRESHNESS_TTL + Duration::from_secs(1),
                    );
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
            assert_eq!(
                registry.calls(),
                usize::from(change != "revision"),
                "{change} must use the mock registry when refreshing"
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

        let registry = MockBindingRegistry::start(&initial, false).await;
        let state = registry.attach(state);
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
            .timeout(Duration::from_secs(10))
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

        *registry.body.write().await = snapshot_json(&added_snapshot);
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
        *registry.body.write().await = snapshot_json(&revoked_snapshot);
        state.refresh_bindings().await.expect("revoke future model");
        tokio::time::pause();
        tokio::time::advance(BINDINGS_ON_DEMAND_MIN_INTERVAL).await;
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
        *registry.body.write().await = snapshot_json(&readded_snapshot);
        state.refresh_bindings().await.expect("new row revision");
        let (body, revision) = request_b(false, "11");
        let response = test_adapter_request(&client, &adapter_url, &body, revision).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(calls.load(Ordering::Relaxed), 3);

        adapter_task.abort();
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
    async fn proxy_forwards_anthropic_beta_and_rewrites_only_model() {
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
        request
            .headers_mut()
            .insert("x-api-key", HeaderValue::from_static("buyer-api-key"));
        request.headers_mut().insert(
            "anthropic-beta",
            HeaderValue::from_static("future-feature, interleaved-thinking-2025-05-14"),
        );
        request.headers_mut().insert(
            "anthropic-workspace-id",
            HeaderValue::from_static("buyer-workspace"),
        );
        request.headers_mut().insert(
            "x-amzn-bedrock-session-token",
            HeaderValue::from_static("buyer-session-token"),
        );
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
        assert!(headers.get("x-api-key").is_none());
        assert_eq!(
            headers
                .get("anthropic-beta")
                .and_then(|value| value.to_str().ok()),
            Some("future-feature, interleaved-thinking-2025-05-14")
        );
        assert!(headers.get("anthropic-workspace-id").is_none());
        assert!(headers.get("x-amzn-bedrock-session-token").is_none());
        assert!(headers.get(EXECUTION_POLICY_HEADER).is_none());
        upstream_task.abort();
    }

    #[tokio::test]
    async fn opus_55_adaptive_summarized_body_and_effort_are_forwarded_with_bound_model() {
        const MODEL: &str = "claude-opus-5-5";
        const SELECTOR: &str = "anthropic.claude-opus-5-5-v1";
        const RESPONSE_MODEL: &str = "claude-opus-5-5-bedrock-echo";

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
                    let message_start = json!({
                        "type": "message_start",
                        "message": { "model": RESPONSE_MODEL },
                    });
                    let message_stop = json!({ "type": "message_stop" });
                    let body = format!(
                        "event: message_start\ndata: {message_start}\n\nevent: message_stop\ndata: {message_stop}\n\n"
                    );
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "text/event-stream")
                        .body(Body::from(body))
                        .expect("stream response")
                }
            }),
        );
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let upstream_addr = upstream_listener.local_addr().expect("address");
        let upstream_task = tokio::spawn(async move {
            axum::serve(upstream_listener, upstream_app)
                .await
                .expect("upstream");
        });
        let state = BedrockMantleState::for_test(
            &format!("http://{upstream_addr}/anthropic/v1/messages"),
            "Bearer configured-only",
        );
        install_test_binding(&state, MODEL, SELECTOR, RESPONSE_MODEL, 11).await;

        let mut body = json!({
            "model": MODEL,
            "stream": true,
            "max_tokens": 16,
            "thinking": { "type": "adaptive", "display": "summarized" },
            "output_config": { "effort": "medium" },
            "messages": [{ "role": "user", "content": "Reason about this." }]
        });
        let mut request = request("/v1/messages", &body.to_string());
        request.headers_mut().insert(
            MODEL_BINDING_REVISION_HEADER,
            HeaderValue::from_static("11"),
        );
        let response = handle_request(State(AppState(state)), request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = to_bytes(response.into_body(), MAX_RESPONSE_BODY)
            .await
            .expect("stream body");
        assert!(String::from_utf8_lossy(&response_body).contains(MODEL));

        body["model"] = json!(SELECTOR);
        let (headers, sent) = received
            .lock()
            .expect("capture")
            .take()
            .expect("upstream request");
        let sent: Value = serde_json::from_slice(&sent).expect("sent JSON");
        assert_eq!(sent, body);
        assert_eq!(
            headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer configured-only")
        );
        upstream_task.abort();
    }

    #[tokio::test]
    async fn unknown_request_fields_and_content_blocks_are_forwarded_unchanged() {
        const SELECTOR: &str = "anthropic.test-model-a-v1";
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
                        json!({ "model": TEST_RESPONSE_MODEL_A }).to_string(),
                    )
                }
            }),
        );
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let upstream_addr = upstream_listener.local_addr().expect("address");
        let upstream_task = tokio::spawn(async move {
            axum::serve(upstream_listener, upstream_app)
                .await
                .expect("upstream");
        });
        let state = BedrockMantleState::for_test(
            &format!("http://{upstream_addr}/anthropic/v1/messages"),
            "Bearer configured-only",
        );
        let mut body = json!({
            "model": TEST_MODEL_A,
            "max_tokens": 16,
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "future_content_block",
                    "payload": { "preserve": [1, 2, 3] }
                }]
            }],
            "future_top_level_field": { "preserve": true }
        });
        let request = request("/v1/messages", &body.to_string());
        let response = handle_request(State(AppState(state)), request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let (headers, sent) = received
            .lock()
            .expect("capture")
            .take()
            .expect("upstream request");
        body["model"] = json!(SELECTOR);
        assert!(headers.get("anthropic-beta").is_none());
        assert_eq!(
            serde_json::from_slice::<Value>(&sent).expect("sent JSON"),
            body
        );
        upstream_task.abort();
    }

    async fn install_test_binding(
        state: &BedrockMantleState,
        model: &str,
        selector: &str,
        response_model: &str,
        revision: u64,
    ) {
        let cache_arc = state.registry.cache_for_test();
        let mut cache = cache_arc.write().await;
        let mut snapshot = cache
            .snapshots
            .current()
            .expect("test binding snapshot")
            .as_ref()
            .clone();
        snapshot.revision = revision;
        snapshot.bindings.insert(
            model.to_owned(),
            ModelBinding {
                provider: "anthropic".to_owned(),
                model: model.to_owned(),
                upstream_model: selector.to_owned(),
                response_model: response_model.to_owned(),
                revision,
            },
        );
        cache.apply(snapshot, Instant::now()).expect("test binding");
    }

    fn snapshot_with_model_revision(revision: u64) -> BindingsSnapshot {
        let mut snapshot = test_bindings_payload();
        snapshot.revision += 1;
        snapshot
            .bindings
            .get_mut(TEST_MODEL_A)
            .expect("test binding")
            .revision = revision;
        snapshot
    }

    fn invalid_bindings_payload() -> BindingsSnapshot {
        let mut snapshot = test_bindings_payload();
        snapshot.network = "testnet".to_owned();
        snapshot
    }

    async fn expire_bindings(state: &BedrockMantleState) {
        let cache_arc = state.registry.cache_for_test();
        let mut cache = cache_arc.write().await;
        cache.snapshots.age(
            Instant::now(),
            BINDINGS_FRESHNESS_TTL + Duration::from_secs(1),
        );
    }

    fn paused_clock_guard() -> JoinHandle<()> {
        tokio::spawn(async {
            loop {
                // Keep the paused clock from auto-advancing while this spinner yields.
                tokio::task::yield_now().await;
            }
        })
    }

    async fn wait_for_generation(
        receiver: &mut watch::Receiver<BindingRefreshStatus>,
        previous: u64,
    ) -> u64 {
        loop {
            let current = receiver.borrow_and_update().generation();
            if current != previous {
                return current;
            }
            receiver.changed().await.expect("binding refresh status");
        }
    }

    struct MockBindingRegistry {
        url: String,
        body: Arc<RwLock<Vec<u8>>>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
        entered: Arc<tokio::sync::Semaphore>,
        release: Arc<tokio::sync::Semaphore>,
        task: JoinHandle<()>,
    }

    impl MockBindingRegistry {
        async fn start(snapshot: &BindingsSnapshot, blocked: bool) -> Self {
            let body = Arc::new(RwLock::new(snapshot_json(snapshot)));
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let entered = Arc::new(tokio::sync::Semaphore::new(0));
            let release = Arc::new(tokio::sync::Semaphore::new(0));
            let registry_body = body.clone();
            let registry_calls = calls.clone();
            let registry_entered = entered.clone();
            let registry_release = release.clone();
            let registry_app = Router::new().route(
                "/model-bindings/bedrock",
                get(move || {
                    let body = registry_body.clone();
                    let calls = registry_calls.clone();
                    let entered = registry_entered.clone();
                    let release = registry_release.clone();
                    async move {
                        calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        entered.add_permits(1);
                        if blocked {
                            release
                                .acquire()
                                .await
                                .expect("registry response release")
                                .forget();
                        }
                        let body = body.read().await.clone();
                        ([(CONTENT_TYPE, "application/json")], body)
                    }
                }),
            );
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("registry listener");
            let address = listener.local_addr().expect("registry address");
            let task = tokio::spawn(async move {
                axum::serve(listener, registry_app)
                    .await
                    .expect("mock registry");
            });
            Self {
                url: format!("http://{address}/model-bindings/bedrock"),
                body,
                calls,
                entered,
                release,
                task,
            }
        }

        fn attach(&self, state: BedrockMantleState) -> BedrockMantleState {
            state.with_test_registry_url(&self.url)
        }

        async fn wait_for_call(&self) {
            self.entered
                .acquire()
                .await
                .expect("mock registry semaphore")
                .forget();
        }

        fn release(&self, count: usize) {
            self.release.add_permits(count);
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl Drop for MockBindingRegistry {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn request(uri: &str, body: &str) -> Request<Body> {
        request_with_revision(uri, body, "7")
    }

    fn request_with_revision(uri: &str, body: &str, revision: &str) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header(EXECUTION_POLICY_HEADER, EXACT_CANONICAL_NO_REPLAY_POLICY)
            .header(MODEL_BINDING_REVISION_HEADER, revision)
            .body(Body::from(body.to_owned()))
            .expect("request")
    }

    async fn test_state() -> (
        BedrockMantleState,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        test_state_with_response(TEST_RESPONSE_MODEL_A).await
    }

    async fn test_state_with_response(
        response_model: &'static str,
    ) -> (
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
                    let body = json!({ "model": response_model }).to_string();
                    ([(CONTENT_TYPE, "application/json")], body)
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
