//! The measured cloud-adapter model translation hop.
//!
//! Envoy remains responsible for all cloud TLS, host rewrite, SNI, and SAN
//! matching. This crate only accepts an already-authenticated loopback request,
//! replaces one top-level JSON member, and forwards the request to Envoy's
//! loopback egress listener. Responses are never parsed or rewritten.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http_body_util::{combinators::BoxBody, BodyExt as _, Full};
use hyper::{
    body::{Body as _, Buf, Bytes, Incoming},
    header::{HeaderValue, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING},
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    task::AbortHandle,
    time::{timeout_at, Instant},
};

/// The cloud adapters whose request surfaces are qualified for this hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudProvider {
    /// Azure `OpenAI` chat completions.
    AzureOpenAi,
    /// Microsoft Foundry Anthropic Messages.
    Foundry,
    /// AWS Bedrock Mantle, rejected until its response echo is qualified.
    Bedrock,
}

impl CloudProvider {
    /// The internal Envoy selector value.
    #[must_use]
    pub const fn selector(self) -> &'static str {
        match self {
            Self::AzureOpenAi => "azure-openai",
            Self::Foundry => "foundry",
            Self::Bedrock => "bedrock",
        }
    }

    /// Parse the internal selector that Envoy adds before entering the hop.
    #[must_use]
    pub fn from_selector(value: &str) -> Option<Self> {
        match value {
            "azure-openai" => Some(Self::AzureOpenAi),
            "foundry" => Some(Self::Foundry),
            "bedrock" => Some(Self::Bedrock),
            _ => None,
        }
    }

    /// The canonical model IDs accepted by this adapter's map.
    #[must_use]
    pub const fn known_model_ids(self) -> &'static [&'static str] {
        match self {
            Self::AzureOpenAi => AZURE_OPENAI_MODEL_IDS,
            Self::Foundry => FOUNDRY_MODEL_IDS,
            Self::Bedrock => BEDROCK_MODEL_IDS,
        }
    }

    /// The ARM model class this adapter is allowed to serve.
    #[must_use]
    pub const fn model_class(self) -> CloudModelClass {
        match self {
            Self::AzureOpenAi => CloudModelClass::OpenAi,
            Self::Foundry | Self::Bedrock => CloudModelClass::Anthropic,
        }
    }
}

/// The model publisher class asserted by ARM for a qualified deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudModelClass {
    /// Azure `OpenAI` model format.
    OpenAi,
    /// Anthropic model format.
    Anthropic,
}

/// A request surface in the cloud qualification matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudSurface {
    /// Azure `OpenAI` `/openai/v1/chat/completions`.
    AzureChatCompletions,
    /// Azure `OpenAI` `/openai/v1/responses`.
    AzureResponses,
    /// Microsoft Foundry `/anthropic/v1/messages`.
    FoundryMessages,
    /// The future Bedrock Mantle messages surface.
    BedrockMessages,
}

impl CloudSurface {
    /// The public API path represented by this row.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::AzureChatCompletions => "/v1/chat/completions",
            Self::AzureResponses => "/v1/responses",
            Self::FoundryMessages | Self::BedrockMessages => "/v1/messages",
        }
    }
}

/// Whether a surface/mode has an authoritative upstream model echo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qualification {
    /// True when the model echo is suitable for registry/gateway admission.
    pub qualified: bool,
    /// Evidence-backed explanation shown by doctor and rejection paths.
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QualificationRow {
    provider: CloudProvider,
    surface: CloudSurface,
    model_class: CloudModelClass,
    streaming: bool,
    qualification: Qualification,
}

const QUALIFIED_MODEL_ECHO_REASON: &str =
    "2026-09-09 live echo identifies the upstream model (dated Azure model or Foundry model)";
pub const AZURE_RESPONSES_UNQUALIFIED_REASON: &str =
    "2026-09-09 live Azure Responses echo identifies the deployment name, not the upstream model; this surface remains unqualified even with ARM-attested deployment binding";
const BEDROCK_UNQUALIFIED_REASON: &str =
    "Bedrock is unqualified: no authoritative live model echo has been admitted";

// Evidence date: 2026-09-09, gm's own Azure account, alias gm-echo-test.
const QUALIFICATION_MATRIX: &[QualificationRow] = &[
    // Evidence date: 2026-09-09. Azure chat non-streaming echoed gpt-5-2025-08-07.
    QualificationRow {
        provider: CloudProvider::AzureOpenAi,
        surface: CloudSurface::AzureChatCompletions,
        model_class: CloudModelClass::OpenAi,
        streaming: false,
        qualification: Qualification {
            qualified: true,
            reason: QUALIFIED_MODEL_ECHO_REASON,
        },
    },
    // Evidence date: 2026-09-09. Azure chat streaming echoed the dated model after its annotation frame.
    QualificationRow {
        provider: CloudProvider::AzureOpenAi,
        surface: CloudSurface::AzureChatCompletions,
        model_class: CloudModelClass::OpenAi,
        streaming: true,
        qualification: Qualification {
            qualified: true,
            reason: QUALIFIED_MODEL_ECHO_REASON,
        },
    },
    // Evidence date: 2026-09-09. Azure Responses non-streaming echoed gm-echo-test, the deployment name.
    QualificationRow {
        provider: CloudProvider::AzureOpenAi,
        surface: CloudSurface::AzureResponses,
        model_class: CloudModelClass::OpenAi,
        streaming: false,
        qualification: Qualification {
            qualified: false,
            reason: AZURE_RESPONSES_UNQUALIFIED_REASON,
        },
    },
    // Evidence date: 2026-09-09. Azure Responses response.created echoed gm-echo-test, the deployment name.
    QualificationRow {
        provider: CloudProvider::AzureOpenAi,
        surface: CloudSurface::AzureResponses,
        model_class: CloudModelClass::OpenAi,
        streaming: true,
        qualification: Qualification {
            qualified: false,
            reason: AZURE_RESPONSES_UNQUALIFIED_REASON,
        },
    },
    // Evidence date: 2026-09-09. Foundry Messages non-streaming echoed claude-sonnet-4-6.
    QualificationRow {
        provider: CloudProvider::Foundry,
        surface: CloudSurface::FoundryMessages,
        model_class: CloudModelClass::Anthropic,
        streaming: false,
        qualification: Qualification {
            qualified: true,
            reason: QUALIFIED_MODEL_ECHO_REASON,
        },
    },
    // Evidence date: 2026-09-09. Foundry Messages streaming message_start echoed claude-sonnet-4-6.
    QualificationRow {
        provider: CloudProvider::Foundry,
        surface: CloudSurface::FoundryMessages,
        model_class: CloudModelClass::Anthropic,
        streaming: true,
        qualification: Qualification {
            qualified: true,
            reason: QUALIFIED_MODEL_ECHO_REASON,
        },
    },
    // Evidence date: 2026-09-09. Bedrock has no qualifying echo evidence.
    QualificationRow {
        provider: CloudProvider::Bedrock,
        surface: CloudSurface::BedrockMessages,
        model_class: CloudModelClass::Anthropic,
        streaming: false,
        qualification: Qualification {
            qualified: false,
            reason: BEDROCK_UNQUALIFIED_REASON,
        },
    },
    // Evidence date: 2026-09-09. Bedrock has no qualifying echo evidence.
    QualificationRow {
        provider: CloudProvider::Bedrock,
        surface: CloudSurface::BedrockMessages,
        model_class: CloudModelClass::Anthropic,
        streaming: true,
        qualification: Qualification {
            qualified: false,
            reason: BEDROCK_UNQUALIFIED_REASON,
        },
    },
];

/// Look up the checked-in adapter/surface/streaming qualification row.
#[must_use]
pub fn qualification(
    provider: CloudProvider,
    surface: CloudSurface,
    streaming: bool,
) -> Option<Qualification> {
    QUALIFICATION_MATRIX
        .iter()
        .find(|row| {
            row.provider == provider
                && row.model_class == provider.model_class()
                && row.surface == surface
                && row.streaming == streaming
        })
        .map(|row| row.qualification)
}

/// Azure `OpenAI` canonical IDs known by the miner's current provider catalog.
///
/// This is deliberately a static snapshot rather than an operator-controlled
/// allowlist: a deployment map may select data, but it cannot introduce a new
/// model identity into a measured image.
pub const AZURE_OPENAI_MODEL_IDS: &[&str] = &[
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.4-nano",
    "gpt-5.5",
    "gpt-5.5-pro",
    "gpt-5.6",
    "gpt-5.6-luna",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "o3",
    "o4-mini",
];

/// Microsoft Foundry canonical IDs known by the miner's current provider
/// catalog.
pub const FOUNDRY_MODEL_IDS: &[&str] = &[
    "claude-fable-5",
    "claude-haiku-4-5",
    "claude-opus-4-7",
    "claude-opus-4-8",
    "claude-opus-5",
    "claude-sonnet-4-6",
    "claude-sonnet-5",
];

/// Legacy Bedrock canonical IDs, retained for configuration diagnostics only.
pub const BEDROCK_MODEL_IDS: &[&str] = &["claude-sonnet-4-6"];

const MAX_MAP_BYTES: usize = 4096;
const MAX_MAP_ENTRIES: usize = 64;
const MIN_DEPLOYMENT_NAME_BYTES: usize = 2;
const MAX_DEPLOYMENT_NAME_BYTES: usize = 64;
const MAX_CANONICAL_NAME_BYTES: usize = 128;
const MAX_JSON_DEPTH: usize = 128;
const DEFAULT_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_BUFFERED_BYTES: usize = 64 * 1024 * 1024;
const MAX_BUFFERED_BYTES: usize = 512 * 1024 * 1024;
const REQUIRED_BUFFERED_EXTRA_BYTES: usize = MAX_DEPLOYMENT_NAME_BYTES;
const DEFAULT_CONCURRENCY: usize = 16;
const MAX_CONCURRENCY: usize = 256;
const DEFAULT_TIMEOUT_MS: u64 = 1_800_000;
const MAX_TIMEOUT_MS: u64 = 3_600_000;
const INTERNAL_EGRESS_ADDR: &str = "127.0.0.1:8084";

/// A validated canonical-to-deployment map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentMap {
    provider: CloudProvider,
    entries: BTreeMap<String, String>,
}

impl DeploymentMap {
    /// The adapter this map belongs to.
    #[must_use]
    pub const fn provider(&self) -> CloudProvider {
        self.provider
    }

    /// Look up a deployment by canonical model ID.
    #[must_use]
    pub fn get(&self, canonical: &str) -> Option<&str> {
        self.entries.get(canonical).map(String::as_str)
    }

    /// Iterate in canonical ID order for deterministic doctor output.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(canonical, deployment)| (canonical.as_str(), deployment.as_str()))
    }

    /// Number of mapped canonical IDs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no canonical IDs are mapped.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serialize the validated map in one deterministic, single-line form.
    #[must_use]
    pub fn canonical_string(&self) -> String {
        self.entries
            .iter()
            .map(|(canonical, deployment)| format!("{canonical}={deployment}"))
            .collect::<Vec<_>>()
            .join(";")
    }
}

/// Deployment-map validation failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeploymentMapError {
    #[error("deployment map is empty")]
    Empty,
    #[error("deployment map exceeds {MAX_MAP_BYTES} bytes")]
    TooLarge,
    #[error("deployment map contains more than {MAX_MAP_ENTRIES} entries")]
    TooManyEntries,
    #[error("deployment map entry {entry} is empty")]
    EmptyEntry { entry: usize },
    #[error("deployment map must not contain carriage returns or newlines")]
    ContainsNewline,
    #[error("deployment map entry {entry} must contain exactly one '='")]
    InvalidSeparator { entry: usize },
    #[error("canonical model in deployment map entry {entry} is empty")]
    EmptyCanonical { entry: usize },
    #[error("deployment name in deployment map entry {entry} is empty")]
    EmptyDeployment { entry: usize },
    #[error("canonical model in deployment map entry {entry} is too long")]
    CanonicalTooLong { entry: usize },
    #[error("canonical model '{canonical}' is not known for {provider}")]
    UnknownCanonical { provider: String, canonical: String },
    #[error("canonical model '{canonical}' has no qualified {provider} adapter/surface row")]
    UnqualifiedCanonical { provider: String, canonical: String },
    #[error("canonical model '{canonical}' is duplicated in the deployment map")]
    DuplicateCanonical { canonical: String },
    #[error(
        "deployment name in deployment map entry {entry} must be {MIN_DEPLOYMENT_NAME_BYTES}-{MAX_DEPLOYMENT_NAME_BYTES} ASCII letters, numbers, hyphens, or underscores"
    )]
    InvalidDeployment { entry: usize },
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::AzureOpenAi => "azure-openai",
            Self::Foundry => "foundry",
            Self::Bedrock => "bedrock",
        })
    }
}

/// Parse and validate `canonical=deployment;canonical=deployment`.
///
/// # Errors
///
/// Returns a [`DeploymentMapError`] when the map is empty, exceeds a bound,
/// uses invalid syntax, names an unknown canonical model, repeats a canonical
/// model, or contains an invalid deployment name.
pub fn parse_deployment_map(
    provider: CloudProvider,
    raw: &str,
) -> Result<DeploymentMap, DeploymentMapError> {
    if raw.contains(['\r', '\n']) {
        return Err(DeploymentMapError::ContainsNewline);
    }
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(DeploymentMapError::Empty);
    }
    if raw.len() > MAX_MAP_BYTES {
        return Err(DeploymentMapError::TooLarge);
    }
    let parts = raw.split(';').collect::<Vec<_>>();
    if parts.len() > MAX_MAP_ENTRIES {
        return Err(DeploymentMapError::TooManyEntries);
    }

    let mut entries = BTreeMap::new();
    for (index, part) in parts.into_iter().enumerate() {
        let entry = index + 1;
        let part = part.trim();
        if part.is_empty() {
            return Err(DeploymentMapError::EmptyEntry { entry });
        }
        let Some((canonical, deployment)) = part.split_once('=') else {
            return Err(DeploymentMapError::InvalidSeparator { entry });
        };
        if deployment.contains('=') {
            return Err(DeploymentMapError::InvalidSeparator { entry });
        }
        let canonical = canonical.trim();
        let deployment = deployment.trim();
        if canonical.is_empty() {
            return Err(DeploymentMapError::EmptyCanonical { entry });
        }
        if deployment.is_empty() {
            return Err(DeploymentMapError::EmptyDeployment { entry });
        }
        if canonical.len() > MAX_CANONICAL_NAME_BYTES {
            return Err(DeploymentMapError::CanonicalTooLong { entry });
        }
        if !provider.known_model_ids().contains(&canonical) {
            return Err(DeploymentMapError::UnknownCanonical {
                provider: provider.to_string(),
                canonical: canonical.to_owned(),
            });
        }
        if !provider_has_qualified_surface(provider) {
            return Err(DeploymentMapError::UnqualifiedCanonical {
                provider: provider.to_string(),
                canonical: canonical.to_owned(),
            });
        }
        if !valid_deployment_name(deployment) {
            return Err(DeploymentMapError::InvalidDeployment { entry });
        }
        if entries
            .insert(canonical.to_owned(), deployment.to_owned())
            .is_some()
        {
            return Err(DeploymentMapError::DuplicateCanonical {
                canonical: canonical.to_owned(),
            });
        }
    }
    Ok(DeploymentMap { provider, entries })
}

fn valid_deployment_name(value: &str) -> bool {
    (MIN_DEPLOYMENT_NAME_BYTES..=MAX_DEPLOYMENT_NAME_BYTES).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn provider_has_qualified_surface(provider: CloudProvider) -> bool {
    QUALIFICATION_MATRIX.iter().any(|row| {
        row.provider == provider
            && row.model_class == provider.model_class()
            && row.qualification.qualified
    })
}

/// Model-identity error returned before an upstream request is made.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RewriteError {
    #[error("request body is not valid UTF-8 JSON")]
    InvalidUtf8,
    #[error("request body is not a JSON object")]
    TopLevelNotObject,
    #[error("request JSON is malformed")]
    MalformedJson,
    #[error("top-level JSON member 'model' is missing")]
    MissingModel,
    #[error("top-level JSON member 'model' is duplicated")]
    DuplicateModel,
    #[error("top-level JSON member 'model' must be a string")]
    ModelNotString,
    #[error("canonical model is not mapped for this cloud adapter")]
    UnmappedModel,
    #[error("cloud hop is disabled for this provider")]
    DisabledProvider,
}

/// Replace only the raw top-level `model` value and leave every other body
/// byte untouched. The JSON scanner validates structure but never
/// parse-and-reserializes the request.
///
/// # Errors
///
/// Returns a [`RewriteError`] when the body is invalid JSON, is not a
/// top-level object, has a missing, duplicated, non-string, or unmapped
/// `model`, or targets a disabled provider.
pub fn rewrite_model_bytes(
    provider: CloudProvider,
    body: &[u8],
    map: &DeploymentMap,
) -> Result<Vec<u8>, RewriteError> {
    if provider == CloudProvider::Bedrock {
        return Err(RewriteError::DisabledProvider);
    }
    if map.provider != provider {
        return Err(RewriteError::UnmappedModel);
    }
    std::str::from_utf8(body).map_err(|_| RewriteError::InvalidUtf8)?;

    let mut cursor = JsonCursor { body, position: 0 };
    cursor.skip_whitespace();
    if cursor.peek() != Some(b'{') {
        return Err(RewriteError::TopLevelNotObject);
    }
    let mut replacement = None;
    scan_object(&mut cursor, 0, true, &mut replacement)?;
    cursor.skip_whitespace();
    if cursor.position != body.len() {
        return Err(RewriteError::MalformedJson);
    }
    let Some(ModelMember { start, end, model }) = replacement else {
        return Err(RewriteError::MissingModel);
    };
    let Some(deployment) = map.get(&model) else {
        return Err(RewriteError::UnmappedModel);
    };

    let mut rewritten = Vec::with_capacity(body.len() + deployment.len());
    rewritten.extend_from_slice(&body[..start]);
    rewritten.push(b'"');
    rewritten.extend_from_slice(deployment.as_bytes());
    rewritten.push(b'"');
    rewritten.extend_from_slice(&body[end..]);
    Ok(rewritten)
}

/// Extract the unique top-level string `model` member using the same strict
/// scanner and duplicate-key rule as [`rewrite_model_bytes`].
///
/// This is used by `gmcli doctor` for upstream response echoes. A generic
/// `serde_json::Value` would silently keep the last duplicate key and could
/// turn an ambiguous response into a false identity pass.
///
/// # Errors
/// Returns a [`RewriteError`] when the body is invalid JSON, is not a
/// top-level object, or has a missing, duplicated, or non-string `model`.
pub fn extract_model_echo(body: &[u8]) -> Result<String, RewriteError> {
    std::str::from_utf8(body).map_err(|_| RewriteError::InvalidUtf8)?;
    let mut cursor = JsonCursor { body, position: 0 };
    cursor.skip_whitespace();
    if cursor.peek() != Some(b'{') {
        return Err(RewriteError::TopLevelNotObject);
    }
    let mut member = None;
    scan_object(&mut cursor, 0, true, &mut member)?;
    cursor.skip_whitespace();
    if cursor.position != body.len() {
        return Err(RewriteError::MalformedJson);
    }
    member
        .map(|member| member.model)
        .ok_or(RewriteError::MissingModel)
}

/// Exact echo match plus a provider-owned dated model suffix. The suffix forms
/// are the dated IDs seen in the direct/OpenAI and Anthropic catalog surfaces.
#[must_use]
pub fn echo_matches_model(canonical: &str, echoed: &str) -> bool {
    echoed == canonical || valid_dated_suffix(canonical, echoed)
}

fn valid_dated_suffix(canonical: &str, echoed: &str) -> bool {
    echoed
        .strip_prefix(canonical)
        .and_then(|suffix| suffix.strip_prefix('-'))
        .is_some_and(|date| match date.len() {
            8 => date.bytes().all(|byte| byte.is_ascii_digit()),
            10 => date.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 4 | 7) {
                    byte == b'-'
                } else {
                    byte.is_ascii_digit()
                }
            }),
            _ => false,
        })
}

struct JsonCursor<'a> {
    body: &'a [u8],
    position: usize,
}

struct ModelMember {
    start: usize,
    end: usize,
    model: String,
}

impl JsonCursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.body.get(self.position).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.position += 1;
        Some(byte)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.position += 1;
        }
    }
}

fn scan_object(
    cursor: &mut JsonCursor<'_>,
    depth: usize,
    root: bool,
    replacement: &mut Option<ModelMember>,
) -> Result<(), RewriteError> {
    if depth > MAX_JSON_DEPTH || cursor.advance() != Some(b'{') {
        return Err(RewriteError::MalformedJson);
    }
    cursor.skip_whitespace();
    if cursor.peek() == Some(b'}') {
        cursor.advance();
        return Ok(());
    }

    loop {
        cursor.skip_whitespace();
        let key_start = cursor.position;
        let key_end = scan_string(cursor)?;
        let is_model_key =
            root && json_string_equals_ascii(&cursor.body[key_start..key_end], b"model");
        cursor.skip_whitespace();
        if cursor.advance() != Some(b':') {
            return Err(RewriteError::MalformedJson);
        }
        cursor.skip_whitespace();
        let value_start = cursor.position;
        scan_value(cursor, depth + 1, replacement, false)?;
        let value_end = cursor.position;

        if is_model_key {
            if replacement.is_some() {
                return Err(RewriteError::DuplicateModel);
            }
            if cursor.body.get(value_start) != Some(&b'"') {
                return Err(RewriteError::ModelNotString);
            }
            let model = decode_bounded_json_string(
                &cursor.body[value_start..value_end],
                MAX_CANONICAL_NAME_BYTES,
            )?;
            *replacement = Some(ModelMember {
                start: value_start,
                end: value_end,
                model,
            });
        }

        cursor.skip_whitespace();
        match cursor.advance() {
            Some(b',') => {}
            Some(b'}') => return Ok(()),
            _ => return Err(RewriteError::MalformedJson),
        }
    }
}

fn scan_value(
    cursor: &mut JsonCursor<'_>,
    depth: usize,
    replacement: &mut Option<ModelMember>,
    root: bool,
) -> Result<(), RewriteError> {
    if depth > MAX_JSON_DEPTH {
        return Err(RewriteError::MalformedJson);
    }
    match cursor.peek() {
        Some(b'"') => {
            scan_string(cursor)?;
            Ok(())
        }
        Some(b'{') => scan_object(cursor, depth, root, replacement),
        Some(b'[') => scan_array(cursor, depth, replacement),
        Some(b't') => scan_literal(cursor, b"true"),
        Some(b'f') => scan_literal(cursor, b"false"),
        Some(b'n') => scan_literal(cursor, b"null"),
        Some(byte) if byte == b'-' || byte.is_ascii_digit() => scan_number(cursor),
        _ => Err(RewriteError::MalformedJson),
    }
}

fn scan_array(
    cursor: &mut JsonCursor<'_>,
    depth: usize,
    replacement: &mut Option<ModelMember>,
) -> Result<(), RewriteError> {
    cursor.advance();
    cursor.skip_whitespace();
    if cursor.peek() == Some(b']') {
        cursor.advance();
        return Ok(());
    }
    loop {
        cursor.skip_whitespace();
        scan_value(cursor, depth + 1, replacement, false)?;
        cursor.skip_whitespace();
        match cursor.advance() {
            Some(b',') => {}
            Some(b']') => return Ok(()),
            _ => return Err(RewriteError::MalformedJson),
        }
    }
}

fn scan_string(cursor: &mut JsonCursor<'_>) -> Result<usize, RewriteError> {
    if cursor.advance() != Some(b'"') {
        return Err(RewriteError::MalformedJson);
    }
    loop {
        match cursor.advance() {
            Some(b'"') => return Ok(cursor.position),
            Some(b'\\') => match cursor.advance() {
                Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {}
                Some(b'u') => {
                    for _ in 0..4 {
                        if cursor
                            .advance()
                            .is_none_or(|byte| !byte.is_ascii_hexdigit())
                        {
                            return Err(RewriteError::MalformedJson);
                        }
                    }
                }
                _ => return Err(RewriteError::MalformedJson),
            },
            Some(byte) if byte < 0x20 => return Err(RewriteError::MalformedJson),
            Some(_) => {}
            None => return Err(RewriteError::MalformedJson),
        }
    }
}

/// Compare a scanned JSON string with an ASCII name without allocating its
/// decoded contents. This is used for object keys, including escaped keys,
/// so large irrelevant keys never become owned `String`s during the scan.
fn json_string_equals_ascii(raw: &[u8], expected: &[u8]) -> bool {
    if raw.first() != Some(&b'"') || raw.last() != Some(&b'"') {
        return false;
    }
    let mut position = 1;
    let end = raw.len() - 1;
    let mut expected_position = 0;
    while position < end {
        let Some(byte) = next_json_ascii_byte(raw, &mut position, end) else {
            return false;
        };
        if expected.get(expected_position) != Some(&byte) {
            return false;
        }
        expected_position += 1;
    }
    expected_position == expected.len()
}

fn next_json_ascii_byte(raw: &[u8], position: &mut usize, end: usize) -> Option<u8> {
    let byte = *raw.get(*position)?;
    *position += 1;
    if byte != b'\\' {
        return (byte < 0x80).then_some(byte);
    }
    let escaped = *raw.get(*position)?;
    *position += 1;
    match escaped {
        b'"' => Some(b'"'),
        b'\\' => Some(b'\\'),
        b'/' => Some(b'/'),
        b'b' => Some(0x08),
        b'f' => Some(0x0c),
        b'n' => Some(b'\n'),
        b'r' => Some(b'\r'),
        b't' => Some(b'\t'),
        b'u' => {
            let code = parse_hex_escape(raw, position, end)?;
            if code <= 0x7f {
                u8::try_from(code).ok()
            } else {
                None
            }
        }
        _ => None,
    }
}

fn parse_hex_escape(raw: &[u8], position: &mut usize, end: usize) -> Option<u32> {
    if end.saturating_sub(*position) < 4 {
        return None;
    }
    let mut value = 0_u32;
    for _ in 0..4 {
        let digit = hex_value(*raw.get(*position)?);
        if digit == 0xff {
            return None;
        }
        value = value.checked_mul(16)?.checked_add(u32::from(digit))?;
        *position += 1;
    }
    Some(value)
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0xff,
    }
}

/// Decode only the bounded top-level model value. The scanner has already
/// validated the string grammar; this small decoder handles escapes without
/// serde's scratch allocation and stops before an attacker-sized canonical
/// value can grow an owned string.
fn decode_bounded_json_string(raw: &[u8], max_bytes: usize) -> Result<String, RewriteError> {
    if raw.first() != Some(&b'"') || raw.last() != Some(&b'"') {
        return Err(RewriteError::ModelNotString);
    }
    let mut output = String::with_capacity(max_bytes);
    let mut position = 1;
    let end = raw.len() - 1;
    while position < end {
        let character = if raw[position] == b'\\' {
            position += 1;
            let escaped = *raw.get(position).ok_or(RewriteError::ModelNotString)?;
            position += 1;
            match escaped {
                b'"' => '"',
                b'\\' => '\\',
                b'/' => '/',
                b'b' => '\u{0008}',
                b'f' => '\u{000c}',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                b'u' => decode_unicode_escape(raw, &mut position, end)?,
                _ => return Err(RewriteError::ModelNotString),
            }
        } else {
            let remaining = std::str::from_utf8(&raw[position..end])
                .map_err(|_| RewriteError::ModelNotString)?;
            let character = remaining
                .chars()
                .next()
                .ok_or(RewriteError::ModelNotString)?;
            position += character.len_utf8();
            character
        };
        if output.len().saturating_add(character.len_utf8()) > max_bytes {
            return Err(RewriteError::UnmappedModel);
        }
        output.push(character);
    }
    Ok(output)
}

fn decode_unicode_escape(
    raw: &[u8],
    position: &mut usize,
    end: usize,
) -> Result<char, RewriteError> {
    let first = parse_hex_escape(raw, position, end).ok_or(RewriteError::ModelNotString)?;
    if (0xd800..=0xdbff).contains(&first) {
        if end.saturating_sub(*position) < 6
            || raw.get(*position) != Some(&b'\\')
            || raw.get(*position + 1) != Some(&b'u')
        {
            return Err(RewriteError::ModelNotString);
        }
        *position += 2;
        let second = parse_hex_escape(raw, position, end).ok_or(RewriteError::ModelNotString)?;
        if !(0xdc00..=0xdfff).contains(&second) {
            return Err(RewriteError::ModelNotString);
        }
        let code_point = 0x1_0000 + ((first - 0xd800) << 10) + (second - 0xdc00);
        char::from_u32(code_point).ok_or(RewriteError::ModelNotString)
    } else if (0xdc00..=0xdfff).contains(&first) {
        Err(RewriteError::ModelNotString)
    } else {
        char::from_u32(first).ok_or(RewriteError::ModelNotString)
    }
}

fn scan_literal(cursor: &mut JsonCursor<'_>, literal: &[u8]) -> Result<(), RewriteError> {
    let end = cursor.position.saturating_add(literal.len());
    if cursor.body.get(cursor.position..end) == Some(literal) {
        cursor.position = end;
        Ok(())
    } else {
        Err(RewriteError::MalformedJson)
    }
}

fn scan_number(cursor: &mut JsonCursor<'_>) -> Result<(), RewriteError> {
    let start = cursor.position;
    if cursor.peek() == Some(b'-') {
        cursor.advance();
    }
    match cursor.advance() {
        Some(b'0') => {
            if cursor.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(RewriteError::MalformedJson);
            }
        }
        Some(byte) if (b'1'..=b'9').contains(&byte) => {
            while cursor.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                cursor.advance();
            }
        }
        _ => return Err(RewriteError::MalformedJson),
    }
    if cursor.peek() == Some(b'.') {
        cursor.advance();
        if !cursor.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            return Err(RewriteError::MalformedJson);
        }
        while cursor.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            cursor.advance();
        }
    }
    if matches!(cursor.peek(), Some(b'e' | b'E')) {
        cursor.advance();
        if matches!(cursor.peek(), Some(b'+' | b'-')) {
            cursor.advance();
        }
        if !cursor.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            return Err(RewriteError::MalformedJson);
        }
        while cursor.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            cursor.advance();
        }
    }
    if cursor.position == start {
        Err(RewriteError::MalformedJson)
    } else {
        Ok(())
    }
}

/// Runtime settings for the loopback proxy.
#[derive(Debug, Clone)]
pub struct CloudHopConfig {
    pub azure_openai: Option<DeploymentMap>,
    pub foundry: Option<DeploymentMap>,
    pub max_request_bytes: usize,
    pub max_buffered_bytes: usize,
    pub max_concurrency: usize,
    pub timeout: Duration,
}

impl CloudHopConfig {
    /// Read and validate all hop configuration from the process environment.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] when a selected adapter lacks a deployment
    /// map, a map is invalid, or a resource limit is outside its bound.
    pub fn from_env() -> Result<Self, ConfigError> {
        let azure_openai = parse_optional_map(
            "AZURE_OPENAI_DEPLOYMENTS",
            CloudProvider::AzureOpenAi,
            selector_is("OPENAI_UPSTREAM", "azure"),
        )?;
        let foundry = parse_optional_map(
            "AZURE_FOUNDRY_DEPLOYMENTS",
            CloudProvider::Foundry,
            selector_is("ANTHROPIC_UPSTREAM", "foundry"),
        )?;
        let max_request_bytes = bounded_usize(
            "GM_CLOUD_HOP_MAX_REQUEST_BYTES",
            env_or_gateway_cap(),
            1,
            MAX_REQUEST_BYTES,
            DEFAULT_REQUEST_BYTES,
        )?;
        let minimum_buffered = required_buffered_bytes(max_request_bytes);
        let default_buffered = DEFAULT_BUFFERED_BYTES.max(minimum_buffered);
        let max_buffered_bytes = bounded_usize(
            "GM_CLOUD_HOP_MAX_BUFFERED_BYTES",
            std::env::var("GM_CLOUD_HOP_MAX_BUFFERED_BYTES").ok(),
            minimum_buffered,
            MAX_BUFFERED_BYTES,
            default_buffered,
        )?;
        let max_concurrency = bounded_usize(
            "GM_CLOUD_HOP_MAX_CONCURRENCY",
            std::env::var("GM_CLOUD_HOP_MAX_CONCURRENCY").ok(),
            1,
            MAX_CONCURRENCY,
            DEFAULT_CONCURRENCY,
        )?;
        let timeout_ms = bounded_u64(
            "GM_CLOUD_HOP_TIMEOUT_MS",
            std::env::var("GM_CLOUD_HOP_TIMEOUT_MS").ok(),
            1,
            MAX_TIMEOUT_MS,
            DEFAULT_TIMEOUT_MS,
        )?;

        Ok(Self {
            azure_openai,
            foundry,
            max_request_bytes,
            max_buffered_bytes,
            max_concurrency,
            timeout: Duration::from_millis(timeout_ms),
        })
    }

    /// Whether at least one qualified cloud adapter is enabled.
    #[must_use]
    pub fn has_enabled_provider(&self) -> bool {
        self.azure_openai.is_some() || self.foundry.is_some()
    }

    fn map_for(&self, provider: CloudProvider) -> Option<&DeploymentMap> {
        match provider {
            CloudProvider::AzureOpenAi => self.azure_openai.as_ref(),
            CloudProvider::Foundry => self.foundry.as_ref(),
            CloudProvider::Bedrock => None,
        }
    }
}

fn required_buffered_bytes(max_request_bytes: usize) -> usize {
    max_request_bytes
        .saturating_mul(2)
        .saturating_add(REQUIRED_BUFFERED_EXTRA_BYTES)
}

/// Environment configuration failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{name} is required when the selected cloud upstream is enabled")]
    MissingMap { name: &'static str },
    #[error("{name} must be a decimal integer")]
    InvalidInteger { name: &'static str },
    #[error("{name} must be between {min} and {max}")]
    IntegerOutOfRange {
        name: &'static str,
        min: usize,
        max: usize,
    },
    #[error("GM_CLOUD_HOP_TIMEOUT_MS must be between {min} and {max}")]
    TimeoutOutOfRange { min: u64, max: u64 },
    #[error("{name} has invalid deployment map: {source}")]
    InvalidMap {
        name: &'static str,
        source: DeploymentMapError,
    },
}

fn selector_is(name: &str, expected: &str) -> bool {
    std::env::var(name).unwrap_or_else(|_| "direct".to_owned()) == expected
}

fn env_or_gateway_cap() -> Option<String> {
    request_cap_value(
        std::env::var("GM_CLOUD_HOP_MAX_REQUEST_BYTES").ok(),
        std::env::var("GM_GATEWAY_MAX_REQUEST_BODY_BYTES").ok(),
    )
}

fn request_cap_value(hop: Option<String>, gateway: Option<String>) -> Option<String> {
    hop.filter(|value| !value.trim().is_empty())
        .or_else(|| gateway.filter(|value| !value.trim().is_empty()))
}

fn parse_optional_map(
    name: &'static str,
    provider: CloudProvider,
    required: bool,
) -> Result<Option<DeploymentMap>, ConfigError> {
    let raw = std::env::var(name).ok();
    match raw.filter(|value| !value.trim().is_empty()) {
        Some(raw) => parse_deployment_map(provider, &raw)
            .map(Some)
            .map_err(|source| ConfigError::InvalidMap { name, source }),
        None if required => Err(ConfigError::MissingMap { name }),
        None => Ok(None),
    }
}

fn bounded_usize(
    name: &'static str,
    raw: Option<String>,
    min: usize,
    max: usize,
    default: usize,
) -> Result<usize, ConfigError> {
    let Some(raw) = raw.filter(|value| !value.trim().is_empty()) else {
        return Ok(default);
    };
    let value = raw
        .parse::<usize>()
        .map_err(|_| ConfigError::InvalidInteger { name })?;
    if !(min..=max).contains(&value) {
        return Err(ConfigError::IntegerOutOfRange { name, min, max });
    }
    Ok(value)
}

fn bounded_u64(
    name: &'static str,
    raw: Option<String>,
    min: u64,
    max: u64,
    default: u64,
) -> Result<u64, ConfigError> {
    let Some(raw) = raw.filter(|value| !value.trim().is_empty()) else {
        return Ok(default);
    };
    let value = raw
        .parse::<u64>()
        .map_err(|_| ConfigError::InvalidInteger { name })?;
    if !(min..=max).contains(&value) {
        return Err(ConfigError::TimeoutOutOfRange { min, max });
    }
    Ok(value)
}

type ResponseBody = BoxBody<Bytes, ResponseBodyError>;

#[derive(Debug, Error)]
enum ResponseBodyError {
    #[error("upstream response body failed")]
    Upstream(#[source] hyper::Error),
    #[error("cloud hop response body timed out")]
    Timeout,
}

struct TimedResponseBody {
    body: Incoming,
    request_permit: Option<OwnedSemaphorePermit>,
    deadline: Instant,
    watchdog: Option<AbortHandle>,
    upstream_connection: Option<AbortHandle>,
    finished: bool,
}

impl TimedResponseBody {
    fn new(
        body: Incoming,
        request_permit: OwnedSemaphorePermit,
        deadline: Instant,
        cancellation: watch::Sender<bool>,
        upstream_connection: AbortHandle,
    ) -> Self {
        let watchdog = tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            let _ = cancellation.send(true);
        })
        .abort_handle();
        Self {
            body,
            request_permit: Some(request_permit),
            deadline,
            watchdog: Some(watchdog),
            upstream_connection: Some(upstream_connection),
            finished: false,
        }
    }

    fn finish(&mut self) {
        self.finished = true;
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.abort();
        }
        if let Some(upstream_connection) = self.upstream_connection.take() {
            upstream_connection.abort();
        }
        self.request_permit.take();
    }
}

impl hyper::body::Body for TimedResponseBody {
    type Data = Bytes;
    type Error = ResponseBodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        if Instant::now() >= this.deadline {
            this.finish();
            return Poll::Ready(Some(Err(ResponseBodyError::Timeout)));
        }

        match Pin::new(&mut this.body).poll_frame(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                this.finish();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(error))) => {
                this.finish();
                Poll::Ready(Some(Err(ResponseBodyError::Upstream(error))))
            }
        }
    }
}

impl Drop for TimedResponseBody {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Serve the hop and forward to Envoy's fixed loopback egress listener.
///
/// # Errors
///
/// Returns an I/O error when the listener cannot accept a connection or the
/// fixed egress address cannot be constructed.
pub async fn serve(listener: TcpListener, config: CloudHopConfig) -> Result<(), std::io::Error> {
    serve_with_upstream(
        listener,
        config,
        INTERNAL_EGRESS_ADDR
            .parse::<SocketAddr>()
            .map_err(std::io::Error::other)?,
    )
    .await
}

/// Variant with an injected egress address used by unit tests.
///
/// # Errors
///
/// Returns an I/O error when accepting a connection fails.
pub async fn serve_with_upstream(
    listener: TcpListener,
    config: CloudHopConfig,
    upstream_addr: SocketAddr,
) -> Result<(), std::io::Error> {
    let required_buffered = required_buffered_bytes(config.max_request_bytes);
    if config.max_buffered_bytes < required_buffered {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "max_buffered_bytes must be at least {required_buffered} for a {}-byte request cap",
                config.max_request_bytes
            ),
        ));
    }
    let state = Arc::new(ProxyState {
        buffered: Arc::new(Semaphore::new(config.max_buffered_bytes)),
        requests: Arc::new(Semaphore::new(config.max_concurrency)),
        config,
        upstream_addr,
    });
    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        let (cancellation, cancellation_rx) = watch::channel(false);
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, state, cancellation, cancellation_rx).await
            {
                tracing::warn!(error = %error, "cloud hop connection ended");
            }
        });
    }
}

struct ProxyState {
    config: CloudHopConfig,
    upstream_addr: SocketAddr,
    buffered: Arc<Semaphore>,
    requests: Arc<Semaphore>,
}

async fn serve_connection(
    stream: TcpStream,
    state: Arc<ProxyState>,
    cancellation: watch::Sender<bool>,
    mut cancellation_rx: watch::Receiver<bool>,
) -> Result<(), hyper::Error> {
    let io = TokioIo::new(stream);
    let service = service_fn(move |request| {
        let state = Arc::clone(&state);
        let cancellation = cancellation.clone();
        async move { Ok::<_, Infallible>(handle_request(request, state, cancellation).await) }
    });
    let connection = hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service);
    tokio::select! {
        result = connection => result,
        result = wait_for_cancellation(&mut cancellation_rx) => {
            let _ = result;
            Ok(())
        }
    }
}

async fn wait_for_cancellation(
    cancellation: &mut watch::Receiver<bool>,
) -> Result<(), watch::error::RecvError> {
    while !*cancellation.borrow() {
        cancellation.changed().await?;
    }
    Ok(())
}

struct RequestRejection {
    status: StatusCode,
    message: String,
}

impl RequestRejection {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn aggregate_limit() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "cloud hop aggregate buffering limit reached",
        )
    }
}

impl From<RewriteError> for RequestRejection {
    fn from(error: RewriteError) -> Self {
        Self::new(StatusCode::BAD_REQUEST, error.to_string())
    }
}

async fn handle_request(
    request: Request<Incoming>,
    state: Arc<ProxyState>,
    cancellation: watch::Sender<bool>,
) -> Response<ResponseBody> {
    match proxy_request(request, state, cancellation).await {
        Ok(response) => response,
        Err(error) => json_error(error.status, &error.message),
    }
}

async fn proxy_request(
    request: Request<Incoming>,
    state: Arc<ProxyState>,
    cancellation: watch::Sender<bool>,
) -> Result<Response<ResponseBody>, RequestRejection> {
    let deadline = Instant::now() + state.config.timeout;
    let (selector, map) = request_map(&request, &state.config)?;
    let request_permit = timeout_at(deadline, Arc::clone(&state.requests).acquire_owned())
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or_else(|| {
            RequestRejection::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "cloud hop concurrency limit timed out",
            )
        })?;
    let (parts, request_body) = request.into_parts();
    let body = buffered_request(request_body, &state, deadline).await?;
    let rewritten = rewrite_buffered_request(selector, body.as_ref(), map, &state.buffered)?;
    drop(body);
    let forwarded = forward_request(parts, rewritten, selector, state, deadline)
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "cloud hop upstream forwarding failed");
            RequestRejection::new(
                StatusCode::BAD_GATEWAY,
                "cloud hop upstream forwarding failed",
            )
        })?;
    Ok(box_response(
        forwarded.response,
        request_permit,
        deadline,
        cancellation,
        forwarded.connection_abort,
    ))
}

fn request_map<'a>(
    request: &Request<Incoming>,
    config: &'a CloudHopConfig,
) -> Result<(CloudProvider, &'a DeploymentMap), RequestRejection> {
    let selector = request
        .headers()
        .get("x-gm-cloud-hop-provider")
        .and_then(|value| value.to_str().ok())
        .and_then(CloudProvider::from_selector)
        .ok_or_else(|| {
            RequestRejection::new(
                StatusCode::NOT_FOUND,
                "cloud hop selector missing or invalid",
            )
        })?;
    if selector == CloudProvider::Bedrock {
        return Err(RequestRejection::new(
            StatusCode::NOT_FOUND,
            "cloud hop is disabled for this provider",
        ));
    }
    let map = config.map_for(selector).ok_or_else(|| {
        RequestRejection::new(
            StatusCode::NOT_FOUND,
            "cloud hop is not configured for this provider",
        )
    })?;
    if request.method() != Method::POST {
        return Err(RequestRejection::new(
            StatusCode::NOT_FOUND,
            "cloud hop surface is not enabled",
        ));
    }
    let surface = surface_for_path(selector, request.uri().path()).ok_or_else(|| {
        RequestRejection::new(StatusCode::NOT_FOUND, "cloud hop surface is not enabled")
    })?;
    for streaming in [false, true] {
        let row = qualification(selector, surface, streaming).ok_or_else(|| {
            RequestRejection::new(StatusCode::NOT_FOUND, "cloud hop surface is not enabled")
        })?;
        if !row.qualified {
            return Err(RequestRejection::new(StatusCode::BAD_REQUEST, row.reason));
        }
    }
    let declared_length = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| raw.parse::<usize>().ok());
    if usize::try_from(request.body().size_hint().lower())
        .is_ok_and(|size| size > config.max_request_bytes)
        || declared_length.is_some_and(|size| size > config.max_request_bytes)
    {
        return Err(RequestRejection::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "cloud hop request body is too large",
        ));
    }
    Ok((selector, map))
}

async fn buffered_request(
    body: Incoming,
    state: &ProxyState,
    deadline: Instant,
) -> Result<BufferedBytes, RequestRejection> {
    match timeout_at(
        deadline,
        read_request_body(
            body,
            state.config.max_request_bytes,
            Arc::clone(&state.buffered),
        ),
    )
    .await
    {
        Ok(Ok(body)) => Ok(body),
        Ok(Err(ReadBodyError::TooLarge)) => Err(RequestRejection::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "cloud hop request body is too large",
        )),
        Ok(Err(ReadBodyError::AggregateLimit)) => Err(RequestRejection::aggregate_limit()),
        Ok(Err(ReadBodyError::Trailers)) => Err(RequestRejection::new(
            StatusCode::BAD_REQUEST,
            "cloud hop request trailers are not supported",
        )),
        Ok(Err(ReadBodyError::Body(_))) => Err(RequestRejection::new(
            StatusCode::BAD_REQUEST,
            "cloud hop request body stream failed",
        )),
        Err(_) => Err(RequestRejection::new(
            StatusCode::REQUEST_TIMEOUT,
            "cloud hop request body timed out",
        )),
    }
}

fn rewrite_buffered_request(
    selector: CloudProvider,
    body: &[u8],
    map: &DeploymentMap,
    buffered: &Arc<Semaphore>,
) -> Result<BufferedBytes, RequestRejection> {
    let capacity = rewrite_capacity(body, map)?;
    let units = u32::try_from(capacity).map_err(|_| RequestRejection::aggregate_limit())?;
    let mut permit = Arc::clone(buffered)
        .try_acquire_many_owned(units)
        .map_err(|_| RequestRejection::aggregate_limit())?;
    let rewritten = rewrite_model_bytes(selector, body, map)?;
    let extra = rewritten.capacity().saturating_sub(capacity);
    if extra > 0 {
        let units = u32::try_from(extra).map_err(|_| RequestRejection::aggregate_limit())?;
        permit.merge(
            Arc::clone(buffered)
                .try_acquire_many_owned(units)
                .map_err(|_| RequestRejection::aggregate_limit())?,
        );
    }
    // Hyper can retain upload frames after the response arrives. The storage
    // reservation must follow those bytes rather than the response lifetime.
    Ok(BufferedBytes::new(Bytes::from(rewritten), Some(permit)))
}

async fn read_request_body(
    mut body: Incoming,
    max_request_bytes: usize,
    buffered: Arc<Semaphore>,
) -> Result<BufferedBytes, ReadBodyError> {
    let mut permit = None;
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(ReadBodyError::Body)?;
        if let Ok(data) = frame.into_data() {
            let next_len = bytes
                .len()
                .checked_add(data.len())
                .ok_or(ReadBodyError::TooLarge)?;
            if next_len > max_request_bytes {
                return Err(ReadBodyError::TooLarge);
            }
            reserve_buffer_capacity(&mut bytes, &mut permit, next_len, &buffered)?;
            bytes.extend_from_slice(&data);
        } else {
            return Err(ReadBodyError::Trailers);
        }
    }
    Ok(BufferedBytes::new(Bytes::from(bytes), permit))
}

/// A request allocation and the semaphore reservation that accounts for it.
/// Keeping them in one `Buf` value makes the reservation follow the allocation
/// through hyper's transport-held request frames until the bytes are dropped.
struct BufferedBytes {
    bytes: Bytes,
    _permit: Option<OwnedSemaphorePermit>,
}

impl BufferedBytes {
    fn new(bytes: Bytes, permit: Option<OwnedSemaphorePermit>) -> Self {
        Self {
            bytes,
            _permit: permit,
        }
    }
}

impl AsRef<[u8]> for BufferedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Buf for BufferedBytes {
    fn remaining(&self) -> usize {
        self.bytes.remaining()
    }

    fn chunk(&self) -> &[u8] {
        self.bytes.chunk()
    }

    fn advance(&mut self, count: usize) {
        self.bytes.advance(count);
    }
}

/// Reserve only the capacity the request buffer is about to acquire. The
/// semaphore therefore accounts for allocated storage rather than the
/// configured maximum request size, while `reserve_exact` keeps the aggregate
/// budget sufficient for a full request plus its rewritten copy.
fn reserve_buffer_capacity(
    bytes: &mut Vec<u8>,
    permit: &mut Option<OwnedSemaphorePermit>,
    required: usize,
    buffered: &Arc<Semaphore>,
) -> Result<(), ReadBodyError> {
    if required <= bytes.capacity() {
        return Ok(());
    }
    let before = bytes.capacity();
    let requested = required - before;
    let requested_u32 = u32::try_from(requested).map_err(|_| ReadBodyError::AggregateLimit)?;
    let new_permit = buffered
        .clone()
        .try_acquire_many_owned(requested_u32)
        .map_err(|_| ReadBodyError::AggregateLimit)?;
    bytes.reserve_exact(required - bytes.len());
    let actual = bytes.capacity().saturating_sub(before);
    if actual > requested {
        let extra = actual - requested;
        let extra_u32 = u32::try_from(extra).map_err(|_| ReadBodyError::AggregateLimit)?;
        let extra_permit = buffered
            .clone()
            .try_acquire_many_owned(extra_u32)
            .map_err(|_| ReadBodyError::AggregateLimit)?;
        merge_buffer_permit(permit, extra_permit);
    }
    merge_buffer_permit(permit, new_permit);
    Ok(())
}

fn merge_buffer_permit(slot: &mut Option<OwnedSemaphorePermit>, permit: OwnedSemaphorePermit) {
    if let Some(existing) = slot.as_mut() {
        existing.merge(permit);
    } else {
        *slot = Some(permit);
    }
}

#[derive(Debug, Error)]
enum ReadBodyError {
    #[error("request body stream failed")]
    Body(#[source] hyper::Error),
    #[error("request body is too large")]
    TooLarge,
    #[error("aggregate request buffering limit reached")]
    AggregateLimit,
    #[error("request trailers are not supported")]
    Trailers,
}

fn surface_for_path(provider: CloudProvider, path: &str) -> Option<CloudSurface> {
    let surfaces: &[CloudSurface] = match provider {
        CloudProvider::AzureOpenAi => &[
            CloudSurface::AzureChatCompletions,
            CloudSurface::AzureResponses,
        ],
        CloudProvider::Foundry => &[CloudSurface::FoundryMessages],
        CloudProvider::Bedrock => &[CloudSurface::BedrockMessages],
    };
    surfaces
        .iter()
        .copied()
        .find(|surface| surface.path() == path)
}

async fn forward_request(
    mut parts: hyper::http::request::Parts,
    body: BufferedBytes,
    selector: CloudProvider,
    state: Arc<ProxyState>,
    deadline: Instant,
) -> Result<ForwardedResponse, ForwardError> {
    let headers_to_remove = parts
        .headers
        .keys()
        .filter(|name| {
            name.as_str().starts_with("x-gm-") && name.as_str() != "x-gm-cloud-hop-provider"
        })
        .cloned()
        .collect::<Vec<_>>();
    for name in headers_to_remove {
        parts.headers.remove(name);
    }
    parts.headers.remove(CONTENT_LENGTH);
    parts.headers.remove(TRANSFER_ENCODING);
    parts.headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&body.as_ref().len().to_string())
            .map_err(|_| ForwardError::HeaderValue)?,
    );
    parts.headers.insert(
        "x-gm-cloud-hop-provider",
        selector
            .selector()
            .parse()
            .map_err(|_| ForwardError::HeaderValue)?,
    );
    let request = Request::from_parts(parts, Full::new(body));
    let stream = timeout_at(deadline, TcpStream::connect(state.upstream_addr))
        .await
        .map_err(|_| ForwardError::Timeout)??;
    let io = TokioIo::new(stream);
    let (mut sender, connection) = timeout_at(deadline, hyper::client::conn::http1::handshake(io))
        .await
        .map_err(|_| ForwardError::Timeout)?
        .map_err(ForwardError::Http)?;
    let connection_task = tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(error = %error, "cloud hop egress connection ended");
        }
    });
    let connection_abort = connection_task.abort_handle();
    match timeout_at(deadline, sender.send_request(request)).await {
        Ok(Ok(response)) => Ok(ForwardedResponse {
            response,
            connection_abort,
        }),
        Ok(Err(error)) => {
            connection_task.abort();
            Err(ForwardError::Http(error))
        }
        Err(_) => {
            connection_task.abort();
            Err(ForwardError::Timeout)
        }
    }
}

struct ForwardedResponse {
    response: Response<Incoming>,
    connection_abort: AbortHandle,
}

fn box_response(
    response: Response<Incoming>,
    request_permit: OwnedSemaphorePermit,
    deadline: Instant,
    cancellation: watch::Sender<bool>,
    upstream_connection: AbortHandle,
) -> Response<ResponseBody> {
    let (parts, body) = response.into_parts();
    let body = TimedResponseBody::new(
        body,
        request_permit,
        deadline,
        cancellation,
        upstream_connection,
    );
    let body = BoxBody::new(body);
    Response::from_parts(parts, body)
}

fn rewrite_capacity(body: &[u8], map: &DeploymentMap) -> Result<usize, RewriteError> {
    let model = extract_model_echo(body)?;
    let deployment = map.get(&model).ok_or(RewriteError::UnmappedModel)?;
    body.len()
        .checked_add(deployment.len())
        .ok_or(RewriteError::MalformedJson)
}

#[derive(Debug, Error)]
enum ForwardError {
    #[error("connect timeout")]
    Timeout,
    #[error("upstream connection failed")]
    Io(#[from] std::io::Error),
    #[error("upstream HTTP exchange failed")]
    Http(#[source] hyper::Error),
    #[error("invalid forwarded header")]
    HeaderValue,
}

fn json_error(status: StatusCode, message: &str) -> Response<ResponseBody> {
    let body = serde_json::json!({
        "error": {
            "type": "gm_cloud_hop_invalid_request",
            "message": message,
        }
    })
    .to_string();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, body.len())
        .body(full_body(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(full_body(Bytes::from_static(b"{}"))))
}

fn full_body(body: Bytes) -> ResponseBody {
    Full::new(body)
        .map_err(|never: Infallible| match never {})
        .boxed()
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::*;
    use hyper::service::service_fn;
    use hyper::{body::Frame, client::conn::http1, server::conn::http1 as server_http1};
    use std::{
        collections::VecDeque,
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        task::{Context, Poll},
    };
    use tokio::sync::oneshot;

    struct ChunkBody {
        chunks: VecDeque<Bytes>,
    }

    impl hyper::body::Body for ChunkBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.chunks.pop_front().map(|chunk| Ok(Frame::data(chunk))))
        }
    }

    struct StalledBody;

    impl hyper::body::Body for StalledBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    struct FirstChunkThenPending {
        sent: bool,
    }

    impl hyper::body::Body for FirstChunkThenPending {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if self.sent {
                Poll::Pending
            } else {
                self.sent = true;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"first")))))
            }
        }
    }

    struct FloodingBody {
        remaining: usize,
        chunk: Bytes,
    }

    impl hyper::body::Body for FloodingBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if self.remaining == 0 {
                return Poll::Pending;
            }
            self.remaining -= 1;
            Poll::Ready(Some(Ok(Frame::data(self.chunk.clone()))))
        }
    }

    fn quick_test_body() -> BoxBody<Bytes, Infallible> {
        Full::new(Bytes::from_static(b"ok"))
            .map_err(|never: Infallible| match never {})
            .boxed()
    }

    async fn send_hop_request(
        hop_addr: SocketAddr,
        chunks: Vec<Bytes>,
    ) -> Result<Response<Incoming>, hyper::Error> {
        send_hop_request_to(hop_addr, "/v1/chat/completions", chunks).await
    }

    async fn send_hop_request_to(
        hop_addr: SocketAddr,
        path: &str,
        chunks: Vec<Bytes>,
    ) -> Result<Response<Incoming>, hyper::Error> {
        send_selected_hop_request(hop_addr, Method::POST, path, "azure-openai", chunks).await
    }

    async fn send_selected_hop_request(
        hop_addr: SocketAddr,
        method: Method,
        path: &str,
        selector: &str,
        chunks: Vec<Bytes>,
    ) -> Result<Response<Incoming>, hyper::Error> {
        let stream = TcpStream::connect(hop_addr).await.expect("hop connect");
        let io = TokioIo::new(stream);
        let (mut sender, connection) = http1::handshake(io).await.expect("hop handshake");
        tokio::spawn(connection);
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("x-gm-cloud-hop-provider", selector)
            .header(CONTENT_TYPE, "application/json")
            .body(ChunkBody {
                chunks: chunks.into_iter().collect(),
            })
            .expect("request");
        sender.send_request(request).await
    }

    fn test_config(
        max_buffered_bytes: usize,
        max_concurrency: usize,
        timeout: Duration,
    ) -> CloudHopConfig {
        test_config_with_request(
            1024 * 1024,
            max_buffered_bytes.max(required_buffered_bytes(1024 * 1024)),
            max_concurrency,
            timeout,
        )
    }

    fn test_config_with_request(
        max_request_bytes: usize,
        max_buffered_bytes: usize,
        max_concurrency: usize,
        timeout: Duration,
    ) -> CloudHopConfig {
        CloudHopConfig {
            azure_openai: Some(azure_map()),
            foundry: Some(foundry_map()),
            max_request_bytes,
            max_buffered_bytes,
            max_concurrency,
            timeout,
        }
    }

    #[derive(Clone, Copy)]
    enum FirstResponse {
        Stalled,
        ChunkThenPending,
        Flooding,
    }

    fn spawn_counted_upstream(
        listener: TcpListener,
        first_response: FirstResponse,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let address = listener.local_addr().expect("upstream address");
        let request_count = Arc::new(AtomicUsize::new(0));
        let accept_task = tokio::spawn({
            let request_count = Arc::clone(&request_count);
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let request_count = Arc::clone(&request_count);
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let service = service_fn(move |request: Request<Incoming>| {
                            let request_number = request_count.fetch_add(1, Ordering::SeqCst);
                            async move {
                                let _ = request
                                    .into_body()
                                    .collect()
                                    .await
                                    .expect("upstream request body");
                                let body = if request_number == 0 {
                                    match first_response {
                                        FirstResponse::Stalled => BoxBody::new(StalledBody),
                                        FirstResponse::ChunkThenPending => {
                                            BoxBody::new(FirstChunkThenPending { sent: false })
                                        }
                                        FirstResponse::Flooding => BoxBody::new(FloodingBody {
                                            remaining: 2048,
                                            chunk: Bytes::from(vec![b'x'; 16 * 1024]),
                                        }),
                                    }
                                } else {
                                    quick_test_body()
                                };
                                Ok::<_, Infallible>(Response::new(body))
                            }
                        });
                        let _ = server_http1::Builder::new()
                            .serve_connection(io, service)
                            .await;
                    });
                }
            }
        });
        (address, accept_task)
    }

    fn azure_map() -> DeploymentMap {
        parse_deployment_map(
            CloudProvider::AzureOpenAi,
            "gpt-5.5=my-gpt55;gpt-5.6=prod_gpt56",
        )
        .expect("valid Azure map")
    }

    fn foundry_map() -> DeploymentMap {
        parse_deployment_map(CloudProvider::Foundry, "claude-sonnet-4-6=gm-echo-test")
            .expect("valid Foundry map")
    }

    #[test]
    fn targeted_replacement_preserves_every_other_byte() {
        let body = b" { \"model\" : \"gpt-5.5\", \"n\": 1e+03, \"nested\": {\"model\":\"untouched\"}, \"modelish\": true } \n";
        let rewritten =
            rewrite_model_bytes(CloudProvider::AzureOpenAi, body, &azure_map()).expect("rewrite");
        assert_eq!(
            String::from_utf8(rewritten).expect("UTF-8"),
            " { \"model\" : \"my-gpt55\", \"n\": 1e+03, \"nested\": {\"model\":\"untouched\"}, \"modelish\": true } \n"
        );
    }

    #[test]
    fn rejects_missing_non_string_duplicate_and_unmapped_models() {
        for (body, expected) in [
            (br#"{"messages":[]}"#.as_slice(), RewriteError::MissingModel),
            (br#"{"model":7}"#.as_slice(), RewriteError::ModelNotString),
            (
                br#"{"model":"gpt-5.5","model":"gpt-5.5"}"#.as_slice(),
                RewriteError::DuplicateModel,
            ),
            (
                br#"{"model":"gpt-4o"}"#.as_slice(),
                RewriteError::UnmappedModel,
            ),
        ] {
            assert_eq!(
                rewrite_model_bytes(CloudProvider::AzureOpenAi, body, &azure_map())
                    .expect_err("rejection"),
                expected
            );
        }
        assert_eq!(
            rewrite_model_bytes(
                CloudProvider::AzureOpenAi,
                &[b'{', b'"', 0xff],
                &azure_map()
            )
            .expect_err("invalid UTF-8 rejection"),
            RewriteError::InvalidUtf8
        );
    }

    #[test]
    fn rejects_malformed_json_and_non_object_bodies() {
        assert_eq!(
            rewrite_model_bytes(CloudProvider::AzureOpenAi, br"[]", &azure_map())
                .expect_err("array rejection"),
            RewriteError::TopLevelNotObject
        );
        assert_eq!(
            rewrite_model_bytes(
                CloudProvider::AzureOpenAi,
                br#"{"model":"gpt-5.5",}"#,
                &azure_map()
            )
            .expect_err("trailing comma rejection"),
            RewriteError::MalformedJson
        );
    }

    #[test]
    fn handles_large_body_without_reserializing_numbers_or_strings() {
        let filler = "x".repeat(512 * 1024);
        let body = format!(r#"{{"model":"gpt-5.5","text":"{filler}","value":9007199254740993}}"#);
        let rewritten =
            rewrite_model_bytes(CloudProvider::AzureOpenAi, body.as_bytes(), &azure_map())
                .expect("large rewrite");
        let rewritten = String::from_utf8(rewritten).expect("UTF-8");
        assert!(rewritten.starts_with(r#"{"model":"my-gpt55","text":""#));
        assert!(rewritten.ends_with(r#"","value":9007199254740993}"#));
        assert_eq!(
            rewritten.len(),
            body.len() - "gpt-5.5".len() + "my-gpt55".len()
        );
    }

    #[test]
    fn accepts_exact_and_dated_echoes_only() {
        assert!(echo_matches_model("gpt-5.5", "gpt-5.5"));
        assert!(echo_matches_model("gpt-5.5", "gpt-5.5-2026-04-23"));
        assert!(echo_matches_model(
            "claude-haiku-4-5",
            "claude-haiku-4-5-20251001"
        ));
        assert!(!echo_matches_model("gpt-5.5", "gpt-5.5-mini-2026-04-23"));
        assert!(!echo_matches_model("gpt-5.5", "gpt-5.5-2026-4-23"));
    }

    #[test]
    fn model_echo_extraction_uses_the_strict_duplicate_rule() {
        assert_eq!(
            extract_model_echo(br#" { "model": "gpt-5.5", "usage": {} } "#)
                .expect("unique model echo"),
            "gpt-5.5"
        );
        assert_eq!(
            extract_model_echo(br#"{"model":"gpt-5.5","model":"other"}"#)
                .expect_err("duplicate model is ambiguous"),
            RewriteError::DuplicateModel
        );
    }

    #[test]
    fn qualification_matrix_matches_the_live_surface_evidence() {
        for streaming in [false, true] {
            assert!(qualification(
                CloudProvider::AzureOpenAi,
                CloudSurface::AzureChatCompletions,
                streaming,
            )
            .is_some_and(|row| row.qualified));
            assert!(qualification(
                CloudProvider::Foundry,
                CloudSurface::FoundryMessages,
                streaming,
            )
            .is_some_and(|row| row.qualified));
            assert!(!qualification(
                CloudProvider::AzureOpenAi,
                CloudSurface::AzureResponses,
                streaming,
            )
            .is_some_and(|row| row.qualified));
            assert!(!qualification(
                CloudProvider::Bedrock,
                CloudSurface::BedrockMessages,
                streaming,
            )
            .is_some_and(|row| row.qualified));
        }
    }

    #[tokio::test]
    async fn azure_responses_is_rejected_with_an_explanatory_json_error() {
        let hop_listener = TcpListener::bind("127.0.0.1:0").await.expect("hop bind");
        let hop_addr = hop_listener.local_addr().expect("hop address");
        tokio::spawn(serve_with_upstream(
            hop_listener,
            test_config(2 * 1024 * 1024, 1, Duration::from_secs(5)),
            "127.0.0.1:1".parse().expect("unused upstream address"),
        ));

        let mut response = send_hop_request_to(
            hop_addr,
            "/v1/responses",
            vec![Bytes::from_static(br#"{"model":"gpt-5.5"}"#)],
        )
        .await
        .expect("hop response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        let body = response
            .body_mut()
            .collect()
            .await
            .expect("error body")
            .to_bytes();
        let body = String::from_utf8(body.to_vec()).expect("JSON error body");
        assert!(body.contains("gm_cloud_hop_invalid_request"));
        assert!(body.contains(AZURE_RESPONSES_UNQUALIFIED_REASON));
    }

    const REJECTED_HOP_REQUESTS: &[(Method, &str, &str, &str, StatusCode)] = &[
        (
            Method::GET,
            "/v1/models",
            "azure-openai",
            "{}",
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "/v1/responses",
            "azure-openai",
            "{}",
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "/v1/chat/completions",
            "invalid",
            "{}",
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "/v1/chat/completions",
            "foundry",
            "{}",
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "/v1/messages",
            "bedrock",
            "{}",
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "/v1/messages/count_tokens",
            "foundry",
            "{}",
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "/v1/chat/completions",
            "azure-openai",
            "{",
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "/v1/chat/completions",
            "azure-openai",
            "{}",
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "/v1/chat/completions",
            "azure-openai",
            r#"{"model":3}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "/v1/chat/completions",
            "azure-openai",
            r#"{"model":"gpt-cheap"}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "/v1/chat/completions",
            "azure-openai",
            r#"{"model":"gpt-5.5","model":"gpt-5.6"}"#,
            StatusCode::BAD_REQUEST,
        ),
    ];

    #[tokio::test]
    async fn request_admission_rejects_invalid_inputs_without_egress() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.expect("upstream");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let hop = TcpListener::bind("127.0.0.1:0").await.expect("hop");
        let hop_addr = hop.local_addr().expect("hop address");
        let task = tokio::spawn(serve_with_upstream(
            hop,
            test_config_with_request(64, required_buffered_bytes(64), 1, Duration::from_secs(5)),
            upstream_addr,
        ));
        for &(ref method, path, selector, body, status) in REJECTED_HOP_REQUESTS {
            let response = send_selected_hop_request(
                hop_addr,
                method.clone(),
                path,
                selector,
                vec![Bytes::from_static(body.as_bytes())],
            )
            .await
            .expect("hop response");
            assert_eq!(response.status(), status, "{selector} {path} {body}");
        }
        let oversized = vec![
            Bytes::from_static(br#"{"model":"gpt-5.5","padding":""#),
            Bytes::from(vec![b'x'; 64]),
            Bytes::from_static(br#""}"#),
        ];
        let response = send_hop_request(hop_addr, oversized)
            .await
            .expect("oversized response");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), upstream.accept())
                .await
                .is_err(),
            "rejected requests must never connect to egress"
        );
        task.abort();
    }

    #[tokio::test]
    async fn foundry_rewrites_only_the_request_and_preserves_a_mismatched_echo() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.expect("upstream");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let raw_response =
            Bytes::from_static(br#"{ "model" : "cheap-model", "value":1.2300e+03 }"#);
        let response_copy = raw_response.clone();
        let (observed_tx, observed_rx) = oneshot::channel();
        let observed_tx = Arc::new(Mutex::new(Some(observed_tx)));
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream.accept().await.expect("egress connection");
            let service = service_fn(move |request: Request<Incoming>| {
                let tx = observed_tx
                    .lock()
                    .expect("sender")
                    .take()
                    .expect("one request");
                let response = response_copy.clone();
                async move {
                    tx.send(
                        request
                            .into_body()
                            .collect()
                            .await
                            .expect("upload")
                            .to_bytes(),
                    )
                    .expect("observation");
                    Ok::<_, Infallible>(Response::new(Full::new(response)))
                }
            });
            let _ = server_http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
        let hop = TcpListener::bind("127.0.0.1:0").await.expect("hop");
        let hop_addr = hop.local_addr().expect("hop address");
        let task = tokio::spawn(serve_with_upstream(
            hop,
            test_config(3 * 1024 * 1024, 1, Duration::from_secs(5)),
            upstream_addr,
        ));
        let request = Bytes::from_static(
            br#"{ "model":"claude-sonnet-4-6", "n":1.2300e+03, "nested":{"model":"leave-me"} }"#,
        );
        let response = send_selected_hop_request(
            hop_addr,
            Method::POST,
            "/v1/messages",
            "foundry",
            vec![request],
        )
        .await
        .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .expect("response body")
                .to_bytes(),
            raw_response
        );
        assert_eq!(
            observed_rx.await.expect("rewritten request"),
            Bytes::from_static(
                br#"{ "model":"gm-echo-test", "n":1.2300e+03, "nested":{"model":"leave-me"} }"#
            )
        );
        task.abort();
        upstream_task.abort();
    }

    #[test]
    fn gateway_body_cap_is_used_only_when_hop_cap_is_absent() {
        assert_eq!(
            request_cap_value(Some("123".to_owned()), Some("456".to_owned())),
            Some("123".to_owned())
        );
        assert_eq!(
            request_cap_value(Some("  ".to_owned()), Some("456".to_owned())),
            Some("456".to_owned())
        );
        assert_eq!(request_cap_value(None, Some(" ".to_owned())), None);
    }

    #[tokio::test]
    async fn serving_rejects_an_aggregate_budget_below_the_peak_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("hop bind");
        let config = test_config_with_request(1024, 1024, 1, Duration::from_secs(1));
        let error = serve_with_upstream(
            listener,
            config,
            "127.0.0.1:1".parse().expect("unused upstream address"),
        )
        .await
        .expect_err("an invalid aggregate budget must fail before serving");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("max_buffered_bytes"));
    }

    #[test]
    fn rewrite_storage_capacity_covers_the_original_and_new_buffers() {
        let body = br#"{"model":"gpt-5.5"}"#;
        assert_eq!(
            rewrite_capacity(body, &azure_map()),
            Ok(body.len() + "my-gpt55".len())
        );
    }

    #[test]
    fn buffer_growth_accounts_for_existing_spare_capacity() {
        let buffered = Arc::new(Semaphore::new(100));
        let mut bytes = Vec::with_capacity(10);
        bytes.extend_from_slice(b"12345");
        let mut permit = Some(
            buffered
                .clone()
                .try_acquire_many_owned(10)
                .expect("initial storage"),
        );
        reserve_buffer_capacity(&mut bytes, &mut permit, 15, &buffered).expect("grow buffer");
        assert!(
            bytes.capacity() >= 15,
            "extension must not allocate beyond its reservation"
        );
        bytes.extend_from_slice(b"6789012345");
        assert_eq!(100 - buffered.available_permits(), bytes.capacity());
        drop(bytes);
        drop(permit);
        assert_eq!(buffered.available_permits(), 100);
    }

    #[test]
    fn large_escaped_nested_keys_do_not_change_model_rewrite() {
        let escaped_key = r"\u006e".repeat(512 * 1024);
        let body = format!(r#"{{"{escaped_key}":{{"{escaped_key}":true}},"model":"gpt-5.5"}}"#);
        let rewritten =
            rewrite_model_bytes(CloudProvider::AzureOpenAi, body.as_bytes(), &azure_map())
                .expect("irrelevant escaped keys must be scanned without decoding");
        assert!(rewritten.ends_with(br#""model":"my-gpt55"}"#));
    }

    #[test]
    fn an_escaped_model_value_is_bounded_before_allocation() {
        let body = format!(r#"{{"model":"{}"}}"#, r"\u0067".repeat(1024));
        assert_eq!(
            extract_model_echo(body.as_bytes()),
            Err(RewriteError::UnmappedModel)
        );
    }

    #[test]
    fn map_validation_rejects_unknown_duplicate_and_bad_deployment_names() {
        assert!(matches!(
            parse_deployment_map(
                CloudProvider::Foundry,
                "claude-sonnet-4-6=good;claude-sonnet-4-6=other"
            ),
            Err(DeploymentMapError::DuplicateCanonical { .. })
        ));
        assert!(matches!(
            parse_deployment_map(CloudProvider::Foundry, "gpt-5.5=good"),
            Err(DeploymentMapError::UnknownCanonical { .. })
        ));
        assert!(matches!(
            parse_deployment_map(CloudProvider::Foundry, "claude-sonnet-4-6=bad.name"),
            Err(DeploymentMapError::InvalidDeployment { .. })
        ));
        assert!(matches!(
            parse_deployment_map(CloudProvider::Foundry, ""),
            Err(DeploymentMapError::Empty)
        ));
        assert!(matches!(
            parse_deployment_map(CloudProvider::Foundry, "claude-sonnet-4-6"),
            Err(DeploymentMapError::InvalidSeparator { .. })
        ));
        assert!(matches!(
            parse_deployment_map(CloudProvider::Foundry, "claude-sonnet-4-6=aa;"),
            Err(DeploymentMapError::EmptyEntry { .. })
        ));
        assert!(matches!(
            parse_deployment_map(CloudProvider::Foundry, "claude-sonnet-4-6=gm-echo\n-test"),
            Err(DeploymentMapError::ContainsNewline)
        ));
        let canonical = parse_deployment_map(
            CloudProvider::AzureOpenAi,
            " gpt-5.6 = prod_gpt56 ; gpt-5.5 = azure-gpt55 ",
        )
        .expect("boundary whitespace is normalized");
        assert_eq!(
            canonical.canonical_string(),
            "gpt-5.5=azure-gpt55;gpt-5.6=prod_gpt56"
        );
    }

    #[test]
    fn map_validation_enforces_input_and_entry_bounds() {
        assert!(matches!(
            parse_deployment_map(
                CloudProvider::Foundry,
                &format!("claude-sonnet-4-6={}", "a".repeat(65))
            ),
            Err(DeploymentMapError::InvalidDeployment { .. })
        ));
        assert!(matches!(
            parse_deployment_map(
                CloudProvider::Foundry,
                &format!("claude-sonnet-4-6={}", "a".repeat(4090))
            ),
            Err(DeploymentMapError::TooLarge)
        ));
        assert!(matches!(
            parse_deployment_map(CloudProvider::Foundry, &"claude-sonnet-4-6=aa;".repeat(65)),
            Err(DeploymentMapError::TooManyEntries)
        ));
    }

    #[test]
    fn bedrock_rewrite_is_disabled() {
        let map = foundry_map();
        assert_eq!(
            rewrite_model_bytes(
                CloudProvider::Bedrock,
                br#"{"model":"claude-sonnet-4-6"}"#,
                &map,
            )
            .expect_err("Bedrock must remain disabled"),
            RewriteError::DisabledProvider
        );
    }

    #[tokio::test]
    async fn fragmented_upload_fits_the_constant_buffer_budget() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream_listener.local_addr().expect("upstream address");
        let (forwarded_tx, forwarded_rx) = oneshot::channel();
        let forwarded_tx = Arc::new(Mutex::new(Some(forwarded_tx)));
        tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.expect("upstream accept");
            let io = TokioIo::new(stream);
            let service = service_fn(move |request: Request<Incoming>| {
                let forwarded_tx = Arc::clone(&forwarded_tx);
                async move {
                    let body = request
                        .into_body()
                        .collect()
                        .await
                        .expect("fragmented request body")
                        .to_bytes();
                    if let Some(forwarded_tx) = forwarded_tx
                        .lock()
                        .expect("forwarded body sender lock")
                        .take()
                    {
                        forwarded_tx.send(body).expect("forwarded body receiver");
                    }
                    Ok::<_, Infallible>(Response::new(quick_test_body()))
                }
            });
            server_http1::Builder::new()
                .serve_connection(io, service)
                .await
                .expect("upstream serve");
        });

        let original = Bytes::from(
            format!(r#"{{"model":"gpt-5.5","padding":"{}"}}"#, "x".repeat(4096)).into_bytes(),
        );
        let rewrite_storage = rewrite_capacity(&original, &azure_map()).expect("rewrite size");
        let aggregate_budget = required_buffered_bytes(original.len());
        assert!(original.len() + rewrite_storage <= aggregate_budget);
        let hop_listener = TcpListener::bind("127.0.0.1:0").await.expect("hop bind");
        let hop_addr = hop_listener.local_addr().expect("hop address");
        tokio::spawn(serve_with_upstream(
            hop_listener,
            test_config_with_request(original.len(), aggregate_budget, 1, Duration::from_secs(5)),
            upstream_addr,
        ));

        let chunks = original
            .iter()
            .map(|byte| Bytes::copy_from_slice(std::slice::from_ref(byte)))
            .collect();
        let mut response = send_hop_request(hop_addr, chunks)
            .await
            .expect("hop response");
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = response
            .body_mut()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        assert_eq!(response_body, Bytes::from_static(b"ok"));
        assert_eq!(
            forwarded_rx.await.expect("forwarded body"),
            Bytes::from(
                format!(r#"{{"model":"my-gpt55","padding":"{}"}}"#, "x".repeat(4096)).into_bytes(),
            )
        );
    }

    #[tokio::test]
    async fn round4_uploaded_storage_is_released_before_response_completion() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let upstream_addr = upstream_listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let (stream, _) = upstream_listener.accept().await.expect("accept");
                tokio::spawn(async move {
                    let service = service_fn(|request: Request<Incoming>| async move {
                        let uploaded = request.into_body().collect().await.expect("upload");
                        drop(uploaded);
                        Ok::<_, Infallible>(Response::new(StalledBody))
                    });
                    let _ = server_http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        let hop_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let hop_addr = hop_listener.local_addr().expect("addr");
        tokio::spawn(serve_with_upstream(
            hop_listener,
            test_config_with_request(
                4096,
                required_buffered_bytes(4096),
                4,
                Duration::from_secs(5),
            ),
            upstream_addr,
        ));
        let original = Bytes::from(format!(
            r#"{{"model":"gpt-5.5","padding":"{}"}}"#,
            "x".repeat(4000)
        ));
        let first = send_hop_request(hop_addr, vec![original.clone()])
            .await
            .expect("first");
        assert_eq!(first.status(), StatusCode::OK);
        let second = send_hop_request(hop_addr, vec![original])
            .await
            .expect("second");
        assert_eq!(second.status(), StatusCode::OK, "first upload was consumed and freed; its open response must hold only a concurrency permit");
        drop(first);
    }

    #[tokio::test]
    async fn concurrent_small_uploads_do_not_reserve_the_full_request_cap() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let (upstream_addr, upstream_task) =
            spawn_counted_upstream(upstream_listener, FirstResponse::Flooding);
        let hop_listener = TcpListener::bind("127.0.0.1:0").await.expect("hop bind");
        let hop_addr = hop_listener.local_addr().expect("hop address");
        tokio::spawn(serve_with_upstream(
            hop_listener,
            test_config_with_request(
                DEFAULT_REQUEST_BYTES,
                DEFAULT_BUFFERED_BYTES,
                4,
                Duration::from_secs(5),
            ),
            upstream_addr,
        ));

        let request = || {
            send_hop_request(
                hop_addr,
                vec![Bytes::from_static(br#"{"model":"gpt-5.5"}"#)],
            )
        };
        let (first, second, third, fourth) =
            tokio::join!(request(), request(), request(), request());
        for response in [first, second, third, fourth] {
            let response = response.expect("hop response");
            assert_eq!(response.status(), StatusCode::OK);
        }
        upstream_task.abort();
    }

    #[tokio::test]
    async fn stalled_upstream_body_times_out_and_releases_admission() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let (upstream_addr, upstream_task) =
            spawn_counted_upstream(upstream_listener, FirstResponse::Stalled);
        let hop_listener = TcpListener::bind("127.0.0.1:0").await.expect("hop bind");
        let hop_addr = hop_listener.local_addr().expect("hop address");
        tokio::spawn(serve_with_upstream(
            hop_listener,
            test_config(2 * 1024 * 1024, 1, Duration::from_millis(100)),
            upstream_addr,
        ));

        let mut first = send_hop_request(
            hop_addr,
            vec![Bytes::from_static(br#"{"model":"gpt-5.5"}"#)],
        )
        .await
        .expect("first hop response");
        assert_eq!(first.status(), StatusCode::OK);
        let timed_out = tokio::time::timeout(Duration::from_secs(1), first.body_mut().frame())
            .await
            .expect("response timeout task");
        assert!(matches!(timed_out, Some(Err(_))));

        let mut second = send_hop_request(
            hop_addr,
            vec![Bytes::from_static(br#"{"model":"gpt-5.5"}"#)],
        )
        .await
        .expect("second hop response");
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(
            second
                .body_mut()
                .collect()
                .await
                .expect("second response body")
                .to_bytes(),
            Bytes::from_static(b"ok")
        );
        upstream_task.abort();
    }

    #[tokio::test]
    async fn slow_consumer_holds_admission_until_response_body_is_dropped() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let (upstream_addr, upstream_task) =
            spawn_counted_upstream(upstream_listener, FirstResponse::Flooding);
        let hop_listener = TcpListener::bind("127.0.0.1:0").await.expect("hop bind");
        let hop_addr = hop_listener.local_addr().expect("hop address");
        tokio::spawn(serve_with_upstream(
            hop_listener,
            test_config(2 * 1024 * 1024, 1, Duration::from_millis(100)),
            upstream_addr,
        ));

        let first = send_hop_request(
            hop_addr,
            vec![Bytes::from_static(br#"{"model":"gpt-5.5"}"#)],
        )
        .await
        .expect("first hop response");
        assert_eq!(first.status(), StatusCode::OK);
        let mut second_task = tokio::spawn(send_hop_request(
            hop_addr,
            vec![Bytes::from_static(br#"{"model":"gpt-5.5"}"#)],
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut second_task)
                .await
                .is_err(),
            "a non-reading consumer should not be admitted before the deadline"
        );
        second_task.abort();
        let _ = second_task.await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let mut second = send_hop_request(
            hop_addr,
            vec![Bytes::from_static(br#"{"model":"gpt-5.5"}"#)],
        )
        .await
        .expect("deadline must release a non-reading response");
        assert_eq!(second.status(), StatusCode::OK);
        let _ = second
            .body_mut()
            .collect()
            .await
            .expect("second response body");
        drop(first);
        upstream_task.abort();
    }

    #[tokio::test]
    async fn stalled_after_progress_times_out_at_the_absolute_deadline() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let (upstream_addr, upstream_task) =
            spawn_counted_upstream(upstream_listener, FirstResponse::ChunkThenPending);
        let hop_listener = TcpListener::bind("127.0.0.1:0").await.expect("hop bind");
        let hop_addr = hop_listener.local_addr().expect("hop address");
        tokio::spawn(serve_with_upstream(
            hop_listener,
            test_config(2 * 1024 * 1024, 1, Duration::from_millis(100)),
            upstream_addr,
        ));

        let mut first = send_hop_request(
            hop_addr,
            vec![Bytes::from_static(br#"{"model":"gpt-5.5"}"#)],
        )
        .await
        .expect("first hop response");
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(
            first
                .body_mut()
                .frame()
                .await
                .expect("first response frame")
                .expect("first response data")
                .into_data()
                .expect("first response frame data"),
            Bytes::from_static(b"first")
        );
        let started = Instant::now();
        let timed_out = tokio::time::timeout(Duration::from_secs(1), first.body_mut().frame())
            .await
            .expect("response timeout task");
        assert!(matches!(timed_out, Some(Err(_))));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "absolute deadline was not enforced after progress"
        );
        upstream_task.abort();
    }

    #[tokio::test]
    async fn cancelling_a_response_body_releases_admission() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let (upstream_addr, upstream_task) =
            spawn_counted_upstream(upstream_listener, FirstResponse::ChunkThenPending);
        let hop_listener = TcpListener::bind("127.0.0.1:0").await.expect("hop bind");
        let hop_addr = hop_listener.local_addr().expect("hop address");
        tokio::spawn(serve_with_upstream(
            hop_listener,
            test_config(2 * 1024 * 1024, 1, Duration::from_secs(5)),
            upstream_addr,
        ));
        let (ready_tx, ready_rx) = oneshot::channel();
        let response_task = tokio::spawn(async move {
            let mut response = send_hop_request(
                hop_addr,
                vec![Bytes::from_static(br#"{"model":"gpt-5.5"}"#)],
            )
            .await
            .expect("first hop response");
            let _ = response
                .body_mut()
                .frame()
                .await
                .expect("first response frame")
                .expect("first response data");
            ready_tx.send(()).expect("response readiness receiver");
            std::future::pending::<()>().await;
        });
        ready_rx.await.expect("response readiness");
        response_task.abort();
        let _ = response_task.await;

        let mut second = send_hop_request(
            hop_addr,
            vec![Bytes::from_static(br#"{"model":"gpt-5.5"}"#)],
        )
        .await
        .expect("second hop response");
        assert_eq!(second.status(), StatusCode::OK);
        let _ = second
            .body_mut()
            .collect()
            .await
            .expect("second response body");
        upstream_task.abort();
    }

    #[tokio::test]
    async fn response_status_headers_and_stream_frames_pass_through() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream_listener.local_addr().expect("upstream address");
        let (observed_tx, observed_rx) = oneshot::channel();
        let observed_tx = Arc::new(Mutex::new(Some(observed_tx)));
        tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.expect("upstream accept");
            let io = TokioIo::new(stream);
            let service = service_fn(move |request: Request<Incoming>| {
                let observed_tx = observed_tx.lock().expect("observation sender lock").take();
                async move {
                    let (parts, body) = request.into_parts();
                    let body = body.collect().await.expect("forwarded body").to_bytes();
                    if let Some(observed_tx) = observed_tx {
                        observed_tx
                            .send(Request::from_parts(parts, body))
                            .expect("observation receiver");
                    }
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::PARTIAL_CONTENT)
                            .header("x-upstream-marker", "preserve-me")
                            .body(ChunkBody {
                                chunks: VecDeque::from([
                                    Bytes::from_static(b"first-"),
                                    Bytes::from_static(b"second"),
                                ]),
                            })
                            .expect("response"),
                    )
                }
            });
            server_http1::Builder::new()
                .serve_connection(io, service)
                .await
                .expect("upstream serve");
        });

        let hop_listener = TcpListener::bind("127.0.0.1:0").await.expect("hop bind");
        let hop_addr = hop_listener.local_addr().expect("hop address");
        let config = test_config(
            required_buffered_bytes(1024 * 1024),
            2,
            Duration::from_secs(5),
        );
        tokio::spawn(serve_with_upstream(hop_listener, config, upstream_addr));

        let stream = TcpStream::connect(hop_addr).await.expect("hop connect");
        let io = TokioIo::new(stream);
        let (mut sender, connection) = http1::handshake(io).await.expect("hop handshake");
        tokio::spawn(connection);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/chat/completions")
            .header("x-gm-cloud-hop-provider", "azure-openai")
            .header("x-gm-node-key", "must-not-forward")
            .header("x-gm-upstream-slot", "must-not-forward")
            .header("x-gm-request-id", "request-id")
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(br#"{"model":"gpt-5.5"}"#)))
            .expect("request");
        let mut response = sender.send_request(request).await.expect("hop response");
        let forwarded = observed_rx.await.expect("forwarded request observation");
        assert_eq!(forwarded.uri().path(), "/v1/chat/completions");
        assert_eq!(
            forwarded.headers()["x-gm-cloud-hop-provider"],
            "azure-openai"
        );
        assert!(!forwarded.headers().contains_key("x-gm-node-key"));
        assert!(!forwarded.headers().contains_key("x-gm-upstream-slot"));
        assert_eq!(forwarded.headers()[CONTENT_LENGTH], "20");
        assert_eq!(
            forwarded.body(),
            &Bytes::from_static(br#"{"model":"my-gpt55"}"#)
        );
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()["x-upstream-marker"], "preserve-me");
        let first = response
            .body_mut()
            .frame()
            .await
            .expect("first response frame")
            .expect("first response frame is valid")
            .into_data()
            .expect("first response frame is data");
        assert_eq!(first, Bytes::from_static(b"first-"));
        let second = response
            .body_mut()
            .frame()
            .await
            .expect("second response frame")
            .expect("second response frame is valid")
            .into_data()
            .expect("second response frame is data");
        assert_eq!(second, Bytes::from_static(b"second"));
        assert!(response.body_mut().frame().await.is_none());
    }
    #[tokio::test]
    async fn round5_cancel_before_headers_releases_transport_storage() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("valid cancellation fixture");
        let addr = listener.local_addr().expect("valid cancellation fixture");
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("valid cancellation fixture");
            accepted_tx.send(()).expect("valid cancellation fixture");
            std::future::pending::<()>().await;
            drop(stream);
        });
        let size = 16 * 1024 * 1024;
        let buffered = Arc::new(Semaphore::new(size));
        let permit = buffered
            .clone()
            .acquire_many_owned(u32::try_from(size).expect("fixture fits u32"))
            .await
            .expect("valid cancellation fixture");
        let body = BufferedBytes::new(Bytes::from(vec![b'x'; size]), Some(permit));
        let state = Arc::new(ProxyState {
            config: test_config_with_request(size, size * 2 + 64, 1, Duration::from_millis(100)),
            upstream_addr: addr,
            buffered: buffered.clone(),
            requests: Arc::new(Semaphore::new(1)),
        });
        let (parts, ()) = Request::builder()
            .method(Method::POST)
            .uri("/v1/chat/completions")
            .body(())
            .expect("valid cancellation fixture")
            .into_parts();
        let task = tokio::spawn(forward_request(
            parts,
            body,
            CloudProvider::AzureOpenAi,
            state,
            Instant::now() + Duration::from_millis(100),
        ));
        accepted_rx.await.expect("valid cancellation fixture");
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            buffered.available_permits(),
            0,
            "transport must still own the incomplete upload"
        );
        task.abort();
        let _ = task.await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let available = buffered.available_permits();
        upstream.abort();
        assert_eq!(
            available, size,
            "cancelled pre-header forwarding must free transport storage by its deadline"
        );
    }
}
