//! The measured cloud-adapter model translation hop.
//!
//! Envoy remains responsible for all cloud TLS, host rewrite, SNI, and SAN
//! matching. This crate only accepts an already-authenticated loopback request,
//! replaces one top-level JSON member, and forwards the request to Envoy's
//! loopback egress listener. Responses are never parsed or rewritten.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use http_body_util::{BodyExt as _, Full};
use hyper::{
    body::{Body as _, Bytes, Incoming},
    header::{HeaderValue, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING},
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

/// The cloud adapters whose request surfaces are qualified for this hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudProvider {
    /// Azure `OpenAI` chat completions and Responses.
    AzureOpenAi,
    /// Microsoft Foundry Anthropic Messages.
    Foundry,
    /// AWS Bedrock Mantle. Kept in the type and static table for a reviewed
    /// future enablement, but disabled below until its response echo is live-
    /// observed.
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

/// Canonical IDs represented by the reviewed static Mantle table.
pub const BEDROCK_MODEL_IDS: &[&str] = &["claude-sonnet-4-6"];

/// The reviewed Mantle table. It is intentionally unreachable from Envoy
/// while [`BEDROCK_HOP_ENABLED`] is false: enable only after a live Bedrock
/// response proves that the upstream echo identifies the underlying model.
pub const BEDROCK_MANTLE_DEPLOYMENTS: &[(&str, &str)] =
    &[("claude-sonnet-4-6", "anthropic.claude-sonnet-4-6-v1")];

/// Build-time safety fence for Bedrock. Do not flip this until the Mantle
/// response `model` echo has been observed on the exact routed surface and
/// added to the qualified echo evidence.
pub const BEDROCK_HOP_ENABLED: bool = false;

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

/// Construct the reviewed static Bedrock table for future use.
#[must_use]
pub fn bedrock_deployment_map() -> DeploymentMap {
    DeploymentMap {
        provider: CloudProvider::Bedrock,
        entries: BEDROCK_MANTLE_DEPLOYMENTS
            .iter()
            .map(|(canonical, deployment)| ((*canonical).to_owned(), (*deployment).to_owned()))
            .collect(),
    }
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
    #[error("cloud hop does not support this HTTP surface")]
    UnsupportedSurface,
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
    if provider == CloudProvider::Bedrock && !BEDROCK_HOP_ENABLED {
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
    scan_object(&mut cursor, 0, true, map, &mut replacement)?;
    cursor.skip_whitespace();
    if cursor.position != body.len() {
        return Err(RewriteError::MalformedJson);
    }
    let Some((start, end, deployment)) = replacement else {
        return Err(RewriteError::MissingModel);
    };

    let mut rewritten = Vec::with_capacity(body.len() + deployment.len());
    rewritten.extend_from_slice(&body[..start]);
    rewritten.push(b'"');
    rewritten.extend_from_slice(deployment.as_bytes());
    rewritten.push(b'"');
    rewritten.extend_from_slice(&body[end..]);
    Ok(rewritten)
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
    map: &DeploymentMap,
    replacement: &mut Option<(usize, usize, String)>,
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
        let key = serde_json::from_slice::<String>(&cursor.body[key_start..key_end])
            .map_err(|_| RewriteError::MalformedJson)?;
        cursor.skip_whitespace();
        if cursor.advance() != Some(b':') {
            return Err(RewriteError::MalformedJson);
        }
        cursor.skip_whitespace();
        let value_start = cursor.position;
        scan_value(cursor, depth + 1, map, replacement, false)?;
        let value_end = cursor.position;

        if root && key == "model" {
            if replacement.is_some() {
                return Err(RewriteError::DuplicateModel);
            }
            if cursor.body.get(value_start) != Some(&b'"') {
                return Err(RewriteError::ModelNotString);
            }
            let model = serde_json::from_slice::<String>(&cursor.body[value_start..value_end])
                .map_err(|_| RewriteError::ModelNotString)?;
            let Some(deployment) = map.get(&model) else {
                return Err(RewriteError::UnmappedModel);
            };
            *replacement = Some((value_start, value_end, deployment.to_owned()));
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
    map: &DeploymentMap,
    replacement: &mut Option<(usize, usize, String)>,
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
        Some(b'{') => scan_object(cursor, depth, root, map, replacement),
        Some(b'[') => scan_array(cursor, depth, map, replacement),
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
    map: &DeploymentMap,
    replacement: &mut Option<(usize, usize, String)>,
) -> Result<(), RewriteError> {
    cursor.advance();
    cursor.skip_whitespace();
    if cursor.peek() == Some(b']') {
        cursor.advance();
        return Ok(());
    }
    loop {
        cursor.skip_whitespace();
        scan_value(cursor, depth + 1, map, replacement, false)?;
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
        let default_buffered = DEFAULT_BUFFERED_BYTES.max(max_request_bytes);
        let max_buffered_bytes = bounded_usize(
            "GM_CLOUD_HOP_MAX_BUFFERED_BYTES",
            std::env::var("GM_CLOUD_HOP_MAX_BUFFERED_BYTES").ok(),
            max_request_bytes,
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
    std::env::var("GM_CLOUD_HOP_MAX_REQUEST_BYTES")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var("GM_GATEWAY_MAX_REQUEST_BODY_BYTES").ok())
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

type ResponseBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

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
    let state = Arc::new(ProxyState {
        buffered: Arc::new(Semaphore::new(config.max_buffered_bytes)),
        requests: Arc::new(Semaphore::new(config.max_concurrency)),
        config,
        upstream_addr,
    });
    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, state).await {
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

async fn serve_connection(stream: TcpStream, state: Arc<ProxyState>) -> Result<(), hyper::Error> {
    let io = TokioIo::new(stream);
    let service = service_fn(move |request| {
        let state = Arc::clone(&state);
        async move { Ok::<_, Infallible>(handle_request(request, state).await) }
    });
    hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service)
        .await
}

#[expect(
    clippy::too_many_lines,
    reason = "the request lifecycle keeps admission, rewrite, and streaming ownership together"
)]
async fn handle_request(
    request: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Response<ResponseBody> {
    let Some(selector) = request
        .headers()
        .get("x-gm-cloud-hop-provider")
        .and_then(|value| value.to_str().ok())
        .and_then(CloudProvider::from_selector)
    else {
        return json_error(
            StatusCode::NOT_FOUND,
            "cloud hop selector missing or invalid",
        );
    };
    if selector == CloudProvider::Bedrock && !BEDROCK_HOP_ENABLED {
        return json_error(
            StatusCode::NOT_FOUND,
            "cloud hop is disabled for this provider",
        );
    }
    let Some(map) = state.config.map_for(selector) else {
        return json_error(
            StatusCode::NOT_FOUND,
            "cloud hop is not configured for this provider",
        );
    };
    if request.method() != Method::POST || !supported_surface(selector, request.uri().path()) {
        return json_error(StatusCode::NOT_FOUND, "cloud hop surface is not enabled");
    }
    if usize::try_from(request.body().size_hint().lower())
        .is_ok_and(|size| size > state.config.max_request_bytes)
    {
        return json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "cloud hop request body is too large",
        );
    }
    if let Some(value) = request.headers().get(CONTENT_LENGTH) {
        if value
            .to_str()
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .is_some_and(|size| size > state.config.max_request_bytes)
        {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "cloud hop request body is too large",
            );
        }
    }

    let Ok(Ok(request_permit)) = timeout(
        state.config.timeout,
        Arc::clone(&state.requests).acquire_owned(),
    )
    .await
    else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cloud hop concurrency limit timed out",
        );
    };
    let (parts, request_body) = request.into_parts();
    let (body, buffer_permits) = match timeout(
        state.config.timeout,
        read_request_body(
            request_body,
            state.config.max_request_bytes,
            Arc::clone(&state.buffered),
        ),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(ReadBodyError::TooLarge)) => {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "cloud hop request body is too large",
            )
        }
        Ok(Err(ReadBodyError::AggregateLimit)) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cloud hop aggregate buffering limit reached",
            )
        }
        Ok(Err(ReadBodyError::Trailers)) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "cloud hop request trailers are not supported",
            )
        }
        Ok(Err(ReadBodyError::Body(_))) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "cloud hop request body stream failed",
            )
        }
        Err(_) => {
            return json_error(
                StatusCode::REQUEST_TIMEOUT,
                "cloud hop request body timed out",
            )
        }
    };
    let rewritten = match rewrite_model_bytes(selector, &body, map) {
        Ok(body) => body,
        Err(error) => {
            let message = error.to_string();
            return json_error(StatusCode::BAD_REQUEST, &message);
        }
    };

    match forward_request(parts, rewritten, selector, state).await {
        Ok(response) => box_response(response, request_permit, buffer_permits),
        Err(error) => {
            tracing::warn!(error = %error, "cloud hop upstream forwarding failed");
            json_error(
                StatusCode::BAD_GATEWAY,
                "cloud hop upstream forwarding failed",
            )
        }
    }
}

async fn read_request_body(
    mut body: Incoming,
    max_request_bytes: usize,
    buffered: Arc<Semaphore>,
) -> Result<(Bytes, Vec<OwnedSemaphorePermit>), ReadBodyError> {
    let mut bytes = Vec::new();
    let mut permits = Vec::new();
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
            let permit = if data.is_empty() {
                None
            } else {
                Some(
                    buffered
                        .clone()
                        .try_acquire_many_owned(
                            data.len()
                                .try_into()
                                .map_err(|_| ReadBodyError::AggregateLimit)?,
                        )
                        .map_err(|_| ReadBodyError::AggregateLimit)?,
                )
            };
            bytes.extend_from_slice(&data);
            if let Some(permit) = permit {
                permits.push(permit);
            }
        } else {
            return Err(ReadBodyError::Trailers);
        }
    }
    Ok((Bytes::from(bytes), permits))
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

fn supported_surface(provider: CloudProvider, path: &str) -> bool {
    match provider {
        CloudProvider::AzureOpenAi => matches!(path, "/v1/chat/completions" | "/v1/responses"),
        CloudProvider::Foundry => path == "/v1/messages",
        CloudProvider::Bedrock => false,
    }
}

async fn forward_request(
    mut parts: hyper::http::request::Parts,
    body: Vec<u8>,
    selector: CloudProvider,
    state: Arc<ProxyState>,
) -> Result<Response<Incoming>, ForwardError> {
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
        HeaderValue::from_str(&body.len().to_string()).map_err(|_| ForwardError::HeaderValue)?,
    );
    parts.headers.insert(
        "x-gm-cloud-hop-provider",
        selector
            .selector()
            .parse()
            .map_err(|_| ForwardError::HeaderValue)?,
    );
    let request = Request::from_parts(parts, Full::new(Bytes::from(body)));
    let stream = timeout(
        state.config.timeout,
        TcpStream::connect(state.upstream_addr),
    )
    .await
    .map_err(|_| ForwardError::Timeout)??;
    let io = TokioIo::new(stream);
    let (mut sender, connection) = timeout(
        state.config.timeout,
        hyper::client::conn::http1::handshake(io),
    )
    .await
    .map_err(|_| ForwardError::Timeout)?
    .map_err(ForwardError::Http)?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(error = %error, "cloud hop egress connection ended");
        }
    });
    timeout(state.config.timeout, sender.send_request(request))
        .await
        .map_err(|_| ForwardError::Timeout)?
        .map_err(ForwardError::Http)
}

fn box_response(
    response: Response<Incoming>,
    request_permit: OwnedSemaphorePermit,
    buffer_permits: Vec<OwnedSemaphorePermit>,
) -> Response<ResponseBody> {
    let (parts, body) = response.into_parts();
    let body = body
        .map_frame(move |frame| {
            // Keep both admission permits until the response body is dropped,
            // not merely until upstream response headers arrive. This makes
            // the limits describe complete in-flight cloud requests and keeps
            // aggregate request storage accounted for during a long stream.
            let _ = (&request_permit, &buffer_permits);
            frame
        })
        .boxed();
    Response::from_parts(parts, body)
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
    clippy::assertions_on_constants,
    clippy::expect_used,
    reason = "tests intentionally panic on unexpected values and assert safety constants"
)]
mod tests {
    use super::*;
    use hyper::service::service_fn;
    use hyper::{body::Frame, client::conn::http1, server::conn::http1 as server_http1};
    use std::{
        collections::VecDeque,
        pin::Pin,
        task::{Context, Poll},
    };

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
    fn bedrock_table_is_present_but_hop_is_disabled() {
        let map = bedrock_deployment_map();
        assert_eq!(
            map.get("claude-sonnet-4-6"),
            Some("anthropic.claude-sonnet-4-6-v1")
        );
        assert!(!BEDROCK_HOP_ENABLED);
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
    async fn response_status_headers_and_stream_frames_pass_through() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let upstream_addr = upstream_listener.local_addr().expect("upstream address");
        tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.expect("upstream accept");
            let io = TokioIo::new(stream);
            let service = service_fn(|_request: Request<Incoming>| async {
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
            });
            server_http1::Builder::new()
                .serve_connection(io, service)
                .await
                .expect("upstream serve");
        });

        let hop_listener = TcpListener::bind("127.0.0.1:0").await.expect("hop bind");
        let hop_addr = hop_listener.local_addr().expect("hop address");
        let config = CloudHopConfig {
            azure_openai: Some(azure_map()),
            foundry: Some(foundry_map()),
            max_request_bytes: 1024 * 1024,
            max_buffered_bytes: 2 * 1024 * 1024,
            max_concurrency: 2,
            timeout: Duration::from_secs(5),
        };
        tokio::spawn(serve_with_upstream(hop_listener, config, upstream_addr));

        let stream = TcpStream::connect(hop_addr).await.expect("hop connect");
        let io = TokioIo::new(stream);
        let (mut sender, connection) = http1::handshake(io).await.expect("hop handshake");
        tokio::spawn(connection);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/chat/completions")
            .header("x-gm-cloud-hop-provider", "azure-openai")
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(br#"{"model":"gpt-5.5"}"#)))
            .expect("request");
        let mut response = sender.send_request(request).await.expect("hop response");
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
}
