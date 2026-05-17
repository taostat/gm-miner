//! Per-provider capability check logic.
//!
//! Each provider has a single exported function `check_<provider>()` that:
//!   1. Verifies the corresponding env var is set.
//!   2. Calls the upstream's free /models endpoint using the env-var key.
//!   3. Returns a `CapabilityResponse` with the model list.
//!
//! The callers (routes.rs) cache nothing — freshness is the whole point.
//! The registry controls polling cadence (10-minute default).
//!
//! Contract: docs/contracts/miner-capability.md

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

/// Canonical response shape per miner-capability.md.
#[derive(Debug, Serialize)]
pub struct CapabilityResponse {
    pub schema_version: &'static str,
    pub provider: &'static str,
    pub checked_at: String,
    pub env_var_present: bool,
    pub upstream_ok: bool,
    pub models: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub rate_limit_headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CapabilityResponse {
    fn ok(provider: &'static str, models: Vec<String>) -> Self {
        Self {
            schema_version: "1",
            provider,
            checked_at: Utc::now().to_rfc3339(),
            env_var_present: true,
            upstream_ok: true,
            models,
            rate_limit_headers: HashMap::new(),
            error: None,
        }
    }

    fn missing_key(provider: &'static str, env_var: &str) -> Self {
        Self {
            schema_version: "1",
            provider,
            checked_at: Utc::now().to_rfc3339(),
            env_var_present: false,
            upstream_ok: false,
            models: vec![],
            rate_limit_headers: HashMap::new(),
            error: Some(format!("{env_var} not set")),
        }
    }

    fn upstream_error(provider: &'static str, msg: String) -> Self {
        Self {
            schema_version: "1",
            provider,
            checked_at: Utc::now().to_rfc3339(),
            env_var_present: true,
            upstream_ok: false,
            models: vec![],
            rate_limit_headers: HashMap::new(),
            error: Some(msg),
        }
    }
}

/// Anthropic model list item shape.
#[derive(Deserialize)]
struct AnthropicModelEntry {
    id: String,
}

#[derive(Deserialize)]
struct AnthropicModelsResponse {
    data: Vec<AnthropicModelEntry>,
}

/// Check Anthropic capability via `GET <https://api.anthropic.com/v1/models>`
pub async fn check_anthropic(client: &reqwest::Client) -> CapabilityResponse {
    let key = match std::env::var("ANTHROPIC_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => return CapabilityResponse::missing_key("anthropic", "ANTHROPIC_API_KEY"),
    };

    let result = client
        .get("https://api.anthropic.com/v1/models")
        .header("x-api-key", &key)
        .header("anthropic-version", "2023-06-01")
        .send()
        .await;

    match result {
        Err(e) => {
            warn!("anthropic /models request failed: {e}");
            CapabilityResponse::upstream_error("anthropic", format!("network error: {e}"))
        }
        Ok(resp) => {
            let status = resp.status();
            // Capture rate-limit headers before consuming body.
            let rate_headers = extract_rate_headers(
                &resp,
                &[
                    "anthropic-ratelimit-requests-limit",
                    "anthropic-ratelimit-requests-remaining",
                ],
            );

            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                warn!("anthropic /models returned {status}: {body}");
                return CapabilityResponse::upstream_error(
                    "anthropic",
                    format!("upstream {status}: {body}"),
                );
            }

            match resp.json::<AnthropicModelsResponse>().await {
                Err(e) => {
                    warn!("anthropic /models parse error: {e}");
                    CapabilityResponse::upstream_error("anthropic", format!("parse error: {e}"))
                }
                Ok(body) => {
                    let models: Vec<String> = body.data.into_iter().map(|m| m.id).collect();
                    info!("anthropic capability ok: {} models", models.len());
                    let mut resp = CapabilityResponse::ok("anthropic", models);
                    resp.rate_limit_headers = rate_headers;
                    resp
                }
            }
        }
    }
}

/// `OpenAI` model list item shape.
#[derive(Deserialize)]
struct OpenAIModelEntry {
    id: String,
}

#[derive(Deserialize)]
struct OpenAIModelsResponse {
    data: Vec<OpenAIModelEntry>,
}

/// Check `OpenAI` capability via `GET <https://api.openai.com/v1/models>`
pub async fn check_openai(client: &reqwest::Client) -> CapabilityResponse {
    let key = match std::env::var("OPENAI_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => return CapabilityResponse::missing_key("openai", "OPENAI_API_KEY"),
    };

    let result = client
        .get("https://api.openai.com/v1/models")
        .bearer_auth(&key)
        .send()
        .await;

    match result {
        Err(e) => {
            warn!("openai /models request failed: {e}");
            CapabilityResponse::upstream_error("openai", format!("network error: {e}"))
        }
        Ok(resp) => {
            let status = resp.status();
            let rate_headers = extract_rate_headers(
                &resp,
                &[
                    "x-ratelimit-limit-requests",
                    "x-ratelimit-remaining-requests",
                ],
            );

            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                warn!("openai /models returned {status}: {body}");
                return CapabilityResponse::upstream_error(
                    "openai",
                    format!("upstream {status}: {body}"),
                );
            }

            match resp.json::<OpenAIModelsResponse>().await {
                Err(e) => {
                    warn!("openai /models parse error: {e}");
                    CapabilityResponse::upstream_error("openai", format!("parse error: {e}"))
                }
                Ok(body) => {
                    let models: Vec<String> = body.data.into_iter().map(|m| m.id).collect();
                    info!("openai capability ok: {} models", models.len());
                    let mut resp = CapabilityResponse::ok("openai", models);
                    resp.rate_limit_headers = rate_headers;
                    resp
                }
            }
        }
    }
}

/// Gemini model list item shape.
/// `GET <https://generativelanguage.googleapis.com/v1beta/models?key>`
#[derive(Deserialize)]
struct GeminiModelEntry {
    name: String,
}

#[derive(Deserialize)]
struct GeminiModelsResponse {
    models: Vec<GeminiModelEntry>,
}

/// Check Gemini capability via GET .../v1beta/models
pub async fn check_gemini(client: &reqwest::Client) -> CapabilityResponse {
    let key = match std::env::var("GOOGLE_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => return CapabilityResponse::missing_key("gemini", "GOOGLE_API_KEY"),
    };

    let url = format!("https://generativelanguage.googleapis.com/v1beta/models?key={key}");

    let result = client.get(&url).send().await;

    match result {
        Err(e) => {
            warn!("gemini models request failed: {e}");
            CapabilityResponse::upstream_error("gemini", format!("network error: {e}"))
        }
        Ok(resp) => {
            let status = resp.status();

            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                warn!("gemini models returned {status}: {body}");
                return CapabilityResponse::upstream_error(
                    "gemini",
                    format!("upstream {status}: {body}"),
                );
            }

            match resp.json::<GeminiModelsResponse>().await {
                Err(e) => {
                    warn!("gemini models parse error: {e}");
                    CapabilityResponse::upstream_error("gemini", format!("parse error: {e}"))
                }
                Ok(body) => {
                    // Gemini names look like "models/gemini-2.5-pro"; strip prefix.
                    let models: Vec<String> = body
                        .models
                        .into_iter()
                        .map(|m| m.name.strip_prefix("models/").unwrap_or(&m.name).to_owned())
                        .collect();
                    info!("gemini capability ok: {} models", models.len());
                    CapabilityResponse::ok("gemini", models)
                }
            }
        }
    }
}

/// Extract named headers from a response into a plain `HashMap`.
fn extract_rate_headers(resp: &reqwest::Response, names: &[&str]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for name in names {
        if let Some(val) = resp.headers().get(*name).and_then(|v| v.to_str().ok()) {
            out.insert(name.to_string(), val.to_string());
        }
    }
    out
}
