//! Testnet-only native Gemini image preflight/canary.
//!
//! The canary is intentionally a buyer-side request through the GM gateway,
//! not a provider-key or worker health probe. It first reads the gateway's
//! live `/v1/models` availability snapshot for both image SKUs, and only then
//! sends one small, non-streaming native `generateContent` request for each.
//! The response parser retains usage and settled-cost metadata while never
//! retaining or printing the generated image body.

use anyhow::{bail, Context as _, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use reqwest::{header, Client, Response};
use serde::Serialize;
use serde_json::{json, Value};
use std::fmt;

use gm_miner_cli::{client::build_http_client, network::Network, types::GEMINI_IMAGE_MODELS};

const MODELS_PATH: &str = "/v1/models";
const CREDITS_PATH: &str = "/v1/credits";
const GENERATE_CONTENT_PATH_PREFIX: &str = "/v1beta/models/";
const GENERATE_CONTENT_ACTION: &str = ":generateContent";

// The gateway accepts request bodies up to 16 MiB. Keep the native image
// response reader bounded by that same conservative transport limit so a
// malformed or unexpectedly large response cannot grow an unbounded Vec. A
// normal 1K image response is well below this ceiling.
const MAX_NATIVE_IMAGE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_GATEWAY_ERROR_RESPONSE_BYTES: usize = 64 * 1024;

// This text is deliberately fixed and intentionally never appears in output,
// logs, or an error. The canary proves native image forwarding and settlement;
// it is not a user prompt or an image-quality check.
const CANARY_PROMPT: &str = "Create a simple abstract square test image.";

/// Run the paid Gemini image canary for the selected network.
///
/// The only supported network is testnet. `buyer_api_key` is the GM buyer key
/// used by the gateway, not either provider key stored for a miner worker. A
/// gateway URL override is useful for local/mock verification; production
/// callers should leave it unset so the network profile supplies the host.
pub(crate) async fn cmd_image_canary(
    network: Network,
    gateway_url: Option<&str>,
    buyer_api_key: &str,
) -> Result<()> {
    ensure_testnet(network)?;
    if buyer_api_key.trim().is_empty() {
        bail!("a funded GM buyer key is required; pass `--buyer-api-key` or set GM_API_KEY");
    }
    let gateway_url = gateway_url.unwrap_or_else(|| network.default_gateway_url());
    let client = build_http_client()?;
    match run_image_canary_with_client(&client, gateway_url, buyer_api_key).await {
        Ok(run) => print_run(&run),
        Err(error) => {
            // A generation request can fail after dispatch and still be
            // charged. Preserve every safe per-attempt observation and the
            // run-level balance reconciliation before returning non-zero.
            if let Some(partial) = error.downcast_ref::<PartialCanaryFailure>() {
                print_run(&partial.run)?;
                return Err(anyhow::anyhow!(partial.message.clone()));
            }
            Err(error)
        }
    }
}

fn print_run(run: &ImageCanaryRun) -> Result<()> {
    for report in &run.reports {
        // This is the complete output surface by design. In particular, do
        // not print the request/response body, prompt, image data, or key.
        println!(
            "{}",
            serde_json::to_string(report).context("serialize image canary report")?
        );
    }
    println!(
        "{}",
        serde_json::to_string(&run.summary).context("serialize image canary summary")?
    );
    Ok(())
}

/// A machine-readable, safe reconciliation line emitted after one SKU probe.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct ImageCanaryReport {
    pub(crate) record: &'static str,
    pub(crate) model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) request_id: Option<String>,
    pub(crate) outcome: &'static str,
    pub(crate) billing_status: BillingStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) usage: Option<UsageDimensions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) settled_ndollars: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) failure: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) balance_before_ndollars: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) balance_after_ndollars: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The observed run-level debit, when both balances are available and the
    /// balance moved down. During a partial run it is evidence for the whole
    /// run and must not be attributed to one SKU.
    pub(crate) balance_delta_ndollars: Option<u64>,
    /// `ok` when both balance reads agree with all known settled charges;
    /// `unknown` when at least one dispatched probe has uncertain billing;
    /// `unavailable` when the gateway did not expose a readable balance; or
    /// `mismatch` when the observed balance contradicts known charges.
    pub(crate) reconciliation: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct ImageCanarySummary {
    pub(crate) record: &'static str,
    pub(crate) successful_probes: usize,
    pub(crate) failed_probes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) known_settled_ndollars: Option<u64>,
    pub(crate) unknown_billing_probes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) balance_before_ndollars: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) balance_after_ndollars: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) balance_delta_ndollars: Option<u64>,
    pub(crate) reconciliation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageCanaryRun {
    reports: Vec<ImageCanaryReport>,
    summary: ImageCanarySummary,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BillingStatus {
    Settled,
    Unbilled,
    Unknown,
}

/// The usage dimensions needed to audit an image request without exposing its
/// native response body. Gemini's modality details are normalised into the
/// same text/audio/image split used by GM settlement.
#[expect(
    clippy::struct_field_names,
    reason = "wire-facing usage dimensions intentionally share the token suffix"
)]
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub(crate) struct UsageDimensions {
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) cache_read_tokens: u64,
    pub(crate) cache_write_5m_tokens: u64,
    pub(crate) cache_write_1h_tokens: u64,
    pub(crate) audio_input_tokens: u64,
    pub(crate) audio_output_tokens: u64,
    pub(crate) image_input_tokens: u64,
    pub(crate) image_output_tokens: u64,
    pub(crate) reasoning_tokens: u64,
    /// Gemini's tool-use prompt tokens are separate from prompt and candidate
    /// tokens. The canary does not send tools, but retaining this field keeps
    /// the usage evidence faithful when a gateway fixture includes it.
    pub(crate) tool_use_prompt_tokens: u64,
    pub(crate) total_tokens: u64,
}

#[derive(Debug)]
struct ImageCanaryObservation {
    model: String,
    request_id: Option<String>,
    outcome: &'static str,
    billing_status: BillingStatus,
    http_status: Option<u16>,
    usage: Option<UsageDimensions>,
    settled_ndollars: Option<u64>,
    failure: Option<String>,
}

#[derive(Debug)]
struct PartialCanaryFailure {
    run: ImageCanaryRun,
    message: String,
}

impl fmt::Display for PartialCanaryFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PartialCanaryFailure {}

#[derive(Debug, serde::Deserialize)]
struct ModelListResponse {
    #[serde(default)]
    data: Vec<ModelAvailability>,
}

#[derive(Debug, serde::Deserialize)]
struct ModelAvailability {
    id: String,
    #[serde(default)]
    available: bool,
}

/// The injectable core used by the wiremock tests and by the production
/// command. Offer discovery happens before either balance or generation call,
/// making a missing SKU a strict no-spend gate.
async fn run_image_canary_with_client(
    client: &Client,
    gateway_url: &str,
    buyer_api_key: &str,
) -> Result<ImageCanaryRun> {
    let gateway_url = gateway_url.trim_end_matches('/');
    if gateway_url.is_empty() {
        bail!("the Gemini image canary gateway URL cannot be empty");
    }
    let missing = fetch_missing_live_offers(client, gateway_url).await?;
    if !missing.is_empty() {
        bail!(
            "Gemini image canary stopped before spending: no live eligible offer for {}",
            missing.join(", ")
        );
    }

    let balance_before = fetch_balance(client, gateway_url, buyer_api_key).await;
    let mut observations = Vec::with_capacity(GEMINI_IMAGE_MODELS.len());
    for model in GEMINI_IMAGE_MODELS {
        observations.push(send_image_probe(client, gateway_url, buyer_api_key, model).await);
    }
    // Read the balance even when a provider request failed: it is still useful
    // to tell an operator whether a failed request consumed anything, and this
    // read is never an image/provider call.
    let balance_after = fetch_balance(client, gateway_url, buyer_api_key).await;

    let settled_total = observations
        .iter()
        .filter_map(|observation| observation.settled_ndollars)
        .try_fold(0_u64, u64::checked_add);
    let unknown_billing_probes = observations
        .iter()
        .filter(|observation| observation.billing_status == BillingStatus::Unknown)
        .count();
    let successful_probes = observations
        .iter()
        .filter(|observation| observation.outcome == "succeeded")
        .count();
    let failed_probes = observations.len().saturating_sub(successful_probes);
    let reconciliation = match (settled_total, balance_before, balance_after) {
        (None, _, _) => "mismatch",
        (Some(known), Some(before), Some(after)) => match before.checked_sub(after) {
            Some(observed) if observed < known => "mismatch",
            Some(observed) if unknown_billing_probes > 0 && observed >= known => "unknown",
            Some(observed) if observed == known => "ok",
            None | Some(_) => "mismatch",
        },
        _ => "unavailable",
    };
    let run = run_for_observations(
        observations,
        balance_before,
        balance_after,
        reconciliation,
        settled_total,
        unknown_billing_probes,
        successful_probes,
        failed_probes,
    );

    if reconciliation == "mismatch" {
        let message = match (settled_total, balance_before, balance_after) {
            (None, _, _) => {
                "Gemini image canary reconciliation mismatch: settled amount overflowed".to_owned()
            }
            (Some(known), Some(before), Some(after)) => format!(
                "Gemini image canary reconciliation mismatch: known settled charges total {known} nUSD, balance changed from {before} to {after} nUSD"
            ),
            _ => "Gemini image canary reconciliation mismatch".to_owned(),
        };
        return Err(PartialCanaryFailure { run, message }.into());
    }
    if failed_probes > 0 {
        let failures = run
            .reports
            .iter()
            .filter_map(|report| {
                report
                    .failure
                    .as_ref()
                    .map(|failure| format!("{}: {failure}", report.model))
            })
            .collect::<Vec<_>>();
        return Err(PartialCanaryFailure {
            run,
            message: format!(
                "Gemini image canary partial failure: request failure(s): {}",
                failures.join("; ")
            ),
        }
        .into());
    }

    Ok(run)
}

#[expect(
    clippy::too_many_arguments,
    reason = "All run-level reconciliation values are assembled at one output boundary"
)]
fn run_for_observations(
    observations: Vec<ImageCanaryObservation>,
    balance_before: Option<u64>,
    balance_after: Option<u64>,
    reconciliation: &'static str,
    known_settled_ndollars: Option<u64>,
    unknown_billing_probes: usize,
    successful_probes: usize,
    failed_probes: usize,
) -> ImageCanaryRun {
    let balance_delta_ndollars =
        balance_before.and_then(|before| balance_after.and_then(|after| before.checked_sub(after)));
    let reports = observations
        .into_iter()
        .map(|observation| ImageCanaryReport {
            record: "probe",
            model: observation.model,
            request_id: observation.request_id,
            outcome: observation.outcome,
            billing_status: observation.billing_status,
            http_status: observation.http_status,
            usage: observation.usage,
            settled_ndollars: observation.settled_ndollars,
            failure: observation.failure,
            balance_before_ndollars: balance_before,
            balance_after_ndollars: balance_after,
            balance_delta_ndollars,
            reconciliation,
        })
        .collect();
    ImageCanaryRun {
        reports,
        summary: ImageCanarySummary {
            record: "summary",
            successful_probes,
            failed_probes,
            known_settled_ndollars,
            unknown_billing_probes,
            balance_before_ndollars: balance_before,
            balance_after_ndollars: balance_after,
            balance_delta_ndollars,
            reconciliation,
        },
    }
}

fn ensure_testnet(network: Network) -> Result<()> {
    if network != Network::Testnet {
        bail!(
            "Gemini image canary is testnet-only; pass `--network testnet` and use a funded testnet buyer key"
        );
    }
    Ok(())
}

async fn fetch_missing_live_offers(
    client: &Client,
    gateway_url: &str,
) -> Result<Vec<&'static str>> {
    let url = format!("{gateway_url}{MODELS_PATH}?api_shape=generateContent");
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {MODELS_PATH}"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("GET {MODELS_PATH} failed ({status})");
    }
    let body = response
        .bytes()
        .await
        .context("read live Gemini offer response")?;
    let list: ModelListResponse =
        serde_json::from_slice(&body).context("parse live Gemini offer response")?;
    Ok(GEMINI_IMAGE_MODELS
        .into_iter()
        .filter(|model| {
            !list
                .data
                .iter()
                .any(|entry| entry.id == *model && entry.available)
        })
        .collect())
}

async fn fetch_balance(client: &Client, gateway_url: &str, buyer_api_key: &str) -> Option<u64> {
    let url = format!("{gateway_url}{CREDITS_PATH}");
    let response = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {buyer_api_key}"))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body = response.bytes().await.ok()?;
    let value: Value = serde_json::from_slice(&body).ok()?;
    let balance = value.get("balance")?;
    value_u64(balance, &["nano_usd", "nanoUsd"])
}

#[expect(
    clippy::too_many_lines,
    reason = "The probe keeps the bounded response and billing evidence lifecycle explicit"
)]
async fn send_image_probe(
    client: &Client,
    gateway_url: &str,
    buyer_api_key: &str,
    model: &str,
) -> ImageCanaryObservation {
    let url =
        format!("{gateway_url}{GENERATE_CONTENT_PATH_PREFIX}{model}{GENERATE_CONTENT_ACTION}");
    let Ok(mut response) = client
        .post(url)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-goog-api-key", buyer_api_key)
        .json(&image_probe_body())
        .send()
        .await
    else {
        return failed_observation(
            model,
            None,
            None,
            BillingStatus::Unknown,
            None,
            "transport error",
        );
    };
    let status = response.status();
    let request_id_header = response
        .headers()
        .get("x-gm-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned);
    if !status.is_success() {
        // The gateway's error envelope contains safe billing metadata. Read it
        // under a small bound, retain only the allowlisted fields below, and
        // discard the provider/gateway error object itself.
        let (billing_status, settled_ndollars) = read_gateway_failure_billing(&mut response, model)
            .await
            .unwrap_or((BillingStatus::Unknown, None));
        return failed_observation(
            model,
            request_id_header,
            Some(status.as_u16()),
            billing_status,
            settled_ndollars,
            &format!("HTTP {}", status.as_u16()),
        );
    }
    let Ok(body) =
        read_bounded_response(&mut response, model, MAX_NATIVE_IMAGE_RESPONSE_BYTES).await
    else {
        return failed_observation(
            model,
            request_id_header,
            Some(status.as_u16()),
            BillingStatus::Unknown,
            None,
            "invalid or oversized success response",
        );
    };
    let value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return failed_observation(
                model,
                request_id_header,
                Some(status.as_u16()),
                BillingStatus::Unknown,
                None,
                "invalid success response",
            );
        }
    };
    let request_id = request_id_header.or_else(|| {
        value
            .get("responseId")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let usage = parse_usage_dimensions(&value);
    let settled_ndollars = parse_settled_ndollars(&value);
    let failure = if request_id.is_none() {
        Some("success response had no request ID")
    } else if usage.is_none() {
        Some("success response had no usage metadata")
    } else if usage
        .as_ref()
        .is_some_and(|usage| validate_image_probe_response(&value, model, usage).is_err())
    {
        Some("success response had no valid image candidate")
    } else if settled_ndollars.is_none() {
        Some("success response had no settled nUSD")
    } else {
        None
    };
    if let Some(failure) = failure {
        let billing_status = if settled_ndollars.is_some() {
            BillingStatus::Settled
        } else {
            BillingStatus::Unknown
        };
        return failed_observation(
            model,
            request_id,
            Some(status.as_u16()),
            billing_status,
            settled_ndollars,
            failure,
        );
    }
    ImageCanaryObservation {
        model: model.to_owned(),
        request_id,
        outcome: "succeeded",
        billing_status: BillingStatus::Settled,
        http_status: Some(status.as_u16()),
        usage,
        settled_ndollars,
        failure: None,
    }
}

fn failed_observation(
    model: &str,
    request_id: Option<String>,
    http_status: Option<u16>,
    billing_status: BillingStatus,
    settled_ndollars: Option<u64>,
    failure: &str,
) -> ImageCanaryObservation {
    ImageCanaryObservation {
        model: model.to_owned(),
        request_id,
        outcome: "failed",
        billing_status,
        http_status,
        usage: None,
        settled_ndollars,
        failure: Some(failure.to_owned()),
    }
}

async fn read_gateway_failure_billing(
    response: &mut Response,
    model: &str,
) -> Result<(BillingStatus, Option<u64>)> {
    let body = read_bounded_response(response, model, MAX_GATEWAY_ERROR_RESPONSE_BYTES).await?;
    let value: Value = serde_json::from_slice(&body).context("parse gateway error envelope")?;
    Ok(parse_gateway_failure_billing(&value))
}

fn parse_gateway_failure_billing(value: &Value) -> (BillingStatus, Option<u64>) {
    match value.get("billing_status").and_then(Value::as_str) {
        Some("settled") => match value_u64(value, &["cost_ndollars"]) {
            Some(cost) => (BillingStatus::Settled, Some(cost)),
            None => (BillingStatus::Unknown, None),
        },
        Some("unbilled") => (BillingStatus::Unbilled, None),
        _ => (BillingStatus::Unknown, None),
    }
}

fn validate_image_probe_response(
    value: &Value,
    model: &str,
    usage: &UsageDimensions,
) -> Result<()> {
    if usage.image_output_tokens == 0 {
        bail!("native Gemini response for {model} had no positive image output usage");
    }
    if !has_supported_non_empty_image(value) {
        bail!("native Gemini response for {model} had no supported non-empty image candidate");
    }
    Ok(())
}

// Inspect the native response shape, decode one candidate only for bounded
// signature validation, and drop those bytes before returning. The response
// Value, including any inline image string, is never printed or retained in
// the reconciliation report.
#[derive(Clone, Copy)]
enum SupportedImageFormat {
    Png,
    Jpeg,
    Webp,
    Avif,
    Gif,
}

fn has_supported_non_empty_image(value: &Value) -> bool {
    value
        .get("candidates")
        .and_then(Value::as_array)
        .is_some_and(|candidates| candidates.iter().any(candidate_has_image))
}

fn candidate_has_image(candidate: &Value) -> bool {
    candidate
        .get("content")
        .and_then(|content| content.get("parts"))
        .and_then(Value::as_array)
        .is_some_and(|parts| parts.iter().any(part_has_image))
}

fn part_has_image(part: &Value) -> bool {
    let Some(inline_data) = part.get("inlineData").or_else(|| part.get("inline_data")) else {
        return false;
    };
    let Some(mime_type) = inline_data
        .get("mimeType")
        .or_else(|| inline_data.get("mime_type"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    let Some(format) = supported_image_format(mime_type) else {
        return false;
    };
    let Some(data) = inline_data.get("data").and_then(Value::as_str) else {
        return false;
    };
    if data.trim().is_empty() {
        return false;
    }
    if data.len() > MAX_NATIVE_IMAGE_RESPONSE_BYTES {
        return false;
    }
    let Ok(decoded_bytes) = BASE64_STANDARD.decode(data.trim()) else {
        return false;
    };
    let matches_signature = has_image_signature(format, &decoded_bytes);
    drop(decoded_bytes);
    matches_signature
}

// Keep this set aligned with the dashboard's image contract: the canary only
// validates the provider payload and never stores or renders the decoded data.
fn supported_image_format(mime_type: &str) -> Option<SupportedImageFormat> {
    let mime_type = mime_type.trim();
    if mime_type.eq_ignore_ascii_case("image/png") {
        Some(SupportedImageFormat::Png)
    } else if mime_type.eq_ignore_ascii_case("image/jpeg") {
        Some(SupportedImageFormat::Jpeg)
    } else if mime_type.eq_ignore_ascii_case("image/webp") {
        Some(SupportedImageFormat::Webp)
    } else if mime_type.eq_ignore_ascii_case("image/avif") {
        Some(SupportedImageFormat::Avif)
    } else if mime_type.eq_ignore_ascii_case("image/gif") {
        Some(SupportedImageFormat::Gif)
    } else {
        None
    }
}

fn has_image_signature(format: SupportedImageFormat, bytes: &[u8]) -> bool {
    match format {
        SupportedImageFormat::Png => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        SupportedImageFormat::Jpeg => bytes.starts_with(&[0xff, 0xd8, 0xff]),
        SupportedImageFormat::Webp => {
            bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP"
        }
        SupportedImageFormat::Avif => {
            if bytes.len() < 16 || &bytes[4..8] != b"ftyp" {
                return false;
            }
            let major_brand = &bytes[8..12];
            major_brand == b"avif"
                || major_brand == b"avis"
                || bytes[16..]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .any(|brand| brand == b"avif" || brand == b"avis")
        }
        SupportedImageFormat::Gif => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
    }
}

#[cfg(test)]
async fn read_bounded_native_response(mut response: Response, model: &str) -> Result<Vec<u8>> {
    read_bounded_response(&mut response, model, MAX_NATIVE_IMAGE_RESPONSE_BYTES).await
}

async fn read_bounded_response(
    response: &mut Response,
    model: &str,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if let Some(content_length) = response.content_length() {
        if content_length > max_bytes as u64 {
            bail!("native Gemini response for {model} exceeds the {max_bytes}-byte safety limit");
        }
    }

    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0);
    let mut body = Vec::with_capacity(initial_capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("read native Gemini response for {model}"))?
    {
        if chunk.len() > max_bytes.saturating_sub(body.len()) {
            bail!("native Gemini response for {model} exceeds the {max_bytes}-byte safety limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Native Gemini `generateContent` request for the canary. The image model
/// accepts IMAGE-only responses; `tools` is intentionally absent, which makes
/// grounding/search impossible. This body is never logged or printed.
fn image_probe_body() -> Value {
    json!({
        "contents": [{
            "role": "user",
            "parts": [{"text": CANARY_PROMPT}]
        }],
        "generationConfig": {
            "candidateCount": 1,
            "responseModalities": ["IMAGE"],
            "imageConfig": {"imageSize": "1K"}
        }
    })
}

fn parse_usage_dimensions(value: &Value) -> Option<UsageDimensions> {
    let usage = value.get("usageMetadata")?;
    if usage.is_null() {
        return None;
    }
    let prompt_total = value_u64(usage, &["promptTokenCount", "prompt_token_count"]).unwrap_or(0);
    let output_total =
        value_u64(usage, &["candidatesTokenCount", "candidates_token_count"]).unwrap_or(0);
    let cache_read = value_u64(
        usage,
        &["cachedContentTokenCount", "cached_content_token_count"],
    )
    .unwrap_or(0);
    let image_input = value_u64(usage, &["imageInputTokenCount", "image_input_token_count"])
        .unwrap_or_else(|| {
            modality_tokens(
                usage,
                &["promptTokensDetails", "prompt_tokens_details"],
                "IMAGE",
            )
        });
    let image_output = value_u64(
        usage,
        &["imageOutputTokenCount", "image_output_token_count"],
    )
    .unwrap_or_else(|| {
        modality_tokens(
            usage,
            &["candidatesTokensDetails", "candidates_tokens_details"],
            "IMAGE",
        )
    });
    let audio_input = modality_tokens(
        usage,
        &["promptTokensDetails", "prompt_tokens_details"],
        "AUDIO",
    );
    let audio_output = modality_tokens(
        usage,
        &["candidatesTokensDetails", "candidates_tokens_details"],
        "AUDIO",
    );
    let thoughts = value_u64(usage, &["thoughtsTokenCount", "thoughts_token_count"]).unwrap_or(0);
    let tool_use_prompt = value_u64(
        usage,
        &["toolUsePromptTokenCount", "tool_use_prompt_token_count"],
    )
    .unwrap_or(0);
    // Gemini defines totalTokenCount as prompt + candidates + tool-use prompt
    // + thoughts. `candidatesTokenCount` excludes thoughts, so keep visible
    // candidate output and reasoning separate and only use this sum as the
    // fallback when a provider omits totalTokenCount.
    let derived_total = prompt_total
        .saturating_add(output_total)
        .saturating_add(tool_use_prompt)
        .saturating_add(thoughts);
    let total =
        value_u64(usage, &["totalTokenCount", "total_token_count"]).unwrap_or(derived_total);
    if prompt_total == 0
        && output_total == 0
        && cache_read == 0
        && image_input == 0
        && image_output == 0
        && audio_input == 0
        && audio_output == 0
        && thoughts == 0
        && tool_use_prompt == 0
    {
        return None;
    }
    Some(UsageDimensions {
        input_tokens: prompt_total
            .saturating_sub(cache_read)
            .saturating_sub(image_input)
            .saturating_sub(audio_input),
        output_tokens: output_total
            .saturating_sub(image_output)
            .saturating_sub(audio_output),
        cache_read_tokens: cache_read,
        cache_write_5m_tokens: 0,
        cache_write_1h_tokens: 0,
        audio_input_tokens: audio_input,
        audio_output_tokens: audio_output,
        image_input_tokens: image_input,
        image_output_tokens: image_output,
        reasoning_tokens: thoughts,
        tool_use_prompt_tokens: tool_use_prompt,
        total_tokens: total,
    })
}

fn modality_tokens(usage: &Value, keys: &[&str], modality: &str) -> u64 {
    keys.iter()
        .find_map(|key| usage.get(*key))
        .and_then(Value::as_array)
        .map_or(0, |entries| {
            entries
                .iter()
                .filter(|entry| entry.get("modality").and_then(Value::as_str) == Some(modality))
                .filter_map(|entry| value_u64(entry, &["tokenCount", "token_count"]))
                .fold(0_u64, u64::saturating_add)
        })
}

fn parse_settled_ndollars(value: &Value) -> Option<u64> {
    let usage = value.get("usageMetadata");
    usage
        .and_then(|metadata| {
            value_u64(
                metadata,
                &[
                    "costNanoUsd",
                    "cost_nano_usd",
                    "settledNanoUsd",
                    "settled_ndollars",
                ],
            )
        })
        .or_else(|| {
            value_u64(
                value,
                &[
                    "costNanoUsd",
                    "cost_nano_usd",
                    "settledNanoUsd",
                    "settled_ndollars",
                ],
            )
        })
}

fn value_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(|candidate| {
            candidate
                .as_u64()
                .or_else(|| candidate.as_str().and_then(|raw| raw.parse().ok()))
        })
    })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "wiremock assertions intentionally panic on unexpected fixtures"
)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use wiremock::{
        matchers::{body_json, header, method, path},
        Mock, MockServer, Request, ResponseTemplate,
    };

    fn client() -> Client {
        build_http_client().expect("http client")
    }

    const TEST_IMAGE_BASE64: &str =
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

    async fn mount_live_offers(server: &MockServer, available: bool) {
        Mock::given(method("GET"))
            .and(path(MODELS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": GEMINI_IMAGE_MODELS
                    .iter()
                    .map(|model| json!({"id": model, "available": available}))
                    .collect::<Vec<_>>(),
            })))
            .mount(server)
            .await;
    }

    fn native_response(model: &str, request_id: &str, settled_ndollars: u64) -> Value {
        json!({
            "responseId": request_id,
            "modelVersion": model,
            "candidates": [{"content": {"parts": [{"inlineData": {"mimeType": "image/png", "data": TEST_IMAGE_BASE64}}]}}],
            "usageMetadata": {
                "promptTokenCount": 100,
                "candidatesTokenCount": 1_680,
                "promptTokensDetails": [
                    {"modality": "TEXT", "tokenCount": 40},
                    {"modality": "IMAGE", "tokenCount": 60}
                ],
                "candidatesTokensDetails": [
                    {"modality": "IMAGE", "tokenCount": 1_600},
                    {"modality": "TEXT", "tokenCount": 80}
                ],
                "toolUsePromptTokenCount": 13,
                "thoughtsTokenCount": 20,
                "totalTokenCount": 1_813,
                "costNanoUsd": settled_ndollars
            }
        })
    }

    fn native_text_response(model: &str, request_id: &str, settled_ndollars: u64) -> Value {
        json!({
            "responseId": request_id,
            "modelVersion": model,
            "candidates": [{
                "content": {"parts": [{"text": "I cannot provide that image."}]},
                "finishReason": "SAFETY"
            }],
            "usageMetadata": {
                "promptTokenCount": 100,
                "candidatesTokenCount": 7,
                "imageOutputTokenCount": 1,
                "thoughtsTokenCount": 0,
                "totalTokenCount": 107,
                "costNanoUsd": settled_ndollars
            }
        })
    }

    async fn mount_native_responses(server: &MockServer, settled_ndollars: u64) {
        for (index, model) in GEMINI_IMAGE_MODELS.into_iter().enumerate() {
            mount_native_response(
                server,
                model,
                &format!("gm-request-{index}"),
                settled_ndollars,
            )
            .await;
        }
    }

    async fn mount_native_response(
        server: &MockServer,
        model: &str,
        request_id: &str,
        settled_ndollars: u64,
    ) {
        Mock::given(method("POST"))
            .and(path(format!(
                "{GENERATE_CONTENT_PATH_PREFIX}{model}{GENERATE_CONTENT_ACTION}"
            )))
            .and(header("x-goog-api-key", "buyer-secret"))
            .and(body_json(image_probe_body()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-gm-request-id", request_id)
                    .set_body_json(native_response(model, request_id, settled_ndollars)),
            )
            .mount(server)
            .await;
    }

    async fn mount_native_text_response(
        server: &MockServer,
        model: &str,
        request_id: &str,
        settled_ndollars: u64,
    ) {
        Mock::given(method("POST"))
            .and(path(format!(
                "{GENERATE_CONTENT_PATH_PREFIX}{model}{GENERATE_CONTENT_ACTION}"
            )))
            .and(header("x-goog-api-key", "buyer-secret"))
            .and(body_json(image_probe_body()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-gm-request-id", request_id)
                    .set_body_json(native_text_response(model, request_id, settled_ndollars)),
            )
            .mount(server)
            .await;
    }

    async fn mount_native_failure(server: &MockServer, model: &str) {
        Mock::given(method("POST"))
            .and(path(format!(
                "{GENERATE_CONTENT_PATH_PREFIX}{model}{GENERATE_CONTENT_ACTION}"
            )))
            .and(header("x-goog-api-key", "buyer-secret"))
            .and(body_json(image_probe_body()))
            .respond_with(
                ResponseTemplate::new(500)
                    .insert_header("x-gm-request-id", format!("{model}-failure"))
                    .set_body_json(json!({
                        "error": {"code": 500, "message": "provider failure"},
                        "charged": false,
                        "billing_status": "unbilled",
                        "potentially_charged": false
                    })),
            )
            .mount(server)
            .await;
    }

    async fn mount_billed_native_failure(
        server: &MockServer,
        model: &str,
        request_id: &str,
        settled_ndollars: u64,
    ) {
        Mock::given(method("POST"))
            .and(path(format!(
                "{GENERATE_CONTENT_PATH_PREFIX}{model}{GENERATE_CONTENT_ACTION}"
            )))
            .and(header("x-goog-api-key", "buyer-secret"))
            .and(body_json(image_probe_body()))
            .respond_with(
                ResponseTemplate::new(422)
                    .insert_header("x-gm-request-id", request_id)
                    .set_body_json(json!({
                        "error": {"code": 422, "message": "content rejected"},
                        "cost_ndollars": settled_ndollars,
                        "charged": true,
                        "billing_status": "settled",
                        "potentially_charged": false
                    })),
            )
            .mount(server)
            .await;
    }

    async fn mount_credit_sequence(server: &MockServer, before: u64, after: u64) {
        let calls = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET"))
            .and(path(CREDITS_PATH))
            .respond_with({
                let calls = Arc::clone(&calls);
                move |_request: &Request| {
                    let value = if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        before
                    } else {
                        after
                    };
                    ResponseTemplate::new(200).set_body_json(json!({
                        "balance": {"nano_usd": value}
                    }))
                }
            })
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn missing_live_offer_fails_before_any_paid_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(MODELS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [{"id": GEMINI_IMAGE_MODELS[0], "available": true}],
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let error = run_image_canary_with_client(&client(), &server.uri(), "buyer-secret")
            .await
            .expect_err("the missing SKU must gate spend");
        let message = error.to_string();
        assert!(message.contains(GEMINI_IMAGE_MODELS[1]), "{message}");
        assert!(message.contains("before spending"), "{message}");
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method.as_str() == "POST")
                .count(),
            0
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.url.path() == CREDITS_PATH)
                .count(),
            0,
            "the offer gate must run before balance reads too"
        );
    }

    #[tokio::test]
    async fn both_skus_send_native_guarded_requests_and_reconcile_balances() {
        let server = MockServer::start().await;
        mount_live_offers(&server, true).await;
        mount_native_responses(&server, 123).await;
        mount_credit_sequence(&server, 10_000, 9_754).await;

        let run = run_image_canary_with_client(&client(), &server.uri(), "buyer-secret")
            .await
            .expect("both image requests reconcile");
        let reports = &run.reports;
        assert_eq!(reports.len(), 2);
        assert!(reports.iter().all(|report| report.reconciliation == "ok"));
        assert!(reports
            .iter()
            .all(|report| report.balance_before_ndollars == Some(10_000)));
        assert!(reports
            .iter()
            .all(|report| report.balance_after_ndollars == Some(9_754)));
        let usage = reports[0].usage.as_ref().expect("successful usage");
        assert_eq!(usage.image_input_tokens, 60);
        assert_eq!(usage.image_output_tokens, 1_600);
        assert_eq!(usage.tool_use_prompt_tokens, 13);
        assert_eq!(usage.total_tokens, 1_813);
        assert_eq!(reports[0].settled_ndollars, Some(123));
        assert_eq!(run.summary.known_settled_ndollars, Some(246));
        assert_eq!(run.summary.failed_probes, 0);

        let requests = server.received_requests().await.expect("requests");
        let native_requests: Vec<_> = requests
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .collect();
        assert_eq!(native_requests.len(), 2);
        for request in native_requests {
            let body: Value = serde_json::from_slice(&request.body).expect("native body");
            assert_eq!(body["generationConfig"]["candidateCount"], 1);
            assert_eq!(body["generationConfig"]["imageConfig"]["imageSize"], "1K");
            assert_eq!(
                body["generationConfig"]["responseModalities"],
                json!(["IMAGE"])
            );
            assert!(body.get("tools").is_none(), "grounding must be absent");
            assert_eq!(
                request
                    .headers
                    .get("x-goog-api-key")
                    .and_then(|value| value.to_str().ok()),
                Some("buyer-secret")
            );
        }
    }

    #[tokio::test]
    async fn balance_debit_mismatch_fails_reconciliation() {
        let server = MockServer::start().await;
        mount_live_offers(&server, true).await;
        mount_native_responses(&server, 123).await;
        mount_credit_sequence(&server, 10_000, 9_999).await;

        let error = run_image_canary_with_client(&client(), &server.uri(), "buyer-secret")
            .await
            .expect_err("a balance mismatch must fail the canary");
        assert!(error.to_string().contains("reconciliation mismatch"));
        let partial = error
            .downcast_ref::<PartialCanaryFailure>()
            .expect("mismatch retains safe evidence");
        assert_eq!(partial.run.reports.len(), 2);
        assert!(partial
            .run
            .reports
            .iter()
            .all(|report| report.reconciliation == "mismatch"));
        assert!(partial
            .run
            .reports
            .iter()
            .all(|report| report.balance_delta_ndollars == Some(1)));
        assert_eq!(partial.run.summary.reconciliation, "mismatch");
    }

    #[tokio::test]
    async fn first_success_second_failure_returns_first_reconciliation_evidence() {
        let server = MockServer::start().await;
        mount_live_offers(&server, true).await;
        mount_native_response(&server, GEMINI_IMAGE_MODELS[0], "first-request", 123).await;
        mount_native_failure(&server, GEMINI_IMAGE_MODELS[1]).await;
        mount_credit_sequence(&server, 10_000, 9_877).await;

        let error = run_image_canary_with_client(&client(), &server.uri(), "buyer-secret")
            .await
            .expect_err("a later SKU failure must make the run non-zero");
        assert!(error.to_string().contains("partial failure"));
        let partial = error
            .downcast_ref::<PartialCanaryFailure>()
            .expect("partial result retains successful evidence");
        assert_eq!(partial.run.reports.len(), 2);
        let report = &partial.run.reports[0];
        assert_eq!(report.model, GEMINI_IMAGE_MODELS[0]);
        assert_eq!(report.request_id.as_deref(), Some("first-request"));
        assert_eq!(report.settled_ndollars, Some(123));
        assert_eq!(report.balance_before_ndollars, Some(10_000));
        assert_eq!(report.balance_after_ndollars, Some(9_877));
        assert_eq!(report.balance_delta_ndollars, Some(123));
        assert_eq!(report.reconciliation, "ok");
        let failed = &partial.run.reports[1];
        assert_eq!(failed.outcome, "failed");
        assert_eq!(failed.billing_status, BillingStatus::Unbilled);
        assert_eq!(partial.run.summary.known_settled_ndollars, Some(123));
        assert_eq!(partial.run.summary.failed_probes, 1);
        let safe = serde_json::to_string(report).expect("safe partial report");
        assert!(!safe.contains("provider-secret"));
        assert!(!safe.contains(TEST_IMAGE_BASE64));
    }

    #[tokio::test]
    async fn first_failure_second_success_returns_second_reconciliation_evidence() {
        let server = MockServer::start().await;
        mount_live_offers(&server, true).await;
        mount_native_failure(&server, GEMINI_IMAGE_MODELS[0]).await;
        mount_native_response(&server, GEMINI_IMAGE_MODELS[1], "second-request", 456).await;
        mount_credit_sequence(&server, 10_000, 9_544).await;

        let error = run_image_canary_with_client(&client(), &server.uri(), "buyer-secret")
            .await
            .expect_err("an earlier SKU failure must make the run non-zero");
        assert!(error.to_string().contains("partial failure"));
        let partial = error
            .downcast_ref::<PartialCanaryFailure>()
            .expect("partial result retains successful evidence");
        assert_eq!(partial.run.reports.len(), 2);
        let report = &partial.run.reports[1];
        assert_eq!(report.model, GEMINI_IMAGE_MODELS[1]);
        assert_eq!(report.request_id.as_deref(), Some("second-request"));
        assert_eq!(report.settled_ndollars, Some(456));
        assert_eq!(report.balance_delta_ndollars, Some(456));
        assert_eq!(report.reconciliation, "ok");
    }

    #[tokio::test]
    async fn failed_charged_probe_retains_billing_and_zero_success_run_summary() {
        let server = MockServer::start().await;
        mount_live_offers(&server, true).await;
        mount_billed_native_failure(
            &server,
            GEMINI_IMAGE_MODELS[0],
            "charged-failure-request",
            321,
        )
        .await;
        mount_native_failure(&server, GEMINI_IMAGE_MODELS[1]).await;
        mount_credit_sequence(&server, 10_000, 9_679).await;

        let error = run_image_canary_with_client(&client(), &server.uri(), "buyer-secret")
            .await
            .expect_err("failed probes keep a non-zero command result");
        let partial = error
            .downcast_ref::<PartialCanaryFailure>()
            .expect("failed probes retain reconciliation evidence");
        assert_eq!(partial.run.reports.len(), 2);
        let charged = &partial.run.reports[0];
        assert_eq!(charged.outcome, "failed");
        assert_eq!(charged.http_status, Some(422));
        assert_eq!(
            charged.request_id.as_deref(),
            Some("charged-failure-request")
        );
        assert_eq!(charged.billing_status, BillingStatus::Settled);
        assert_eq!(charged.settled_ndollars, Some(321));
        assert_eq!(partial.run.summary.successful_probes, 0);
        assert_eq!(partial.run.summary.failed_probes, 2);
        assert_eq!(partial.run.summary.known_settled_ndollars, Some(321));
        assert_eq!(partial.run.summary.unknown_billing_probes, 0);
        assert_eq!(partial.run.summary.balance_delta_ndollars, Some(321));
        assert_eq!(partial.run.summary.reconciliation, "ok");

        let summary = serde_json::to_string(&partial.run.summary).expect("safe summary");
        assert!(summary.contains("\"record\":\"summary\""));
        assert!(summary.contains("\"known_settled_ndollars\":321"));
        assert!(!summary.contains("content rejected"));
        assert!(!summary.contains("buyer-secret"));
    }

    #[tokio::test]
    async fn first_success_second_text_only_200_preserves_first_evidence() {
        let server = MockServer::start().await;
        mount_live_offers(&server, true).await;
        mount_native_response(&server, GEMINI_IMAGE_MODELS[0], "first-request", 123).await;
        mount_native_text_response(&server, GEMINI_IMAGE_MODELS[1], "refusal-request", 999).await;
        mount_credit_sequence(&server, 10_000, 8_878).await;

        let error = run_image_canary_with_client(&client(), &server.uri(), "buyer-secret")
            .await
            .expect_err("a text-only 200 must fail the canary");
        assert!(error.to_string().contains("partial failure"));
        let partial = error
            .downcast_ref::<PartialCanaryFailure>()
            .expect("partial result retains successful evidence");
        assert_eq!(partial.run.reports.len(), 2);
        assert_eq!(partial.run.reports[0].model, GEMINI_IMAGE_MODELS[0]);
        assert_eq!(
            partial.run.reports[0].request_id.as_deref(),
            Some("first-request")
        );
        assert_eq!(partial.run.reports[0].settled_ndollars, Some(123));
        assert_eq!(partial.run.reports[1].outcome, "failed");
        assert_eq!(partial.run.reports[1].settled_ndollars, Some(999));
        assert_eq!(partial.run.summary.reconciliation, "ok");
    }

    #[tokio::test]
    async fn first_text_only_200_second_success_preserves_second_evidence() {
        let server = MockServer::start().await;
        mount_live_offers(&server, true).await;
        mount_native_text_response(&server, GEMINI_IMAGE_MODELS[0], "refusal-request", 999).await;
        mount_native_response(&server, GEMINI_IMAGE_MODELS[1], "second-request", 456).await;
        mount_credit_sequence(&server, 10_000, 8_545).await;

        let error = run_image_canary_with_client(&client(), &server.uri(), "buyer-secret")
            .await
            .expect_err("a text-only 200 must fail the canary");
        assert!(error.to_string().contains("partial failure"));
        let partial = error
            .downcast_ref::<PartialCanaryFailure>()
            .expect("partial result retains successful evidence");
        assert_eq!(partial.run.reports.len(), 2);
        assert_eq!(partial.run.reports[1].model, GEMINI_IMAGE_MODELS[1]);
        assert_eq!(
            partial.run.reports[1].request_id.as_deref(),
            Some("second-request")
        );
        assert_eq!(partial.run.reports[1].settled_ndollars, Some(456));
        assert_eq!(partial.run.reports[0].outcome, "failed");
        assert_eq!(partial.run.reports[0].settled_ndollars, Some(999));
        assert_eq!(partial.run.summary.reconciliation, "ok");
    }

    #[tokio::test]
    async fn declared_oversized_native_response_is_rejected_before_body_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_NATIVE_IMAGE_RESPONSE_BYTES + 1
            );
            let _ = socket.write_all(headers.as_bytes()).await;
        });

        let response = client()
            .get(format!("http://{address}"))
            .send()
            .await
            .expect("oversized response headers");
        let error = read_bounded_native_response(response, GEMINI_IMAGE_MODELS[0])
            .await
            .expect_err("declared oversized response");
        assert!(error.to_string().contains("safety limit"), "{error:?}");
        server.await.expect("server");
    }

    #[tokio::test]
    async fn chunked_oversized_native_response_is_rejected_while_streaming() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            let _ = socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await;
            let test_limit = 1024;
            let first_chunk = vec![b'x'; test_limit];
            let chunk_header = format!("{:X}\r\n", first_chunk.len());
            let _ = socket.write_all(chunk_header.as_bytes()).await;
            let _ = socket.write_all(&first_chunk).await;
            let _ = socket.write_all(b"\r\n1\r\nx\r\n0\r\n\r\n").await;
        });

        let response = client()
            .get(format!("http://{address}"))
            .send()
            .await
            .expect("chunked response headers");
        let mut response = response;
        let error = read_bounded_response(&mut response, GEMINI_IMAGE_MODELS[0], 1024)
            .await
            .expect_err("chunked oversized response");
        assert!(error.to_string().contains("safety limit"), "{error:?}");
        server.await.expect("server");
    }

    #[test]
    fn native_response_parser_keeps_only_safe_reconciliation_fields() {
        let value = native_response("gemini-3.1-flash-image", "request-1", 321);
        let usage = parse_usage_dimensions(&value).expect("usage");
        assert_eq!(usage.input_tokens, 40);
        assert_eq!(usage.output_tokens, 80);
        assert_eq!(usage.image_input_tokens, 60);
        assert_eq!(usage.image_output_tokens, 1_600);
        assert_eq!(usage.reasoning_tokens, 20);
        assert_eq!(usage.tool_use_prompt_tokens, 13);
        assert_eq!(usage.total_tokens, 1_813);
        assert_eq!(parse_settled_ndollars(&value), Some(321));
        let report = ImageCanaryReport {
            record: "probe",
            model: "gemini-3.1-flash-image".to_owned(),
            request_id: Some("request-1".to_owned()),
            outcome: "succeeded",
            billing_status: BillingStatus::Settled,
            http_status: Some(200),
            usage: Some(usage),
            settled_ndollars: Some(321),
            failure: None,
            balance_before_ndollars: Some(1_000),
            balance_after_ndollars: Some(679),
            balance_delta_ndollars: Some(321),
            reconciliation: "ok",
        };
        let output = serde_json::to_string(&report).expect("safe report");
        assert!(output.contains("request-1"));
        assert!(output.contains("image_input_tokens"));
        assert!(output.contains("321"));
        assert!(!output.contains(TEST_IMAGE_BASE64));
        assert!(!output.contains(CANARY_PROMPT));
        assert!(!output.contains("buyer-secret"));
    }

    #[test]
    fn testnet_gate_refuses_mainnet_before_building_a_client() {
        let error = ensure_testnet(Network::Mainnet).expect_err("mainnet is forbidden");
        assert!(error.to_string().contains("testnet-only"));
    }

    #[test]
    fn canonical_gemini_usage_separates_visible_output_from_thoughts() {
        let value = json!({
            "usageMetadata": {
                "promptTokenCount": 19,
                "candidatesTokenCount": 7,
                "toolUsePromptTokenCount": 11,
                "thoughtsTokenCount": 41
            }
        });
        let usage = parse_usage_dimensions(&value).expect("canonical usage");
        assert_eq!(usage.input_tokens, 19);
        assert_eq!(usage.output_tokens, 7);
        assert_eq!(usage.tool_use_prompt_tokens, 11);
        assert_eq!(usage.reasoning_tokens, 41);
        assert_eq!(usage.total_tokens, 78);
        assert!(usage.reasoning_tokens > usage.output_tokens);
    }

    #[test]
    fn image_validation_requires_non_empty_supported_inline_data() {
        let mut value = native_response("gemini-3.1-flash-image", "request-1", 321);
        let usage = parse_usage_dimensions(&value).expect("usage");
        validate_image_probe_response(&value, "gemini-3.1-flash-image", &usage)
            .expect("image response");

        value["candidates"][0]["content"]["parts"][0]["inlineData"]["data"] = json!("not-base64!");
        let error = validate_image_probe_response(&value, "gemini-3.1-flash-image", &usage)
            .expect_err("invalid base64 image data");
        assert!(
            error.to_string().contains("supported non-empty image"),
            "{error:?}"
        );

        value["candidates"][0]["content"]["parts"][0]["inlineData"]["data"] = json!("aGVsbG8=");
        let error = validate_image_probe_response(&value, "gemini-3.1-flash-image", &usage)
            .expect_err("signature-mismatched image data");
        assert!(
            error.to_string().contains("supported non-empty image"),
            "{error:?}"
        );

        value["candidates"][0]["content"]["parts"][0]["inlineData"]["data"] = json!("   ");
        let error = validate_image_probe_response(&value, "gemini-3.1-flash-image", &usage)
            .expect_err("empty image data");
        assert!(error.to_string().contains("non-empty image"), "{error:?}");

        value["candidates"][0]["content"]["parts"][0]["inlineData"]["data"] =
            json!(TEST_IMAGE_BASE64);
        value["candidates"][0]["content"]["parts"][0]["inlineData"]["mimeType"] =
            json!("text/plain");
        let error = validate_image_probe_response(&value, "gemini-3.1-flash-image", &usage)
            .expect_err("non-image inline data");
        assert!(
            error.to_string().contains("supported non-empty image"),
            "{error:?}"
        );
    }

    #[test]
    fn image_validation_requires_positive_image_output_usage() {
        let mut value = native_response("gemini-3.1-flash-image", "request-1", 321);
        value["usageMetadata"]["candidatesTokensDetails"] =
            json!([{"modality": "TEXT", "tokenCount": 1_680}]);
        let usage = parse_usage_dimensions(&value).expect("usage");
        let error = validate_image_probe_response(&value, "gemini-3.1-flash-image", &usage)
            .expect_err("missing image output usage");
        assert!(
            error.to_string().contains("positive image output usage"),
            "{error:?}"
        );
    }

    #[test]
    fn supported_image_signatures_match_the_dashboard_mime_set() {
        let fixtures = [
            (SupportedImageFormat::Png, TEST_IMAGE_BASE64),
            (SupportedImageFormat::Jpeg, "/9j/4A=="),
            (SupportedImageFormat::Webp, "UklGRgAAAABXRUJQ"),
            (SupportedImageFormat::Avif, "AAAAAGZ0eXBhdmlmAAAAAA=="),
            (SupportedImageFormat::Gif, "R0lGODlh"),
        ];
        for (format, encoded) in fixtures {
            let bytes = BASE64_STANDARD.decode(encoded).expect("fixture base64");
            assert!(
                has_image_signature(format, &bytes),
                "signature should match fixture {encoded}"
            );
        }
    }
}
