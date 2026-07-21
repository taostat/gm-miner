//! `gmcli check-streaming` — detect buffered upstream streaming.

use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use gm_miner_cli::{
    client::{build_http_client, RegistryClient, ME_PATH},
    config::{Config, ProviderKeys, WorkerRecord},
    types::{MinerStatus, ProductCatalogResponse, Provider, WorkerListResponse},
};
use reqwest::Url;
use serde_json::Value;

use crate::commands::deploy::fetch_hotkey;

const MIN_CONTENT_CHUNKS: usize = 4;
const DISTINCT_BUCKET: Duration = Duration::from_millis(150);
const MIN_STREAMING_SPAN: Duration = Duration::from_millis(750);
const MIN_STREAMING_RATIO: f64 = 0.35;
const BUFFERED_BURST_SPAN: Duration = Duration::from_millis(250);
const BUFFERED_FIRST_WAIT: Duration = Duration::from_secs(1);
const BUFFERED_RATIO: f64 = 0.20;
const MAX_TOKENS: u32 = 32;

const BUFFERED_GUIDANCE: &str = "Your {provider} upstream returned a buffered response: \
the whole completion arrived in one burst instead of token-by-token. Buyers see slow \
first-token and this worker is less likely to be routed to. Check the upstream account \
and any proxy in front of it for response buffering.";

// Azure-only addendum: Azure OpenAI's default content filter buffers streamed
// completions; the fix is its opt-in Asynchronous Filter (delayed moderation).
const AZURE_GUIDANCE: &str = "If this deployment runs on Azure OpenAI, the usual cause \
is the default synchronous content filter. Fix: enable the 'Asynchronous Filter' \
streaming option in a content-filter (guardrails) configuration in the Azure portal \
and apply it to your deployments (requires API version 2024-02-01 or later). \
Trade-off: content moderation runs after tokens are streamed, so it is delayed.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamingVerdict {
    Streaming,
    Buffered,
    Inconclusive,
}

struct StreamingTarget {
    endpoint: String,
    node_secret: String,
}

struct ProviderProbe {
    provider: Provider,
    /// Canonical gm model id, shown in output. The request body carries the
    /// upstream deployment id when the offer declared one (see [`ProbeModel`]).
    model: String,
    path: &'static str,
    body: Value,
}

/// The two model ids a probe needs: the canonical gm id for display and the
/// upstream deployment/model id to actually send.
///
/// Azure/Bedrock offers map a canonical model to a distinct upstream
/// deployment name; the gateway rewrites the request `model` to that upstream
/// id before forwarding to the miner CVM. This self-test bypasses the gateway,
/// so it performs the same rewrite — otherwise the probe 404s on exactly the
/// cloud setups the streaming check exists to warn about.
struct ProbeModel {
    canonical: String,
    upstream: Option<String>,
}

impl ProbeModel {
    /// The id to place in the request body: the declared upstream deployment
    /// when present, else the canonical gm model id.
    fn wire_model(&self) -> &str {
        self.upstream.as_deref().unwrap_or(&self.canonical)
    }
}

struct ProbeTiming {
    first: Duration,
    last: Duration,
    span: Duration,
    chunks: usize,
}

/// Runs the standalone streaming self-test against the miner's primary worker.
///
/// Discovers the worker endpoint from the registry and the matching node secret
/// from local gmcli config, then sends one streaming probe per configured
/// provider. Per-provider failures are reported inline and do not panic.
pub(crate) async fn cmd_check_streaming(cfg: Config) -> Result<()> {
    let target = resolve_primary_worker(&cfg).await?;
    run_streaming_checks(&cfg, &target).await;
    Ok(())
}

/// Runs the post-deploy streaming self-test as a best-effort advisory.
///
/// Deploy already has the fresh endpoint and node secret in hand, so this path
/// avoids an extra registry lookup. Any error is printed as guidance and never
/// fails the deploy that just succeeded.
pub(crate) async fn deploy_streaming_advisory(cfg: &Config, endpoint: &str, node_secret: &str) {
    println!("\nStreaming self-test (advisory) ...");
    let target = StreamingTarget {
        endpoint: endpoint.to_owned(),
        node_secret: node_secret.to_owned(),
    };
    run_streaming_checks(cfg, &target).await;
}

async fn run_streaming_checks(cfg: &Config, target: &StreamingTarget) {
    let providers = match configured_providers(cfg.provider_keys.as_ref()) {
        Ok(providers) if !providers.is_empty() => providers,
        Ok(_) => {
            println!("  [--] no configured providers to check; run `gmcli set-api-keys` first");
            return;
        }
        Err(err) => {
            println!("  [!!] provider config invalid: {err}");
            return;
        }
    };

    let model_catalog = fetch_probe_models(cfg, &providers).await;
    for provider in providers {
        let model = model_catalog.model_for(&provider);
        let probe = build_probe(provider, &model);
        let result = run_provider_probe(target, &probe).await;
        print_probe_result(&probe, result);
    }
}

async fn resolve_primary_worker(cfg: &Config) -> Result<StreamingTarget> {
    let local = cfg
        .active_network_entry()
        .and_then(|entry| entry.workers.first())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no deployed worker is tracked for {}; run `gmcli deploy` first",
                cfg.resolved_network()
            )
        })?;
    validate_local_worker(local)?;

    let mut client = RegistryClient::new(cfg.clone());
    let hotkey = fetch_hotkey(&mut client).await?;
    let path = format!("/miners/{hotkey}/workers");
    let resp = client
        .get(&path)
        .await
        .with_context(|| format!("GET {path}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("could not fetch worker endpoint from registry ({status}): {body}");
    }
    let workers: WorkerListResponse = resp.json().await.context("parse worker list response")?;
    let endpoint = workers
        .workers
        .iter()
        .find(|worker| worker.worker_id == local.worker_id)
        .map(|worker| worker.endpoint.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "registry has no worker endpoint for local worker {}; run \
                 `gmcli worker list` and redeploy if the local record is stale",
                local.worker_id
            )
        })?;

    Ok(StreamingTarget {
        endpoint,
        node_secret: local.node_secret.clone(),
    })
}

fn validate_local_worker(worker: &WorkerRecord) -> Result<()> {
    if worker.worker_id.trim().is_empty() {
        bail!(
            "the tracked worker '{}' is not registered yet; rerun `gmcli deploy`",
            worker.app_name
        );
    }
    if worker.node_secret.trim().is_empty() {
        bail!(
            "the tracked worker '{}' has no node secret; redeploy it with `gmcli deploy`",
            worker.app_name
        );
    }
    Ok(())
}

fn configured_providers(keys: Option<&ProviderKeys>) -> Result<Vec<Provider>> {
    let Some(keys) = keys else {
        return Ok(Vec::new());
    };
    keys.validate_upstreams()?;

    let mut providers = Vec::new();
    let anthropic_upstream = keys.anthropic_upstream.as_deref().unwrap_or("direct");
    if (anthropic_upstream == "direct" && non_empty(keys.anthropic.as_deref()))
        || (anthropic_upstream == "bedrock" && non_empty(keys.bedrock_api_key.as_deref()))
    {
        providers.push(Provider::Anthropic);
    }
    let openai_upstream = keys.openai_upstream.as_deref().unwrap_or("direct");
    if (openai_upstream == "direct" && non_empty(keys.openai.as_deref()))
        || (openai_upstream == "azure" && non_empty(keys.azure_openai_api_key.as_deref()))
    {
        providers.push(Provider::OpenAI);
    }
    if non_empty(keys.google.as_deref()) {
        providers.push(Provider::Gemini);
    }
    if non_empty(keys.chutes.as_deref()) {
        providers.push(Provider::Chutes);
    }
    if non_empty(keys.zai.as_deref()) {
        providers.push(Provider::Zai);
    }
    if non_empty(keys.moonshot.as_deref()) {
        providers.push(Provider::Moonshot);
    }
    if non_empty(keys.deepinfra.as_deref()) {
        providers.push(Provider::DeepInfra);
    }
    Ok(providers)
}

fn non_empty(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

struct ProbeModels {
    models: std::collections::HashMap<Provider, ProbeModel>,
}

impl ProbeModels {
    fn model_for(&self, provider: &Provider) -> ProbeModel {
        match self.models.get(provider) {
            Some(model) => ProbeModel {
                canonical: model.canonical.clone(),
                upstream: model.upstream.clone(),
            },
            None => ProbeModel {
                canonical: fallback_model(provider).to_owned(),
                upstream: None,
            },
        }
    }
}

/// Resolve the probe model per provider: a canonical gm model id from the
/// public catalog, joined with the miner's own declared `upstream_model` (from
/// `/miners/me`) so cloud-backed offers probe their real upstream deployment.
///
/// Both lookups are best-effort — a failed catalog or offer fetch degrades to
/// the canonical [`fallback_model`], and a missing upstream mapping simply
/// sends the canonical id. The check must never fail the deploy it advises on.
async fn fetch_probe_models(cfg: &Config, providers: &[Provider]) -> ProbeModels {
    let canonical = fetch_canonical_models(cfg, providers).await;
    let upstream = fetch_declared_upstreams(cfg).await;

    let mut models = std::collections::HashMap::new();
    for provider in providers {
        let Some(canonical) = canonical.get(provider).cloned() else {
            continue;
        };
        let upstream = upstream
            .get(&(provider.clone(), canonical.clone()))
            .cloned()
            .flatten();
        models.insert(
            provider.clone(),
            ProbeModel {
                canonical,
                upstream,
            },
        );
    }
    ProbeModels { models }
}

/// Public `GET /products` → the active canonical model per provider.
async fn fetch_canonical_models(
    cfg: &Config,
    providers: &[Provider],
) -> std::collections::HashMap<Provider, String> {
    let url = format!("{}/products", cfg.api_url());
    let catalog = match build_http_client() {
        Ok(client) => match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                resp.json::<ProductCatalogResponse>().await.ok()
            }
            _ => None,
        },
        Err(_) => None,
    };

    let mut models = std::collections::HashMap::new();
    if let Some(catalog) = catalog {
        for provider in providers {
            if let Some(product) = catalog
                .products
                .iter()
                .find(|product| &product.provider == provider && product.status == "active")
            {
                models.insert(provider.clone(), product.model.clone());
            }
        }
    }
    models
}

/// Authenticated `GET /miners/me` → the miner's own declared upstream mapping,
/// keyed by `(provider, canonical model)`. Empty when the miner is not logged
/// in or the registry omits the field.
async fn fetch_declared_upstreams(
    cfg: &Config,
) -> std::collections::HashMap<(Provider, String), Option<String>> {
    let mut client = RegistryClient::new(cfg.clone());
    let status = match client.get(ME_PATH).await {
        Ok(resp) if resp.status().is_success() => resp.json::<MinerStatus>().await.ok(),
        _ => None,
    };

    let mut upstreams = std::collections::HashMap::new();
    if let Some(status) = status {
        for offer in status.products {
            let Ok(provider) = offer.provider.parse::<Provider>() else {
                continue;
            };
            upstreams.insert((provider, offer.model), offer.upstream_model);
        }
    }
    upstreams
}

fn fallback_model(provider: &Provider) -> &'static str {
    match provider {
        Provider::Anthropic => "claude-sonnet-4-6",
        Provider::OpenAI => "gpt-5.5",
        Provider::Gemini => "gemini-2.5-pro",
        Provider::Chutes => "deepseek-ai/DeepSeek-V3-0324",
        Provider::Zai => "glm-5.2",
        Provider::Moonshot => "kimi-k3",
        Provider::DeepInfra => "zai-org/GLM-5.2",
        Provider::Benchmark => "benchmark",
    }
}

fn build_probe(provider: Provider, model: &ProbeModel) -> ProviderProbe {
    match provider {
        Provider::Anthropic => ProviderProbe {
            provider,
            model: model.canonical.clone(),
            path: "/v1/messages",
            body: serde_json::json!({
                "model": model.wire_model(),
                "max_tokens": MAX_TOKENS,
                "stream": true,
                "messages": [{"role": "user", "content": probe_prompt()}],
            }),
        },
        Provider::Gemini => {
            openai_compatible_probe(provider, model, "/v1beta/openai/chat/completions")
        }
        Provider::OpenAI
        | Provider::Chutes
        | Provider::Zai
        | Provider::Moonshot
        | Provider::DeepInfra
        | Provider::Benchmark => openai_compatible_probe(provider, model, "/v1/chat/completions"),
    }
}

fn openai_compatible_probe(
    provider: Provider,
    model: &ProbeModel,
    path: &'static str,
) -> ProviderProbe {
    ProviderProbe {
        provider,
        model: model.canonical.clone(),
        path,
        body: serde_json::json!({
            "model": model.wire_model(),
            "max_tokens": MAX_TOKENS,
            "stream": true,
            "messages": [{"role": "user", "content": probe_prompt()}],
        }),
    }
}

fn probe_prompt() -> &'static str {
    "Count from one to eight, one number per line."
}

async fn run_provider_probe(
    target: &StreamingTarget,
    probe: &ProviderProbe,
) -> Result<Vec<Duration>> {
    let url = endpoint_url(&target.endpoint, probe.path)?;
    let client = build_http_client()?;
    let started = Instant::now();
    let mut response = client
        .post(url.clone())
        .header("accept", "text/event-stream")
        .header("content-type", "application/json")
        .header("x-gm-node-key", &target.node_secret)
        .header("x-gm-provider", probe.provider.as_str())
        .json(&probe.body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("upstream returned {status}: {}", trim_body(&body));
    }

    let mut parser = SseParser::default();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("read SSE stream from {url}"))?
    {
        let offset = started.elapsed();
        parser.push_chunk(&chunk, offset);
    }
    Ok(parser.finish())
}

fn endpoint_url(endpoint: &str, path: &str) -> Result<Url> {
    let base = if endpoint.ends_with('/') {
        endpoint.to_owned()
    } else {
        format!("{endpoint}/")
    };
    let path = path.trim_start_matches('/');
    Url::parse(&base)
        .with_context(|| format!("invalid worker endpoint {endpoint:?}"))?
        .join(path)
        .with_context(|| format!("join worker endpoint {endpoint:?} with /{path}"))
}

fn trim_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.len() > 500 {
        let cutoff = trimmed
            .char_indices()
            .map(|(idx, _)| idx)
            .take_while(|idx| *idx <= 500)
            .last()
            .unwrap_or(0);
        format!("{}...", &trimmed[..cutoff])
    } else if trimmed.is_empty() {
        "<empty body>".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[derive(Default)]
struct SseParser {
    pending: String,
    data: String,
    content_offsets: Vec<Duration>,
    last_offset: Duration,
}

impl SseParser {
    fn push_chunk(&mut self, chunk: &[u8], offset: Duration) {
        self.last_offset = offset;
        self.pending.push_str(&String::from_utf8_lossy(chunk));
        while let Some(newline) = self.pending.find('\n') {
            let line = self.pending[..newline].trim_end_matches('\r').to_owned();
            self.pending.drain(..=newline);
            self.push_line(&line, offset);
        }
    }

    fn push_line(&mut self, line: &str, offset: Duration) {
        if line.is_empty() {
            self.finish_event(offset);
            return;
        }
        if let Some(data) = line.strip_prefix("data:") {
            if !self.data.is_empty() {
                self.data.push('\n');
            }
            self.data.push_str(data.trim_start());
        }
    }

    fn finish_event(&mut self, offset: Duration) {
        let data = self.data.trim();
        if !data.is_empty() && data != "[DONE]" && sse_event_has_content(data) {
            self.content_offsets.push(offset);
        }
        self.data.clear();
    }

    fn finish(mut self) -> Vec<Duration> {
        if !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            self.push_line(pending.trim_end_matches('\r'), self.last_offset);
        }
        self.finish_event(self.last_offset);
        self.content_offsets
    }
}

fn sse_event_has_content(data: &str) -> bool {
    serde_json::from_str::<Value>(data).is_ok_and(|value| json_has_generated_text(&value))
}

fn json_has_generated_text(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(json_has_generated_text),
        Value::Object(map) => map.iter().any(|(key, value)| {
            if matches!(key.as_str(), "content" | "text") {
                return value_contains_generated_text(value);
            }
            matches!(
                key.as_str(),
                "choices" | "delta" | "message" | "content_block" | "candidates" | "parts"
            ) && json_has_generated_text(value)
        }),
        _ => false,
    }
}

fn value_contains_generated_text(value: &Value) -> bool {
    match value {
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(values) => values.iter().any(json_has_generated_text),
        Value::Object(_) => json_has_generated_text(value),
        _ => false,
    }
}

/// Classifies content-bearing SSE chunk offsets as streaming or buffered.
///
/// The classifier requires several content chunks before making a positive
/// call. Buffered responses are a tight content burst after a long first wait;
/// streaming responses have content chunks distributed across multiple arrival
/// buckets over a meaningful share of the total response time.
fn classify_streaming(offsets: &[Duration]) -> StreamingVerdict {
    let Some(timing) = probe_timing(offsets) else {
        return StreamingVerdict::Inconclusive;
    };
    let total = timing.last.as_secs_f64().max(0.001);
    let span_ratio = timing.span.as_secs_f64() / total;
    if timing.chunks >= MIN_CONTENT_CHUNKS
        && timing.first >= BUFFERED_FIRST_WAIT
        && timing.span <= BUFFERED_BURST_SPAN
        && span_ratio <= BUFFERED_RATIO
    {
        return StreamingVerdict::Buffered;
    }
    if timing.chunks >= MIN_CONTENT_CHUNKS
        && distinct_arrival_buckets(offsets) >= 3
        && (timing.span >= MIN_STREAMING_SPAN || span_ratio >= MIN_STREAMING_RATIO)
    {
        return StreamingVerdict::Streaming;
    }
    StreamingVerdict::Inconclusive
}

fn probe_timing(offsets: &[Duration]) -> Option<ProbeTiming> {
    if offsets.len() < 2 {
        return None;
    }
    let first = *offsets.first()?;
    let last = *offsets.last()?;
    Some(ProbeTiming {
        first,
        last,
        span: last.saturating_sub(first),
        chunks: offsets.len(),
    })
}

fn distinct_arrival_buckets(offsets: &[Duration]) -> usize {
    let mut buckets = 0_usize;
    let mut last_bucket = None;
    for offset in offsets {
        if last_bucket.is_none_or(|last| offset.saturating_sub(last) >= DISTINCT_BUCKET) {
            buckets += 1;
            last_bucket = Some(*offset);
        }
    }
    buckets
}

fn print_probe_result(probe: &ProviderProbe, result: Result<Vec<Duration>>) {
    let provider = probe.provider.as_str();
    match result {
        Ok(offsets) => match classify_streaming(&offsets) {
            StreamingVerdict::Streaming => {
                println!(
                    "  [ok] {provider}/{}: streaming ({})",
                    probe.model,
                    timing_summary(&offsets)
                );
            }
            StreamingVerdict::Buffered => {
                println!(
                    "  [!!] {provider}/{}: WARNING buffered ({})",
                    probe.model,
                    timing_summary(&offsets)
                );
                println!(
                    "       {}",
                    BUFFERED_GUIDANCE.replace("{provider}", provider)
                );
                if probe.provider == Provider::OpenAI {
                    println!("       {AZURE_GUIDANCE}");
                }
            }
            StreamingVerdict::Inconclusive => {
                println!(
                    "  [--] {provider}/{}: could not classify streaming behavior ({})",
                    probe.model,
                    timing_summary(&offsets)
                );
            }
        },
        Err(err) => {
            println!(
                "  [!!] {provider}/{}: check failed: {err}\n       Confirm the worker is reachable, this provider is configured on the deployed CVM, and the probe model/deployment exists.",
                probe.model
            );
        }
    }
}

fn timing_summary(offsets: &[Duration]) -> String {
    match probe_timing(offsets) {
        Some(timing) => format!(
            "{} content chunks, first at {}, span {}",
            timing.chunks,
            fmt_duration(timing.first),
            fmt_duration(timing.span)
        ),
        None if offsets.is_empty() => "no content chunks observed".to_owned(),
        None => format!("1 content chunk, first at {}", fmt_duration(offsets[0])),
    }
}

fn fmt_duration(duration: Duration) -> String {
    if duration.as_millis() < 1_000 {
        format!("{}ms", duration.as_millis())
    } else {
        format!("{:.2}s", duration.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    #[test]
    fn classify_clearly_buffered_timing_as_buffered() {
        let offsets = [ms(2_400), ms(2_430), ms(2_455), ms(2_480), ms(2_500)];
        assert_eq!(classify_streaming(&offsets), StreamingVerdict::Buffered);
    }

    #[test]
    fn classify_clearly_streaming_timing_as_streaming() {
        let offsets = [ms(250), ms(620), ms(980), ms(1_360), ms(1_720)];
        assert_eq!(classify_streaming(&offsets), StreamingVerdict::Streaming);
    }

    #[test]
    fn probe_sends_declared_upstream_model_when_present() {
        let model = ProbeModel {
            canonical: "claude-sonnet-4-6".to_owned(),
            upstream: Some("us.anthropic.claude-sonnet-4-6-v1".to_owned()),
        };
        let probe = build_probe(Provider::Anthropic, &model);
        assert_eq!(
            probe.body["model"],
            Value::String("us.anthropic.claude-sonnet-4-6-v1".to_owned())
        );
        assert_eq!(probe.model, "claude-sonnet-4-6");
    }

    #[test]
    fn probe_sends_canonical_model_without_upstream_mapping() {
        let model = ProbeModel {
            canonical: "gpt-5.5".to_owned(),
            upstream: None,
        };
        let probe = build_probe(Provider::OpenAI, &model);
        assert_eq!(probe.body["model"], Value::String("gpt-5.5".to_owned()));
        assert_eq!(probe.model, "gpt-5.5");
    }

    #[test]
    fn zai_probe_uses_openai_compatible_route_and_model() {
        let model = ProbeModel {
            canonical: fallback_model(&Provider::Zai).to_owned(),
            upstream: None,
        };
        let probe = build_probe(Provider::Zai, &model);
        assert_eq!(probe.path, "/v1/chat/completions");
        assert_eq!(probe.body["model"], Value::String("glm-5.2".to_owned()));
        assert_eq!(probe.model, "glm-5.2");
    }

    #[test]
    fn deepinfra_probe_uses_openai_compatible_route_and_model() {
        let model = ProbeModel {
            canonical: fallback_model(&Provider::DeepInfra).to_owned(),
            upstream: None,
        };
        let probe = build_probe(Provider::DeepInfra, &model);
        assert_eq!(probe.path, "/v1/chat/completions");
        assert_eq!(
            probe.body["model"],
            Value::String("zai-org/GLM-5.2".to_owned())
        );
        assert_eq!(probe.model, "zai-org/GLM-5.2");
    }

    #[test]
    fn classify_empty_timing_as_inconclusive() {
        assert_eq!(classify_streaming(&[]), StreamingVerdict::Inconclusive);
    }

    #[test]
    fn classify_single_chunk_timing_as_inconclusive() {
        assert_eq!(
            classify_streaming(&[ms(1_500)]),
            StreamingVerdict::Inconclusive
        );
    }
}
