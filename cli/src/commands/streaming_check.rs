//! `gmcli check-streaming` — detect buffered upstream streaming.

use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use gm_miner_cli::{
    client::{build_data_plane_probe_client, build_http_client, RegistryClient, ME_PATH},
    config::{Config, ProviderKeys, WorkerRecord},
    types::{MinerStatus, ProductCatalogResponse, Provider, WorkerEntry, WorkerListResponse},
    workers::first_live_worker_id,
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

#[derive(Debug)]
struct StreamingTarget {
    endpoint: String,
    node_secret: String,
}

struct ProviderProbe {
    provider: Provider,
    /// Canonical gm model id, shown in output. The request body carries the
    /// upstream deployment id when the offer declared one (see [`ProbeModel`]).
    model: String,
    fallback: bool,
    path: &'static str,
    body: Value,
}

impl ProviderProbe {
    fn model_label(&self) -> String {
        if self.fallback {
            format!("{} [fallback]", self.model)
        } else {
            self.model.clone()
        }
    }
}

/// The two model ids a probe needs: the canonical gm id for display and the
/// upstream deployment/model id to actually send.
///
/// Azure/Bedrock offers map a canonical model to a distinct upstream
/// deployment name; the gateway rewrites the request `model` to that upstream
/// id before forwarding to the miner CVM. This self-test bypasses the gateway,
/// so it performs the same rewrite — otherwise the probe 404s on exactly the
/// cloud setups the streaming check exists to warn about.
#[derive(Clone)]
struct ProbeModel {
    canonical: String,
    upstream: Option<String>,
    fallback: bool,
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
/// provider and per offered `KubeTEE`/NEAR sourcing route. Per-route failures are
/// reported inline and do not panic.
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
        Ok(providers) => providers,
        Err(err) => {
            println!("  [!!] provider config invalid: {err}");
            return;
        }
    };

    let declared = fetch_declared_offers(cfg).await;
    if let Some(declared) = declared.as_ref() {
        for provider in offered_providers_missing_local(declared, &providers) {
            println!(
                "  [--] {provider}: registry has offered routes but no local key is configured; supply was not probed"
            );
        }
    }

    if providers.is_empty() {
        println!("  [--] no configured providers to check; run `gmcli set-api-keys` first");
        return;
    }

    if declared.is_none() {
        for provider in [Provider::Kubetee, Provider::Near] {
            if providers.contains(&provider) {
                println!(
                    "  [--] {provider}: could not read declared offers; probing fallback only (offered-route coverage unknown)"
                );
            }
        }
    }

    let empty_declared = std::collections::HashMap::new();
    let model_catalog = fetch_probe_models(
        cfg,
        &providers,
        declared.as_ref().unwrap_or(&empty_declared),
    )
    .await;
    for provider in providers {
        for model in model_catalog.models_for(&provider) {
            let probe = build_probe(provider.clone(), &model);
            let result = run_provider_probe(target, &probe).await;
            print_probe_result(&probe, result);
        }
    }
}

async fn resolve_primary_worker(cfg: &Config) -> Result<StreamingTarget> {
    let local = cfg
        .active_network_entry()
        .map(|entry| entry.workers.as_slice())
        .unwrap_or_default();
    if local.is_empty() {
        bail!(
            "no deployed worker is tracked for {}; run `gmcli deploy` first",
            cfg.resolved_network()
        );
    }

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

    pick_target_worker(local, &workers.workers)
}

/// Pick which worker `check-streaming` probes: the oldest worker the
/// registry still lists as live ([`first_live_worker_id`]), matched to the
/// local record that carries its `node_secret`.
///
/// Local `WorkerRecord`s are never pruned when the registry deregisters a
/// worker (see `workers::is_secondary_live`'s doc comment), so picking
/// whatever sits at local position 0 can target a long-dead CVM while a live
/// one sits further down the list. Resolving the target `worker_id` from the
/// live registry list first — the same pattern `deploy`/`register-image` use
/// via `first_live_worker_id` — avoids that; the local list is consulted only
/// afterward, to find the matching record's `node_secret`.
///
/// # Errors
/// Returns an error when the registry lists no live worker, when the live
/// worker has no matching local record (the node secret is only ever known
/// locally, so there is nothing to probe with), or when that record is
/// otherwise invalid ([`validate_local_worker`]).
fn pick_target_worker(local: &[WorkerRecord], live: &[WorkerEntry]) -> Result<StreamingTarget> {
    let worker_id = first_live_worker_id(live).ok_or_else(|| {
        anyhow::anyhow!("registry lists no live worker; run `gmcli deploy` first")
    })?;
    let endpoint = live
        .iter()
        .find(|worker| worker.worker_id == worker_id)
        .map(|worker| worker.endpoint.clone())
        .ok_or_else(|| anyhow::anyhow!("internal error: live worker {worker_id} vanished"))?;
    let record = local
        .iter()
        .find(|worker| worker.worker_id == worker_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "registry's live worker {worker_id} has no matching local record; run \
                 `gmcli worker list` and redeploy if the local record is stale"
            )
        })?;
    validate_local_worker(record)?;

    Ok(StreamingTarget {
        endpoint,
        node_secret: record.node_secret.clone(),
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
        || (anthropic_upstream == "foundry" && non_empty(keys.azure_foundry_api_key.as_deref()))
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
    if non_empty(keys.kubetee.as_deref()) {
        providers.push(Provider::Kubetee);
    }
    if non_empty(keys.engy.as_deref()) {
        providers.push(Provider::Engy);
    }
    if non_empty(keys.moonmath.as_deref()) {
        providers.push(Provider::Moonmath);
    }
    if non_empty(keys.near.as_deref()) {
        providers.push(Provider::Near);
    }
    Ok(providers)
}

fn non_empty(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

struct ProbeModels {
    /// One or more models to probe per provider. Sourcing providers (`KubeTEE`, NEAR)
    /// may declare several routes (e.g. `z-ai/glm-5.2` and
    /// `deepseek/deepseek-v4-flash-0731`); each gets its own check.
    models: std::collections::HashMap<Provider, Vec<ProbeModel>>,
}

impl ProbeModels {
    fn models_for(&self, provider: &Provider) -> Vec<ProbeModel> {
        match self.models.get(provider) {
            Some(models) if !models.is_empty() => models.clone(),
            _ => vec![ProbeModel {
                canonical: fallback_model(provider).to_owned(),
                upstream: None,
                fallback: true,
            }],
        }
    }
}

/// Resolve the probe model(s) per provider: a canonical gm model id from the
/// public catalog, joined with the miner's own declared `upstream_model` (from
/// `/miners/me`) so cloud-backed offers probe their real upstream deployment.
///
/// `KubeTEE` and NEAR are sourcing providers, so their supply health is every
/// **offered** model from `/miners/me` (e.g. GLM-5.2 and
/// deepseek-v4-flash-0731), independent of buyer-catalog availability. If
/// nothing is declared, [`fallback_model`] is used at print time. The check
/// must never fail the deploy it advises on.
async fn fetch_probe_models(
    cfg: &Config,
    providers: &[Provider],
    declared: &std::collections::HashMap<(Provider, String), DeclaredOffer>,
) -> ProbeModels {
    let canonical = fetch_canonical_models(cfg, providers).await;

    resolve_probe_models(providers, &canonical, declared)
}

fn resolve_probe_models(
    providers: &[Provider],
    canonical: &std::collections::HashMap<Provider, String>,
    declared: &std::collections::HashMap<(Provider, String), DeclaredOffer>,
) -> ProbeModels {
    let mut models = std::collections::HashMap::new();
    for provider in providers {
        // Offered sourcing routes are the supply being checked. Use
        // `/miners/me` as their authority even when `/products` is unavailable
        // or later gains an unrelated KubeTEE buyer-catalog row.
        if matches!(provider, Provider::Kubetee | Provider::Near) {
            let declared_models = declared_models_for_provider(declared, provider);
            if !declared_models.is_empty() {
                models.insert(provider.clone(), declared_models);
            }
            continue;
        }

        if let Some(canonical) = canonical.get(provider).cloned() {
            let upstream = declared
                .get(&(provider.clone(), canonical.clone()))
                .and_then(|offer| offer.upstream_model.clone());
            models.insert(
                provider.clone(),
                vec![ProbeModel {
                    canonical,
                    upstream,
                    fallback: false,
                }],
            );
        }
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
                .find(|product| product.provider == provider.as_str() && product.status == "active")
            {
                models.insert(provider.clone(), product.model.clone());
            }
        }
    }
    models
}

#[derive(Debug, Clone)]
struct DeclaredOffer {
    upstream_model: Option<String>,
    is_offered: bool,
}

/// Authenticated `GET /miners/me` → declared offers keyed by `(provider, model)`.
async fn fetch_declared_offers(
    cfg: &Config,
) -> Option<std::collections::HashMap<(Provider, String), DeclaredOffer>> {
    let mut client = RegistryClient::new(cfg.clone());
    let resp = client.get(ME_PATH).await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let status = resp.json::<MinerStatus>().await.ok()?;

    let mut offers = std::collections::HashMap::new();
    for offer in status.products {
        let Ok(provider) = offer.provider.parse::<Provider>() else {
            continue;
        };
        offers.insert(
            (provider, offer.model),
            DeclaredOffer {
                upstream_model: offer.upstream_model,
                is_offered: offer.is_offered,
            },
        );
    }
    Some(offers)
}

fn offered_providers_missing_local(
    declared: &std::collections::HashMap<(Provider, String), DeclaredOffer>,
    configured: &[Provider],
) -> Vec<Provider> {
    let mut providers: Vec<_> = declared
        .iter()
        .filter(|(_, offer)| offer.is_offered)
        .map(|((provider, _), _)| provider.clone())
        .filter(|provider| !configured.contains(provider))
        .collect();
    providers.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    providers.dedup();
    providers
}

/// Every currently offered model for `provider`, sorted by model id for stable
/// output. Withdrawn rows remain in `/miners/me` for audit, so they must not be
/// probed merely because no live offer remains.
fn declared_models_for_provider(
    declared: &std::collections::HashMap<(Provider, String), DeclaredOffer>,
    provider: &Provider,
) -> Vec<ProbeModel> {
    let mut rows: Vec<_> = declared
        .iter()
        .filter(|((p, _), offer)| p == provider && offer.is_offered)
        .map(|((_, model), offer)| (model.clone(), offer.clone()))
        .collect();
    rows.sort_by(|(a, _), (b, _)| a.cmp(b));
    rows.into_iter()
        .map(|(canonical, offer)| ProbeModel {
            canonical,
            upstream: offer.upstream_model,
            fallback: false,
        })
        .collect()
}

fn fallback_model(provider: &Provider) -> &'static str {
    match provider {
        Provider::Anthropic => "claude-sonnet-4-6",
        Provider::OpenAI => "gpt-5.5",
        Provider::Gemini => "gemini-2.5-pro",
        Provider::Chutes => "deepseek-ai/DeepSeek-V3-0324",
        // Engy and Moonmath serve the same open GLM weights under this model id.
        Provider::Zai | Provider::Engy | Provider::Moonmath => "glm-5.2",
        Provider::Moonshot => "kimi-k3",
        Provider::DeepInfra => "zai-org/GLM-5.2",
        // Last resort only when `/miners/me` has no kubetee offer. Prefer GLM
        // over kimi; flash is probed once declared (see #185 / sources).
        Provider::Kubetee => "z-ai/glm-5.2",
        Provider::Near => "Qwen/Qwen3.6-27B-FP8",
        Provider::Benchmark => "benchmark",
    }
}

fn build_probe(provider: Provider, model: &ProbeModel) -> ProviderProbe {
    match provider {
        Provider::Anthropic => ProviderProbe {
            provider,
            model: model.canonical.clone(),
            fallback: model.fallback,
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
        | Provider::Kubetee
        | Provider::Engy
        | Provider::Moonmath
        | Provider::Near
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
        fallback: model.fallback,
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
    let client = build_data_plane_probe_client()?;
    let started = Instant::now();
    let mut request = client
        .post(url.clone())
        .header("accept", "text/event-stream")
        .header("content-type", "application/json")
        .header("x-gm-node-key", &target.node_secret)
        .header("x-gm-provider", probe.provider.as_str());
    if probe.provider == Provider::Near {
        let selector = probe.body["model"]
            .as_str()
            .context("NEAR probe has no upstream source model")?;
        request = request.header("x-gm-upstream-model", selector);
    }
    let mut response = request
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
    let model = probe.model_label();
    match result {
        Ok(offsets) => match classify_streaming(&offsets) {
            StreamingVerdict::Streaming => {
                println!(
                    "  [ok] {provider}/{model}: streaming ({})",
                    timing_summary(&offsets)
                );
            }
            StreamingVerdict::Buffered => {
                println!(
                    "  [!!] {provider}/{model}: WARNING buffered ({})",
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
                    "  [--] {provider}/{model}: could not classify streaming behavior ({})",
                    timing_summary(&offsets)
                );
            }
        },
        Err(err) => {
            println!(
                "  [!!] {provider}/{model}: check failed: {err}\n       Confirm the worker is reachable, this provider is configured on the deployed CVM, and the probe model/deployment exists."
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
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
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
            fallback: false,
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
            fallback: false,
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
            fallback: true,
        };
        let probe = build_probe(Provider::Zai, &model);
        assert_eq!(probe.path, "/v1/chat/completions");
        assert_eq!(probe.body["model"], Value::String("glm-5.2".to_owned()));
        assert_eq!(probe.model, "glm-5.2");
    }

    #[test]
    fn kubetee_probe_uses_openai_compatible_route_and_model() {
        let model = ProbeModel {
            canonical: fallback_model(&Provider::Kubetee).to_owned(),
            upstream: None,
            fallback: true,
        };
        let probe = build_probe(Provider::Kubetee, &model);
        assert_eq!(probe.path, "/v1/chat/completions");
        assert_eq!(
            probe.body["model"],
            Value::String("z-ai/glm-5.2".to_owned())
        );
        assert_eq!(probe.model, "z-ai/glm-5.2");
    }

    #[test]
    fn declared_models_include_every_offered_kubetee_route() {
        let mut declared = std::collections::HashMap::new();
        declared.insert(
            (Provider::Kubetee, "moonshotai/kimi-k3".to_owned()),
            DeclaredOffer {
                upstream_model: None,
                is_offered: false,
            },
        );
        declared.insert(
            (Provider::Kubetee, "z-ai/glm-5.2".to_owned()),
            DeclaredOffer {
                upstream_model: None,
                is_offered: true,
            },
        );
        declared.insert(
            (
                Provider::Kubetee,
                "deepseek/deepseek-v4-flash-0731".to_owned(),
            ),
            DeclaredOffer {
                upstream_model: None,
                is_offered: true,
            },
        );
        let models = declared_models_for_provider(&declared, &Provider::Kubetee);
        let ids: Vec<_> = models.iter().map(|m| m.canonical.as_str()).collect();
        assert_eq!(ids, vec!["deepseek/deepseek-v4-flash-0731", "z-ai/glm-5.2"]);
    }

    #[test]
    fn withdrawn_kubetee_routes_degrade_to_the_fallback() {
        let mut declared = std::collections::HashMap::new();
        declared.insert(
            (Provider::Kubetee, "moonshotai/kimi-k3".to_owned()),
            DeclaredOffer {
                upstream_model: None,
                is_offered: false,
            },
        );

        let declared_models = declared_models_for_provider(&declared, &Provider::Kubetee);
        assert!(declared_models.is_empty());

        let catalog = ProbeModels {
            models: std::collections::HashMap::new(),
        };
        let models = catalog.models_for(&Provider::Kubetee);
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].canonical, "z-ai/glm-5.2");
        assert!(models[0].fallback);
        let probe = build_probe(Provider::Kubetee, &models[0]);
        assert_eq!(probe.model_label(), "z-ai/glm-5.2 [fallback]");
    }

    #[test]
    fn catalog_outage_still_checks_every_declared_kubetee_route() {
        let mut declared = std::collections::HashMap::new();
        for model in ["deepseek/deepseek-v4-flash-0731", "z-ai/glm-5.2"] {
            declared.insert(
                (Provider::Kubetee, model.to_owned()),
                DeclaredOffer {
                    upstream_model: None,
                    is_offered: true,
                },
            );
        }

        let canonical = std::collections::HashMap::new();
        let catalog = resolve_probe_models(&[Provider::Kubetee], &canonical, &declared);
        let models = catalog.models_for(&Provider::Kubetee);
        let ids: Vec<_> = models
            .iter()
            .map(|model| model.canonical.as_str())
            .collect();
        assert_eq!(ids, vec!["deepseek/deepseek-v4-flash-0731", "z-ai/glm-5.2"]);
    }

    #[test]
    fn every_offered_near_route_uses_its_hidden_source_model() {
        let declared = std::collections::HashMap::from([
            (
                (Provider::Near, "glm-5.1".to_owned()),
                DeclaredOffer {
                    upstream_model: Some("zai-org/GLM-5.1-FP8".to_owned()),
                    is_offered: true,
                },
            ),
            (
                (Provider::Near, "qwen3.6-27b".to_owned()),
                DeclaredOffer {
                    upstream_model: Some("Qwen/Qwen3.6-27B-FP8".to_owned()),
                    is_offered: true,
                },
            ),
        ]);
        let catalog = resolve_probe_models(
            &[Provider::Near],
            &std::collections::HashMap::new(),
            &declared,
        );
        let models = catalog.models_for(&Provider::Near);
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].canonical, "glm-5.1");
        assert_eq!(models[0].wire_model(), "zai-org/GLM-5.1-FP8");
        assert_eq!(models[1].canonical, "qwen3.6-27b");
        assert_eq!(models[1].wire_model(), "Qwen/Qwen3.6-27B-FP8");
    }

    #[test]
    fn catalog_outage_does_not_fan_out_non_kubetee_routes() {
        let mut declared = std::collections::HashMap::new();
        for model in ["o5", "o5-mini"] {
            declared.insert(
                (Provider::OpenAI, model.to_owned()),
                DeclaredOffer {
                    upstream_model: None,
                    is_offered: true,
                },
            );
        }
        let canonical = std::collections::HashMap::new();
        let catalog = resolve_probe_models(&[Provider::OpenAI], &canonical, &declared);
        let models = catalog.models_for(&Provider::OpenAI);
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].canonical, "gpt-5.5");
        assert!(models[0].fallback);
    }

    #[test]
    fn offered_provider_without_a_local_key_is_reported_once() {
        let mut declared = std::collections::HashMap::new();
        for model in ["deepseek/deepseek-v4-flash-0731", "z-ai/glm-5.2"] {
            declared.insert(
                (Provider::Kubetee, model.to_owned()),
                DeclaredOffer {
                    upstream_model: None,
                    is_offered: true,
                },
            );
        }
        declared.insert(
            (Provider::OpenAI, "gpt-5.5".to_owned()),
            DeclaredOffer {
                upstream_model: None,
                is_offered: true,
            },
        );
        declared.insert(
            (Provider::Moonshot, "moonshotai/kimi-k3".to_owned()),
            DeclaredOffer {
                upstream_model: None,
                is_offered: false,
            },
        );

        let missing = offered_providers_missing_local(&declared, &[Provider::OpenAI]);
        assert_eq!(missing, vec![Provider::Kubetee]);
    }

    #[test]
    fn foundry_anthropic_is_a_configured_provider() {
        let keys = ProviderKeys {
            anthropic_upstream: Some("foundry".to_owned()),
            azure_foundry_endpoint: Some("https://example.services.ai.azure.com".to_owned()),
            azure_foundry_api_key: Some("foundry-key".to_owned()),
            azure_foundry_tenant_id: Some("tenant".to_owned()),
            azure_foundry_subscription_id: Some("subscription".to_owned()),
            azure_foundry_resource_group: Some("resource-group".to_owned()),
            azure_foundry_client_id: Some("client".to_owned()),
            azure_foundry_client_secret: Some("client-secret".to_owned()),
            ..ProviderKeys::default()
        };

        assert_eq!(
            configured_providers(Some(&keys)).expect("valid Foundry configuration"),
            [Provider::Anthropic]
        );
    }

    #[test]
    fn kubetee_supply_routes_win_over_a_catalog_row() {
        let mut declared = std::collections::HashMap::new();
        for model in ["deepseek/deepseek-v4-flash-0731", "z-ai/glm-5.2"] {
            declared.insert(
                (Provider::Kubetee, model.to_owned()),
                DeclaredOffer {
                    upstream_model: None,
                    is_offered: true,
                },
            );
        }
        let canonical =
            std::collections::HashMap::from([(Provider::Kubetee, "z-ai/glm-5.2".to_owned())]);

        let catalog = resolve_probe_models(&[Provider::Kubetee], &canonical, &declared);
        let models = catalog.models_for(&Provider::Kubetee);
        let ids: Vec<_> = models
            .iter()
            .map(|model| model.canonical.as_str())
            .collect();
        assert_eq!(ids, vec!["deepseek/deepseek-v4-flash-0731", "z-ai/glm-5.2"]);
    }

    #[test]
    fn deepinfra_probe_uses_openai_compatible_route_and_model() {
        let model = ProbeModel {
            canonical: fallback_model(&Provider::DeepInfra).to_owned(),
            upstream: None,
            fallback: true,
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
    fn moonmath_probe_uses_openai_compatible_route_and_model() {
        let model = ProbeModel {
            canonical: fallback_model(&Provider::Moonmath).to_owned(),
            upstream: None,
            fallback: true,
        };
        let probe = build_probe(Provider::Moonmath, &model);
        assert_eq!(probe.path, "/v1/chat/completions");
        assert_eq!(probe.body["model"], Value::String("glm-5.2".to_owned()));
        assert_eq!(probe.model, "glm-5.2");
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

    fn live_worker(worker_id: &str, created_at: &str) -> WorkerEntry {
        serde_json::from_value(serde_json::json!({
            "worker_id": worker_id,
            "endpoint": format!("https://{worker_id}.example.org"),
            "status": "active",
            "last_attestation_at": null,
            "created_at": created_at,
        }))
        .expect("decode live worker entry")
    }

    fn local_record(worker_id: &str) -> WorkerRecord {
        WorkerRecord {
            worker_id: worker_id.to_owned(),
            app_id: format!("app_{worker_id}"),
            app_name: format!("gm-miner-{worker_id}"),
            node_secret: format!("secret-{worker_id}"),
            ..Default::default()
        }
    }

    /// Regression: local position 0 was a worker deregistered from the
    /// registry weeks ago, while the actual live worker sat at local
    /// position 2. `check-streaming` must probe the live one, not whatever
    /// sits first in the never-pruned local list.
    #[test]
    fn pick_target_worker_skips_a_dead_local_position_zero() {
        let local = vec![
            local_record("01J0A"), // deregistered, stale local position 0
            local_record("01J0B"), // deregistered
            local_record("01J0Z"), // the live worker, local position 2
        ];
        let live = vec![live_worker("01J0Z", "2026-07-03T00:00:00Z")];

        let target = pick_target_worker(&local, &live).expect("resolves the live worker");
        assert_eq!(target.endpoint, "https://01J0Z.example.org");
        assert_eq!(target.node_secret, "secret-01J0Z");
    }

    /// Ties broken the same way `first_live_worker_id` breaks them: the
    /// oldest `created_at`, regardless of local record order.
    #[test]
    fn pick_target_worker_picks_the_oldest_live_worker() {
        let local = vec![local_record("01J0B"), local_record("01J0A")];
        let live = vec![
            live_worker("01J0B", "2026-07-02T00:00:00Z"),
            live_worker("01J0A", "2026-07-01T00:00:00Z"),
        ];

        let target = pick_target_worker(&local, &live).expect("resolves the oldest live worker");
        assert_eq!(target.node_secret, "secret-01J0A");
    }

    #[test]
    fn pick_target_worker_errors_when_registry_has_no_live_worker() {
        let local = vec![local_record("01J0A")];
        let err = pick_target_worker(&local, &[]).expect_err("no live worker to pick");
        assert!(err.to_string().contains("no live worker"));
    }

    #[test]
    fn pick_target_worker_errors_when_live_worker_has_no_local_record() {
        let local = vec![local_record("01J0A")];
        let live = vec![live_worker("01J0Z", "2026-07-03T00:00:00Z")];
        let err = pick_target_worker(&local, &live).expect_err("no matching local record");
        assert!(err.to_string().contains("no matching local record"));
    }
}
