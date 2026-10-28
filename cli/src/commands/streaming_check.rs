//! `gmcli check-streaming` — detect buffered upstream streaming.

use std::{
    collections::{BTreeSet, HashMap},
    time::{Duration, Instant},
};

use anyhow::{bail, Context as _, Result};
use gm_miner_cli::{
    bedrock_bindings::{
        fetch_bedrock_model_bindings, BedrockModelBinding, MODEL_BINDING_REVISION_HEADER,
    },
    client::{
        build_data_plane_probe_client, build_http_client, RegistryClient, ME_PATH,
        VIDEO_JOBS_HEADER,
    },
    config::{Config, ProviderKeys, WorkerRecord},
    deploy::{fetch_supported_versions, normalize_hash, ImageVersion},
    slots::parse_key_slots,
    types::{
        MinerStatus, Product, ProductCatalogResponse, Provider, SourceProduct, WorkerEntry,
        WorkerListResponse,
    },
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
const EXECUTION_POLICY_HEADER: &str = "x-gm-execution-policy";
const EXACT_CANONICAL_NO_REPLAY_POLICY: &str = "exact-canonical-no-replay-v1";
const BEDROCK_PROVIDER: &str = "anthropic";

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

#[derive(Debug, Clone)]
struct StreamingTarget {
    endpoint: String,
    node_secret: String,
    /// Exact provider/model coverage reported for the selected worker.
    /// `None` is reserved for the immediate post-deploy advisory, where the
    /// just-used configuration is authoritative. `Some(empty)` means registry
    /// ownership is unknown and must be reported as inconclusive, not guessed.
    provider_models: Option<HashMap<Provider, ProviderModelCoverage>>,
    /// Provider -> transport backend for this selected worker. A direct
    /// worker must probe the canonical gm model even when another worker's
    /// miner-scoped offer carries a cloud upstream id. Cloud bindings are
    /// resolved against this map, never against the offer alone.
    worker_backends: HashMap<Provider, String>,
    /// True only when the selected worker's measured compose hash maps to a
    /// currently supported image carrying the execution-policy runtime stamp.
    /// The immediate post-deploy advisory receives the already hash-verified
    /// approval directly.
    bedrock_policy_image_capable: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ProviderModelCoverage {
    unscoped: BTreeSet<String>,
    by_slot: HashMap<String, BTreeSet<String>>,
}

struct ProviderProbe {
    provider: Provider,
    /// Canonical gm model id, shown in output. The request body carries the
    /// upstream deployment id when the offer declared one (see [`ProbeModel`]).
    model: String,
    slot: Option<String>,
    fallback: bool,
    /// Versioned runtime policy. Set only after the selected worker's image,
    /// exact model, backend, and authorized key slot are proven.
    execution_policy: Option<&'static str>,
    model_binding_revision: Option<u64>,
    path: &'static str,
    body: Value,
}

impl ProviderProbe {
    fn model_label(&self) -> String {
        let model = if self.fallback {
            format!("{} [fallback]", self.model)
        } else {
            self.model.clone()
        };
        if let Some(slot) = &self.slot {
            format!("{model} [slot {slot}]")
        } else {
            model
        }
    }
}

#[derive(Clone)]
struct SelectedProbeModel {
    model: ProbeModel,
    slot: Option<String>,
}

/// The two model ids a probe needs: the canonical gm id for display and the
/// upstream deployment/model id to actually send.
///
/// A selected worker's backend determines whether `upstream` is used. The
/// miner's offer is scoped to the hotkey, not to the worker, so an offer's
/// upstream id is only a candidate binding until it is matched to the selected
/// worker backend.
#[derive(Clone)]
struct ProbeModel {
    canonical: String,
    upstream: Option<String>,
    fallback: bool,
    /// Captured from the fixed registry binding snapshot, never from offers.
    binding_revision: Option<u64>,
}

impl ProbeModel {
    /// The id to place in the request body. `models_for_target` clears or
    /// normalizes `upstream` according to the selected worker backend before a
    /// probe is built.
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

struct ProbeRouteAuthorization {
    slot: Option<String>,
    execution_policy: Option<&'static str>,
    model_binding_revision: Option<u64>,
}

/// Runs the standalone streaming self-test against the miner's primary worker.
///
/// Discovers the worker endpoint from the registry and the matching node secret
/// from local gmcli config, then sends one streaming probe per configured
/// provider and per offered sourcing route. Per-route failures are reported
/// inline and do not panic.
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
pub(crate) async fn deploy_streaming_advisory(
    cfg: &Config,
    endpoint: &str,
    node_secret: &str,
    bedrock_policy_image_capable: bool,
) {
    println!("\nStreaming self-test (advisory) ...");
    let target = StreamingTarget {
        endpoint: endpoint.to_owned(),
        node_secret: node_secret.to_owned(),
        provider_models: None,
        worker_backends: cfg
            .provider_keys
            .as_ref()
            .map(|keys| backends_from_config(&keys.worker_backends()))
            .unwrap_or_default(),
        bedrock_policy_image_capable,
    };
    run_streaming_checks(cfg, &target).await;
}

async fn run_streaming_checks(cfg: &Config, target: &StreamingTarget) {
    let configured = if target.provider_models.is_none() {
        match configured_providers(cfg.provider_keys.as_ref()) {
            Ok(providers) => providers,
            Err(err) => {
                println!("  [!!] provider config invalid: {err}");
                return;
            }
        }
    } else {
        Vec::new()
    };
    let providers = providers_for_target(&configured, target);

    let declared = fetch_declared_offers(cfg).await;
    warn_missing_provider_keys(target, &configured, declared.as_ref());
    if providers.is_empty() {
        report_empty_provider_coverage(target, &configured);
        return;
    }
    if declared.is_none() {
        warn_unreadable_declarations(&providers);
    }

    let empty_declared = std::collections::HashMap::new();
    let catalog = fetch_catalog(cfg).await;
    let canonical = canonical_models(&catalog, &providers);
    let routes = fetch_routes(cfg).await;
    let excluded = non_chat_probe_exclusions(&catalog, &routes);
    let mut model_catalog = resolve_probe_models(
        &providers,
        &canonical,
        declared.as_ref().unwrap_or(&empty_declared),
    );
    if target
        .worker_backends
        .get(&Provider::Anthropic)
        .map(String::as_str)
        == Some("bedrock")
    {
        if let Ok(bindings) = fetch_bedrock_model_bindings(cfg.resolved_network()).await {
            let eligible = canonical
                .get(&Provider::Anthropic)
                .map(Vec::as_slice)
                .unwrap_or_default();
            model_catalog.models.insert(
                Provider::Anthropic,
                bedrock_probe_models(&bindings, eligible),
            );
        } else {
            println!(
                "  [--] anthropic: fixed registry model bindings are unavailable; no Bedrock probe sent"
            );
            model_catalog.models.insert(Provider::Anthropic, Vec::new());
        }
    }
    for provider in providers {
        check_provider_streaming(cfg, target, provider, &model_catalog, &excluded).await;
    }
}

/// Use the registry snapshot as the only Bedrock model selector. Intersect its
/// bindings with active buyer products so diagnostics don't probe withdrawn or
/// unpublished models, and carry the registry row revision into the request.
fn bedrock_probe_models(
    bindings: &[BedrockModelBinding],
    active_products: &[String],
) -> Vec<ProbeModel> {
    let active = active_products
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    bindings
        .iter()
        .filter(|binding| active.contains(binding.model.as_str()))
        .map(|binding| ProbeModel {
            canonical: binding.model.clone(),
            upstream: None,
            fallback: false,
            binding_revision: Some(binding.revision),
        })
        .collect()
}

fn warn_missing_provider_keys(
    target: &StreamingTarget,
    configured: &[Provider],
    declared: Option<&HashMap<(Provider, String), DeclaredOffer>>,
) {
    if target.provider_models.is_some() {
        return;
    }
    if let Some(declared) = declared {
        for provider in offered_providers_missing_local(declared, configured) {
            println!(
                "  [--] {provider}: registry has offered routes but no local key is configured; \
                 supply was not probed"
            );
        }
    }
}

fn report_empty_provider_coverage(target: &StreamingTarget, configured: &[Provider]) {
    if target.provider_models.is_some() {
        println!(
            "  [--] selected worker has no verified provider/model coverage; \
             supply probe is inconclusive"
        );
    } else if configured.is_empty() {
        println!("  [--] no configured providers to check; run `gmcli set-api-keys` first");
    } else {
        println!("  [--] selected worker advertises no locally configured provider slots");
    }
}

fn warn_unreadable_declarations(providers: &[Provider]) {
    for provider in sourcing_providers() {
        if providers.contains(&provider) {
            println!(
                "  [--] {provider}: could not read declared offers; \
                 probing fallback only (offered-route coverage unknown)"
            );
        }
    }
}

async fn check_provider_streaming(
    cfg: &Config,
    target: &StreamingTarget,
    provider: Provider,
    model_catalog: &ProbeModels,
    excluded: &BTreeSet<(String, String)>,
) {
    let Some(models) = models_for_target(target, &provider, model_catalog.models_for(&provider))
    else {
        println!(
            "  [--] {provider}: selected worker's exact model coverage or declared upstream \
             deployment is unknown; supply probe is inconclusive"
        );
        return;
    };
    if models.is_empty() {
        if let Some(backend) = target.worker_backends.get(&provider) {
            println!(
                "  [--] {provider}: selected worker's {backend} model binding is \
                 unavailable/unverified; no streaming probe sent"
            );
        } else {
            println!(
                "  [--] {provider}: no probe model overlaps the selected worker's verified \
                 coverage; supply probe is inconclusive"
            );
        }
        return;
    }
    if provider.as_str() == BEDROCK_PROVIDER
        && target.worker_backends.get(&provider).map(String::as_str) == Some("bedrock")
        && !target.bedrock_policy_image_capable
    {
        println!(
            "  [--] {provider}: selected worker's measured image is not \
             approved for the current execution policy; no policy probe sent"
        );
        return;
    }
    for selected in models {
        if excluded.contains(&(
            provider.as_str().to_owned(),
            selected.model.canonical.clone(),
        )) {
            println!(
                "  [--] {provider}/{}: generation product skipped by streaming self-test",
                selected.model.canonical
            );
            continue;
        }
        let Some(route) = probe_route_authorization(cfg, target, &provider, &selected) else {
            println!(
                "  [--] {provider}/{}: exact Bedrock route slot is not verified or derivable; \
                 no streaming probe sent",
                selected.model.canonical
            );
            continue;
        };
        let mut probe = build_probe(provider.clone(), &selected.model, route.slot);
        probe.execution_policy = route.execution_policy;
        probe.model_binding_revision = route.model_binding_revision;
        let result = run_provider_probe(target, &probe).await;
        print_probe_result(&probe, result);
    }
}

/// Authorize the versioned execution policy only when the current image and
/// this probe have an exact Bedrock backend/model/slot binding. Standalone
/// checks use the selected worker's registry-verified slot ownership; the
/// immediate post-deploy advisory derives the slot from the key and node
/// secret used for that deployment because registry slot status may not have
/// arrived yet.
fn probe_route_authorization(
    cfg: &Config,
    target: &StreamingTarget,
    provider: &Provider,
    selected: &SelectedProbeModel,
) -> Option<ProbeRouteAuthorization> {
    let is_bedrock = provider.as_str() == BEDROCK_PROVIDER
        && target.worker_backends.get(provider).map(String::as_str) == Some("bedrock");
    if !is_bedrock {
        return Some(ProbeRouteAuthorization {
            slot: selected.slot.clone(),
            execution_policy: None,
            model_binding_revision: None,
        });
    }

    if !target.bedrock_policy_image_capable
        || selected.model.fallback
        || selected.model.binding_revision.is_none()
        || selected.model.wire_model() != selected.model.canonical
    {
        return None;
    }

    let slot = if let Some(worker_models) = target.provider_models.as_ref() {
        let slot = selected.slot.as_deref()?;
        let verified_models = worker_models.get(provider)?.by_slot.get(slot)?;
        if !verified_models.contains(&selected.model.canonical) {
            return None;
        }
        slot.to_owned()
    } else {
        let keys = cfg.provider_keys.as_ref()?;
        if keys.anthropic_upstream.as_deref() != Some("bedrock")
            || keys.bedrock_region.as_deref() != Some("us-east-1")
        {
            return None;
        }
        let key = keys.bedrock_api_key.as_deref()?;
        if key.trim().is_empty() {
            return None;
        }
        let mut slots = parse_key_slots("anthropic", key, &target.node_secret).ok()?;
        if slots.len() != 1 {
            return None;
        }
        slots.remove(0).id
    };

    Some(ProbeRouteAuthorization {
        slot: Some(slot),
        execution_policy: Some(EXACT_CANONICAL_NO_REPLAY_POLICY),
        model_binding_revision: selected.model.binding_revision,
    })
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

    let mut target = pick_target_worker(local, &workers.workers)?;
    if target
        .worker_backends
        .get(&Provider::Anthropic)
        .map(String::as_str)
        == Some("bedrock")
    {
        let current_compose_hash = first_live_worker_id(&workers.workers)
            .and_then(|worker_id| {
                workers
                    .workers
                    .iter()
                    .find(|worker| worker.worker_id == worker_id)
            })
            .and_then(|worker| worker.image_compose_hash.as_deref())
            .map(str::to_owned);
        if let Some(compose_hash) = current_compose_hash {
            match fetch_supported_versions(&cfg.api_url()).await {
                Ok(versions) => {
                    target.bedrock_policy_image_capable =
                        image_has_bedrock_policy_feature(Some(&compose_hash), &versions);
                }
                // `fetch_supported_versions` includes response bodies in some
                // errors. Keep registry error details out of CLI diagnostics.
                Err(_) => {
                    tracing::warn!("could not verify the selected Bedrock worker image feature");
                }
            }
        }
    }
    Ok(target)
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
    let worker = live
        .iter()
        .find(|worker| worker.worker_id == worker_id)
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
        endpoint: worker.endpoint.clone(),
        node_secret: record.node_secret.clone(),
        provider_models: Some(worker_provider_models(worker)),
        worker_backends: record
            .backends
            .as_ref()
            .map(backends_from_config)
            .unwrap_or_default(),
        bedrock_policy_image_capable: false,
    })
}

fn image_has_bedrock_policy_feature(
    image_compose_hash: Option<&str>,
    versions: &[ImageVersion],
) -> bool {
    let Some(image_compose_hash) = image_compose_hash else {
        return false;
    };
    let image_compose_hash = normalize_hash(image_compose_hash);
    if !is_sha256_hex(&image_compose_hash) {
        return false;
    }
    let matching = versions
        .iter()
        .filter(|version| normalize_hash(&version.compose_hash) == image_compose_hash)
        .collect::<Vec<_>>();
    !matching.is_empty()
        && matching.iter().all(|version| {
            let version_hash = normalize_hash(&version.compose_hash);
            version.status == "supported"
                && is_sha256_hex(&version_hash)
                && version.bedrock_mantle_model_bindings_capable()
        })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn backends_from_config(
    backends: &std::collections::BTreeMap<String, String>,
) -> HashMap<Provider, String> {
    backends
        .iter()
        .filter_map(|(provider, backend)| {
            provider
                .parse()
                .ok()
                .map(|provider| (provider, backend.clone()))
        })
        .collect()
}

fn providers_for_target(configured: &[Provider], target: &StreamingTarget) -> Vec<Provider> {
    let Some(worker_providers) = target.provider_models.as_ref() else {
        return configured.to_vec();
    };
    let mut providers: Vec<_> = worker_providers.keys().cloned().collect();
    providers.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    providers
}

fn worker_provider_models(worker: &WorkerEntry) -> HashMap<Provider, ProviderModelCoverage> {
    let mut coverage = HashMap::<Provider, ProviderModelCoverage>::new();
    for (provider, models) in &worker.supported_models {
        let Ok(provider) = provider.parse() else {
            continue;
        };
        coverage
            .entry(provider)
            .or_default()
            .unscoped
            .extend(models.clone());
    }
    for (provider, slots) in &worker.provider_slot_status {
        let Ok(provider) = provider.parse() else {
            continue;
        };
        let provider_coverage = coverage.entry(provider).or_default();
        for (slot_id, slot) in slots {
            if slot.status.as_deref() != Some("verified") {
                continue;
            }
            provider_coverage
                .by_slot
                .entry(slot_id.clone())
                .or_default()
                .extend(slot.models.iter().cloned());
        }
    }
    coverage
}

fn models_for_target(
    target: &StreamingTarget,
    provider: &Provider,
    mut models: Vec<ProbeModel>,
) -> Option<Vec<SelectedProbeModel>> {
    models = bind_models_to_worker(target, provider, models);
    if models.is_empty() && target.worker_backends.contains_key(provider) {
        return Some(Vec::new());
    }
    let Some(worker_coverage) = target
        .provider_models
        .as_ref()
        .and_then(|providers| providers.get(provider))
    else {
        let models = if target.provider_models.is_none() && !sourcing_providers().contains(provider)
        {
            models.into_iter().take(1).collect()
        } else {
            models
        };
        return Some(
            models
                .into_iter()
                .map(|model| SelectedProbeModel { model, slot: None })
                .collect(),
        );
    };
    if !worker_coverage.by_slot.is_empty()
        && worker_coverage.by_slot.values().all(BTreeSet::is_empty)
    {
        // Legacy registries reported only the provider-wide union in
        // `supported_models`. Once verified slots exist that union cannot say
        // which credential serves which model, and probing it through Envoy's
        // default slot can produce a false failure.
        return None;
    }
    if worker_coverage.unscoped.is_empty() && worker_coverage.by_slot.is_empty() {
        return None;
    }
    let mut selected = Vec::new();
    for model in models {
        let matches = |known: &BTreeSet<String>| {
            known.contains(&model.canonical) || known.contains(model.wire_model())
        };
        let mut slots: Vec<_> = worker_coverage
            .by_slot
            .iter()
            .filter(|(_, known)| matches(known))
            .map(|(slot, _)| slot.clone())
            .collect();
        slots.sort();
        if slots.is_empty() && worker_coverage.by_slot.is_empty() {
            if matches(&worker_coverage.unscoped) {
                selected.push(SelectedProbeModel { model, slot: None });
            }
        } else {
            selected.extend(slots.into_iter().map(|slot| SelectedProbeModel {
                model: model.clone(),
                slot: Some(slot),
            }));
        }
    }
    Some(selected)
}

/// Bind catalog/offer models to the backend of the selected worker.
///
/// Offers are miner-scoped, so their `upstream_model` cannot be used blindly:
/// a direct worker must send the canonical id even when a sibling Bedrock
/// worker's offer carries a deployment id. Bedrock accepts only models present
/// in the fixed registry snapshot; the adapter owns the AWS selector rewrite.
/// Azure, Foundry, and unknown cloud backends stay unverified until an
/// authoritative binding exists.
fn bind_models_to_worker(
    target: &StreamingTarget,
    provider: &Provider,
    models: Vec<ProbeModel>,
) -> Vec<ProbeModel> {
    match target.worker_backends.get(provider).map(String::as_str) {
        None | Some("direct") => models
            .into_iter()
            .map(|mut model| {
                model.upstream = None;
                model.binding_revision = None;
                model
            })
            .collect(),
        Some("bedrock") => models
            .into_iter()
            .filter_map(|mut model| {
                if provider.as_str() != BEDROCK_PROVIDER
                    || model.binding_revision.is_none()
                    || model.fallback
                {
                    return None;
                }
                // The binding row revision proves model admission; the adapter
                // owns the selector rewrite and ignores any offer mapping.
                model.upstream = None;
                Some(model)
            })
            .collect(),
        Some(_) => Vec::new(),
    }
}

fn sourcing_providers() -> [Provider; 5] {
    [
        Provider::DeepInfra,
        Provider::Engy,
        Provider::Kubetee,
        Provider::Moonmath,
        Provider::Near,
    ]
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
    /// One or more models to probe per provider. Sourcing providers may
    /// declare several routes (e.g. `z-ai/glm-5.2` and
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
                binding_revision: None,
            }],
        }
    }
}

/// Resolve the probe model(s) per provider: a canonical gm model id from the
/// public catalog, joined with the miner's own declared `upstream_model` (from
/// `/miners/me`) so cloud-backed offers probe their real upstream deployment.
///
/// Sourcing providers report supply health for every **offered** model from
/// `/miners/me` (e.g. GLM-5.2 and
/// deepseek-v4-flash-0731), independent of buyer-catalog availability. If
/// nothing is declared, [`fallback_model`] is used at print time. The check
/// must never fail the deploy it advises on.
fn resolve_probe_models(
    providers: &[Provider],
    canonical: &std::collections::HashMap<Provider, Vec<String>>,
    declared: &std::collections::HashMap<(Provider, String), DeclaredOffer>,
) -> ProbeModels {
    let mut models = std::collections::HashMap::new();
    for provider in providers {
        // Offered sourcing routes are the supply being checked. Use
        // `/miners/me` as their authority even when `/products` is unavailable
        // or later gains an unrelated buyer-catalog row.
        if sourcing_providers().contains(provider) {
            let declared_models = declared_models_for_provider(declared, provider);
            if !declared_models.is_empty() {
                models.insert(provider.clone(), declared_models);
            }
            continue;
        }

        if let Some(canonical_models) = canonical.get(provider) {
            let provider_models = canonical_models
                .iter()
                .map(|canonical| ProbeModel {
                    canonical: canonical.clone(),
                    upstream: declared
                        .get(&(provider.clone(), canonical.clone()))
                        .filter(|offer| offer.is_offered)
                        .and_then(|offer| offer.upstream_model.clone()),
                    fallback: false,
                    binding_revision: None,
                })
                .collect();
            models.insert(provider.clone(), provider_models);
        }
    }
    ProbeModels { models }
}

/// Public `GET /products`; empty when unreachable so the check never fails the
/// deploy it advises on.
async fn fetch_catalog(cfg: &Config) -> Vec<Product> {
    let url = format!("{}/products", cfg.api_url());
    let Ok(client) = build_http_client() else {
        return Vec::new();
    };
    match client.get(&url).header(VIDEO_JOBS_HEADER, "1").send().await {
        Ok(resp) if resp.status().is_success() => resp
            .json::<ProductCatalogResponse>()
            .await
            .map(|catalog| catalog.products)
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// The active canonical model ids per provider.
fn canonical_models(
    catalog: &[Product],
    providers: &[Provider],
) -> std::collections::HashMap<Provider, Vec<String>> {
    let mut models = std::collections::HashMap::new();
    for provider in providers {
        let provider_models: Vec<_> = catalog
            .iter()
            .filter(|product| product.provider == provider.as_str() && product.status == "active")
            .map(|product| product.model.clone())
            .collect();
        if !provider_models.is_empty() {
            models.insert(provider.clone(), provider_models);
        }
    }
    models
}

/// Authenticated sourcing routes; empty when unreachable, like the catalog.
async fn fetch_routes(cfg: &Config) -> Vec<SourceProduct> {
    let mut client = RegistryClient::new(cfg.clone());
    match crate::commands::sources::fetch_sources(&mut client).await {
        Ok(lookup) => lookup.routes().to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Declared `(provider, model)` pairs the text-only probe must skip: every
/// buyer product whose catalog capabilities publish image or video generation, and
/// every source route that serves one. Source pairs are absent from
/// `GET /products`, so the route is the only link to the capability block.
fn non_chat_probe_exclusions(
    catalog: &[Product],
    routes: &[SourceProduct],
) -> BTreeSet<(String, String)> {
    let mut excluded: BTreeSet<_> = catalog
        .iter()
        .filter(|product| product.has_no_chat_surface())
        .map(|product| (product.provider.clone(), product.model.clone()))
        .collect();
    for route in routes {
        if excluded.contains(&(route.buyer_provider.clone(), route.buyer_model.clone())) {
            excluded.insert((route.provider.clone(), route.model.clone()));
        }
    }
    excluded
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
            binding_revision: None,
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
        Provider::Near => "Qwen/Qwen3.8-27B",
        Provider::Benchmark => "benchmark",
    }
}

fn build_probe(provider: Provider, model: &ProbeModel, slot: Option<String>) -> ProviderProbe {
    match provider {
        Provider::Anthropic => ProviderProbe {
            provider,
            model: model.canonical.clone(),
            slot,
            fallback: model.fallback,
            execution_policy: None,
            model_binding_revision: model.binding_revision,
            path: "/v1/messages",
            body: serde_json::json!({
                "model": model.wire_model(),
                "max_tokens": MAX_TOKENS,
                "stream": true,
                "messages": [{"role": "user", "content": probe_prompt()}],
            }),
        },
        Provider::Gemini => {
            openai_compatible_probe(provider, model, slot, "/v1beta/openai/chat/completions")
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
        | Provider::Benchmark => {
            openai_compatible_probe(provider, model, slot, "/v1/chat/completions")
        }
    }
}

fn openai_compatible_probe(
    provider: Provider,
    model: &ProbeModel,
    slot: Option<String>,
    path: &'static str,
) -> ProviderProbe {
    ProviderProbe {
        provider,
        model: model.canonical.clone(),
        slot,
        fallback: model.fallback,
        execution_policy: None,
        model_binding_revision: None,
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
    if matches!(probe.provider, Provider::Near | Provider::Kubetee) {
        let selector = probe.body["model"]
            .as_str()
            .with_context(|| format!("{} probe has no upstream source model", probe.provider))?;
        request = request.header("x-gm-upstream-model", selector);
    }
    request = apply_upstream_slot(request, probe.slot.as_deref());
    if let Some(execution_policy) = probe.execution_policy {
        request = request.header(EXECUTION_POLICY_HEADER, execution_policy);
    }
    if let Some(revision) = probe.model_binding_revision {
        request = request.header(MODEL_BINDING_REVISION_HEADER, revision.to_string());
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
    if let Some(expected_revision) = probe.model_binding_revision {
        if !response_confirms_binding_revision(response.headers(), expected_revision) {
            bail!("Bedrock adapter response did not confirm the selected model-binding revision");
        }
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

fn response_confirms_binding_revision(headers: &reqwest::header::HeaderMap, expected: u64) -> bool {
    let mut revisions = headers.get_all(MODEL_BINDING_REVISION_HEADER).iter();
    let Some(revision) = revisions.next() else {
        return false;
    };
    let expected = expected.to_string();
    revision.to_str().ok() == Some(expected.as_str()) && revisions.next().is_none()
}

fn apply_upstream_slot(
    request: reqwest::RequestBuilder,
    slot: Option<&str>,
) -> reqwest::RequestBuilder {
    match slot {
        Some(slot) => request.header("x-gm-upstream-slot", slot),
        None => request,
    }
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

    const TEST_APPROVED_BEDROCK_MODEL: &str = "future-approved-bedrock-model";
    const TEST_BEDROCK_BINDING_REVISION: u64 = 7;

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    #[tokio::test]
    async fn a_kubetee_probe_names_its_upstream_model_to_the_selector_gate() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("x-gm-provider", "kubetee"))
            .and(header("x-gm-upstream-model", "z-ai/glm-5.3"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string("data: {}\n\ndata: [DONE]\n\n"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let target = StreamingTarget {
            endpoint: server.uri(),
            node_secret: "secret".to_owned(),
            provider_models: None,
            worker_backends: HashMap::new(),
            bedrock_policy_image_capable: false,
        };
        let probe = ProviderProbe {
            provider: Provider::Kubetee,
            model: "zai/glm-5.3-tee".to_owned(),
            slot: None,
            fallback: false,
            execution_policy: None,
            model_binding_revision: None,
            path: "/v1/chat/completions",
            body: serde_json::json!({"model": "z-ai/glm-5.3", "stream": true}),
        };
        run_provider_probe(&target, &probe)
            .await
            .expect("a KubeTEE probe carries its selector");
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

    fn bedrock_config(key: &str) -> Config {
        Config {
            provider_keys: Some(ProviderKeys {
                anthropic_upstream: Some("bedrock".to_owned()),
                bedrock_region: Some("us-east-1".to_owned()),
                bedrock_api_key: Some(key.to_owned()),
                ..ProviderKeys::default()
            }),
            ..Config::default()
        }
    }

    fn bedrock_model() -> ProbeModel {
        ProbeModel {
            canonical: TEST_APPROVED_BEDROCK_MODEL.to_owned(),
            upstream: Some("anthropic.operator-mapping-must-be-ignored".to_owned()),
            fallback: false,
            binding_revision: Some(TEST_BEDROCK_BINDING_REVISION),
        }
    }

    fn image_version(compose_hash: &str, features: &[&str]) -> ImageVersion {
        ImageVersion {
            git_tag: None,
            compose_hash: compose_hash.to_owned(),
            os_image_hash: "os-hash".to_owned(),
            status: "supported".to_owned(),
            notes: None,
            created_at: "2026-10-21T00:00:00Z".to_owned(),
            image_ref: None,
            features: features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
        }
    }

    #[test]
    fn bedrock_policy_feature_must_match_the_selected_current_image() {
        let old_hash = "a".repeat(64);
        let current_hash = "b".repeat(64);
        let no_feature_hash = "c".repeat(64);
        let blocked_hash = "d".repeat(64);
        let old = image_version(&old_hash, &["bedrock-mantle-model-bindings-v0"]);
        let current = image_version(&current_hash, &["bedrock-mantle-model-bindings-v1"]);
        assert!(!image_has_bedrock_policy_feature(
            Some(&old_hash),
            &[old.clone(), current.clone()]
        ));
        assert!(image_has_bedrock_policy_feature(
            Some(&current_hash),
            &[old.clone(), current.clone()]
        ));

        let no_feature = image_version(&no_feature_hash, &[]);
        assert!(!image_has_bedrock_policy_feature(
            Some(&no_feature_hash),
            &[no_feature]
        ));

        let mut blocked = image_version(&blocked_hash, &["bedrock-mantle-model-bindings-v1"]);
        blocked.status = "blocked".to_owned();
        assert!(!image_has_bedrock_policy_feature(
            Some(&blocked_hash),
            &[blocked]
        ));

        // A duplicate compose hash is ambiguous if any matching row still
        // carries the old measurement stamp.
        assert!(!image_has_bedrock_policy_feature(
            Some(&current_hash),
            &[
                current.clone(),
                image_version(&current_hash, &["bedrock-mantle-model-bindings-v0"]),
            ]
        ));

        assert!(!image_has_bedrock_policy_feature(
            None,
            std::slice::from_ref(&current)
        ));
        assert!(!image_has_bedrock_policy_feature(
            Some(""),
            &[image_version("", &["bedrock-mantle-model-bindings-v1",])]
        ));
        assert!(!image_has_bedrock_policy_feature(
            Some("not-a-sha256"),
            &[image_version(
                "not-a-sha256",
                &["bedrock-mantle-model-bindings-v1"]
            )],
        ));
        assert!(!image_has_bedrock_policy_feature(
            Some(&"e".repeat(64)),
            &[image_version(
                &current_hash,
                &["bedrock-mantle-model-bindings-v1"]
            )],
        ));
    }

    #[tokio::test]
    async fn qualified_bedrock_probe_sends_execution_policy_and_registry_verified_slot() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let node_secret = "selected-worker-node-secret";
        let slot = gm_miner_cli::slots::derive_slot_id(
            BEDROCK_PROVIDER,
            "configured-bedrock-key",
            node_secret,
        )
        .expect("HMAC slot");
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("x-gm-provider", BEDROCK_PROVIDER))
            .and(header("x-gm-upstream-slot", slot.as_str()))
            .and(header(
                MODEL_BINDING_REVISION_HEADER,
                TEST_BEDROCK_BINDING_REVISION.to_string(),
            ))
            .and(header(
                EXECUTION_POLICY_HEADER,
                EXACT_CANONICAL_NO_REPLAY_POLICY,
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .insert_header(
                        MODEL_BINDING_REVISION_HEADER,
                        TEST_BEDROCK_BINDING_REVISION.to_string(),
                    )
                    .set_body_string("data: {}\n\ndata: [DONE]\n\n"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let target = StreamingTarget {
            endpoint: server.uri(),
            node_secret: node_secret.to_owned(),
            provider_models: Some(HashMap::from([(
                Provider::Anthropic,
                ProviderModelCoverage {
                    unscoped: BTreeSet::new(),
                    by_slot: HashMap::from([(
                        slot.clone(),
                        BTreeSet::from([TEST_APPROVED_BEDROCK_MODEL.to_owned()]),
                    )]),
                },
            )])),
            worker_backends: HashMap::from([(Provider::Anthropic, "bedrock".to_owned())]),
            bedrock_policy_image_capable: true,
        };
        let selected = models_for_target(&target, &Provider::Anthropic, vec![bedrock_model()])
            .expect("worker model ownership")
            .remove(0);
        let mut stale_image = target.clone();
        stale_image.bedrock_policy_image_capable = false;
        assert!(probe_route_authorization(
            &Config::default(),
            &stale_image,
            &Provider::Anthropic,
            &selected
        )
        .is_none());
        let route =
            probe_route_authorization(&Config::default(), &target, &Provider::Anthropic, &selected)
                .expect("current image and verified Bedrock slot authorize policy");
        assert_eq!(route.slot.as_deref(), Some(slot.as_str()));
        assert_eq!(
            route.execution_policy,
            Some(EXACT_CANONICAL_NO_REPLAY_POLICY)
        );
        assert_eq!(
            route.model_binding_revision,
            Some(TEST_BEDROCK_BINDING_REVISION)
        );

        let mut probe = build_probe(Provider::Anthropic, &selected.model, route.slot);
        probe.execution_policy = route.execution_policy;
        probe.model_binding_revision = route.model_binding_revision;
        assert_eq!(probe.body["model"], TEST_APPROVED_BEDROCK_MODEL);
        run_provider_probe(&target, &probe)
            .await
            .expect("mock requires execution policy and verified slot");
        check_provider_streaming(
            &Config::default(),
            &stale_image,
            Provider::Anthropic,
            &ProbeModels {
                models: HashMap::from([(Provider::Anthropic, vec![bedrock_model()])]),
            },
            &BTreeSet::new(),
        )
        .await;
    }

    #[test]
    fn post_deploy_bedrock_probe_derives_only_the_configured_single_slot() {
        let cfg = bedrock_config("just-deployed-bedrock-key");
        let target = StreamingTarget {
            endpoint: "https://worker.example.org".to_owned(),
            node_secret: "just-deployed-node-secret".to_owned(),
            provider_models: None,
            worker_backends: HashMap::from([(Provider::Anthropic, "bedrock".to_owned())]),
            bedrock_policy_image_capable: true,
        };
        let selected = models_for_target(&target, &Provider::Anthropic, vec![bedrock_model()])
            .expect("post-deploy configuration is authoritative")
            .remove(0);
        assert_eq!(selected.slot, None);

        let route = probe_route_authorization(&cfg, &target, &Provider::Anthropic, &selected)
            .expect("derive the just-deployed slot");
        let expected = gm_miner_cli::slots::derive_slot_id(
            BEDROCK_PROVIDER,
            "just-deployed-bedrock-key",
            "just-deployed-node-secret",
        )
        .expect("HMAC slot");
        assert_eq!(route.slot.as_deref(), Some(expected.as_str()));
        assert_eq!(
            route.execution_policy,
            Some(EXACT_CANONICAL_NO_REPLAY_POLICY)
        );
    }

    #[tokio::test]
    async fn bedrock_probe_is_inconclusive_without_verified_or_derivable_slot() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let cfg = bedrock_config("configured-key");
        let target = StreamingTarget {
            endpoint: server.uri(),
            node_secret: "secret".to_owned(),
            provider_models: Some(HashMap::from([(
                Provider::Anthropic,
                unscoped_coverage(&[TEST_APPROVED_BEDROCK_MODEL]),
            )])),
            worker_backends: HashMap::from([(Provider::Anthropic, "bedrock".to_owned())]),
            bedrock_policy_image_capable: true,
        };
        let selected = models_for_target(&target, &Provider::Anthropic, vec![bedrock_model()])
            .expect("provider-wide models are known")
            .remove(0);
        assert_eq!(selected.slot, None);
        assert!(
            probe_route_authorization(&cfg, &target, &Provider::Anthropic, &selected).is_none()
        );
        let catalog = ProbeModels {
            models: HashMap::from([(Provider::Anthropic, vec![bedrock_model()])]),
        };
        check_provider_streaming(
            &cfg,
            &target,
            Provider::Anthropic,
            &catalog,
            &BTreeSet::new(),
        )
        .await;
        assert!(server
            .received_requests()
            .await
            .expect("request count")
            .is_empty());

        let mut missing_key = bedrock_config("");
        let target = StreamingTarget {
            provider_models: None,
            ..target
        };
        let selected = models_for_target(&target, &Provider::Anthropic, vec![bedrock_model()])
            .expect("model is canonical")
            .remove(0);
        missing_key
            .provider_keys
            .as_mut()
            .expect("keys")
            .bedrock_api_key = None;
        assert!(
            probe_route_authorization(&missing_key, &target, &Provider::Anthropic, &selected)
                .is_none()
        );
        check_provider_streaming(
            &missing_key,
            &target,
            Provider::Anthropic,
            &catalog,
            &BTreeSet::new(),
        )
        .await;
        assert!(server
            .received_requests()
            .await
            .expect("request count")
            .is_empty());

        let foundry = StreamingTarget {
            endpoint: server.uri(),
            node_secret: "secret".to_owned(),
            provider_models: Some(HashMap::from([(
                Provider::Anthropic,
                unscoped_coverage(&[TEST_APPROVED_BEDROCK_MODEL]),
            )])),
            worker_backends: HashMap::from([(Provider::Anthropic, "foundry".to_owned())]),
            bedrock_policy_image_capable: false,
        };
        check_provider_streaming(
            &cfg,
            &foundry,
            Provider::Anthropic,
            &catalog,
            &BTreeSet::new(),
        )
        .await;
        assert!(server
            .received_requests()
            .await
            .expect("request count")
            .is_empty());
    }

    #[tokio::test]
    async fn direct_anthropic_probe_never_sends_execution_policy() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(|request: &wiremock::Request| {
                !request.headers.contains_key(EXECUTION_POLICY_HEADER)
            })
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string("data: {}\n\ndata: [DONE]\n\n"),
            )
            .expect(1)
            .mount(&server)
            .await;

        // The global configuration may select Bedrock for a sibling worker;
        // this selected worker's direct backend remains authoritative.
        let cfg = bedrock_config("sibling-bedrock-key");
        let target = StreamingTarget {
            endpoint: server.uri(),
            node_secret: "secret".to_owned(),
            provider_models: Some(HashMap::from([(
                Provider::Anthropic,
                unscoped_coverage(&[TEST_APPROVED_BEDROCK_MODEL]),
            )])),
            worker_backends: HashMap::from([(Provider::Anthropic, "direct".to_owned())]),
            bedrock_policy_image_capable: false,
        };
        let selected = models_for_target(&target, &Provider::Anthropic, vec![bedrock_model()])
            .expect("direct worker can probe its canonical model")
            .remove(0);
        let route = probe_route_authorization(&cfg, &target, &Provider::Anthropic, &selected)
            .expect("ordinary direct route");
        assert_eq!(route.execution_policy, None);
        let mut probe = build_probe(Provider::Anthropic, &selected.model, route.slot);
        probe.execution_policy = route.execution_policy;
        run_provider_probe(&target, &probe)
            .await
            .expect("direct request has no execution policy");
    }

    #[test]
    fn probe_sends_declared_upstream_model_when_present() {
        let model = ProbeModel {
            canonical: "claude-sonnet-4-6".to_owned(),
            upstream: Some("anthropic.claude-sonnet-4-6-v1".to_owned()),
            fallback: false,
            binding_revision: None,
        };
        let probe = build_probe(Provider::Anthropic, &model, None);
        assert_eq!(
            probe.body["model"],
            Value::String("anthropic.claude-sonnet-4-6-v1".to_owned())
        );
        assert_eq!(probe.model, "claude-sonnet-4-6");
    }

    #[test]
    fn probe_sends_canonical_model_without_upstream_mapping() {
        let model = ProbeModel {
            canonical: "gpt-5.5".to_owned(),
            upstream: None,
            fallback: false,
            binding_revision: None,
        };
        let probe = build_probe(Provider::OpenAI, &model, None);
        assert_eq!(probe.body["model"], Value::String("gpt-5.5".to_owned()));
        assert_eq!(probe.model, "gpt-5.5");
    }

    #[test]
    fn zai_probe_uses_openai_compatible_route_and_model() {
        let model = ProbeModel {
            canonical: fallback_model(&Provider::Zai).to_owned(),
            upstream: None,
            fallback: true,
            binding_revision: None,
        };
        let probe = build_probe(Provider::Zai, &model, None);
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
            binding_revision: None,
        };
        let probe = build_probe(Provider::Kubetee, &model, None);
        assert_eq!(probe.path, "/v1/chat/completions");
        assert_eq!(
            probe.body["model"],
            Value::String("z-ai/glm-5.2".to_owned())
        );
        assert_eq!(probe.model, "z-ai/glm-5.2");
    }

    fn catalog_row(provider: &str, model: &str, capabilities: Value) -> Product {
        let mut row = serde_json::json!({
            "provider": provider,
            "model": model,
            "status": "active",
            "retail_price": {"dimensions": {"input_per_mtok_ndollars": 1, "output_per_mtok_ndollars": 2}},
        });
        row["capabilities"] = capabilities;
        serde_json::from_value(row).expect("catalog row")
    }

    fn route(
        provider: &str,
        model: &str,
        buyer_provider: &str,
        buyer_model: &str,
    ) -> SourceProduct {
        serde_json::from_value(serde_json::json!({
            "provider": provider,
            "model": model,
            "buyer_provider": buyer_provider,
            "buyer_model": buyer_model,
            "retail_price": {"dimensions": {"input_per_mtok_ndollars": 1, "output_per_mtok_ndollars": 2}},
            "capable_worker_count": 1,
            "already_offered": true,
        }))
        .expect("route")
    }

    #[test]
    fn image_products_are_excluded_from_streaming_probes_by_catalog_capability() {
        let catalog = [
            catalog_row(
                "bfl",
                "flux.2-klein-4b",
                serde_json::json!({"image_generation": true, "image_output": true, "api": "openai_images"}),
            ),
            catalog_row(
                "gemini",
                "gemini-3.1-flash-image",
                serde_json::json!({"api": "gemini_generate_content", "image_generation": true, "image_output": true}),
            ),
            catalog_row(
                "gemini",
                "gemini-3.1-flash",
                serde_json::json!({"api": "gemini_generate_content", "image_generation": false, "image_input": true}),
            ),
            catalog_row("qwen", "qwen3.8-27b-tee", Value::Null),
        ];
        let routes = [
            route(
                "near",
                "black-forest-labs/FLUX.2-klein-4B",
                "bfl",
                "flux.2-klein-4b",
            ),
            route(
                "deepinfra",
                "black-forest-labs/FLUX-2-klein-4b",
                "bfl",
                "flux.2-klein-4b",
            ),
            route("near", "Qwen/Qwen3.8-27B", "qwen", "qwen3.8-27b-tee"),
            route(
                "gemini",
                "gemini-3.1-flash-image",
                "gemini",
                "gemini-3.1-flash-image",
            ),
        ];
        let excluded = non_chat_probe_exclusions(&catalog, &routes);
        for (provider, model) in [
            ("near", "black-forest-labs/FLUX.2-klein-4B"),
            ("deepinfra", "black-forest-labs/FLUX-2-klein-4b"),
            ("bfl", "flux.2-klein-4b"),
            ("gemini", "gemini-3.1-flash-image"),
        ] {
            assert!(
                excluded.contains(&(provider.to_owned(), model.to_owned())),
                "{provider}/{model} publishes image generation and must be skipped"
            );
        }
        for (provider, model) in [
            ("near", "Qwen/Qwen3.8-27B"),
            ("qwen", "qwen3.8-27b-tee"),
            ("gemini", "gemini-3.1-flash"),
            ("near", "black-forest-labs/FLUX-2-klein-4b"),
        ] {
            assert!(
                !excluded.contains(&(provider.to_owned(), model.to_owned())),
                "{provider}/{model} is a text product and must still be probed"
            );
        }
    }

    #[test]
    fn video_products_and_their_sources_are_excluded_from_streaming_probes() {
        let catalog = [
            catalog_row(
                "minimax",
                "h3",
                serde_json::json!({"video_generation": true}),
            ),
            catalog_row(
                "google",
                "veo-3.1-fast",
                serde_json::json!({"api": "openai_videos"}),
            ),
            catalog_row(
                "wan-ai",
                "wan-2.6-t2v",
                serde_json::json!({"video_generation": true, "api": "openai_videos"}),
            ),
            catalog_row("zai", "glm-5.3", Value::Null),
        ];
        let routes = [
            route("kubetee", "minimax/h3", "minimax", "h3"),
            route("deepinfra", "google/veo-3.1-fast", "google", "veo-3.1-fast"),
            route("deepinfra", "Wan-AI/Wan2.6-T2V", "wan-ai", "wan-2.6-t2v"),
            route("kubetee", "z-ai/glm-5.3", "zai", "glm-5.3"),
        ];
        let excluded = non_chat_probe_exclusions(&catalog, &routes);
        let expected = [
            ("minimax", "h3"),
            ("google", "veo-3.1-fast"),
            ("wan-ai", "wan-2.6-t2v"),
            ("kubetee", "minimax/h3"),
            ("deepinfra", "google/veo-3.1-fast"),
            ("deepinfra", "Wan-AI/Wan2.6-T2V"),
        ]
        .map(|(provider, model)| (provider.to_owned(), model.to_owned()))
        .into_iter()
        .collect();
        assert_eq!(excluded, expected);
    }

    #[tokio::test]
    async fn video_catalog_discovery_excludes_generation_sources_from_probes() {
        use gm_miner_cli::config::NetworkEntry;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/products"))
            .and(header("x-gm-video-jobs", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "products": [{
                    "provider": "minimax", "model": "h3", "status": "active",
                    "capabilities": {"api": "openai_videos", "video_generation": true},
                    "retail_price": {"dimensions": {
                        "input_per_mtok_ndollars": 0, "output_per_mtok_ndollars": 0,
                        "output_per_video_second_ndollars": 80_000_000
                    }}
                }],
                "generated_at": "2026-10-09T10:00:00Z"
            })))
            .mount(&server)
            .await;
        let cfg = Config {
            active_network: Some("testnet".to_owned()),
            networks: HashMap::from([(
                "testnet".to_owned(),
                NetworkEntry {
                    api_url: Some(server.uri()),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let catalog = fetch_catalog(&cfg).await;
        let routes = [route("kubetee", "minimax/h3", "minimax", "h3")];
        let excluded = non_chat_probe_exclusions(&catalog, &routes);
        assert!(excluded.contains(&("kubetee".to_owned(), "minimax/h3".to_owned())));
    }

    #[test]
    fn a_catalog_row_without_capabilities_still_decodes_as_a_text_product() {
        let product: Product = serde_json::from_value(serde_json::json!({
            "provider": "qwen",
            "model": "qwen3.8-27b-tee",
            "status": "active",
            "retail_price": {"dimensions": {"input_per_mtok_ndollars": 1, "output_per_mtok_ndollars": 2}},
        }))
        .expect("older registry row");
        assert!(!product.has_no_chat_surface());
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
        let probe = build_probe(Provider::Kubetee, &models[0], None);
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
                (Provider::Near, "z-ai/glm-5.3-flash".to_owned()),
                DeclaredOffer {
                    upstream_model: None,
                    is_offered: true,
                },
            ),
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
        assert_eq!(models.len(), 3);
        assert_eq!(models[0].canonical, "glm-5.1");
        assert_eq!(models[0].wire_model(), "zai-org/GLM-5.1-FP8");
        assert_eq!(models[1].canonical, "qwen3.6-27b");
        assert_eq!(models[1].wire_model(), "Qwen/Qwen3.6-27B-FP8");
        assert_eq!(models[2].canonical, "z-ai/glm-5.3-flash");
        assert_eq!(models[2].wire_model(), "z-ai/glm-5.3-flash");

        // Source declarations store the NEAR model, not the buyer's TEE id.
        // Exercise worker coverage selection before constructing the probe.
        let target = StreamingTarget {
            endpoint: "https://worker.example.org".to_owned(),
            node_secret: "secret".to_owned(),
            provider_models: Some(HashMap::from([(
                Provider::Near,
                unscoped_coverage(&["z-ai/glm-5.3-flash"]),
            )])),
            worker_backends: HashMap::new(),
            bedrock_policy_image_capable: false,
        };
        let selected = models_for_target(&target, &Provider::Near, models).expect("known coverage");
        assert_eq!(selected.len(), 1);
        let probe = build_probe(Provider::Near, &selected[0].model, None);
        assert!(!probe.fallback);
        assert_eq!(probe.path, "/v1/chat/completions");
        assert_eq!(probe.body["model"], "z-ai/glm-5.3-flash");
    }

    #[test]
    fn near_without_offered_routes_preserves_the_qwen_streaming_fallback() {
        // A new CLI may probe an older worker that only admits Qwen chat.
        // New target support must not silently change its advisory probe.
        for declared in [
            std::collections::HashMap::new(),
            std::collections::HashMap::from([(
                (Provider::Near, "z-ai/glm-5.3-flash".to_owned()),
                DeclaredOffer {
                    upstream_model: None,
                    is_offered: false,
                },
            )]),
        ] {
            let catalog = resolve_probe_models(
                &[Provider::Near],
                &std::collections::HashMap::new(),
                &declared,
            );
            let models = catalog.models_for(&Provider::Near);
            assert_eq!(models.len(), 1);
            let probe = build_probe(Provider::Near, &models[0], None);
            assert_eq!(probe.model_label(), "Qwen/Qwen3.8-27B [fallback]");
            assert_eq!(probe.path, "/v1/chat/completions");
            assert_eq!(probe.body["model"], "Qwen/Qwen3.8-27B");
        }
    }

    #[test]
    fn catalog_outage_does_not_fan_out_a_direct_only_provider() {
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
    fn every_offered_engy_and_deepinfra_route_is_probed() {
        let declared = std::collections::HashMap::from([
            (
                (Provider::Engy, "deepseek-v4-flash-0731".to_owned()),
                DeclaredOffer {
                    upstream_model: None,
                    is_offered: true,
                },
            ),
            (
                (Provider::Engy, "qwen3.8-27b".to_owned()),
                DeclaredOffer {
                    upstream_model: None,
                    is_offered: true,
                },
            ),
            (
                (Provider::DeepInfra, "Qwen/Qwen3.6-35B-A3B".to_owned()),
                DeclaredOffer {
                    upstream_model: None,
                    is_offered: true,
                },
            ),
            (
                (Provider::DeepInfra, "Qwen/Qwen3.8-27B".to_owned()),
                DeclaredOffer {
                    upstream_model: None,
                    is_offered: true,
                },
            ),
        ]);
        let catalog = resolve_probe_models(
            &[Provider::Engy, Provider::DeepInfra],
            &std::collections::HashMap::new(),
            &declared,
        );

        let engy: Vec<_> = catalog
            .models_for(&Provider::Engy)
            .into_iter()
            .map(|model| model.canonical)
            .collect();
        assert_eq!(engy, ["deepseek-v4-flash-0731", "qwen3.8-27b"]);

        let deepinfra: Vec<_> = catalog
            .models_for(&Provider::DeepInfra)
            .into_iter()
            .map(|model| model.canonical)
            .collect();
        assert_eq!(deepinfra, ["Qwen/Qwen3.6-35B-A3B", "Qwen/Qwen3.8-27B"]);
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
            std::collections::HashMap::from([(Provider::Kubetee, vec!["z-ai/glm-5.2".to_owned()])]);

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
            binding_revision: None,
        };
        let probe = build_probe(Provider::DeepInfra, &model, None);
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
            binding_revision: None,
        };
        let probe = build_probe(Provider::Moonmath, &model, None);
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

    fn unscoped_coverage(models: &[&str]) -> ProviderModelCoverage {
        ProviderModelCoverage {
            unscoped: models.iter().map(|model| (*model).to_owned()).collect(),
            by_slot: HashMap::new(),
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
    fn selected_worker_limits_probes_to_its_provider_slots() {
        let target = StreamingTarget {
            endpoint: "https://worker.example.org".to_owned(),
            node_secret: "secret".to_owned(),
            provider_models: Some(HashMap::from([(
                Provider::Engy,
                unscoped_coverage(&["qwen3.8-27b"]),
            )])),
            worker_backends: HashMap::new(),
            bedrock_policy_image_capable: false,
        };
        let providers = providers_for_target(
            &[Provider::DeepInfra, Provider::Engy, Provider::OpenAI],
            &target,
        );
        assert_eq!(providers, [Provider::Engy]);
    }

    #[test]
    fn target_worker_carries_registry_provider_slot_ownership() {
        let local = vec![local_record("01J0A")];
        let mut worker = live_worker("01J0A", "2026-07-01T00:00:00Z");
        worker.supported_models = serde_json::from_value(serde_json::json!({
            "deepinfra": ["Qwen/Qwen3.8-27B"]
        }))
        .expect("supported models");
        worker.provider_slot_status = serde_json::from_value(serde_json::json!({
            "engy": {"default": {"status": "verified", "models": ["qwen3.8-27b"]}}
        }))
        .expect("provider slots");

        let target = pick_target_worker(&local, &[worker]).expect("target");
        assert_eq!(
            target.provider_models,
            Some(HashMap::from([
                (
                    Provider::DeepInfra,
                    unscoped_coverage(&["Qwen/Qwen3.8-27B"])
                ),
                (
                    Provider::Engy,
                    ProviderModelCoverage {
                        unscoped: BTreeSet::new(),
                        by_slot: HashMap::from([(
                            "default".to_owned(),
                            BTreeSet::from(["qwen3.8-27b".to_owned()]),
                        )]),
                    }
                ),
            ]))
        );
    }

    #[test]
    fn selected_worker_probes_only_its_exact_models() {
        let target = StreamingTarget {
            endpoint: "https://worker.example.org".to_owned(),
            node_secret: "secret".to_owned(),
            provider_models: Some(HashMap::from([(
                Provider::Engy,
                unscoped_coverage(&["qwen3.8-27b"]),
            )])),
            worker_backends: HashMap::new(),
            bedrock_policy_image_capable: false,
        };
        let models = vec![
            ProbeModel {
                canonical: "qwen3.6-35b-a3b".to_owned(),
                upstream: None,
                fallback: false,
                binding_revision: None,
            },
            ProbeModel {
                canonical: "qwen3.8-27b".to_owned(),
                upstream: None,
                fallback: false,
                binding_revision: None,
            },
        ];

        let selected = models_for_target(&target, &Provider::Engy, models).expect("known models");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].model.canonical, "qwen3.8-27b");
        assert_eq!(selected[0].slot, None);
    }

    #[test]
    fn selected_worker_keeps_each_model_bound_to_its_verified_slot() {
        let target = StreamingTarget {
            endpoint: "https://worker.example.org".to_owned(),
            node_secret: "secret".to_owned(),
            provider_models: Some(HashMap::from([(
                Provider::Engy,
                ProviderModelCoverage {
                    unscoped: BTreeSet::from([
                        "qwen3.6-35b-a3b".to_owned(),
                        "qwen3.8-27b".to_owned(),
                    ]),
                    by_slot: HashMap::from([
                        (
                            "slot-a".to_owned(),
                            BTreeSet::from(["qwen3.6-35b-a3b".to_owned()]),
                        ),
                        (
                            "slot-b".to_owned(),
                            BTreeSet::from(["qwen3.8-27b".to_owned()]),
                        ),
                    ]),
                },
            )])),
            worker_backends: HashMap::new(),
            bedrock_policy_image_capable: false,
        };
        let models = vec![
            ProbeModel {
                canonical: "qwen3.6-35b-a3b".to_owned(),
                upstream: None,
                fallback: false,
                binding_revision: None,
            },
            ProbeModel {
                canonical: "qwen3.8-27b".to_owned(),
                upstream: None,
                fallback: false,
                binding_revision: None,
            },
        ];

        let selected = models_for_target(&target, &Provider::Engy, models).expect("coverage");
        let bindings: Vec<_> = selected
            .iter()
            .map(|selected| (selected.model.canonical.as_str(), selected.slot.as_deref()))
            .collect();
        assert_eq!(
            bindings,
            [
                ("qwen3.6-35b-a3b", Some("slot-a")),
                ("qwen3.8-27b", Some("slot-b")),
            ]
        );

        let probe = build_probe(Provider::Engy, &selected[1].model, selected[1].slot.clone());
        let request = apply_upstream_slot(
            reqwest::Client::new().post("https://worker.example.org/v1/chat/completions"),
            probe.slot.as_deref(),
        )
        .build()
        .expect("request");
        assert_eq!(request.headers()["x-gm-upstream-slot"], "slot-b");
    }

    #[test]
    fn legacy_aggregate_models_with_unmapped_slots_are_inconclusive() {
        let target = StreamingTarget {
            endpoint: "https://worker.example.org".to_owned(),
            node_secret: "secret".to_owned(),
            provider_models: Some(HashMap::from([(
                Provider::Engy,
                ProviderModelCoverage {
                    unscoped: BTreeSet::from([
                        "qwen3.6-35b-a3b".to_owned(),
                        "qwen3.8-27b".to_owned(),
                    ]),
                    by_slot: HashMap::from([
                        ("slot-a".to_owned(), BTreeSet::new()),
                        ("slot-b".to_owned(), BTreeSet::new()),
                    ]),
                },
            )])),
            worker_backends: HashMap::new(),
            bedrock_policy_image_capable: false,
        };
        let models = vec![ProbeModel {
            canonical: "qwen3.8-27b".to_owned(),
            upstream: None,
            fallback: false,
            binding_revision: None,
        }];

        assert!(models_for_target(&target, &Provider::Engy, models).is_none());
    }

    #[test]
    fn direct_worker_ignores_a_sibling_bedrock_offer() {
        let canonical =
            HashMap::from([(Provider::Anthropic, vec!["claude-sonnet-4-6".to_owned()])]);
        let declared = HashMap::from([(
            (Provider::Anthropic, "claude-sonnet-4-6".to_owned()),
            DeclaredOffer {
                upstream_model: Some("anthropic.claude-sonnet-4-6-v1".to_owned()),
                is_offered: true,
            },
        )]);
        let catalog = resolve_probe_models(&[Provider::Anthropic], &canonical, &declared);
        let target = StreamingTarget {
            endpoint: "https://worker.example.org".to_owned(),
            node_secret: "secret".to_owned(),
            provider_models: Some(HashMap::from([(
                Provider::Anthropic,
                unscoped_coverage(&["claude-sonnet-4-6"]),
            )])),
            worker_backends: HashMap::from([(Provider::Anthropic, "direct".to_owned())]),
            bedrock_policy_image_capable: false,
        };

        let selected = models_for_target(
            &target,
            &Provider::Anthropic,
            catalog.models_for(&Provider::Anthropic),
        )
        .expect("direct worker coverage");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].model.wire_model(), "claude-sonnet-4-6");
    }

    #[test]
    fn bedrock_worker_probes_a_registry_approved_future_model() {
        let target = StreamingTarget {
            endpoint: "https://worker.example.org".to_owned(),
            node_secret: "secret".to_owned(),
            provider_models: None,
            worker_backends: HashMap::from([(Provider::Anthropic, "bedrock".to_owned())]),
            bedrock_policy_image_capable: false,
        };
        let selected = models_for_target(
            &target,
            &Provider::Anthropic,
            vec![ProbeModel {
                canonical: TEST_APPROVED_BEDROCK_MODEL.to_owned(),
                upstream: Some("anthropic.operator-mapping-must-be-ignored".to_owned()),
                fallback: false,
                binding_revision: Some(23),
            }],
        )
        .expect("registry-approved Bedrock binding");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].model.wire_model(), TEST_APPROVED_BEDROCK_MODEL);
        let probe = build_probe(Provider::Anthropic, &selected[0].model, None);
        assert_eq!(probe.body["model"], TEST_APPROVED_BEDROCK_MODEL);
        assert_eq!(probe.model_binding_revision, Some(23));
    }

    #[test]
    fn bedrock_response_must_echo_one_exact_selected_binding_revision() {
        use reqwest::header::{HeaderMap, HeaderValue};

        let mut headers = HeaderMap::new();
        assert!(!response_confirms_binding_revision(&headers, 23));
        headers.insert(
            MODEL_BINDING_REVISION_HEADER,
            HeaderValue::from_static("24"),
        );
        assert!(!response_confirms_binding_revision(&headers, 23));
        headers.insert(
            MODEL_BINDING_REVISION_HEADER,
            HeaderValue::from_static("23"),
        );
        assert!(response_confirms_binding_revision(&headers, 23));
        headers.append(
            MODEL_BINDING_REVISION_HEADER,
            HeaderValue::from_static("23"),
        );
        assert!(!response_confirms_binding_revision(&headers, 23));
    }

    #[test]
    fn cli_discovers_future_bedrock_models_and_keeps_the_registry_row_revision() {
        let binding = BedrockModelBinding {
            model: TEST_APPROVED_BEDROCK_MODEL.to_owned(),
            upstream_model: "anthropic.future-system-id-v1".to_owned(),
            response_model: "future-provider-echo".to_owned(),
            revision: 29,
        };
        let discovered =
            bedrock_probe_models(&[binding], &[TEST_APPROVED_BEDROCK_MODEL.to_owned()]);
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].canonical, TEST_APPROVED_BEDROCK_MODEL);
        assert_eq!(discovered[0].binding_revision, Some(29));
        assert_eq!(discovered[0].upstream, None);
    }

    #[test]
    fn bedrock_worker_rejects_models_without_registry_binding_revisions() {
        let target = StreamingTarget {
            endpoint: "https://worker.example.org".to_owned(),
            node_secret: "secret".to_owned(),
            provider_models: None,
            worker_backends: HashMap::from([(Provider::Anthropic, "bedrock".to_owned())]),
            bedrock_policy_image_capable: false,
        };
        let rejected = [
            ProbeModel {
                canonical: "future-approved-model".to_owned(),
                upstream: Some("anthropic.operator-selector".to_owned()),
                fallback: false,
                binding_revision: None,
            },
            ProbeModel {
                canonical: "unreviewed-model".to_owned(),
                upstream: Some("unreviewed-model".to_owned()),
                fallback: false,
                binding_revision: None,
            },
            ProbeModel {
                canonical: "another-unreviewed-model".to_owned(),
                upstream: Some("anthropic.other-selector".to_owned()),
                fallback: false,
                binding_revision: None,
            },
        ];
        let selected = models_for_target(&target, &Provider::Anthropic, rejected.into())
            .expect("unverified Bedrock bindings are reported without probing");
        assert!(selected.is_empty());
    }

    #[test]
    fn unsupported_cloud_bindings_are_unverified_without_a_probe() {
        for (provider, backend, model, upstream) in [
            (Provider::OpenAI, "azure", "gpt-5.6", "deployment-gpt-56"),
            (
                Provider::Anthropic,
                "foundry",
                "claude-sonnet-4-6",
                "foundry-deployment",
            ),
            (
                Provider::Anthropic,
                "bedrock",
                "unreviewed-bedrock-model",
                "anthropic.operator-selector",
            ),
        ] {
            let target = StreamingTarget {
                endpoint: "https://worker.example.org".to_owned(),
                node_secret: "secret".to_owned(),
                provider_models: Some(HashMap::from([(
                    provider.clone(),
                    unscoped_coverage(&[model]),
                )])),
                worker_backends: HashMap::from([(provider.clone(), backend.to_owned())]),
                bedrock_policy_image_capable: false,
            };
            let models = vec![ProbeModel {
                canonical: model.to_owned(),
                upstream: Some(upstream.to_owned()),
                fallback: false,
                binding_revision: None,
            }];

            let selected = models_for_target(&target, &provider, models)
                .expect("unverified cloud binding is reported as an empty selection");
            assert!(selected.is_empty(), "{provider}/{backend}");
        }
    }

    #[test]
    fn known_non_overlapping_worker_models_produce_an_empty_probe_set() {
        let target = StreamingTarget {
            endpoint: "https://worker.example.org".to_owned(),
            node_secret: "secret".to_owned(),
            provider_models: Some(HashMap::from([(
                Provider::Engy,
                unscoped_coverage(&["qwen3.8-27b"]),
            )])),
            worker_backends: HashMap::new(),
            bedrock_policy_image_capable: false,
        };
        let fallback = vec![ProbeModel {
            canonical: "glm-5.2".to_owned(),
            upstream: None,
            fallback: true,
            binding_revision: None,
        }];

        let selected =
            models_for_target(&target, &Provider::Engy, fallback).expect("known coverage");
        assert!(selected.is_empty());
    }

    #[test]
    fn unknown_worker_ownership_never_falls_back_to_current_config() {
        let target = StreamingTarget {
            endpoint: "https://worker.example.org".to_owned(),
            node_secret: "secret".to_owned(),
            provider_models: Some(HashMap::new()),
            worker_backends: HashMap::new(),
            bedrock_policy_image_capable: false,
        };
        assert_eq!(
            providers_for_target(&[Provider::Engy], &target),
            [] as [gm_miner_cli::types::Provider; 0]
        );
    }

    #[test]
    fn declaration_outage_warning_covers_every_sourcing_provider() {
        assert_eq!(
            sourcing_providers(),
            [
                Provider::DeepInfra,
                Provider::Engy,
                Provider::Kubetee,
                Provider::Moonmath,
                Provider::Near,
            ]
        );
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
