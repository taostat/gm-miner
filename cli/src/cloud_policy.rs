//! Cloud model-ID compatibility and transport-selection helpers.
//!
//! Cloud adapters now carry their canonical-to-deployment data through the
//! measured image hop, but the separate registry/gateway response-echo check
//! still owns routing admission. Keep these helpers together so diagnostics
//! and bulk-declaration guidance do not confuse transport capability with the
//! feature-fenced model identity check.

use anyhow::{Context as _, Result};

use crate::{
    client::{RegistryClient, ME_PATH},
    config::{Config, WorkerRecord},
    deploy::{fetch_supported_versions, normalize_hash},
    types::{MinerStatus, WorkerEntry, WorkerListResponse},
};

/// The only Bedrock model-ID tuple currently covered by registry normalization.
/// This does not authorize the worker's cloud transport.
pub const REVIEWED_BEDROCK_PROVIDER: &str = "anthropic";
pub const REVIEWED_BEDROCK_MODEL: &str = "claude-sonnet-4-6";
pub const REVIEWED_BEDROCK_UPSTREAM_MODEL: &str = "anthropic.claude-sonnet-4-6-v1";
/// Legacy AWS Bedrock model id accepted from offers written before Mantle
/// model ids were canonicalized. It normalizes to [`REVIEWED_BEDROCK_UPSTREAM_MODEL`]
/// only for the exact reviewed provider/model pair.
pub const LEGACY_BEDROCK_UPSTREAM_MODEL: &str = "us.anthropic.claude-sonnet-4-6-v1";

/// The declaration decision has two independent consequences. A live worker
/// may need the registry's model-echo compatibility check while still being
/// a known-direct worker that is safe to keep in a bulk declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloudDeclarationPolicy {
    pub requires_capability: bool,
    pub exclude_from_bulk: bool,
}

impl CloudDeclarationPolicy {
    const DIRECT: Self = Self {
        requires_capability: false,
        exclude_from_bulk: false,
    };

    const FENCED: Self = Self {
        requires_capability: true,
        exclude_from_bulk: true,
    };

    const FENCED_BUT_DIRECT: Self = Self {
        requires_capability: true,
        exclude_from_bulk: false,
    };
}

/// Normalize an accepted Bedrock model id to the current Mantle id.
///
/// Returning `None` is intentional for every other model/provider/id
/// combination: transport compatibility alone is not an admission binding.
#[must_use]
pub fn normalize_bedrock_upstream_model(
    provider: &str,
    model: &str,
    upstream_model: &str,
) -> Option<&'static str> {
    if provider == REVIEWED_BEDROCK_PROVIDER
        && model == REVIEWED_BEDROCK_MODEL
        && matches!(
            upstream_model,
            REVIEWED_BEDROCK_UPSTREAM_MODEL | LEGACY_BEDROCK_UPSTREAM_MODEL
        )
    {
        Some(REVIEWED_BEDROCK_UPSTREAM_MODEL)
    } else {
        None
    }
}

/// Return true only for the exact Bedrock provider/model/upstream tuple the
/// registry recognizes for legacy diagnostics. This is not routing admission;
/// the worker's actual backend also needs independently verified provenance.
#[must_use]
pub fn is_reviewed_bedrock_binding(provider: &str, model: &str, upstream_model: &str) -> bool {
    normalize_bedrock_upstream_model(provider, model, upstream_model)
        == Some(REVIEWED_BEDROCK_UPSTREAM_MODEL)
}

/// The explicitly selected cloud adapter for `provider` in the local config.
/// Historical worker records do not establish the current provider-wide
/// selection: a hotkey may have direct siblings or workers created elsewhere.
/// The registry remains authoritative for per-worker admission.
#[must_use]
pub fn configured_cloud_backend(config: &Config, provider: &str) -> Option<&'static str> {
    let selector = config
        .provider_keys
        .as_ref()
        .and_then(|keys| match provider {
            "anthropic" => keys.anthropic_upstream.as_deref(),
            "openai" => keys.openai_upstream.as_deref(),
            _ => None,
        });

    match (provider, selector) {
        ("anthropic", Some("bedrock")) => Some("bedrock"),
        ("anthropic", Some("foundry")) => Some("foundry"),
        ("openai", Some("azure")) => Some("azure"),
        _ => None,
    }
}

/// Whether one recorded worker requires the cloud capability fence for a
/// provider-specific declaration.
///
/// `None` is deliberately treated as unknown provenance, not as direct
/// provenance. Older records and records written by a different CLI version
/// may omit the map, so allowing them through would recreate the selector
/// bypass this fence is meant to close.
#[must_use]
pub fn recorded_worker_requires_cloud_fence(record: &WorkerRecord, provider: &str) -> bool {
    record
        .backends
        .as_ref()
        .is_none_or(|backends| backends.contains_key(provider))
}

/// Resolve the live worker/image provenance needed before treating a
/// declaration as direct-only.
///
/// A local empty worker list is not evidence that the hotkey has no cloud
/// worker. The registry's live list and its approved image feature stamps are
/// therefore consulted on every otherwise-unfenced declaration. Any missing
/// link in that chain is conservative: the registry capability fence is
/// required and bulk declaration omits the affected provider.
pub async fn declaration_policy(
    client: &mut RegistryClient,
    provider: &str,
) -> CloudDeclarationPolicy {
    if !matches!(provider, "anthropic" | "openai") {
        return CloudDeclarationPolicy::DIRECT;
    }
    if has_explicit_cloud_provenance(&client.config, provider) {
        return CloudDeclarationPolicy::FENCED;
    }

    let has_unknown_local_worker = client
        .config
        .active_network_entry()
        .into_iter()
        .flat_map(|network| network.workers.iter())
        .any(|worker| worker.backends.is_none());
    let live_workers = match fetch_live_workers(client).await {
        Ok(Some(workers)) => workers,
        Ok(None) => {
            return if has_unknown_local_worker {
                CloudDeclarationPolicy::FENCED
            } else {
                CloudDeclarationPolicy::DIRECT
            }
        }
        Err(err) => {
            tracing::warn!(provider, error = %err, "could not resolve live worker provenance");
            return CloudDeclarationPolicy::FENCED;
        }
    };

    if live_workers.is_empty() {
        // The registry answered authoritatively that this hotkey has no live
        // worker. A legacy local record still leaves the old worker's
        // provenance unresolved, so it remains fenced until that record is
        // replaced by a deployment with an explicit backend map.
        return if has_unknown_local_worker {
            CloudDeclarationPolicy::FENCED
        } else {
            CloudDeclarationPolicy::DIRECT
        };
    }

    let versions = match fetch_supported_versions(&client.config.api_url()).await {
        Ok(versions) => versions,
        Err(err) => {
            tracing::warn!(provider, error = %err, "could not resolve live worker image provenance");
            return CloudDeclarationPolicy::FENCED;
        }
    };
    let local_workers = client
        .config
        .active_network_entry()
        .map_or(&[][..], |network| network.workers.as_slice());

    let mut has_unknown_provenance = false;
    let mut has_cloud_provenance = false;
    let mut has_binding_image = false;

    for live_worker in &live_workers {
        let image = live_worker.image_compose_hash.as_deref().and_then(|hash| {
            versions
                .iter()
                .find(|version| normalize_hash(&version.compose_hash) == normalize_hash(hash))
        });
        let Some(image) = image else {
            has_unknown_provenance = true;
            continue;
        };
        has_binding_image |= image.cloud_binding_capable();

        let Some(local_worker) = local_workers
            .iter()
            .find(|worker| worker.worker_id == live_worker.worker_id)
        else {
            has_unknown_provenance = true;
            continue;
        };
        has_cloud_provenance |= recorded_worker_requires_cloud_fence(local_worker, provider);
    }

    if has_cloud_provenance || has_unknown_provenance {
        return CloudDeclarationPolicy::FENCED;
    }
    if has_binding_image {
        // A direct worker on a cloud-binding-capable image needs the model-echo fence, but it
        // remains direct supply and must not disappear from a bulk set.
        return CloudDeclarationPolicy::FENCED_BUT_DIRECT;
    }
    CloudDeclarationPolicy::DIRECT
}

fn has_explicit_cloud_provenance(config: &Config, provider: &str) -> bool {
    configured_cloud_backend(config, provider).is_some()
        || config
            .active_network_entry()
            .into_iter()
            .flat_map(|network| network.workers.iter())
            .any(|worker| {
                worker
                    .backends
                    .as_ref()
                    .is_some_and(|backends| backends.contains_key(provider))
            })
}

/// Fetch the registry's live workers. A missing miner row means no worker has
/// ever been registered; a missing worker endpoint for an existing miner is
/// an unresolved provenance error, not proof of an empty worker list.
async fn fetch_live_workers(client: &mut RegistryClient) -> Result<Option<Vec<WorkerEntry>>> {
    let response = client.get(ME_PATH).await.context("GET /miners/me")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("GET /miners/me failed ({status}): {body}");
    }
    let miner: MinerStatus = response.json().await.context("parse /miners/me response")?;
    let path = format!("/miners/{}/workers", miner.hotkey);
    let response = client.get(&path).await.context("GET live workers")?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("GET {path} failed ({status}): {body}");
    }
    let workers: WorkerListResponse = response
        .json()
        .await
        .with_context(|| format!("parse {path} response"))?;
    Ok(Some(workers.workers))
}

/// Whether registering or re-registering the named worker must pass the
/// registry's cloud-model capability fence.
#[must_use]
pub fn cloud_fence_required_for_worker(
    config: &Config,
    app_name: &str,
    current_backends: &std::collections::BTreeMap<String, String>,
) -> bool {
    config
        .provider_keys
        .as_ref()
        .is_some_and(|keys| !keys.worker_backends().is_empty())
        || !current_backends.is_empty()
        || config
            .active_network_entry()
            .and_then(|network| network.worker_by_app_name(app_name))
            .is_some_and(|worker| {
                worker
                    .backends
                    .as_ref()
                    .is_none_or(|backends| !backends.is_empty())
            })
}

/// Whether `register-image` recovery must pass the cloud-model capability
/// fence. An untracked worker has unknown provenance and is therefore fenced.
#[must_use]
pub fn cloud_fence_required_for_image_recovery(
    config: &Config,
    record: Option<&WorkerRecord>,
) -> bool {
    config
        .provider_keys
        .as_ref()
        .is_some_and(|keys| !keys.worker_backends().is_empty())
        || record.is_none_or(|worker| {
            worker
                .backends
                .as_ref()
                .is_none_or(|backends| !backends.is_empty())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, NetworkEntry, ProviderKeys, WorkerRecord};
    use std::collections::{BTreeMap, HashMap};

    #[test]
    fn only_the_reviewed_bedrock_tuple_is_recognized() {
        assert!(is_reviewed_bedrock_binding(
            "anthropic",
            "claude-sonnet-4-6",
            "anthropic.claude-sonnet-4-6-v1"
        ));
        assert!(!is_reviewed_bedrock_binding(
            "anthropic",
            "claude-sonnet-4-6",
            "anthropic.claude-sonnet-4-6-v2"
        ));
        assert!(!is_reviewed_bedrock_binding(
            "anthropic",
            "claude-opus-4-7",
            "anthropic.claude-sonnet-4-6-v1"
        ));
        assert!(!is_reviewed_bedrock_binding(
            "openai",
            "claude-sonnet-4-6",
            "anthropic.claude-sonnet-4-6-v1"
        ));
    }

    #[test]
    fn legacy_reviewed_bedrock_id_normalizes_to_the_mantle_id() {
        assert_eq!(
            normalize_bedrock_upstream_model(
                "anthropic",
                "claude-sonnet-4-6",
                LEGACY_BEDROCK_UPSTREAM_MODEL,
            ),
            Some(REVIEWED_BEDROCK_UPSTREAM_MODEL)
        );
        assert_eq!(
            normalize_bedrock_upstream_model(
                "anthropic",
                "claude-opus-4-7",
                LEGACY_BEDROCK_UPSTREAM_MODEL,
            ),
            None
        );
    }

    #[test]
    fn selected_cloud_adapter_blocks_bulk_supply() {
        let config = Config {
            provider_keys: Some(ProviderKeys {
                anthropic_upstream: Some("foundry".to_owned()),
                openai_upstream: Some("azure".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            configured_cloud_backend(&config, "anthropic"),
            Some("foundry")
        );
        assert_eq!(configured_cloud_backend(&config, "openai"), Some("azure"));
    }

    #[test]
    fn explicit_direct_selector_restores_direct_behavior() {
        let config = Config {
            provider_keys: Some(ProviderKeys {
                anthropic_upstream: Some("direct".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(configured_cloud_backend(&config, "anthropic"), None);
    }

    #[test]
    fn historical_cloud_worker_does_not_establish_current_selection() {
        let mut networks = HashMap::new();
        networks.insert(
            "mainnet".to_owned(),
            NetworkEntry {
                workers: vec![WorkerRecord {
                    backends: Some(BTreeMap::from([(
                        "anthropic".to_owned(),
                        "bedrock".to_owned(),
                    )])),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let config = Config {
            networks,
            ..Default::default()
        };
        assert_eq!(configured_cloud_backend(&config, "anthropic"), None);
    }

    #[test]
    fn mixed_worker_history_does_not_hide_direct_bulk_supply() {
        let config = Config {
            networks: HashMap::from([(
                "mainnet".to_owned(),
                NetworkEntry {
                    workers: vec![
                        WorkerRecord {
                            backends: Some(BTreeMap::from([
                                ("anthropic".to_owned(), "foundry".to_owned()),
                                ("openai".to_owned(), "azure".to_owned()),
                            ])),
                            ..Default::default()
                        },
                        WorkerRecord::default(),
                    ],
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        assert_eq!(configured_cloud_backend(&config, "anthropic"), None);
        assert_eq!(configured_cloud_backend(&config, "openai"), None);
    }

    #[test]
    fn recorded_worker_fence_includes_unknown_provenance() {
        let config = Config {
            provider_keys: Some(ProviderKeys {
                anthropic_upstream: Some("direct".to_owned()),
                ..Default::default()
            }),
            networks: HashMap::from([(
                "mainnet".to_owned(),
                NetworkEntry {
                    workers: vec![
                        WorkerRecord {
                            backends: Some(BTreeMap::from([(
                                "openai".to_owned(),
                                "azure".to_owned(),
                            )])),
                            ..Default::default()
                        },
                        WorkerRecord::default(),
                    ],
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let workers = &config.networks["mainnet"].workers;
        assert!(!recorded_worker_requires_cloud_fence(
            &workers[0],
            "anthropic"
        ));
        assert!(recorded_worker_requires_cloud_fence(&workers[0], "openai"));
        assert!(recorded_worker_requires_cloud_fence(
            &workers[1],
            "anthropic"
        ));
        assert!(recorded_worker_requires_cloud_fence(&workers[1], "openai"));
    }

    #[test]
    fn known_direct_worker_and_direct_selector_are_not_cloud() {
        let config = Config {
            active_network: Some("mainnet".to_owned()),
            provider_keys: Some(ProviderKeys {
                anthropic_upstream: Some("direct".to_owned()),
                ..Default::default()
            }),
            networks: HashMap::from([(
                "mainnet".to_owned(),
                NetworkEntry {
                    workers: vec![WorkerRecord {
                        backends: Some(BTreeMap::new()),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        assert!(!cloud_fence_required_for_worker(
            &config,
            "worker",
            &BTreeMap::new()
        ));
    }

    #[test]
    fn worker_registration_fence_covers_recorded_cloud_and_unknown_sources() {
        let recorded_cloud = WorkerRecord {
            app_name: "cloud".to_owned(),
            backends: Some(BTreeMap::from([("openai".to_owned(), "azure".to_owned())])),
            ..Default::default()
        };
        let unknown = WorkerRecord {
            app_name: "unknown".to_owned(),
            ..Default::default()
        };
        let config = Config {
            active_network: Some("mainnet".to_owned()),
            networks: HashMap::from([(
                "mainnet".to_owned(),
                NetworkEntry {
                    workers: vec![recorded_cloud, unknown],
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        assert!(cloud_fence_required_for_worker(
            &config,
            "cloud",
            &BTreeMap::new()
        ));
        assert!(cloud_fence_required_for_worker(
            &config,
            "unknown",
            &BTreeMap::new()
        ));
        assert!(cloud_fence_required_for_worker(
            &config,
            "new",
            &BTreeMap::from([("anthropic".to_owned(), "foundry".to_owned())])
        ));
    }

    #[test]
    fn worker_registration_fence_includes_current_cloud_selector() {
        let config = Config {
            provider_keys: Some(ProviderKeys {
                openai_upstream: Some("azure".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(cloud_fence_required_for_worker(
            &config,
            "new",
            &BTreeMap::new()
        ));
    }

    #[test]
    fn image_recovery_fences_unknown_record_and_current_cloud_selector() {
        let direct = Config {
            provider_keys: Some(ProviderKeys::default()),
            ..Default::default()
        };
        let known_direct = WorkerRecord {
            backends: Some(BTreeMap::new()),
            ..Default::default()
        };
        assert!(cloud_fence_required_for_image_recovery(&direct, None));
        assert!(!cloud_fence_required_for_image_recovery(
            &direct,
            Some(&known_direct)
        ));

        let cloud = Config {
            provider_keys: Some(ProviderKeys {
                openai_upstream: Some("azure".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(cloud_fence_required_for_image_recovery(
            &cloud,
            Some(&known_direct)
        ));
    }
}
