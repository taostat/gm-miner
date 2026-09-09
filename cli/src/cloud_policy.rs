//! Cloud model-ID compatibility and transport-selection helpers.
//!
//! Cloud adapters now carry their canonical-to-deployment data through the
//! measured image hop, but the separate registry/gateway response-echo check
//! still owns routing admission. Keep these helpers together so diagnostics
//! and bulk-declaration guidance do not confuse transport capability with the
//! feature-fenced model identity check.

use crate::config::{Config, WorkerRecord};

/// The only Bedrock model-ID tuple currently covered by registry normalization.
/// This does not authorize the worker's cloud transport.
pub const REVIEWED_BEDROCK_PROVIDER: &str = "anthropic";
pub const REVIEWED_BEDROCK_MODEL: &str = "claude-sonnet-4-6";
pub const REVIEWED_BEDROCK_UPSTREAM_MODEL: &str = "anthropic.claude-sonnet-4-6-v1";
/// Legacy AWS Bedrock model id accepted from offers written before Mantle
/// model ids were canonicalized. It normalizes to [`REVIEWED_BEDROCK_UPSTREAM_MODEL`]
/// only for the exact reviewed provider/model pair.
pub const LEGACY_BEDROCK_UPSTREAM_MODEL: &str = "us.anthropic.claude-sonnet-4-6-v1";

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

/// Whether declarations for `provider` must use the registry's cloud-model
/// capability fence.
///
/// The decision is the union of the current selectors and every locally
/// recorded worker's provenance. A worker with unknown provenance is treated
/// as cloud-backed conservatively.
#[must_use]
pub fn cloud_fence_required_for_provider(config: &Config, provider: &str) -> bool {
    configured_cloud_backend(config, provider).is_some()
        || config
            .active_network_entry()
            .into_iter()
            .flat_map(|network| network.workers.iter())
            .any(|worker| recorded_worker_requires_cloud_fence(worker, provider))
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
    fn declaration_fence_unions_selectors_recorded_and_unknown_provenance() {
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

        assert!(cloud_fence_required_for_provider(&config, "anthropic"));
        assert!(cloud_fence_required_for_provider(&config, "openai"));
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
        assert!(!cloud_fence_required_for_provider(&config, "anthropic"));
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
