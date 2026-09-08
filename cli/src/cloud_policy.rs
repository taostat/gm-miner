//! Cloud model-ID compatibility and transport-selection helpers.
//!
//! Cloud adapters prove that a worker can speak a provider's transport. They
//! do not, by themselves, prove that the registry has an authoritative model
//! binding for the route or which backend is actually used. All cloud
//! transports remain unavailable for routing pending independent provenance.
//! Keep these helpers together so diagnostics and bulk-declaration guidance
//! do not confuse model-ID compatibility with transport admission.

use crate::config::Config;

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
}
