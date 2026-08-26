//! The registry's current cloud-provider admission boundary.
//!
//! Cloud adapters prove that a worker can speak a provider's transport. They
//! do not, by themselves, prove that the registry has an authoritative model
//! binding for the route. Keep the small amount of policy the CLI needs here
//! so command help and bulk-declaration safety do not drift apart.

use crate::config::Config;

/// The only Bedrock route currently covered by a reviewed registry binding.
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
/// registry currently admits. The adapters remain available for future
/// reviewed bindings; this predicate is deliberately narrower than transport
/// capability.
#[must_use]
pub fn is_reviewed_bedrock_binding(provider: &str, model: &str, upstream_model: &str) -> bool {
    normalize_bedrock_upstream_model(provider, model, upstream_model)
        == Some(REVIEWED_BEDROCK_UPSTREAM_MODEL)
}

/// The selected cloud adapter for `provider`, if this local config says one is
/// active. A configured `direct` selector takes precedence over old worker
/// records: changing the selector back to a direct key restores direct bulk
/// declarations while the old CVM record remains available for recovery.
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
        ("anthropic", Some("bedrock")) => return Some("bedrock"),
        ("anthropic", Some("foundry")) => return Some("foundry"),
        ("openai", Some("azure")) => return Some("azure"),
        // An explicit direct selector means the currently selected supply is
        // direct even if an older worker record used a cloud adapter.
        (_, Some("direct")) => return None,
        _ => {}
    }

    // Configs written before selectors were persisted can still identify a
    // cloud worker through its per-worker provenance map. Unknown backends are
    // intentionally ignored here; registry admission remains the authority.
    config
        .active_network_entry()
        .into_iter()
        .flat_map(|network| network.workers.iter())
        .filter_map(|worker| worker.backends.as_ref())
        .filter_map(|backends| backends.get(provider).map(String::as_str))
        .find_map(|backend| match (provider, backend) {
            ("anthropic", "bedrock") => Some("bedrock"),
            ("anthropic", "foundry") => Some("foundry"),
            ("openai", "azure") => Some("azure"),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, NetworkEntry, ProviderKeys, WorkerRecord};
    use std::collections::{BTreeMap, HashMap};

    #[test]
    fn only_the_reviewed_bedrock_tuple_is_admitted() {
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
    fn legacy_worker_provenance_is_used_without_a_selector() {
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
        assert_eq!(
            configured_cloud_backend(&config, "anthropic"),
            Some("bedrock")
        );
    }
}
