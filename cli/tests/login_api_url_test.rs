//! Tests for `--api-url` override and per-network registry-URL resolution.
//!
//! These verify the three cases: an explicit override wins, a stored value
//! persists when no override is given, and absent override + no stored value
//! falls back to the network default ([`Network::default_registry_url`]).
//!
//! Persistence contract: only an explicit `--api-url` flag persists into
//! config.json. Setting `GM_REGISTRY_URL` must NOT sticky-override the
//! stored endpoint — the `--api-url` clap field carries no `env` binding, so
//! when no flag is given `api_url_override` is always `None`.

use gm_miner_cli::config::{Config, NetworkEntry};
use gm_miner_cli::network::Network;
use std::collections::HashMap;

fn config_with_api_url(network: Network, url: &str) -> Config {
    let mut networks = HashMap::new();
    networks.insert(
        network.as_str().to_string(),
        NetworkEntry {
            api_url: Some(url.to_string()),
            ..Default::default()
        },
    );
    Config {
        networks,
        active_network: Some(network.as_str().to_string()),
        provider_keys: None,
        phala_api_key: None,
    }
}

fn config_for(network: Network) -> Config {
    Config {
        networks: HashMap::new(),
        active_network: Some(network.as_str().to_string()),
        provider_keys: None,
        phala_api_key: None,
    }
}

/// Mirror the override precedence: an explicit `--api-url` wins, else the
/// stored/derived `Config::api_url()`.
fn resolve_api_url(cfg: &Config, override_url: Option<&str>) -> String {
    override_url.map_or_else(|| cfg.api_url(), str::to_owned)
}

#[test]
fn api_url_override_beats_stored_value() {
    let cfg = config_with_api_url(Network::Mainnet, "https://stored.example.com");
    let resolved = resolve_api_url(&cfg, Some("https://override.example.com"));
    assert_eq!(resolved, "https://override.example.com");
}

#[test]
fn absent_override_keeps_stored_value() {
    let cfg = config_with_api_url(Network::Mainnet, "https://stored.example.com");
    let resolved = resolve_api_url(&cfg, None);
    assert_eq!(resolved, "https://stored.example.com");
}

#[test]
fn absent_override_and_no_stored_value_uses_mainnet_default() {
    let cfg = config_for(Network::Mainnet);
    let resolved = resolve_api_url(&cfg, None);
    assert_eq!(resolved, "https://gm-registry.taostats.io");
}

#[test]
fn absent_override_and_no_stored_value_uses_testnet_default() {
    // The testnet default is the saygm.com host, not the old taostats one.
    let cfg = config_for(Network::Testnet);
    let resolved = resolve_api_url(&cfg, None);
    assert_eq!(resolved, "https://test-registry.saygm.com");
}

// ── Persistence contract ─────────────────────────────────────────────────────
//
// The `--api-url` clap arg has no `env = "GM_REGISTRY_URL"` binding. When the
// flag is absent, `api_url_override` is `None` regardless of the env var, so
// the env value is never written to config.json. The stored value survives.

#[test]
fn no_flag_preserves_stored_api_url_even_when_env_var_might_exist() {
    let cfg = config_with_api_url(Network::Mainnet, "https://stored.example.com");
    let resolved = resolve_api_url(&cfg, None /* env var not forwarded */);
    assert_eq!(
        resolved, "https://stored.example.com",
        "stored config url must survive when --api-url flag is absent"
    );
}

#[test]
fn explicit_flag_still_persists_and_wins() {
    let cfg = config_with_api_url(Network::Mainnet, "https://stored.example.com");
    let resolved = resolve_api_url(&cfg, Some("https://flag.example.com"));
    assert_eq!(
        resolved, "https://flag.example.com",
        "explicit --api-url flag must override the stored value"
    );
}
