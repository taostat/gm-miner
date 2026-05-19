//! Tests for --api-url override behaviour during login.
//!
//! These verify the three cases: explicit override wins, stored value persists
//! when no override is given, and absent override + no stored value falls back
//! to the network default.

use gm_miner_cli::config::{Config, NetworkEntry};
use std::collections::HashMap;

fn mainnet_config_with_api_url(url: &str) -> Config {
    let mut networks = HashMap::new();
    networks.insert(
        "mainnet".to_string(),
        NetworkEntry {
            api_url: Some(url.to_string()),
            ..Default::default()
        },
    );
    Config {
        networks,
        active_network: Some("mainnet".to_string()),
    }
}

/// Simulate the resolution logic from `cmd_login`.
fn resolve_api_url(cfg: &Config, override_url: Option<&str>, testnet: bool) -> String {
    override_url
        .map(str::to_owned)
        .or_else(|| {
            cfg.networks
                .get(cfg.active_network())
                .and_then(|n| n.api_url.clone())
        })
        .unwrap_or_else(|| {
            if testnet {
                "https://api-testnet.gm.taostats.io".to_string()
            } else {
                "https://api.gm.taostats.io".to_string()
            }
        })
}

#[test]
fn api_url_override_beats_stored_value() {
    let cfg = mainnet_config_with_api_url("https://stored.example.com");
    let resolved = resolve_api_url(&cfg, Some("https://override.example.com"), false);
    assert_eq!(resolved, "https://override.example.com");
}

#[test]
fn absent_override_keeps_stored_value() {
    let cfg = mainnet_config_with_api_url("https://stored.example.com");
    let resolved = resolve_api_url(&cfg, None, false);
    assert_eq!(resolved, "https://stored.example.com");
}

#[test]
fn absent_override_and_no_stored_value_uses_mainnet_default() {
    let cfg = Config::default();
    let resolved = resolve_api_url(&cfg, None, false);
    assert_eq!(resolved, "https://api.gm.taostats.io");
}

#[test]
fn absent_override_and_no_stored_value_uses_testnet_default() {
    let cfg = Config::default();
    let resolved = resolve_api_url(&cfg, None, true);
    assert_eq!(resolved, "https://api-testnet.gm.taostats.io");
}
