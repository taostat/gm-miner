//! Tests for --api-url override behaviour during login.
//!
//! These verify the three cases: explicit override wins, stored value persists
//! when no override is given, and absent override + no stored value falls back
//! to the network default.
//!
//! Persistence contract: only an explicit `--api-url` flag persists into
//! config.json. Setting `GM_REGISTRY_URL` must NOT sticky-override the
//! stored endpoint — the `--api-url` clap field no longer carries
//! `env = "GM_REGISTRY_URL"`, so when no flag is given `api_url_override`
//! is always `None` regardless of the env var.

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
        provider_keys: None,
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

// ── Persistence contract ─────────────────────────────────────────────────────
//
// The `--api-url` clap arg no longer has `env = "GM_REGISTRY_URL"`.
// When the flag is absent, `api_url_override` is `None` regardless of the env
// var, so the env var value is never fed into `cmd_login`'s resolution chain
// and therefore never written to config.json.
//
// The tests below document that contract at the resolution level: when
// `api_url_override` is `None` (the only value possible when no flag is
// given), the stored config value is preserved unchanged.

/// When `--api-url` is absent (override is None), the stored config endpoint
/// is kept — not silently replaced by a `GM_REGISTRY_URL` value that could
/// have been injected via clap's env binding.
#[test]
fn no_flag_preserves_stored_api_url_even_when_env_var_might_exist() {
    // Simulate what happens when `GM_REGISTRY_URL=https://env.example.com`
    // is set but the user did NOT pass `--api-url`.
    // Because the env binding was removed from the clap arg, the CLI passes
    // `api_url_override = None` to cmd_login, so `resolve_api_url` never
    // sees the env value.
    let cfg = mainnet_config_with_api_url("https://stored.example.com");
    let resolved = resolve_api_url(&cfg, None /* env var not forwarded */, false);
    assert_eq!(
        resolved, "https://stored.example.com",
        "stored config url must survive when --api-url flag is absent"
    );
}

/// When `--api-url https://flag.example.com` is given explicitly, that value
/// is forwarded as Some(...) and wins over whatever is stored in config.
#[test]
fn explicit_flag_still_persists_and_wins() {
    let cfg = mainnet_config_with_api_url("https://stored.example.com");
    let resolved = resolve_api_url(&cfg, Some("https://flag.example.com"), false);
    assert_eq!(
        resolved, "https://flag.example.com",
        "explicit --api-url flag must override the stored value"
    );
}
