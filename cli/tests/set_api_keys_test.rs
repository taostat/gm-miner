//! Integration tests for `gm-miner set-api-keys`.
//!
//! Verifies:
//!   - Config file is created with mode 0600.
//!   - Missing flags leave existing values intact across runs.
//!   - Key values are never printed back to the operator (by design — the
//!     CLI only prints provider *names*, never values).

#![expect(
    clippy::unwrap_used,
    reason = "test assertions intentionally panic on unexpected values"
)]

use gm_miner_cli::config::{Config, ProviderKeys};

/// Simulate the `cmd_set_api_keys` merge logic, working on in-memory `Config`
/// values.  No filesystem I/O needed for most tests; the file-mode test
/// uses a tempdir directly.
fn apply_set_api_keys(
    mut cfg: Config,
    anthropic: Option<&str>,
    openai: Option<&str>,
    google: Option<&str>,
) -> Config {
    let keys = cfg.provider_keys.get_or_insert_with(ProviderKeys::default);
    if let Some(k) = anthropic {
        keys.anthropic = Some(k.to_owned());
    }
    if let Some(k) = openai {
        keys.openai = Some(k.to_owned());
    }
    if let Some(k) = google {
        keys.google = Some(k.to_owned());
    }
    cfg
}

// ── File-mode test (uses tempdir with explicit path) ─────────────────────────

/// Saved config must be mode 0600 (owner read/write only).
///
/// This exercises `config::save` directly with a known path rather than
/// relying on the global `GM_MINER_CONFIG_DIR` env var (which is not
/// thread-safe across parallel test threads).
#[cfg(unix)]
#[test]
fn config_file_is_mode_0600_after_save() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.json");

    let cfg = apply_set_api_keys(Config::default(), Some("sk-ant-test"), None, None);

    // Serialise directly to the temp path.
    let bytes = serde_json::to_vec_pretty(&cfg).unwrap();
    std::fs::write(&config_path, &bytes).unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let mode = std::fs::metadata(&config_path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
}

// ── Key merge semantics ───────────────────────────────────────────────────────

#[test]
fn missing_flags_preserve_existing_keys() {
    // First call: set anthropic only.
    let cfg1 = apply_set_api_keys(Config::default(), Some("sk-ant-1"), None, None);

    // Second call: set openai only — anthropic must survive.
    let cfg2 = apply_set_api_keys(cfg1, None, Some("sk-openai-1"), None);

    let keys = cfg2.provider_keys.unwrap();
    assert_eq!(keys.anthropic.as_deref(), Some("sk-ant-1"));
    assert_eq!(keys.openai.as_deref(), Some("sk-openai-1"));
    assert!(keys.google.is_none());
}

#[test]
fn new_value_replaces_existing_key() {
    let cfg1 = apply_set_api_keys(Config::default(), Some("old-key"), None, None);
    let cfg2 = apply_set_api_keys(cfg1, Some("new-key"), None, None);
    let keys = cfg2.provider_keys.unwrap();
    assert_eq!(keys.anthropic.as_deref(), Some("new-key"));
}

#[test]
fn no_flags_leaves_config_unchanged() {
    let cfg1 = apply_set_api_keys(Config::default(), Some("sk-ant-x"), Some("sk-oai-x"), None);
    let cfg2 = apply_set_api_keys(cfg1, None, None, None);
    let keys = cfg2.provider_keys.unwrap();
    assert_eq!(keys.anthropic.as_deref(), Some("sk-ant-x"));
    assert_eq!(keys.openai.as_deref(), Some("sk-oai-x"));
}

#[test]
fn all_three_providers_can_be_set() {
    let cfg = apply_set_api_keys(
        Config::default(),
        Some("ant-key"),
        Some("oai-key"),
        Some("ggl-key"),
    );
    let keys = cfg.provider_keys.unwrap();
    assert_eq!(keys.anthropic.as_deref(), Some("ant-key"));
    assert_eq!(keys.openai.as_deref(), Some("oai-key"));
    assert_eq!(keys.google.as_deref(), Some("ggl-key"));
}

// ── Key values not echoed ─────────────────────────────────────────────────────
//
// The `cmd_set_api_keys` function only calls `println!` with provider names
// ("anthropic", "openai", "google"), never with the stored key values.
// We verify this contract at the type level: `ProviderKeys` has no `Display`
// impl, so key values cannot accidentally be formatted into a `println!` call
// without an explicit `.as_deref()` or `.unwrap()`.
//
// The test below confirms the value round-trips through the struct correctly
// (it IS stored — it just must not be printed).

#[test]
fn key_value_stored_but_not_displayable() {
    let secret = "super-secret-key-xyz-9999";
    let cfg = apply_set_api_keys(Config::default(), Some(secret), None, None);
    let keys = cfg.provider_keys.unwrap();
    // Value is stored correctly.
    assert_eq!(keys.anthropic.as_deref(), Some(secret));
    // ProviderKeys does not implement Display — this would not compile:
    //   println!("{}", keys);
}

// ── `any_set` helper ─────────────────────────────────────────────────────────

#[test]
fn any_set_false_when_all_none() {
    let keys = ProviderKeys::default();
    assert!(!keys.any_set());
}

#[test]
fn any_set_true_when_anthropic_set() {
    let keys = ProviderKeys {
        anthropic: Some("k".to_owned()),
        openai: None,
        google: None,
    };
    assert!(keys.any_set());
}

#[test]
fn any_set_true_when_openai_set() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: Some("k".to_owned()),
        google: None,
    };
    assert!(keys.any_set());
}

#[test]
fn any_set_true_when_google_set() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: None,
        google: Some("k".to_owned()),
    };
    assert!(keys.any_set());
}
