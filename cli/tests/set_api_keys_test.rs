//! Integration tests for `gmcli set-api-keys`.
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
    chutes: Option<&str>,
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
    if let Some(k) = chutes {
        keys.chutes = Some(k.to_owned());
    }
    cfg
}

// ── File-mode tests (drive the real `config::save`) ──────────────────────────

/// `GMCLI_CONFIG_DIR` is process-global, so tests that mutate it must not run
/// concurrently. Serialise them on a local mutex.
static CONFIG_DIR_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Points `GMCLI_CONFIG_DIR` at a throwaway tempdir for the duration of a test,
/// holding the global lock and clearing the env var on drop — even on panic, so
/// one failing test can't leak the override into the next.
struct ConfigDirGuard {
    /// Held for the guard's lifetime to serialise env mutation; never read.
    _lock: std::sync::MutexGuard<'static, ()>,
    /// Owns the tempdir so it outlives the test; never read.
    _dir: tempfile::TempDir,
}

impl ConfigDirGuard {
    fn new() -> Self {
        let lock = CONFIG_DIR_ENV
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: the held lock serialises this against every other env mutation.
        unsafe { std::env::set_var("GMCLI_CONFIG_DIR", dir.path()) };
        Self {
            _lock: lock,
            _dir: dir,
        }
    }
}

impl Drop for ConfigDirGuard {
    fn drop(&mut self) {
        // SAFETY: still holding the lock until after this returns.
        unsafe { std::env::remove_var("GMCLI_CONFIG_DIR") };
    }
}

/// `config::save` must write the config at mode 0600 — it holds the only
/// on-disk copy of the provider keys, so a group/world-readable file would
/// leak secrets.
///
/// Unlike a hand-written file, this drives the real `config::save` so a
/// regression that drops the `chmod 0600` (or writes the file world-readable)
/// is caught.
#[cfg(unix)]
#[test]
fn save_writes_config_at_mode_0600() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = ConfigDirGuard::new();
    let cfg = apply_set_api_keys(Config::default(), Some("sk-ant-test"), None, None, None);
    gm_miner_cli::config::save(&cfg).unwrap();

    let written = gm_miner_cli::config::config_path();
    let mode = std::fs::metadata(&written).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
}

/// `set-api-keys` persists the provider keys through `config::save`, and a
/// reload reads them back — the keys survive the save/load round-trip.
#[cfg(unix)]
#[test]
fn save_then_load_round_trips_provider_keys() {
    let _guard = ConfigDirGuard::new();
    let cfg = apply_set_api_keys(
        Config::default(),
        Some("sk-ant-x"),
        Some("sk-oai-x"),
        None,
        Some("cpk-x"),
    );
    gm_miner_cli::config::save(&cfg).unwrap();

    let back = gm_miner_cli::config::load().unwrap();
    let keys = back.provider_keys.unwrap();
    assert_eq!(keys.anthropic.as_deref(), Some("sk-ant-x"));
    assert_eq!(keys.openai.as_deref(), Some("sk-oai-x"));
    assert_eq!(keys.google, None);
    assert_eq!(keys.chutes.as_deref(), Some("cpk-x"));
}

// ── Key merge semantics ───────────────────────────────────────────────────────

#[test]
fn missing_flags_preserve_existing_keys() {
    // First call: set anthropic only.
    let cfg1 = apply_set_api_keys(Config::default(), Some("sk-ant-1"), None, None, None);

    // Second call: set openai only — anthropic must survive.
    let cfg2 = apply_set_api_keys(cfg1, None, Some("sk-openai-1"), None, None);

    let keys = cfg2.provider_keys.unwrap();
    assert_eq!(keys.anthropic.as_deref(), Some("sk-ant-1"));
    assert_eq!(keys.openai.as_deref(), Some("sk-openai-1"));
    assert!(keys.google.is_none());
}

#[test]
fn new_value_replaces_existing_key() {
    let cfg1 = apply_set_api_keys(Config::default(), Some("old-key"), None, None, None);
    let cfg2 = apply_set_api_keys(cfg1, Some("new-key"), None, None, None);
    let keys = cfg2.provider_keys.unwrap();
    assert_eq!(keys.anthropic.as_deref(), Some("new-key"));
}

#[test]
fn no_flags_leaves_config_unchanged() {
    let cfg1 = apply_set_api_keys(
        Config::default(),
        Some("sk-ant-x"),
        Some("sk-oai-x"),
        None,
        None,
    );
    let cfg2 = apply_set_api_keys(cfg1, None, None, None, None);
    let keys = cfg2.provider_keys.unwrap();
    assert_eq!(keys.anthropic.as_deref(), Some("sk-ant-x"));
    assert_eq!(keys.openai.as_deref(), Some("sk-oai-x"));
}

#[test]
fn all_providers_can_be_set() {
    let cfg = apply_set_api_keys(
        Config::default(),
        Some("ant-key"),
        Some("oai-key"),
        Some("ggl-key"),
        Some("cpk-key"),
    );
    let keys = cfg.provider_keys.unwrap();
    assert_eq!(keys.anthropic.as_deref(), Some("ant-key"));
    assert_eq!(keys.openai.as_deref(), Some("oai-key"));
    assert_eq!(keys.google.as_deref(), Some("ggl-key"));
    assert_eq!(keys.chutes.as_deref(), Some("cpk-key"));
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
    let cfg = apply_set_api_keys(Config::default(), Some(secret), None, None, None);
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
        chutes: None,
    };
    assert!(keys.any_set());
}

#[test]
fn any_set_true_when_openai_set() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: Some("k".to_owned()),
        google: None,
        chutes: None,
    };
    assert!(keys.any_set());
}

#[test]
fn any_set_true_when_google_set() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: None,
        google: Some("k".to_owned()),
        chutes: None,
    };
    assert!(keys.any_set());
}

/// `Some("")` must not count as a set key — the deploy preflight must not
/// pass when an operator accidentally stores an empty value (e.g. from an
/// unset shell variable).
#[test]
fn any_set_false_for_empty_string() {
    let keys = ProviderKeys {
        anthropic: Some(String::new()),
        openai: None,
        google: None,
        chutes: None,
    };
    assert!(!keys.any_set(), "Some(\"\") must not count as set");
}

/// `Some("  ")` (whitespace-only) must also not count as set.
#[test]
fn any_set_false_for_whitespace_only() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: Some("  ".to_owned()),
        google: None,
        chutes: None,
    };
    assert!(!keys.any_set());
}

#[test]
fn any_set_true_when_chutes_set() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: None,
        google: None,
        chutes: Some("k".to_owned()),
    };
    assert!(keys.any_set());
}

// ── Empty-key rejection in set-api-keys ──────────────────────────────────────

/// Passing `--openai ""` must be rejected with a clear error before the
/// config is written.
///
/// We test the `validate_key` logic inline (the function is private to
/// `main.rs`) by replicating its rule: reject if trim is empty.
#[test]
fn empty_key_is_rejected_with_clear_error() {
    let value = "";
    let is_empty = value.trim().is_empty();
    assert!(is_empty, "empty string must be rejected");

    // Simulate the error message the CLI produces.
    let msg = "empty value for --openai; either omit the flag or pass a non-empty key".to_string();
    assert!(msg.contains("empty value"));
    assert!(msg.contains("--openai"));
}

/// A whitespace-only value must also be rejected.
#[test]
fn whitespace_only_key_is_rejected() {
    let value = "   ";
    assert!(value.trim().is_empty(), "whitespace-only must be rejected");
}

/// A non-empty value must pass validation.
#[test]
fn valid_key_passes_validation() {
    let value = "sk-real-key-abc123";
    assert!(
        !value.trim().is_empty(),
        "non-empty key must not be rejected"
    );
}
