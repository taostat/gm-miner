//! Phala Cloud API key resolution and validation for `gmcli deploy`.
//!
//! A deploy needs a funded Phala Cloud API key to submit the CVM. Miners
//! bring their own funded account (a gm-funded key is only for gm's own
//! testing — the resolution is bring-your-own either way). This module
//! resolves the key in a fixed priority order and validates it against the
//! Phala Cloud API before any irreversible deploy work begins:
//!
//!   1. `--phala-api-key <key>` flag.
//!   2. `PHALA_API_KEY` / `PHALA_CLOUD_API_KEY` env var.
//!   3. An interactive paste, persisted to gmcli config so later deploys
//!      never re-ask.
//!
//! Validation hits `GET {PHALA_API_BASE}/auth/me` with the key in the
//! `X-API-Key` header and reads the account's credit balance, so an invalid
//! key or an empty balance fails up front with a signup / top-up link.

use std::io::{IsTerminal as _, Write as _};

#[cfg(test)]
use std::sync::{mpsc::Sender, Mutex, OnceLock};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::config::{self, Config};

/// Base URL of the Phala Cloud REST API. The `phala` CLI's own SDKs default
/// to this host (`/api/v1` prefix); validation calls `…/auth/me`.
pub const PHALA_API_BASE: &str = "https://cloud-api.phala.com/api/v1";

/// The `X-API-Key` header the Phala Cloud API authenticates with.
pub const PHALA_API_KEY_HEADER: &str = "X-API-Key";

/// Where a miner signs up for (and funds) a Phala Cloud account.
pub const PHALA_SIGNUP_URL: &str = "https://cloud.phala.network";

/// `GET /auth/me` response — only the credit balance is consumed here.
#[derive(Debug, Deserialize)]
struct PhalaCurrentUser {
    #[serde(default)]
    credits: PhalaCredits,
}

/// The `credits` block of [`PhalaCurrentUser`]. Balances are decimal strings
/// in the Phala API (e.g. `"12.50"`); `granted_balance` is promotional credit
/// that still funds deploys, so the effective balance is their sum.
#[derive(Debug, Default, Deserialize)]
struct PhalaCredits {
    #[serde(default)]
    balance: Option<String>,
    #[serde(default)]
    granted_balance: Option<String>,
}

/// Whether `value` parses as a positive decimal amount. Phala returns
/// balances as decimal strings; any value that parses above zero counts as
/// funded. An unparseable or non-positive value is treated as zero so the
/// gate fails closed.
fn is_positive_amount(value: &str) -> bool {
    value.trim().parse::<f64>().is_ok_and(|n| n > 0.0)
}

impl PhalaCredits {
    /// Whether either the paid or the granted balance is positive.
    fn is_funded(&self) -> bool {
        let any = |v: &Option<String>| v.as_deref().is_some_and(is_positive_amount);
        any(&self.balance) || any(&self.granted_balance)
    }
}

/// Validate a Phala Cloud API key and confirm the account has a positive
/// credit balance.
///
/// Hits `GET {api_base}/auth/me` with the key in the `X-API-Key` header. A
/// 401/403 means the key is invalid; a funded-but-zero account fails with a
/// top-up link. `api_base` is injected so tests can point at a mock server.
///
/// # Errors
/// Returns an actionable error when the key is invalid, the account has no
/// balance, or the Phala API is unreachable.
pub async fn validate_key(api_base: &str, key: &str) -> Result<()> {
    let client = crate::client::build_http_client()?;

    let url = format!("{api_base}/auth/me");
    let resp = client
        .get(&url)
        .header(PHALA_API_KEY_HEADER, key)
        .send()
        .await
        .with_context(|| format!("GET {url} — could not reach the Phala Cloud API"))?;

    let status = resp.status();
    if matches!(status.as_u16(), 401 | 403) {
        bail!(
            "Phala Cloud rejected the API key ({status}). Check the key, or \
             create one at {PHALA_SIGNUP_URL} (Dashboard → API Keys)."
        );
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("Phala Cloud /auth/me failed ({status}): {body}");
    }

    let user: PhalaCurrentUser = resp
        .json()
        .await
        .context("parse Phala Cloud /auth/me response")?;
    if !user.credits.is_funded() {
        bail!(
            "your Phala Cloud account has no credit balance — a deploy needs \
             funds to provision the CVM.\n  \
             top up at {PHALA_SIGNUP_URL} (Dashboard → Deposit), then re-run."
        );
    }
    Ok(())
}

/// The Phala API key already configured non-interactively (env var, else the
/// `stored_key` saved in gmcli config) — no prompt, no validation. Returned so
/// a recovery path like `register-image` can scope the same key onto its
/// `phala` subprocess that `deploy` uses, without re-running the full
/// interactive resolution. `None` when only a `phala` CLI session exists (the
/// subprocess inherits that anyway).
#[must_use]
pub fn stored_key(config_key: Option<&str>) -> Option<String> {
    key_from_env().or_else(|| non_empty(config_key).map(str::to_owned))
}

/// Read the Phala API key from the environment, preferring `PHALA_API_KEY`
/// and falling back to `PHALA_CLOUD_API_KEY` (the var the `phala` CLI itself
/// honours). Whitespace-only values are ignored.
fn key_from_env() -> Option<String> {
    crate::deploy::non_empty_env("PHALA_API_KEY")
        .or_else(|| crate::deploy::non_empty_env("PHALA_CLOUD_API_KEY"))
}

/// Resolve the Phala Cloud API key for a deploy, validating it before
/// returning. Priority: `--phala-api-key` flag, then env, then the stored
/// config value, then an interactive paste (persisted for next time).
///
/// `assume_yes` (the deploy `--yes`) and a non-TTY both suppress the prompt:
/// in a non-interactive run there is no one to paste, so the function prints
/// guidance and fails rather than blocking. A flag/env key is never persisted
/// (it is a per-run override); a freshly-pasted key is.
///
/// Returns `Ok(None)` when no explicit key is configured but the `phala` CLI
/// already holds a login session (`phala whoami` succeeds): the deploy reuses
/// that session, so there is no key to export or balance to pre-check here —
/// Phala Cloud enforces the balance at deploy time. Returns `Ok(Some(key))`
/// when an explicit key (flag/env/config/paste) was resolved and validated.
///
/// # Errors
/// Returns an error when no key and no CLI session exist in a non-interactive
/// context, the paste is empty, or [`validate_key`] rejects the resolved key.
pub async fn resolve_key(flag: Option<&str>, assume_yes: bool) -> Result<Option<String>> {
    let source = match resolve_key_source(flag)? {
        Some(source) => source,
        None if phala_cli_logged_in() => {
            println!("Using your existing `phala` CLI login session.");
            return Ok(None);
        }
        None => KeySource {
            key: prompt_for_key(assume_yes)?,
            persist: true,
        },
    };

    validate_key(PHALA_API_BASE, &source.key).await?;

    if source.persist {
        persist_key(&source.key)?;
        println!("Saved the Phala Cloud API key to gmcli config for next time.");
    }
    Ok(Some(source.key))
}

/// Whether the `phala` CLI already holds a login session. `phala whoami` exits
/// non-zero when unauthenticated, so a zero exit means a usable session — the
/// same probe `gmcli doctor`'s Phala check uses, kept consistent here.
fn phala_cli_logged_in() -> bool {
    std::process::Command::new("phala")
        .arg("whoami")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A short label for whichever credential source a deploy would use, or `None`
/// when none is configured. The same precedence deploy follows: an env key,
/// then the stored config key, then an existing `phala` CLI login session.
///
/// `stored_key` is the value of `Config::phala_api_key` (network-independent).
/// `gmcli doctor` calls this so its Phala check accepts exactly the sources
/// deploy accepts — otherwise it would report a usable deploy as not ready.
#[must_use]
pub fn credential_source(stored_key: Option<&str>) -> Option<&'static str> {
    if key_from_env().is_some() {
        return Some("PHALA_API_KEY / PHALA_CLOUD_API_KEY env var");
    }
    if non_empty(stored_key).is_some() {
        return Some("saved gmcli config key");
    }
    phala_cli_logged_in().then_some("`phala` CLI login session")
}

/// The non-interactive key sources, in priority order: flag, env, stored
/// config. `None` means "fall through to the interactive prompt". Gathers the
/// env and stored values, then delegates the precedence to [`pick_key_source`].
fn resolve_key_source(flag: Option<&str>) -> Result<Option<KeySource>> {
    let env = key_from_env();
    let stored = config::load()
        .context("load gmcli config")?
        .phala_api_key
        .filter(|s| !s.trim().is_empty());
    Ok(pick_key_source(flag, env.as_deref(), stored.as_deref()))
}

/// A resolved key plus whether it must be persisted. A flag/env override is a
/// per-run value (never persisted); a stored key is already saved.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeySource {
    key: String,
    persist: bool,
}

/// Pick the key from the non-interactive sources in precedence order: flag,
/// then env, then stored config. Pure — the side-effecting gather lives in
/// [`resolve_key_source`] — so the precedence is unit-testable. Whitespace-only
/// values at any tier are ignored. `None` means no source matched.
fn pick_key_source(
    flag: Option<&str>,
    env: Option<&str>,
    stored: Option<&str>,
) -> Option<KeySource> {
    let key = non_empty(flag)
        .or_else(|| non_empty(env))
        .or_else(|| non_empty(stored))?;
    // No non-interactive source is ever re-persisted: a flag/env value is a
    // per-run override and a stored value is already saved.
    Some(KeySource {
        key: key.to_owned(),
        persist: false,
    })
}

/// Trim a candidate key, treating whitespace-only as absent.
fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

/// Prompt the operator to paste a Phala Cloud API key, printing the signup
/// link first. A non-interactive context (`--yes` or a non-TTY) cannot paste,
/// so it prints guidance and fails instead of blocking forever.
fn prompt_for_key(assume_yes: bool) -> Result<String> {
    if assume_yes || !std::io::stdin().is_terminal() {
        bail!(
            "no Phala Cloud API key found and this is a non-interactive run.\n  \
             pass --phala-api-key <key>, or set PHALA_API_KEY, then re-run.\n  \
             create a key at {PHALA_SIGNUP_URL} (Dashboard → API Keys)."
        );
    }

    println!("A Phala Cloud API key is needed to deploy your miner's CVM.");
    println!("  Sign up and create a key (Dashboard → API Keys): {PHALA_SIGNUP_URL}");
    print!("Paste your Phala Cloud API key: ");
    std::io::stdout().flush().ok();

    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("read Phala Cloud API key")?;
    let key = line.trim().to_owned();
    if key.is_empty() {
        bail!("no key entered — re-run `gmcli deploy` and paste your Phala Cloud API key.");
    }
    Ok(key)
}

/// Persist `key` to gmcli config (network-independent). Loads a fresh config
/// so a concurrent edit elsewhere is not clobbered, mirroring `set-api-keys`.
fn persist_key(key: &str) -> Result<()> {
    #[cfg(test)]
    notify_test_lock_attempt();

    config::with_config_lock(|| {
        let mut cfg: Config = config::load().context("load gmcli config")?;
        cfg.phala_api_key = Some(key.to_owned());
        config::save(&cfg).context("persist Phala Cloud API key")
    })
}

#[cfg(test)]
static TEST_LOCK_ATTEMPT: OnceLock<Mutex<Option<Sender<()>>>> = OnceLock::new();

/// Notify the concurrency regression exactly when `persist_key` enters the
/// shared-lock path. The hook is test-only and never changes production I/O.
#[cfg(test)]
fn notify_test_lock_attempt() {
    let observer = TEST_LOCK_ATTEMPT
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(observer) = observer {
        let _ = observer.send(());
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::{is_positive_amount, persist_key, pick_key_source, validate_key, PhalaCredits};
    use crate::config::{self, Config, NetworkEntry, WorkerRecord};
    use anyhow::Context;
    use std::sync::mpsc::{self, Receiver};
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn observe_next_lock_attempt() -> Receiver<()> {
        let (sender, receiver) = mpsc::channel();
        let mut observer = super::TEST_LOCK_ATTEMPT
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *observer = Some(sender);
        receiver
    }

    fn with_temp_config_dir() -> (TempDir, std::sync::MutexGuard<'static, ()>) {
        let guard = crate::config::TEST_CONFIG_DIR_ENV
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("create tempdir");
        // SAFETY: this test holds the process-local guard for its whole scope.
        unsafe { std::env::set_var("GMCLI_CONFIG_DIR", dir.path()) };
        (dir, guard)
    }

    #[test]
    fn positive_amount_parsing() {
        assert!(is_positive_amount("12.50"));
        assert!(is_positive_amount("0.01"));
        assert!(!is_positive_amount("0"));
        assert!(!is_positive_amount("0.00"));
        assert!(!is_positive_amount(""));
        assert!(!is_positive_amount("nan-ish"));
    }

    #[test]
    fn credits_funded_when_granted_only() {
        let credits = PhalaCredits {
            balance: Some("0".to_owned()),
            granted_balance: Some("5.00".to_owned()),
        };
        assert!(credits.is_funded(), "granted credit must count as funded");
    }

    #[test]
    fn credits_unfunded_when_all_zero() {
        let credits = PhalaCredits {
            balance: Some("0".to_owned()),
            granted_balance: None,
        };
        assert!(!credits.is_funded());
    }

    // ── key-source precedence ─────────────────────────────────────────────────

    #[test]
    fn pick_key_source_prefers_the_flag() {
        let source = pick_key_source(Some("flag-key"), Some("env-key"), Some("stored-key"))
            .expect("flag must resolve");
        assert_eq!(source.key, "flag-key");
        assert!(!source.persist, "a flag override is never persisted");
    }

    #[test]
    fn pick_key_source_falls_back_to_env_then_stored() {
        let env =
            pick_key_source(None, Some("env-key"), Some("stored-key")).expect("env must resolve");
        assert_eq!(env.key, "env-key");
        assert!(!env.persist);

        let stored = pick_key_source(None, None, Some("stored-key")).expect("stored must resolve");
        assert_eq!(stored.key, "stored-key");
        assert!(!stored.persist, "a stored key is already saved");
    }

    #[test]
    fn pick_key_source_ignores_blank_tiers_and_returns_none() {
        // A whitespace-only flag falls through to env; all-blank yields None
        // (the caller then prompts and persists the pasted key).
        let source =
            pick_key_source(Some("   "), Some("env-key"), None).expect("blank flag falls through");
        assert_eq!(source.key, "env-key");
        assert!(pick_key_source(Some("  "), Some(""), Some("\t")).is_none());
        assert!(pick_key_source(None, None, None).is_none());
    }

    #[test]
    fn phala_key_persistence_preserves_a_concurrent_worker_update() {
        let (_dir, _guard) = with_temp_config_dir();
        let mut entry = NetworkEntry::default();
        entry.workers.push(WorkerRecord {
            worker_id: "worker-1".to_owned(),
            app_id: "app-1".to_owned(),
            app_name: "miner-1".to_owned(),
            node_secret: "old-secret".to_owned(),
            ..Default::default()
        });
        let mut cfg = Config::default();
        cfg.networks.insert("mainnet".to_owned(), entry);
        cfg.active_network = Some("mainnet".to_owned());
        config::save(&cfg).expect("seed config");

        let (stale_loaded_tx, stale_loaded_rx) = mpsc::channel();
        let (allow_stale_save_tx, allow_stale_save_rx) = mpsc::channel();
        let writer = thread::spawn(move || {
            config::with_config_lock(|| {
                // This snapshot predates the key write and models a worker
                // update already holding the shared config lock.
                let mut stale = config::load().expect("load under lock");
                stale_loaded_tx
                    .send(())
                    .map_err(|_| anyhow::anyhow!("main test thread stopped receiving"))?;
                allow_stale_save_rx
                    .recv_timeout(Duration::from_secs(2))
                    .context("timed out waiting to save stale worker update")?;
                stale.active_entry_mut().workers[0].node_secret = "new-secret".to_owned();
                config::save(&stale)
            })
            .is_ok()
        });

        let stale_loaded = stale_loaded_rx.recv_timeout(Duration::from_secs(2));
        assert!(
            stale_loaded.is_ok(),
            "worker writer must load its stale snapshot within the bounded wait"
        );

        // Start the key write while the stale worker writer holds `.lock`.
        // The test hook is emitted at the lock-attempt boundary, not before a
        // scheduled thread call, so a delayed thread cannot turn the baseline
        // into a false pass. The bounded receives only prevent a broken test
        // from hanging forever if a worker or lock path fails.
        let lock_attempt = observe_next_lock_attempt();
        let (result_tx, result_rx) = mpsc::channel();
        let key_writer = thread::spawn(move || {
            result_tx
                .send(persist_key("test-key").is_ok())
                .expect("send key writer result");
        });

        // Fixed code emits this signal before blocking on the held lock. The
        // baseline never emits it; it still completes its unlocked write, and
        // the stale writer is released after this bounded failed observation.
        let attempted = lock_attempt.recv_timeout(Duration::from_secs(2));
        allow_stale_save_tx
            .send(())
            .expect("release stale worker writer");
        assert!(writer.join().expect("writer thread must finish"));
        let key_saved = result_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("key writer must finish after the lock is released");
        assert!(key_saved, "key persistence must succeed");
        key_writer.join().expect("key writer thread must finish");
        assert!(
            attempted.is_ok(),
            "persist_key must enter the shared config lock before saving"
        );

        let final_cfg = config::load().expect("reload final config");
        assert_eq!(
            final_cfg.phala_api_key.as_deref(),
            Some("test-key"),
            "the worker writer must not overwrite the key"
        );
        assert_eq!(
            final_cfg
                .networks
                .get("mainnet")
                .expect("mainnet entry")
                .workers[0]
                .node_secret,
            "new-secret"
        );
    }

    async fn mock_auth_me(body: serde_json::Value, status: u16) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth/me"))
            .and(header("X-API-Key", "test-key"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn validate_key_accepts_a_funded_account() {
        let server = mock_auth_me(serde_json::json!({"credits": {"balance": "10.00"}}), 200).await;
        validate_key(&server.uri(), "test-key")
            .await
            .expect("a funded key must validate");
    }

    #[tokio::test]
    async fn validate_key_rejects_an_empty_balance() {
        let server = mock_auth_me(serde_json::json!({"credits": {"balance": "0"}}), 200).await;
        let err = validate_key(&server.uri(), "test-key")
            .await
            .expect_err("an unfunded account must be rejected");
        assert!(err.to_string().contains("no credit balance"), "got: {err}");
    }

    #[tokio::test]
    async fn validate_key_rejects_an_invalid_key() {
        let server = mock_auth_me(serde_json::json!({"detail": "nope"}), 401).await;
        let err = validate_key(&server.uri(), "test-key")
            .await
            .expect_err("a 401 must be rejected");
        assert!(
            err.to_string().contains("rejected the API key"),
            "got: {err}"
        );
    }
}
