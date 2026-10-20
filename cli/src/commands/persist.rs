//! Config + token persistence helpers and the `login` command.
//!
//! Every persist path re-loads under [`config::with_config_lock`] before
//! writing so a concurrent `deploy` (which lands three worker records over
//! several minutes — the widest race window in the CLI) is never clobbered.

use anyhow::{Context as _, Result};

use gm_miner_cli::{
    auth,
    client::get_auth_config,
    config::{self, Config, WorkerRecord},
    network::Network,
};

/// Load config and resolve the active network.
///
/// `explicit_network` is the network the user named this run (`--network` /
/// `--testnet`), or `None` to use the sticky stored selection. An explicit
/// choice is persisted so later commands target it without retyping the flag;
/// the previous default-to-mainnet-every-run behaviour was the audit's biggest
/// day-2 footgun.
///
/// `--api-url` is *not* sticky: it is applied to the in-memory config for this
/// run only (falling back to `GM_REGISTRY_URL`) and never written back here.
pub(crate) fn load_config(
    explicit_network: Option<Network>,
    api_url_override: Option<String>,
) -> Result<Config> {
    let mut cfg = config::load().context("load config")?;

    if let Some(network) = explicit_network {
        // Persist the explicit choice so it sticks across later commands. An
        // empty stored value (or a different prior selection) is overwritten.
        let changed = cfg.resolved_network() != network || cfg.active_network.is_none();
        cfg.set_network(network);
        if changed {
            persist_active_network(network).context("persist selected network")?;
        }
    }

    // Explicit --api-url flag wins; fall back to GM_REGISTRY_URL for a
    // this-run-only override. Stored in `api_url_override` (which `save` never
    // serializes), so a token refresh mid-run can't persist the throwaway URL
    // as the sticky per-network `api_url`.
    cfg.api_url_override = api_url_override.or_else(|| std::env::var("GM_REGISTRY_URL").ok());

    Ok(cfg)
}

/// Ensure the active network's access token is usable, refreshing it silently
/// if it has expired (or is within the expiry margin).
///
/// Refreshes a known expired or near-expiry token. Missing tokens or expiry
/// metadata retain the existing registry/preflight checks. The sequence is:
///   1. Token still valid → return `cfg` untouched (no network call).
///   2. Token expired but a `refresh_token` is stored → POST the
///      `refresh_token` grant. On success the new tokens are persisted and
///      returned. The auth-gateway rotates the refresh token, so a rotated
///      value in the response replaces the stored one.
///   3. No refresh token, or the refresh was rejected (revoked / expired /
///      grant not permitted) → fall back to the full device-code flow.
///
/// The auth-gateway mints `exp` at the next subnet epoch boundary rather
/// than a flat TTL, so a refresh grant taken in the closing seconds of an
/// epoch comes back still inside [`config::TOKEN_EXPIRY_MARGIN_SECS`] — the
/// issuer cannot mint a token past the boundary it hasn't crossed yet.
/// Retrying step 2 immediately would land the same result. Instead, once,
/// this waits for the reported expiry plus a five-second cushion and refreshes
/// again. One wait is capped at 305 seconds. A short-tempo issuer or inaccurate
/// expiry estimate can still leave the second token inside the margin; return
/// an actionable error in that case rather than repeat login indefinitely.
/// The refresh path never opens a browser; the device fallback can.
///
/// # Errors
/// Returns an error if `/auth/config` cannot be fetched, the device-flow
/// fallback fails, the refreshed config cannot be saved, or the token still
/// fails the expiry margin after the bounded retry.
pub(crate) async fn ensure_fresh_token(cfg: Config) -> Result<Config> {
    ensure_fresh_token_with(
        cfg,
        async |cfg| obtain_fresh_token(cfg, true).await,
        tokio::time::sleep,
    )
    .await
}

// Injectable token acquisition and timer let tests exercise persistence and
// retry control without wall-clock deadlines or a browser.
async fn ensure_fresh_token_with<F, W, Fut>(
    mut cfg: Config,
    mut obtain: F,
    mut wait: W,
) -> Result<Config>
where
    F: AsyncFnMut(&Config) -> Result<(auth::TokenResponse, bool)>,
    W: FnMut(std::time::Duration) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    // Keep retries bounded even if the issuer never supplies a sufficient TTL.
    const MAX_ATTEMPTS: u32 = 2;
    // An override device login starts a different refresh chain. None of its
    // descendants may replace the stored registry's credentials.
    let mut follows_stored_refresh = true;

    for attempt in 0..MAX_ATTEMPTS {
        if !cfg
            .active_tokens()
            .is_some_and(config::TokenEntry::is_expired_or_near)
        {
            return Ok(cfg);
        }

        let wait_secs = with_auth_lock(async || {
            // A different process may have consumed our refresh token while
            // we waited for the lock or for an epoch boundary. Override device
            // logins have a private chain that must never be replaced from disk.
            if follows_stored_refresh {
                reload_credentials(&mut cfg)?;
            }
            if !cfg
                .active_tokens()
                .is_some_and(config::TokenEntry::is_expired_or_near)
            {
                return Ok(None);
            }

            let (token, from_refresh_grant) = obtain(&cfg).await?;
            // Only a refresh grant may retain a non-rotated refresh token.
            // A device login starts a new chain, even when it returns none.
            let previous_refresh = if from_refresh_grant {
                cfg.active_tokens().and_then(|t| t.refresh_token.clone())
            } else {
                None
            };
            let entry = token.to_entry_keeping(previous_refresh);
            let network = cfg.active_network().to_owned();
            let override_active = cfg.api_url_override.is_some();
            cfg.active_entry_mut().tokens = Some(entry.clone());
            // Normal device logins are persisted and can be reloaded on retry.
            // Only override device logins leave the shared refresh chain.
            follows_stored_refresh &= from_refresh_grant || !override_active;
            persist_refreshed_tokens(network, entry, override_active, follows_stored_refresh)
                .context("save refreshed token")?;

            if !cfg
                .active_tokens()
                .is_some_and(config::TokenEntry::is_expired_or_near)
            {
                return Ok(None);
            }
            anyhow::ensure!(
                attempt + 1 < MAX_ATTEMPTS,
                "access token still expires within {}s after waiting and refreshing again — \
                 check the issuer's token lifetime/subnet tempo and the local clock; \
                 retry once the issuer can provide a longer-lived token",
                config::TOKEN_EXPIRY_MARGIN_SECS
            );

            Ok(Some(
                cfg.active_tokens()
                    .and_then(config::TokenEntry::seconds_until_expiry)
                    .unwrap_or(0)
                    .clamp(0, config::TOKEN_EXPIRY_MARGIN_SECS)
                    .saturating_add(5),
            ))
        })
        .await?;

        let Some(wait_secs) = wait_secs else {
            return Ok(cfg);
        };
        // Release the auth lock during the epoch wait. The next attempt
        // re-acquires it and reloads before deciding whether to refresh.
        eprintln!(
            "Refreshed access token is still near expiry (possibly an epoch boundary) \
             — waiting {wait_secs}s before one more refresh."
        );
        wait(std::time::Duration::from_secs(
            u64::try_from(wait_secs).unwrap_or(0),
        ))
        .await;
    }

    Ok(cfg)
}

/// Serialize authentication across processes, independently of config writes.
/// Never remove this lockfile: replacing its inode could admit two owners.
/// Nonblocking attempts let the async runtime keep making progress; dropping
/// the future or exiting the process releases the OS lock automatically.
async fn with_auth_lock<T>(operation: impl AsyncFnOnce() -> Result<T>) -> Result<T> {
    let mut lock = open_auth_lock()?;
    loop {
        match lock.try_write() {
            Ok(_guard) => return operation().await,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error).context("acquire auth lock"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

fn open_auth_lock() -> Result<fd_lock::RwLock<std::fs::File>> {
    let path = config::config_path().with_file_name(".auth.lock");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create auth lock directory")?;
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .context("open auth lock")?;
    Ok(fd_lock::RwLock::new(file))
}

/// Reload only the selected network's credentials, preserving this command's
/// network selection and runtime settings. Called under the auth lock before
/// using a shared refresh chain, including before any device-login fallback.
fn reload_credentials(cfg: &mut Config) -> Result<()> {
    let mut disk = config::load().context("reload credentials")?;
    let stored = disk
        .networks
        .remove(cfg.active_network())
        .unwrap_or_default();
    if cfg.api_url_override.is_some() {
        // Override access tokens belong to a different registry. Only the
        // shared rotating refresh token may be adopted from disk.
        if let Some(tokens) = cfg.active_entry_mut().tokens.as_mut() {
            tokens.refresh_token = stored.tokens.and_then(|tokens| tokens.refresh_token);
        }
    } else {
        let entry = cfg.active_entry_mut();
        entry.api_url = stored.api_url;
        entry.tokens = stored.tokens;
    }
    Ok(())
}

/// Persist the result of a token refresh.
///
/// Without an `--api-url` override the whole token entry is written. With an
/// override active the access token was minted against a this-run-only registry,
/// so it must never become the stored entry's token. Only when the token came
/// from the stored refresh chain (`follows_stored_refresh`) — which rotates
/// and consumes the stored refresh token — is the rotated refresh token merged back,
/// keeping the stored refresh chain alive for the next non-override run. A
/// device-login fallback against the override registry persists nothing. Every
/// path touches only the named network's `tokens` under the lock, re-loading so
/// a concurrent `deploy` write survives.
fn persist_refreshed_tokens(
    network: String,
    entry: config::TokenEntry,
    override_active: bool,
    follows_stored_refresh: bool,
) -> Result<()> {
    if override_active {
        if !follows_stored_refresh {
            return Ok(());
        }
        let Some(rotated) = entry.refresh_token else {
            return Ok(());
        };
        return persist_rotated_refresh_token(network, rotated);
    }
    persist_active_tokens(network, entry)
}

/// Merge only a rotated `refresh_token` into `network`'s stored tokens, leaving
/// the persisted access token and expiry untouched. Used on override runs so a
/// token minted against the override registry never becomes the stored token.
fn persist_rotated_refresh_token(network: String, rotated: String) -> Result<()> {
    config::with_config_lock(|| {
        let mut on_disk = config::load().context("load gmcli config")?;
        on_disk
            .networks
            .entry(network)
            .or_default()
            .tokens
            .get_or_insert_with(Default::default)
            .refresh_token = Some(rotated);
        config::save(&on_disk)
    })
}

/// Persist a refreshed token onto `network`'s entry under the config lock,
/// re-loading from disk so a token refresh can't clobber a worker record a
/// concurrent `deploy` wrote since this command's config was first loaded. Only
/// that network's `tokens` field is touched — `active_network` is left as it is
/// on disk, so a concurrent `--network` selection survives the refresh.
fn persist_active_tokens(network: String, tokens: config::TokenEntry) -> Result<()> {
    config::with_config_lock(|| {
        let mut on_disk = config::load().context("load gmcli config")?;
        on_disk.networks.entry(network).or_default().tokens = Some(tokens);
        config::save(&on_disk)
    })
}

/// Persist the sticky active-network selection under the config lock: re-load
/// from disk and write only `active_network`, leaving every network's tokens,
/// workers, and keys as they are on disk.
fn persist_active_network(network: Network) -> Result<()> {
    config::with_config_lock(|| {
        let mut on_disk = config::load().context("load gmcli config")?;
        on_disk.set_network(network);
        config::save(&on_disk)
    })
}

/// Persist a successful `login` under the config lock: re-load from disk and
/// write only `network`'s `api_url` + `tokens`, plus the sticky `active_network`
/// (login is the user's explicit network selection). Re-loading means the slow
/// device-code flow can't clobber a worker record a concurrent `deploy` wrote.
fn persist_login(network: &str, api_url: String, tokens: config::TokenEntry) -> Result<()> {
    config::with_config_lock(|| {
        let mut on_disk = config::load().context("load gmcli config")?;
        let entry = on_disk.networks.entry(network.to_owned()).or_default();
        entry.api_url = Some(api_url);
        entry.tokens = Some(tokens);
        on_disk.active_network = Some(network.to_owned());
        config::save(&on_disk)
    })
}

/// Persist a `register-hotkey` result under the config lock: re-load and write
/// only `network`'s `registered_hotkey`, so concurrent worker/token writes
/// survive.
pub(crate) fn persist_registered_hotkey(network: &str, record: config::HotkeyRecord) -> Result<()> {
    config::with_config_lock(|| {
        let mut on_disk = config::load().context("load gmcli config")?;
        on_disk
            .networks
            .entry(network.to_owned())
            .or_default()
            .set_registered_hotkey(record);
        config::save(&on_disk)
    })
}

/// Non-interactively refresh the active token if it is expired and a
/// `refresh_token` is stored. Never opens a browser or runs the device-code
/// flow — a diagnostic like `doctor` must report state, not mutate auth by
/// launching an interactive login.
///
/// Returns the latest stored credentials, refreshed when possible. A missing
/// or rejected refresh token, or an unreachable auth-gateway, leaves those
/// credentials unchanged so the caller can report the logged-out/expired state.
/// If another authentication owns the lock, skip refreshing rather than wait
/// for an interactive login to complete.
pub(crate) async fn try_refresh_token(mut cfg: Config) -> Config {
    let needs_refresh = cfg
        .active_tokens()
        .is_some_and(config::TokenEntry::is_expired_or_near);
    if !needs_refresh {
        return cfg;
    }
    let mut lock = match open_auth_lock() {
        Ok(lock) => lock,
        Err(error) => {
            tracing::warn!("failed to open auth lock: {error}");
            return cfg;
        }
    };
    // Diagnostics must not wait for another command's interactive login.
    // A busy lock means skip refreshing, never submit the shared token unlocked.
    let _guard = match lock.try_write() {
        Ok(guard) => guard,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return cfg,
        Err(error) => {
            tracing::warn!("failed to acquire auth lock: {error}");
            return cfg;
        }
    };
    if let Err(error) = reload_credentials(&mut cfg) {
        tracing::warn!("failed to reload credentials: {error}");
        return cfg;
    }
    if !cfg
        .active_tokens()
        .is_some_and(config::TokenEntry::is_expired_or_near)
    {
        return cfg;
    }
    let Some(refresh) = cfg.active_tokens().and_then(|t| t.refresh_token.clone()) else {
        return cfg;
    };

    let api_url = cfg.api_url();
    let Ok(auth_cfg) = get_auth_config(&api_url).await else {
        return cfg;
    };
    let Ok(auth::RefreshOutcome::Refreshed(token)) =
        auth::refresh_token(&auth_cfg.token_url, &auth_cfg.client_id, &refresh).await
    else {
        return cfg;
    };

    let previous_refresh = cfg.active_tokens().and_then(|t| t.refresh_token.clone());
    let entry = token.to_entry_keeping(previous_refresh);
    let network = cfg.active_network().to_owned();
    let override_active = cfg.api_url_override.is_some();
    cfg.active_entry_mut().tokens = Some(entry.clone());
    // try_refresh_token only ever reaches here via a successful refresh grant.
    if let Err(e) = persist_refreshed_tokens(network, entry, override_active, true) {
        tracing::warn!("failed to persist refreshed tokens: {e}");
    }

    cfg
}

/// Obtain a fresh access token: try the stored `refresh_token` first, fall
/// back to the device-code flow when there is none or it is rejected.
///
/// The returned flag is true only when the token came from a successful refresh
/// grant, false when it came from a device login. The caller must track whether
/// a prior attempt already switched away from the stored refresh chain. With
/// `--api-url`, only rotations descended from that stored chain may be saved;
/// a device-login token belongs to the override registry.
///
/// Split out of [`ensure_fresh_token`] so the refresh-vs-device decision is a
/// single linear function with no config mutation.
async fn obtain_fresh_token(
    cfg: &Config,
    open_browser: bool,
) -> Result<(auth::TokenResponse, bool)> {
    let api_url = cfg.api_url();
    let auth_cfg = get_auth_config(&api_url)
        .await
        .with_context(|| format!("fetch auth config from {api_url}/auth/config"))?;
    let stored_refresh = cfg.active_tokens().and_then(|t| t.refresh_token.clone());

    let Some(refresh) = stored_refresh else {
        eprintln!("Access token expired — re-authenticating.");
        return Ok((device_login_from(&auth_cfg, open_browser).await?, false));
    };

    match auth::refresh_token(&auth_cfg.token_url, &auth_cfg.client_id, &refresh).await? {
        auth::RefreshOutcome::Refreshed(token) => {
            eprintln!("Access token refreshed.");
            Ok((token, true))
        }
        auth::RefreshOutcome::Rejected => {
            eprintln!("Stored credentials have expired — re-authenticating.");
            Ok((device_login_from(&auth_cfg, open_browser).await?, false))
        }
    }
}

/// Run the device-code flow using endpoints from an already-fetched
/// [`AuthConfig`]. Shared by `cmd_login` and the [`ensure_fresh_token`]
/// fallback so neither re-fetches `/auth/config`.
///
/// [`AuthConfig`]: gm_miner_cli::client::AuthConfig
async fn device_login_from(
    auth_cfg: &gm_miner_cli::client::AuthConfig,
    open_browser: bool,
) -> Result<auth::TokenResponse> {
    auth::device_login(
        &auth_cfg.device_code_url,
        &auth_cfg.token_url,
        &auth_cfg.client_id,
        &auth_cfg.scopes,
        open_browser,
    )
    .await
}

pub(crate) async fn cmd_login(
    explicit_network: Option<Network>,
    api_url_override: Option<String>,
    open_browser: bool,
) -> Result<()> {
    with_auth_lock(async || {
        // `config::load()` already returns Config::default() when the file
        // is absent (first-time login). A failure here means the file
        // exists but is unreadable or invalid JSON — surfacing that as a
        // hard error matches the other commands' behaviour and prevents
        // a normal re-login from silently wiping an operator's existing
        // mainnet/testnet tokens.
        let mut cfg =
            config::load().context("load gmcli config (delete ~/.gmcli/config.json if corrupted)")?;

        // An explicit --network/--testnet selects (and sticks) the network this
        // login targets; otherwise the stored sticky selection is kept so a
        // re-login doesn't silently switch networks.
        if let Some(network) = explicit_network {
            cfg.set_network(network);
        }

        let api_url = api_url_override.unwrap_or_else(|| cfg.api_url());

        // Fetch OAuth endpoints and client identity from the registry. Nothing
        // auth-related is baked into the binary — it all comes from the registry
        // at login time.
        let auth_cfg = get_auth_config(&api_url)
            .await
            .with_context(|| format!("fetch auth config from {api_url}/auth/config"))?;

        let token = device_login_from(&auth_cfg, open_browser).await?;

        let network = cfg.active_network().to_owned();
        persist_login(&network, api_url, token.to_entry()).context("save config")?;

        println!("Login successful ({} network).", cfg.resolved_network());
        println!("Credentials saved to {}", config::config_path().display());
        println!(
            "\nNext: gmcli set-api-keys --anthropic <key>  (and/or --openai / --google / --chutes / --zai / --moonshot / --deepinfra / --kubetee / --engy / --moonmath)"
        );
        Ok(())
    })
    .await
}

/// Upsert `record` into the active network's workers and save the config.
///
/// The load → mutate → save runs under [`config::with_config_lock`] so a
/// concurrent `gmcli` command can't read the old config, mutate its own copy,
/// and clobber this write — `deploy` lands three worker records over several
/// minutes, the widest race window in the CLI.
pub(crate) fn persist_worker_record(network: &str, record: WorkerRecord) -> Result<()> {
    config::with_config_lock(|| {
        let mut cfg = config::load().context("load gmcli config")?;
        cfg.active_network = Some(network.to_owned());
        cfg.active_entry_mut().upsert_worker(record);
        config::save(&cfg).context("persist worker record to gmcli config")
    })
}

/// Persist a fresh terms acceptance to the local config under the config lock,
/// stamping the current version and an RFC 3339 timestamp.
pub(crate) fn persist_accepted_terms() -> Result<()> {
    config::with_config_lock(|| {
        let mut cfg = config::load().context("load gmcli config")?;
        cfg.accepted_terms = Some(config::AcceptedTerms {
            version: gm_miner_cli::terms::CURRENT_TERMS_VERSION.to_owned(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
        config::save(&cfg).context("persist terms acceptance to gmcli config")
    })
}

/// Drop a provisional worker record (a deploy that never registered) from the
/// local config. No registry DELETE: nothing was ever registered.
pub(crate) fn remove_provisional_worker(network: &str, id: &str) -> Result<()> {
    let removed = config::with_config_lock(|| {
        let mut cfg = config::load().context("load gmcli config")?;
        cfg.active_network = Some(network.to_owned());
        let removed = cfg.active_entry_mut().remove_provisional_worker(id);
        config::save(&cfg).context("persist worker removal to gmcli config")?;
        Ok(removed)
    })?;

    match removed {
        Some(w) if !w.app_id.is_empty() => {
            println!(
                "Dropped the unregistered worker record for '{}'.\n\
                 Tear down its CVM separately:\n  phala cvms delete {}",
                w.app_name, w.app_id
            );
        }
        Some(w) => {
            println!(
                "Dropped the unregistered worker record for '{}'.",
                w.app_name
            );
        }
        None => println!("No provisional worker matched '{id}'."),
    }
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test fixtures panic when their declared setup is unexpectedly invalid"
)]
mod tests {
    use super::*;
    use crate::test_support::ConfigDirGuard;
    use gm_miner_cli::config::{NetworkEntry, TokenEntry};
    use std::collections::HashMap;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config_with_near_expiry(api_url: &str, expires_in_secs: i64) -> Config {
        let mut networks = HashMap::new();
        networks.insert(
            "testnet".to_owned(),
            NetworkEntry {
                api_url: Some(api_url.to_owned()),
                tokens: Some(TokenEntry {
                    access_token: Some("stale-access".to_owned()),
                    token_expires_at: Some(
                        (chrono::Utc::now() + chrono::Duration::seconds(expires_in_secs))
                            .to_rfc3339(),
                    ),
                    refresh_token: Some("stored-refresh".to_owned()),
                }),
                ..Default::default()
            },
        );
        Config {
            networks,
            active_network: Some("testnet".to_owned()),
            ..Default::default()
        }
    }

    async fn mount_auth_config(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/auth/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code_url": format!("{}/device/code", server.uri()),
                "token_url": format!("{}/token", server.uri()),
                "client_id": "gm-miner-cli",
                "scopes": ["subnet:482:miner"],
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn concurrent_refreshes_reuse_the_saved_rotation() {
        let _guard = ConfigDirGuard::new();
        // Two commands, command + doctor, and two independent processes.
        for mode in 0..3 {
            let server = MockServer::start().await;
            mount_auth_config(&server).await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("refresh_token=stored-refresh"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_delay(std::time::Duration::from_millis(100))
                        .set_body_json(serde_json::json!({
                            "access_token": "fresh-access",
                            "refresh_token": "rotated-refresh",
                            "expires_in": 3600,
                        })),
                )
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/device/code"))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
            let cfg = config_with_near_expiry(&server.uri(), 60);
            config::save(&cfg).expect("seed credentials");
            if mode == 2 {
                let spawn = || {
                    tokio::process::Command::new(std::env::current_exe().expect("test binary"))
                        .args([
                            "--exact",
                            "commands::persist::tests::refresh_process_child",
                            "--ignored",
                        ])
                        .env(
                            "GMCLI_TEST_REFRESH_CHILD",
                            serde_json::to_string(&cfg).expect("fixture"),
                        )
                        .kill_on_drop(true)
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()
                        .expect("spawn CLI test process")
                };
                let first = spawn();
                let second = spawn();
                let (first, second) =
                    tokio::time::timeout(std::time::Duration::from_secs(15), async {
                        tokio::join!(first.wait_with_output(), second.wait_with_output())
                    })
                    .await
                    .expect("processes must not deadlock");
                for result in [first, second] {
                    let output = result.expect("child output");
                    assert!(
                        output.status.success(),
                        "{} {}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                continue;
            }
            let (first, second) = tokio::join!(ensure_fresh_token(cfg.clone()), async {
                if mode == 1 {
                    Ok(try_refresh_token(cfg).await)
                } else {
                    ensure_fresh_token(cfg).await
                }
            });
            for (index, result) in [first, second].into_iter().enumerate() {
                let cfg = result.expect("refresh without login");
                if mode == 1
                    && index == 1
                    && cfg.active_tokens().expect("tokens").is_expired_or_near()
                {
                    continue;
                }
                assert_eq!(
                    cfg.active_tokens()
                        .expect("tokens")
                        .refresh_token
                        .as_deref(),
                    Some("rotated-refresh")
                );
            }
        }
    }

    #[tokio::test]
    #[ignore = "subprocess helper invoked by concurrent_refreshes_reuse_the_saved_rotation"]
    async fn refresh_process_child() {
        let cfg = serde_json::from_str(
            &std::env::var("GMCLI_TEST_REFRESH_CHILD").expect("child fixture"),
        )
        .expect("fixture config");
        let cfg = ensure_fresh_token(cfg)
            .await
            .expect("refresh without device login");
        assert_eq!(
            cfg.active_tokens()
                .expect("tokens")
                .refresh_token
                .as_deref(),
            Some("rotated-refresh")
        );
    }

    #[tokio::test]
    async fn boundary_retry_reloads_credentials_saved_during_wait() {
        let _guard = ConfigDirGuard::new();
        let cfg = config_with_near_expiry("https://unused.invalid", 60);
        config::save(&cfg).expect("seed credentials");
        let mut attempts = 0;
        let cfg = ensure_fresh_token_with(
            cfg,
            async |_| {
                attempts += 1;
                Ok((
                    auth::TokenResponse {
                        access_token: "boundary-access".to_owned(),
                        refresh_token: Some("boundary-refresh".to_owned()),
                        expires_in: Some(2),
                        token_type: None,
                    },
                    true,
                ))
            },
            |_| {
                let mut disk = config::load().expect("load boundary token");
                disk.active_entry_mut().tokens = Some(
                    auth::TokenResponse {
                        access_token: "other-command-access".to_owned(),
                        refresh_token: Some("other-command-refresh".to_owned()),
                        expires_in: Some(3600),
                        token_type: None,
                    }
                    .to_entry(),
                );
                config::save(&disk).expect("another command refreshed during wait");
                std::future::ready(())
            },
        )
        .await
        .expect("reuse fresh credentials");
        assert_eq!(
            attempts, 1,
            "must not replay the consumed boundary refresh token"
        );
        assert_eq!(
            cfg.active_tokens().expect("tokens").access_token.as_deref(),
            Some("other-command-access")
        );
    }

    #[tokio::test]
    async fn device_login_without_refresh_token_does_not_keep_rejected_token() {
        let _guard = ConfigDirGuard::new();
        for override_active in [false, true] {
            let mut cfg = config_with_near_expiry("https://stored.invalid", 60);
            config::save(&cfg).expect("seed credentials");
            if override_active {
                cfg.api_url_override = Some("https://override.invalid".to_owned());
            }
            let cfg = ensure_fresh_token_with(
                cfg,
                async |_| {
                    Ok((
                        auth::TokenResponse {
                            access_token: "device-access".to_owned(),
                            refresh_token: None,
                            expires_in: Some(3600),
                            token_type: None,
                        },
                        false,
                    ))
                },
                |_| std::future::ready(()),
            )
            .await
            .expect("device login succeeded");
            assert_eq!(
                cfg.active_tokens().expect("tokens").refresh_token,
                None,
                "a new login must not inherit the rejected refresh token"
            );
            let disk = config::load().expect("saved credentials");
            assert_eq!(
                disk.active_tokens()
                    .expect("tokens")
                    .refresh_token
                    .as_deref(),
                if override_active {
                    Some("stored-refresh")
                } else {
                    None
                }
            );
        }
    }

    #[tokio::test]
    async fn stale_command_reuses_login_without_changing_selected_network() {
        let _guard = ConfigDirGuard::new();
        let mut stale = config_with_near_expiry("https://old.invalid", 60);
        stale
            .active_entry_mut()
            .tokens
            .as_mut()
            .expect("tokens")
            .refresh_token = None;
        let mut disk = config_with_near_expiry("https://new.invalid", 3600);
        disk.set_network(Network::Mainnet);
        config::save(&disk).expect("concurrent login and network selection");
        let cfg = ensure_fresh_token(stale)
            .await
            .expect("reuse login without HTTP");
        assert_eq!(cfg.active_network(), "testnet");
        assert_eq!(cfg.api_url(), "https://new.invalid");
        assert!(!cfg.active_tokens().expect("tokens").is_expired_or_near());
        assert_eq!(config::load().expect("disk").active_network(), "mainnet");
    }

    #[tokio::test]
    async fn override_retry_adopts_only_the_shared_refresh_rotation() {
        let _guard = ConfigDirGuard::new();
        let mut cfg = config_with_near_expiry("https://stored.invalid", 60);
        config::save(&cfg).expect("seed credentials");
        cfg.api_url_override = Some("https://override.invalid".to_owned());
        let mut attempts = 0;
        let cfg = ensure_fresh_token_with(
            cfg,
            async |cfg| {
                attempts += 1;
                assert_eq!(cfg.api_url(), "https://override.invalid");
                if attempts == 2 {
                    let token = cfg.active_tokens().expect("tokens");
                    assert_eq!(token.access_token.as_deref(), Some("override-access"));
                    assert_eq!(
                        token.refresh_token.as_deref(),
                        Some("other-command-refresh")
                    );
                }
                Ok((
                    auth::TokenResponse {
                        access_token: "override-access".to_owned(),
                        refresh_token: Some("override-rotation".to_owned()),
                        expires_in: Some(if attempts == 1 { 2 } else { 3600 }),
                        token_type: None,
                    },
                    true,
                ))
            },
            |_| {
                // Taking the auth lock here also proves the boundary wait released it.
                async {
                    with_auth_lock(async || {
                        let mut disk = config_with_near_expiry("https://stored.invalid", 3600);
                        disk.active_entry_mut()
                            .tokens
                            .as_mut()
                            .expect("tokens")
                            .refresh_token = Some("other-command-refresh".to_owned());
                        config::with_config_lock(|| config::save(&disk))
                    })
                    .await
                    .expect("other command refresh");
                }
            },
        )
        .await
        .expect("override refresh");
        assert_eq!(attempts, 2);
        assert_eq!(
            cfg.api_url_override.as_deref(),
            Some("https://override.invalid")
        );
        let disk = config::load().expect("stored config");
        assert_eq!(
            disk.active_tokens()
                .expect("tokens")
                .access_token
                .as_deref(),
            Some("stale-access")
        );
        assert_eq!(
            disk.active_tokens()
                .expect("tokens")
                .refresh_token
                .as_deref(),
            Some("override-rotation")
        );
    }

    #[tokio::test]
    async fn doctor_does_not_wait_for_an_interactive_login() {
        let _guard = ConfigDirGuard::new();
        let cfg = config_with_near_expiry("https://unused.invalid", 60);
        config::save(&cfg).expect("seed credentials");
        with_auth_lock(async || {
            let cfg = tokio::time::timeout(
                std::time::Duration::from_millis(250),
                try_refresh_token(cfg),
            )
            .await
            .expect("doctor must skip refresh while login owns the lock");
            assert_eq!(
                cfg.active_tokens()
                    .expect("tokens")
                    .refresh_token
                    .as_deref(),
                Some("stored-refresh")
            );
            Ok(())
        })
        .await
        .expect("hold login lock");
    }

    #[tokio::test]
    async fn cancelling_auth_releases_lock_and_config_writes_remain_available() {
        let _guard = ConfigDirGuard::new();
        let (entered, receiver) = tokio::sync::oneshot::channel();
        let mut operation = Box::pin(with_auth_lock(async || {
            config::with_config_lock(|| config::save(&Config::default()))?;
            entered.send(()).expect("notify holder entered");
            std::future::pending::<Result<()>>().await
        }));
        tokio::select! {
            result = &mut operation => { result.expect("holder"); }
            result = receiver => { result.expect("holder acquired lock"); }
        }
        drop(operation);
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            with_auth_lock(async || Ok(())),
        )
        .await
        .expect("cancelled future releases lock")
        .expect("acquire after cancellation");
    }

    /// The auth-gateway mints `exp` at the next subnet epoch boundary, so a
    /// refresh taken near the end of an epoch can come back still inside the
    /// margin. `ensure_fresh_token` must wait out that boundary and refresh
    /// again rather than handing back a token `preflight_auth` will reject —
    /// the regression this guards is `ensure_fresh_token` returning after a
    /// single refresh even when the result is still unusable.
    #[tokio::test]
    async fn epoch_boundary_refresh_waits_and_retries_once() {
        let _guard = ConfigDirGuard::new();
        let server = MockServer::start().await;
        mount_auth_config(&server).await;

        // First refresh: still inside the margin (epoch boundary 2s away).
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("refresh_token=stored-refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "boundary-access",
                "refresh_token": "boundary-refresh",
                "token_type": "Bearer",
                "expires_in": 2,
            })))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;

        // Second refresh, after the wait: a fresh epoch, comfortably clear
        // of the margin.
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("refresh_token=boundary-refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "fresh-epoch-access",
                "refresh_token": "fresh-epoch-refresh",
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = config_with_near_expiry(&server.uri(), 2);
        config::save(&cfg).expect("seed active network");
        let mut waits = Vec::new();
        let cfg = ensure_fresh_token_with(
            cfg,
            async |cfg| obtain_fresh_token(cfg, false).await,
            |duration| {
                waits.push(duration);
                std::future::ready(())
            },
        )
        .await
        .expect("ensure_fresh_token must wait out the boundary and succeed");
        assert_eq!(waits.len(), 1);
        assert!((5..=7).contains(&waits[0].as_secs()));
        assert_eq!(
            config::load()
                .expect("saved config")
                .active_tokens()
                .expect("tokens")
                .refresh_token
                .as_deref(),
            Some("fresh-epoch-refresh")
        );

        let token = cfg.active_tokens().expect("token entry");
        assert_eq!(token.access_token.as_deref(), Some("fresh-epoch-access"));
        assert!(
            !token.is_expired_or_near(),
            "the returned token must clear the deploy margin"
        );
    }

    /// A token that is comfortably fresh on the first refresh must not
    /// trigger any wait — `ensure_fresh_token` returns after one round trip.
    #[tokio::test]
    async fn fresh_refresh_does_not_wait() {
        let _guard = ConfigDirGuard::new();
        let server = MockServer::start().await;
        mount_auth_config(&server).await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "fresh-access",
                "refresh_token": "fresh-refresh",
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;

        let cfg = config_with_near_expiry(&server.uri(), 60);
        config::save(&cfg).expect("seed credentials");
        let mut waits = Vec::new();
        let cfg = ensure_fresh_token_with(
            cfg,
            async |cfg| obtain_fresh_token(cfg, false).await,
            |duration| {
                waits.push(duration);
                std::future::ready(())
            },
        )
        .await
        .expect("ensure_fresh_token must succeed");
        assert!(waits.is_empty(), "a single fresh refresh must not wait");

        let token = cfg.active_tokens().expect("token entry");
        assert_eq!(token.access_token.as_deref(), Some("fresh-access"));
    }

    #[tokio::test]
    async fn override_device_login_then_refresh_keeps_disk_credentials() {
        let _guard = ConfigDirGuard::new();
        let server = MockServer::start().await;
        mount_auth_config(&server).await;
        let mut cfg = config_with_near_expiry("https://stored.invalid", 60);
        config::save(&cfg).expect("seed stored credentials");
        let before = std::fs::read(config::config_path()).expect("read seeded config");
        cfg.api_url_override = Some(server.uri());

        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("refresh_token=stored-refresh"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/device/code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "device", "user_code": "code",
                "verification_uri": format!("{}/verify", server.uri()),
                "interval": 0, "expires_in": 3600,
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("device_code=device"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "override-boundary", "refresh_token": "override-refresh",
                "token_type": "Bearer", "expires_in": 2,
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("refresh_token=override-refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "override-fresh", "refresh_token": "override-rotated",
                "token_type": "Bearer", "expires_in": 3600,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut waits = Vec::new();
        let cfg = ensure_fresh_token_with(
            cfg,
            async |cfg| obtain_fresh_token(cfg, false).await,
            |duration| {
                waits.push(duration);
                std::future::ready(())
            },
        )
        .await
        .expect("refresh after device fallback");
        assert_eq!(waits.len(), 1);
        assert_eq!(
            cfg.active_tokens().expect("tokens").access_token.as_deref(),
            Some("override-fresh")
        );
        assert_eq!(
            std::fs::read(config::config_path()).expect("read config"),
            before,
            "override device-login descendants must never replace stored credentials"
        );
    }

    #[tokio::test]
    async fn device_login_refresh_chain_is_not_persisted_under_override() {
        let _guard = ConfigDirGuard::new();
        let mut cfg = config_with_near_expiry("https://stored.invalid", 60);
        config::save(&cfg).expect("seed stored credentials");
        let before = std::fs::read(config::config_path()).expect("read config");
        cfg.api_url_override = Some("https://override.invalid".to_owned());
        let mut attempts = 0;
        let mut waits = 0;
        let cfg = ensure_fresh_token_with(
            cfg,
            async |cfg| {
                attempts += 1;
                let (refresh, ttl, from_refresh) = if attempts == 1 {
                    ("override-login", 2, false)
                } else {
                    assert_eq!(
                        cfg.active_tokens()
                            .expect("tokens")
                            .refresh_token
                            .as_deref(),
                        Some("override-login")
                    );
                    ("override-rotated", 3600, true)
                };
                Ok((
                    auth::TokenResponse {
                        access_token: "override-access".to_owned(),
                        refresh_token: Some(refresh.to_owned()),
                        expires_in: Some(ttl),
                        token_type: Some("Bearer".to_owned()),
                    },
                    from_refresh,
                ))
            },
            |_| {
                waits += 1;
                std::future::ready(())
            },
        )
        .await
        .expect("fresh token");
        assert_eq!((attempts, waits), (2, 1));
        assert!(!cfg.active_tokens().expect("tokens").is_expired_or_near());
        assert_eq!(
            std::fs::read(config::config_path()).expect("read config"),
            before,
            "override device-login descendants must not replace stored credentials"
        );
    }

    #[tokio::test]
    async fn short_lived_issuer_fails_after_one_wait() {
        let _guard = ConfigDirGuard::new();
        let cfg = config_with_near_expiry("https://unused.invalid", 60);
        config::save(&cfg).expect("seed active network");
        let mut attempts = 0;
        let mut waits = 0;
        let result = ensure_fresh_token_with(
            cfg,
            async |_| {
                attempts += 1;
                Ok((
                    auth::TokenResponse {
                        access_token: "short-access".to_owned(),
                        refresh_token: Some("rotation".to_owned()),
                        expires_in: Some(2),
                        token_type: Some("Bearer".to_owned()),
                    },
                    true,
                ))
            },
            |_| {
                waits += 1;
                std::future::ready(())
            },
        )
        .await;
        assert_eq!((attempts, waits), (2, 1));
        let error = result.expect_err("must not claim a near-expiry token is fresh");
        assert!(error.to_string().contains("300s"), "{error}");
        assert!(error.to_string().contains("issuer"), "{error}");
        assert_eq!(
            config::load()
                .expect("saved rotation")
                .active_tokens()
                .expect("tokens")
                .refresh_token
                .as_deref(),
            Some("rotation")
        );
    }

    #[tokio::test]
    async fn boundary_retry_preserves_rotation_and_concurrent_config_changes() {
        let _guard = ConfigDirGuard::new();
        for override_active in [false, true] {
            for rotate_again in [false, true] {
                let mut cfg = config_with_near_expiry("https://stored.invalid", 60);
                config::save(&cfg).expect("seed config");
                let original_expiry = cfg
                    .active_tokens()
                    .expect("tokens")
                    .token_expires_at
                    .clone();
                if override_active {
                    cfg.api_url_override = Some("https://override.invalid".to_owned());
                }
                let mut attempts = 0;
                let mut waits = Vec::new();
                let cfg = ensure_fresh_token_with(
                    cfg,
                    async |cfg| {
                        attempts += 1;
                        let previous = if attempts == 1 {
                            "stored-refresh"
                        } else {
                            "boundary-refresh"
                        };
                        assert_eq!(
                            cfg.active_tokens()
                                .expect("tokens")
                                .refresh_token
                                .as_deref(),
                            Some(previous)
                        );
                        Ok((
                            auth::TokenResponse {
                                access_token: if attempts == 1 {
                                    "boundary-access"
                                } else {
                                    "fresh-access"
                                }
                                .to_owned(),
                                refresh_token: if attempts == 1 {
                                    Some("boundary-refresh".to_owned())
                                } else if rotate_again {
                                    Some("fresh-refresh".to_owned())
                                } else {
                                    None
                                },
                                expires_in: Some(if attempts == 1 { 2 } else { 3600 }),
                                token_type: None,
                            },
                            true,
                        ))
                    },
                    |duration| {
                        waits.push(duration);
                        let mut disk = config::load().expect("read first persisted rotation");
                        assert_eq!(
                            disk.active_tokens()
                                .expect("tokens")
                                .refresh_token
                                .as_deref(),
                            Some("boundary-refresh")
                        );
                        disk.phala_api_key = Some("concurrent-change".to_owned());
                        config::save(&disk).expect("simulate concurrent change during wait");
                        std::future::ready(())
                    },
                )
                .await
                .expect("fresh after boundary");
                assert_eq!(attempts, 2);
                assert_eq!(waits.len(), 1);
                assert!((5..=7).contains(&waits[0].as_secs()));
                assert!(!cfg.active_tokens().expect("tokens").is_expired_or_near());
                let disk = config::load().expect("saved config");
                assert_eq!(disk.phala_api_key.as_deref(), Some("concurrent-change"));
                let token = disk.active_tokens().expect("saved tokens");
                assert_eq!(
                    token.refresh_token.as_deref(),
                    Some(if rotate_again {
                        "fresh-refresh"
                    } else {
                        "boundary-refresh"
                    })
                );
                assert_eq!(
                    token.access_token.as_deref(),
                    Some(if override_active {
                        "stale-access"
                    } else {
                        "fresh-access"
                    })
                );
                if override_active {
                    assert_eq!(token.token_expires_at, original_expiry);
                }
                assert_eq!(disk.api_url(), "https://stored.invalid");
            }
        }
    }

    #[tokio::test]
    async fn a_fresh_first_response_requests_no_boundary_wait() {
        let _guard = ConfigDirGuard::new();
        let mut attempts = 0;
        let mut waits = 0;
        let cfg = config_with_near_expiry("https://unused.invalid", 60);
        config::save(&cfg).expect("seed credentials");
        let cfg = ensure_fresh_token_with(
            cfg,
            async |_| {
                attempts += 1;
                Ok((
                    auth::TokenResponse {
                        access_token: "fresh-access".to_owned(),
                        refresh_token: None,
                        expires_in: Some(3600),
                        token_type: None,
                    },
                    true,
                ))
            },
            |_| {
                waits += 1;
                std::future::ready(())
            },
        )
        .await
        .expect("fresh after one request");
        assert_eq!((attempts, waits), (1, 0));
        assert_eq!(
            cfg.active_tokens()
                .expect("tokens")
                .refresh_token
                .as_deref(),
            Some("stored-refresh")
        );
    }
}
