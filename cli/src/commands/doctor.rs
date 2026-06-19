//! `gmcli doctor` — a preflight checklist run before deploying.

use anyhow::{bail, Result};

use gm_miner_cli::{client::RegistryClient, config::Config, network::Network, types::MinerStatus};

use crate::commands::persist::try_refresh_token;

/// The state of one `doctor` checklist line.
#[derive(PartialEq, Eq)]
enum Status {
    /// Ready — nothing to do.
    Pass,
    /// A normal pre-deploy state worth surfacing but not a failure (e.g. the
    /// hotkey isn't registered yet — the first `deploy` registers it).
    Info,
    /// Needs the operator's attention before deploying.
    Fail,
}

/// One line of the `doctor` checklist: a status mark, a label, and an
/// optional note (the resolved detail for a pass, the actionable fix for a
/// fail, or context for an info line).
struct Check {
    status: Status,
    label: String,
    note: String,
}

impl Check {
    fn pass(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Pass,
            label: label.into(),
            note: detail.into(),
        }
    }

    fn info(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Info,
            label: label.into(),
            note: detail.into(),
        }
    }

    fn fail(label: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            status: Status::Fail,
            label: label.into(),
            note: fix.into(),
        }
    }

    fn is_failure(&self) -> bool {
        self.status == Status::Fail
    }

    fn render(&self) {
        let (mark, note_prefix) = match self.status {
            Status::Pass => ("[ok]", "      "),
            Status::Info => ("[--]", "      "),
            Status::Fail => ("[!!]", "      → "),
        };
        println!("  {mark} {}", self.label);
        if !self.note.is_empty() {
            println!("{note_prefix}{}", self.note);
        }
    }
}

/// `gmcli doctor` — a preflight checklist run before deploying.
///
/// Each check renders green/red with an actionable fix. The hotkey-
/// registration check probes `GET /miners/me`; a 401/403/404 renders as
/// "not registered on subnet N" rather than a raw body, and its remedy names
/// `register-hotkey`.
pub(crate) async fn cmd_doctor(cfg: Config) -> Result<()> {
    let network = cfg.resolved_network();
    println!(
        "gmcli doctor — preflight for {network} (netuid {})\n",
        network.netuid()
    );

    // Non-interactively refresh an expired-but-refreshable token up front so
    // the checklist reflects what a real deploy would see. Unlike the deploy
    // path's `ensure_fresh_token`, this never falls back to an interactive
    // device-code login — a preflight diagnostic must not open a browser or
    // block on auth. A refresh that can't happen leaves the config as-is and
    // `login_check`/`hotkey_check` report the true state.
    let cfg = try_refresh_token(cfg).await;

    let mut checks = vec![
        network_check(network, &cfg),
        login_check(&cfg),
        provider_keys_check(&cfg),
        phala_cli_check(),
        phala_api_key_check(&cfg),
    ];
    checks.push(hotkey_check(cfg).await);

    for check in &checks {
        check.render();
    }

    let failures = checks.iter().filter(|c| c.is_failure()).count();
    println!();
    if failures == 0 {
        println!("All checks passed — you're ready to `gmcli deploy`.");
        Ok(())
    } else {
        bail!("{failures} check(s) need attention before deploying (see above).");
    }
}

fn network_check(network: Network, cfg: &Config) -> Check {
    Check::pass(
        format!("Network: {network} (netuid {})", network.netuid()),
        format!("registry {} · chain {}", cfg.api_url(), network.chain_ws()),
    )
}

fn login_check(cfg: &Config) -> Check {
    match cfg.active_tokens() {
        Some(t) if t.access_token.is_some() && !t.is_expired_or_near() => {
            Check::pass("Logged in (token valid)", String::new())
        }
        // An expired access token with a stored refresh token is not a
        // failure: the next registry call refreshes it silently
        // (`ensure_fresh_token`), so the operator does not need to log in
        // again.
        Some(t) if t.access_token.is_some() && t.refresh_token.is_some() => {
            Check::pass("Logged in (token refreshes on next use)", String::new())
        }
        Some(t) if t.access_token.is_some() => {
            Check::fail("Logged in", "your session has expired — run `gmcli login`")
        }
        _ => Check::fail("Logged in", "not logged in — run `gmcli login`"),
    }
}

fn provider_keys_check(cfg: &Config) -> Check {
    let set: Vec<&str> = cfg.provider_keys.as_ref().map_or_else(Vec::new, |k| {
        let mut names = Vec::new();
        if k.anthropic.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            names.push("anthropic");
        }
        if k.openai.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            names.push("openai");
        }
        if k.google.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            names.push("google");
        }
        if k.chutes.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            names.push("chutes");
        }
        names
    });
    if set.is_empty() {
        Check::fail(
            "Provider keys set",
            "no provider keys — run `gmcli set-api-keys --anthropic <key>` (and/or --openai / --google / --chutes)",
        )
    } else {
        Check::pass(
            format!("Provider keys set ({})", set.join(", ")),
            String::new(),
        )
    }
}

fn phala_cli_check() -> Check {
    let on_path = std::process::Command::new("phala")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if on_path {
        Check::pass("`phala` CLI on PATH", String::new())
    } else {
        Check::fail(
            "`phala` CLI on PATH",
            "not found — install with `npm i -g phala`",
        )
    }
}

fn phala_api_key_check(cfg: &Config) -> Check {
    // Accept exactly the sources `deploy` resolves a Phala credential from
    // (env var, saved gmcli config key, or an existing `phala` CLI session),
    // so doctor never reports a deploy that can authenticate as not ready.
    match gm_miner_cli::phala::credential_source(cfg.phala_api_key.as_deref()) {
        Some(source) => Check::pass(format!("Phala Cloud credential ({source})"), String::new()),
        None => Check::fail(
            "Phala Cloud API key",
            "no Phala credential — set PHALA_API_KEY, run `phala auth login`, \
             or paste a key when `gmcli deploy` prompts (it is then saved)",
        ),
    }
}

/// Probe `GET /miners/me` and classify the result for the doctor checklist.
///
/// A 401/403/404 means the hotkey isn't registered on the subnet — rendered
/// as an actionable line, never the raw body. The 404 remedy names
/// `register-hotkey` (and its `--hotkey-ss58` bring-your-own escape hatch).
async fn hotkey_check(cfg: Config) -> Check {
    let network = cfg.resolved_network();
    let netuid = network.netuid();
    if cfg
        .active_tokens()
        .and_then(|t| t.access_token.as_deref())
        .is_none()
    {
        return Check::fail(
            format!("Registered with gm on subnet {netuid}"),
            "can't check until you're logged in — run `gmcli login`",
        );
    }

    let mut client = RegistryClient::new(cfg.clone());
    let resp = match client.get(gm_miner_cli::client::ME_PATH).await {
        Ok(resp) => resp,
        Err(err) => {
            return Check::fail(
                format!("Registered with gm on subnet {netuid}"),
                format!("couldn't reach the registry: {err}"),
            );
        }
    };

    let label = format!("Registered with gm on subnet {netuid}");
    let status = resp.status();
    if status.is_success() {
        let hotkey = resp
            .json::<MinerStatus>()
            .await
            .map_or_else(|_| "<registered>".to_owned(), |m| m.hotkey);
        return Check::pass(label, hotkey);
    }
    // A 404 is the expected state before the first deploy: the registry has no
    // miner record for this hotkey yet. This branch is only reached once logged
    // in, so the hotkey identity is already known — the only step left is
    // `deploy`, which posts `/miners/register` and creates the record this probe
    // reads. Surface it as informational, not a failure — doctor *precedes* it.
    if status.as_u16() == 404 {
        let who = cfg
            .token_hotkey()
            .map_or_else(|| "your hotkey".to_owned(), |hk| format!("hotkey {hk}"));
        return Check::info(
            label,
            format!(
                "no registry record for {who} on `{network}` yet — your first \
                 `gmcli deploy` creates it. On the wrong network? Pass \
                 `--network mainnet`/`--network testnet`."
            ),
        );
    }
    // A 401/403 with a valid-looking token usually means the wrong network.
    if matches!(status.as_u16(), 401 | 403) {
        return Check::fail(
            label,
            format!(
                "registry rejected the request ({status}). On the wrong network? \
                 You're on `{network}` — pass `--network mainnet`/`--network testnet`."
            ),
        );
    }
    Check::fail(label, format!("registry returned {status}"))
}
