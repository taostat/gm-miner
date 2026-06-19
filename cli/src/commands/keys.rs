//! `gmcli set-api-keys` — persist provider API keys.

use anyhow::{bail, Context as _, Result};

use gm_miner_cli::{
    config::{self, ProviderKeys},
    network::Network,
};

/// Validate a key value passed to `set-api-keys`: reject empty / whitespace-only
/// strings with an actionable error rather than silently storing them.
fn validate_key(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("empty value for --{name}; either omit the flag or pass a non-empty key");
    }
    Ok(())
}

pub(crate) fn cmd_set_api_keys(
    explicit_network: Option<Network>,
    anthropic: Option<String>,
    openai: Option<String>,
    google: Option<String>,
    chutes: Option<String>,
) -> Result<()> {
    // Reject empty values up front so they don't pass the deploy preflight.
    if let Some(ref k) = anthropic {
        validate_key("anthropic", k)?;
    }
    if let Some(ref k) = openai {
        validate_key("openai", k)?;
    }
    if let Some(ref k) = google {
        validate_key("google", k)?;
    }
    if let Some(ref k) = chutes {
        validate_key("chutes", k)?;
    }

    // Load → mutate → save under the lock so a concurrent `deploy` save can't
    // be clobbered, and re-read fresh inside the lock so we merge onto the
    // latest on-disk state rather than a snapshot taken before the lock.
    let (has_anthropic, has_openai, has_google, has_chutes) = config::with_config_lock(|| {
        let mut cfg = config::load()
            .context("load gmcli config (delete ~/.gmcli/config.json if corrupted)")?;

        // Provider keys are network-independent, but an explicit --network here
        // is still the user's sticky selection — persist it so the promise holds
        // even when set-api-keys is the command that carries the flag.
        if let Some(network) = explicit_network {
            cfg.set_network(network);
        }

        let keys = cfg.provider_keys.get_or_insert_with(ProviderKeys::default);
        if let Some(k) = anthropic {
            keys.anthropic = Some(k);
        }
        if let Some(k) = openai {
            keys.openai = Some(k);
        }
        if let Some(k) = google {
            keys.google = Some(k);
        }
        if let Some(k) = chutes {
            keys.chutes = Some(k);
        }
        let snapshot = (
            keys.anthropic.is_some(),
            keys.openai.is_some(),
            keys.google.is_some(),
            keys.chutes.is_some(),
        );

        config::save(&cfg).context("save config")?;
        Ok(snapshot)
    })?;

    let mut set_names: Vec<&str> = Vec::new();
    if has_anthropic {
        set_names.push("anthropic");
    }
    if has_openai {
        set_names.push("openai");
    }
    if has_google {
        set_names.push("google");
    }
    if has_chutes {
        set_names.push("chutes");
    }

    // Report which providers are now configured — never print the values.
    if set_names.is_empty() {
        println!("No keys stored (pass --anthropic, --openai, --google, or --chutes to set one).");
    } else {
        println!("Provider keys updated.");
        for name in &set_names {
            println!("  {name}: set");
        }
        println!("\nNext: gmcli deploy --image-repo ghcr.io/<owner>/gm-miner");
    }
    Ok(())
}
