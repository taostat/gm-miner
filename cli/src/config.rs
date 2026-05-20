//! CLI configuration persisted to `~/.gm-miner/config.json`.
//!
//! Pattern mirrors blockmachine's `auth_config.py`, adapted for Rust.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default config directory.
fn config_dir() -> PathBuf {
    std::env::var("GM_MINER_CONFIG_DIR").map_or_else(
        |_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".gm-miner")
        },
        PathBuf::from,
    )
}

/// Path to the config file.
#[must_use]
pub fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

/// Per-network token set.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_expires_at: Option<String>,
}

/// Per-network configuration.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NetworkEntry {
    pub auth_url: Option<String>,
    pub api_url: Option<String>,
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenEntry>,
}

/// Provider API keys persisted by `gm-miner set-api-keys`.
///
/// Values are stored in `~/.gm-miner/config.json` (mode 0600).
/// Missing fields mean "not configured" — the deploy command treats
/// a completely absent `provider_keys` section the same as all-None.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProviderKeys {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anthropic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openai: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google: Option<String>,
}

impl ProviderKeys {
    /// Returns true if at least one key is set to a non-empty, non-whitespace value.
    ///
    /// `Some("")` and `Some("  ")` are treated as not set so that accidental
    /// empty-string assignments (e.g. from an unset shell variable) don't
    /// silently pass the deploy preflight check.
    #[must_use]
    pub fn any_set(&self) -> bool {
        let non_empty = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.trim().is_empty());
        non_empty(&self.anthropic) || non_empty(&self.openai) || non_empty(&self.google)
    }
}

/// Root config structure.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub networks: std::collections::HashMap<String, NetworkEntry>,
    /// Which network is currently active.
    pub active_network: Option<String>,
    /// Provider API keys set by `gm-miner set-api-keys`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_keys: Option<ProviderKeys>,
}

impl Config {
    /// Active network name, defaulting to `"mainnet"`.
    #[must_use]
    pub fn active_network(&self) -> &str {
        self.active_network.as_deref().unwrap_or("mainnet")
    }

    /// Mutable reference to the active network entry (creating it if absent).
    pub fn active_entry_mut(&mut self) -> &mut NetworkEntry {
        let key = self.active_network().to_owned();
        self.networks.entry(key).or_default()
    }

    /// Current tokens for the active network.
    #[must_use]
    pub fn active_tokens(&self) -> Option<&TokenEntry> {
        self.networks
            .get(self.active_network())
            .and_then(|n| n.tokens.as_ref())
    }

    /// Auth URL for the active network.
    #[must_use]
    pub fn auth_url(&self) -> String {
        self.networks
            .get(self.active_network())
            .and_then(|n| n.auth_url.clone())
            .unwrap_or_else(|| "https://auth.taostats.io".to_string())
    }

    /// Registry API URL for the active network.
    #[must_use]
    pub fn api_url(&self) -> String {
        self.networks
            .get(self.active_network())
            .and_then(|n| n.api_url.clone())
            .unwrap_or_else(|| "https://api.gm.taostats.io".to_string())
    }

    /// OAuth client ID.
    #[must_use]
    pub fn client_id(&self) -> String {
        self.networks
            .get(self.active_network())
            .and_then(|n| n.client_id.clone())
            .unwrap_or_else(|| "gm-miner".to_string())
    }
}

/// Load config from disk, returning a default if the file doesn't exist.
///
/// # Errors
/// Returns an error if the file exists but cannot be read or parsed.
pub fn load() -> Result<Config> {
    let path = config_path();
    if !path.exists() {
        return Ok(Config::default());
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

/// Persist config to disk, creating the directory if needed.
///
/// # Errors
/// Returns an error if the directory cannot be created, the file cannot be
/// written, or (on Unix) the permissions cannot be set.
pub fn save(cfg: &Config) -> Result<()> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create config dir {}", dir.display()))?;

    let path = config_path();
    let bytes = serde_json::to_vec_pretty(cfg).context("serialize config")?;
    std::fs::write(&path, &bytes).with_context(|| format!("write {}", path.display()))?;

    // Restrict permissions on Unix so the file is not world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, perms)
            .with_context(|| format!("chmod 600 {}", path.display()))?;
    }

    Ok(())
}
