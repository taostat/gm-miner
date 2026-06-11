//! Read sealed OAuth env vars into per-provider config.
//!
//! Env-var surface is the one `gm-miner deploy --paste-{codex,claude}-auth`
//! writes into the encrypted Phala-cloud env (`docs/auth-modes.md`):
//!
//! ```text
//! GM_OPENAI_OAUTH_REFRESH_TOKEN
//! GM_OPENAI_OAUTH_INITIAL_ACCESS_TOKEN
//! GM_OPENAI_OAUTH_EXPIRES_AT          # RFC 3339
//! GM_ANTHROPIC_OAUTH_REFRESH_TOKEN
//! GM_ANTHROPIC_OAUTH_INITIAL_ACCESS_TOKEN
//! GM_ANTHROPIC_OAUTH_EXPIRES_AT
//! ```
//!
//! A provider is "enabled" iff its `*_REFRESH_TOKEN` is set. A provider
//! that is enabled without the matching `*_INITIAL_ACCESS_TOKEN` /
//! `*_EXPIRES_AT` is a configuration error and refuses to boot — the
//! deploy step always writes all three together, so a partial set
//! means the env was tampered with.

use std::env;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};

use crate::provider::OauthProvider;

/// Per-provider startup config — the result of reading the sealed env
/// vars at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    pub provider: OauthProvider,
    pub refresh_token: String,
    pub initial_access_token: String,
    pub initial_expires_at: DateTime<Utc>,
}

/// Whole-sidecar config — the subset of providers that were enabled
/// at boot, plus the bind addresses for the two HTTP listeners.
#[derive(Debug, Clone)]
pub struct SidecarConfig {
    pub providers: Vec<ProviderConfig>,
    pub token_bind_addr: String,
    pub metrics_bind_addr: String,
}

/// Default bind address for the token endpoint Envoy queries via its
/// `lua` filter. Loopback only — nothing outside the CVM should reach
/// this endpoint, the same posture `attestd` uses.
pub const DEFAULT_TOKEN_BIND_ADDR: &str = "127.0.0.1:7100";
/// Default bind address for the Prometheus scrape endpoint. Loopback
/// only — Envoy's metrics listener stitches the sidecar's scrape into
/// the same external `/stats/prometheus` URL via a future cluster.
pub const DEFAULT_METRICS_BIND_ADDR: &str = "127.0.0.1:7101";

/// Env-var name for an override to [`DEFAULT_TOKEN_BIND_ADDR`].
pub const TOKEN_BIND_ADDR_ENV: &str = "GM_AUTH_SIDECAR_TOKEN_BIND_ADDR";
/// Env-var name for an override to [`DEFAULT_METRICS_BIND_ADDR`].
pub const METRICS_BIND_ADDR_ENV: &str = "GM_AUTH_SIDECAR_METRICS_BIND_ADDR";

impl SidecarConfig {
    /// Read the sealed env vars and assemble the boot config.
    ///
    /// A sidecar with **zero** enabled providers is still a valid
    /// configuration — the operator may have removed every paste flag
    /// from their last deploy. The binary stays up so the HTTP
    /// endpoints exist (Envoy will 503 on every provider route) but
    /// the worker pool is empty.
    ///
    /// # Errors
    /// Returns an error if a provider has a refresh token set but is
    /// missing one of the other two sibling vars, or if `EXPIRES_AT`
    /// is not parseable RFC 3339.
    pub fn from_env() -> Result<Self> {
        Self::from_getter(|k| env::var(k).ok())
    }

    /// Build a config by reading from an arbitrary getter — the
    /// production entry point [`from_env`](Self::from_env) wraps this
    /// with `std::env::var`, the test suite injects a `HashMap` so it
    /// does not have to mutate the process env.
    ///
    /// # Errors
    /// See [`SidecarConfig::from_env`].
    pub fn from_getter<F>(getter: F) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut providers = Vec::new();
        for provider in OauthProvider::all() {
            if let Some(cfg) = ProviderConfig::from_getter(*provider, &getter)? {
                providers.push(cfg);
            }
        }
        let token_bind_addr =
            getter(TOKEN_BIND_ADDR_ENV).unwrap_or_else(|| DEFAULT_TOKEN_BIND_ADDR.to_owned());
        let metrics_bind_addr =
            getter(METRICS_BIND_ADDR_ENV).unwrap_or_else(|| DEFAULT_METRICS_BIND_ADDR.to_owned());
        Ok(Self {
            providers,
            token_bind_addr,
            metrics_bind_addr,
        })
    }
}

impl ProviderConfig {
    /// Build a [`ProviderConfig`] for one provider by reading its
    /// three sealed env vars from the process env.
    ///
    /// # Errors
    /// See [`SidecarConfig::from_env`].
    pub fn from_env(provider: OauthProvider) -> Result<Option<Self>> {
        Self::from_getter(provider, |k| env::var(k).ok())
    }

    /// Per-provider variant of [`SidecarConfig::from_getter`]. Returns
    /// `Ok(None)` when the refresh token is unset — that provider
    /// runs in api-key mode and the sidecar does no work for it.
    ///
    /// # Errors
    /// See [`SidecarConfig::from_env`].
    pub fn from_getter<F>(provider: OauthProvider, getter: F) -> Result<Option<Self>>
    where
        F: Fn(&str) -> Option<String>,
    {
        let names = EnvVarNames::for_provider(provider);
        let Some(refresh_token) = getter(names.refresh_token) else {
            return Ok(None);
        };
        if refresh_token.is_empty() {
            return Ok(None);
        }

        let initial_access_token = getter(names.initial_access_token).with_context(|| {
            format!(
                "{provider} OAuth subscription enabled (found {}) but {} is missing — \
                 re-run `gm-miner deploy --paste-{}-auth` to rewrite all three vars together",
                names.refresh_token,
                names.initial_access_token,
                cli_paste_flag_suffix(provider),
            )
        })?;
        if initial_access_token.trim().is_empty() {
            bail!(
                "{} is set but empty — re-run the gm-miner paste flag to rewrite the sealed env",
                names.initial_access_token,
            );
        }

        let expires_raw = getter(names.expires_at).with_context(|| {
            format!(
                "{provider} OAuth subscription enabled (found {}) but {} is missing — \
                 re-run `gm-miner deploy --paste-{}-auth` to rewrite all three vars together",
                names.refresh_token,
                names.expires_at,
                cli_paste_flag_suffix(provider),
            )
        })?;
        let initial_expires_at = parse_rfc3339_utc(&expires_raw).with_context(|| {
            format!(
                "{} carries unparseable RFC 3339 timestamp: {expires_raw:?}",
                names.expires_at,
            )
        })?;

        Ok(Some(Self {
            provider,
            refresh_token,
            initial_access_token,
            initial_expires_at,
        }))
    }
}

/// Per-provider env-var name bundle. Mirrors `OauthEnvVars` in the CLI
/// crate; kept duplicated here on purpose so the sidecar binary does
/// not pull the CLI crate in transitively.
#[derive(Debug, Clone, Copy)]
struct EnvVarNames {
    refresh_token: &'static str,
    initial_access_token: &'static str,
    expires_at: &'static str,
}

impl EnvVarNames {
    fn for_provider(provider: OauthProvider) -> Self {
        match provider {
            OauthProvider::Openai => Self {
                refresh_token: "GM_OPENAI_OAUTH_REFRESH_TOKEN",
                initial_access_token: "GM_OPENAI_OAUTH_INITIAL_ACCESS_TOKEN",
                expires_at: "GM_OPENAI_OAUTH_EXPIRES_AT",
            },
            OauthProvider::Anthropic => Self {
                refresh_token: "GM_ANTHROPIC_OAUTH_REFRESH_TOKEN",
                initial_access_token: "GM_ANTHROPIC_OAUTH_INITIAL_ACCESS_TOKEN",
                expires_at: "GM_ANTHROPIC_OAUTH_EXPIRES_AT",
            },
        }
    }
}

fn cli_paste_flag_suffix(provider: OauthProvider) -> &'static str {
    match provider {
        OauthProvider::Openai => "codex",
        OauthProvider::Anthropic => "claude",
    }
}

fn parse_rfc3339_utc(s: &str) -> Result<DateTime<Utc>> {
    let parsed = DateTime::parse_from_rfc3339(s)
        .with_context(|| format!("not an RFC 3339 timestamp: {s}"))?;
    Ok(parsed.with_timezone(&Utc))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn rfc3339_far_future() -> &'static str {
        "2030-01-01T00:00:00+00:00"
    }

    fn getter_for(values: HashMap<String, String>) -> impl Fn(&str) -> Option<String> {
        move |k| values.get(k).cloned()
    }

    #[test]
    fn missing_refresh_token_yields_none() {
        let cfg =
            ProviderConfig::from_getter(OauthProvider::Openai, getter_for(HashMap::new())).unwrap();
        assert!(cfg.is_none());
    }

    #[test]
    fn empty_refresh_token_yields_none() {
        let mut m = HashMap::new();
        m.insert("GM_OPENAI_OAUTH_REFRESH_TOKEN".to_owned(), String::new());
        let cfg = ProviderConfig::from_getter(OauthProvider::Openai, getter_for(m)).unwrap();
        assert!(cfg.is_none());
    }

    #[test]
    fn complete_triple_yields_some() {
        let mut m = HashMap::new();
        m.insert("GM_ANTHROPIC_OAUTH_REFRESH_TOKEN".to_owned(), "rt-a".into());
        m.insert(
            "GM_ANTHROPIC_OAUTH_INITIAL_ACCESS_TOKEN".to_owned(),
            "at-a".into(),
        );
        m.insert(
            "GM_ANTHROPIC_OAUTH_EXPIRES_AT".to_owned(),
            rfc3339_far_future().into(),
        );
        let cfg = ProviderConfig::from_getter(OauthProvider::Anthropic, getter_for(m))
            .unwrap()
            .unwrap();
        assert_eq!(cfg.refresh_token, "rt-a");
        assert_eq!(cfg.initial_access_token, "at-a");
        assert_eq!(cfg.initial_expires_at.to_rfc3339(), rfc3339_far_future());
    }

    #[test]
    fn missing_initial_access_token_is_rejected() {
        let mut m = HashMap::new();
        m.insert("GM_OPENAI_OAUTH_REFRESH_TOKEN".to_owned(), "rt-o".into());
        m.insert(
            "GM_OPENAI_OAUTH_EXPIRES_AT".to_owned(),
            rfc3339_far_future().into(),
        );
        let err = ProviderConfig::from_getter(OauthProvider::Openai, getter_for(m)).unwrap_err();
        let s = format!("{err:#}");
        assert!(
            s.contains("GM_OPENAI_OAUTH_INITIAL_ACCESS_TOKEN"),
            "got: {s}"
        );
        assert!(s.contains("--paste-codex-auth"), "got: {s}");
    }

    #[test]
    fn empty_initial_access_token_is_rejected() {
        let mut m = HashMap::new();
        m.insert("GM_ANTHROPIC_OAUTH_REFRESH_TOKEN".to_owned(), "rt-a".into());
        m.insert(
            "GM_ANTHROPIC_OAUTH_INITIAL_ACCESS_TOKEN".to_owned(),
            "   ".into(),
        );
        m.insert(
            "GM_ANTHROPIC_OAUTH_EXPIRES_AT".to_owned(),
            rfc3339_far_future().into(),
        );
        let err = ProviderConfig::from_getter(OauthProvider::Anthropic, getter_for(m)).unwrap_err();
        assert!(format!("{err:#}").contains("empty"));
    }

    #[test]
    fn malformed_expires_at_is_rejected() {
        let mut m = HashMap::new();
        m.insert("GM_ANTHROPIC_OAUTH_REFRESH_TOKEN".to_owned(), "rt-a".into());
        m.insert(
            "GM_ANTHROPIC_OAUTH_INITIAL_ACCESS_TOKEN".to_owned(),
            "at-a".into(),
        );
        m.insert(
            "GM_ANTHROPIC_OAUTH_EXPIRES_AT".to_owned(),
            "not-a-date".into(),
        );
        let err = ProviderConfig::from_getter(OauthProvider::Anthropic, getter_for(m)).unwrap_err();
        assert!(format!("{err:#}").contains("RFC 3339"));
    }

    #[test]
    fn sidecar_config_picks_up_both_providers() {
        let mut m = HashMap::new();
        for prefix in ["GM_OPENAI_OAUTH", "GM_ANTHROPIC_OAUTH"] {
            m.insert(format!("{prefix}_REFRESH_TOKEN"), "rt".into());
            m.insert(format!("{prefix}_INITIAL_ACCESS_TOKEN"), "at".into());
            m.insert(format!("{prefix}_EXPIRES_AT"), rfc3339_far_future().into());
        }
        let cfg = SidecarConfig::from_getter(getter_for(m)).unwrap();
        assert_eq!(cfg.providers.len(), 2);
        assert_eq!(cfg.token_bind_addr, DEFAULT_TOKEN_BIND_ADDR);
    }

    #[test]
    fn sidecar_config_with_no_providers_is_ok() {
        let cfg = SidecarConfig::from_getter(getter_for(HashMap::new())).unwrap();
        assert!(cfg.providers.is_empty());
        assert_eq!(cfg.token_bind_addr, DEFAULT_TOKEN_BIND_ADDR);
        assert_eq!(cfg.metrics_bind_addr, DEFAULT_METRICS_BIND_ADDR);
    }
}
