//! Manual-paste OAuth subscription auth for the miner runtime.
//!
//! Phase A scope (see `docs/auth-modes.md`):
//!
//!   - The operator runs Codex CLI / Claude Code CLI on their own laptop
//!     and completes the OAuth flow there.
//!   - `gm-miner deploy --paste-codex-auth <path>` and
//!     `--paste-claude-auth <path>` parse the resulting `auth.json` and
//!     emit `GM_OPENAI_OAUTH_*` / `GM_ANTHROPIC_OAUTH_*` env vars wired
//!     into the same Phala-Cloud-encrypted `.env` the provider API keys
//!     use today. The native OAuth flow inside gm-miner is Phase B.
//!
//! The wire shapes parsed here follow `docs/research/oauth-subscription-
//! prior-art.md` (Hermes / `OpenClaw` research):
//!
//!   - Claude Code's `~/.claude/.credentials.json` carries
//!     `{ accessToken, refreshToken, expiresAt }` (ms-since-epoch).
//!     Hermes mirrors that shape in `~/.hermes/.anthropic_oauth.json`.
//!   - Codex CLI's auth file carries `{ access_token, refresh_token,
//!     expires_at }` (seconds-since-epoch) — `snake_case`, matching the
//!     OAuth wire response. Hermes nests it under an `openai-codex` key
//!     in `~/.hermes/auth.json`.
//!
//! Both shapes are accepted defensively (the file the operator pastes
//! may come from either CLI) and normalised into [`PastedOauthAuth`].

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// Parsed contents of an operator-pasted OAuth auth.json, normalised
/// across the Codex / Claude Code / Hermes shapes the research file
/// documents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PastedOauthAuth {
    /// Long-lived `refresh_token`. Reserved for the Phase B in-CVM
    /// refresh worker; emitted into the encrypted env today so a Phase
    /// B upgrade is drop-in.
    pub refresh_token: String,
    /// `access_token` from the paste — usable until `expires_at_rfc3339`.
    pub initial_access_token: String,
    /// Expiry of `initial_access_token` as an RFC 3339 timestamp.
    pub expires_at_rfc3339: String,
}

/// Raw JSON envelope tolerant of the three layouts operators actually
/// paste from real CLIs:
///
/// 1. **Hermes-style** — top-level `openai-codex` or `anthropic` block.
/// 2. **Codex CLI stock** — `~/.codex/auth.json` wraps the credentials
///    under a `tokens` key (alongside an unrelated `OPENAI_API_KEY`).
/// 3. **Claude Code stock** — `~/.claude/.credentials.json` wraps the
///    credentials under a `claudeAiOauth` key.
/// 4. **Flat** — top-level fields directly, used by some other CLIs.
///
/// Provider-specific blocks (Hermes nested, Codex `tokens`, Claude Code
/// `claudeAiOauth`) take priority over the flat fallback when the file
/// targets that provider. This lets an operator paste either a curated
/// auth.json or the unmodified stock file from their CLI.
#[derive(Debug, Deserialize)]
struct RawAuthFile {
    // Hermes-style nested layouts.
    #[serde(default, rename = "openai-codex")]
    openai_codex: Option<RawOauthBlock>,
    #[serde(default)]
    anthropic: Option<RawOauthBlock>,

    // Codex CLI stock auth.json — credentials nested under `tokens`.
    #[serde(default)]
    tokens: Option<RawOauthBlock>,

    // Claude Code stock .credentials.json — credentials nested under
    // `claudeAiOauth`.
    #[serde(default, rename = "claudeAiOauth")]
    claude_ai_oauth: Option<RawOauthBlock>,

    // Flat layout — read when no nested block applies.
    #[serde(flatten)]
    flat: RawOauthBlock,
}

/// One OAuth credential block. Accepts both camelCase (Anthropic-style)
/// and `snake_case` (`OpenAI` / OAuth-wire-shape) field names, plus both
/// seconds- and milliseconds-since-epoch for `expires_at`.
#[derive(Debug, Default, Deserialize)]
struct RawOauthBlock {
    #[serde(default, alias = "accessToken")]
    access_token: Option<String>,
    #[serde(default, alias = "refreshToken")]
    refresh_token: Option<String>,
    #[serde(default, alias = "expiresAt")]
    expires_at: Option<serde_json::Value>,
}

/// Which provider a paste targets. Selects which nested block to prefer
/// when the file carries the Hermes layout and disambiguates error
/// messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OauthProvider {
    /// `ChatGPT` Plus / `OpenAI` Codex.
    Openai,
    /// Claude Pro / Claude Max (Anthropic).
    Anthropic,
}

impl OauthProvider {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
        }
    }
}

impl std::fmt::Display for OauthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse an operator-pasted auth.json into the normalised
/// [`PastedOauthAuth`] form.
///
/// `provider` picks the right nested block when the file uses the
/// Hermes layout (`auth.json` with `openai-codex` / `anthropic` keys);
/// a flat file (Claude Code or Codex CLI) is read regardless of which
/// provider is requested.
///
/// # Errors
/// Returns an error if the bytes are not JSON, or if the resulting
/// block is missing any of `access_token`, `refresh_token`, or
/// `expires_at`.
pub fn parse_pasted_auth_json(bytes: &[u8], provider: OauthProvider) -> Result<PastedOauthAuth> {
    let raw: RawAuthFile = serde_json::from_slice(bytes).context("parse pasted auth.json")?;

    // Prefer the nested provider-specific block when present, falling
    // through wrapper variants in order of specificity, then to the
    // flat top-level shape. Either path produces the same
    // `RawOauthBlock`, so the downstream extraction is unconditional.
    //
    // Codex priority: Hermes `openai-codex` block → Codex CLI `tokens`
    // wrapper → flat.
    // Anthropic priority: Hermes `anthropic` block → Claude Code
    // `claudeAiOauth` wrapper → flat.
    let block = match provider {
        OauthProvider::Openai => raw.openai_codex.or(raw.tokens).unwrap_or(raw.flat),
        OauthProvider::Anthropic => raw.anthropic.or(raw.claude_ai_oauth).unwrap_or(raw.flat),
    };

    let access_token = block.access_token.ok_or_else(|| {
        anyhow::anyhow!(
            "pasted {provider} auth.json is missing access_token / accessToken — \
             re-export the file from your CLI"
        )
    })?;
    let refresh_token = block.refresh_token.ok_or_else(|| {
        anyhow::anyhow!(
            "pasted {provider} auth.json is missing refresh_token / refreshToken — \
             re-export the file from your CLI"
        )
    })?;
    let expires_raw = block.expires_at.ok_or_else(|| {
        anyhow::anyhow!(
            "pasted {provider} auth.json is missing expires_at / expiresAt — \
             re-export the file from your CLI"
        )
    })?;

    if access_token.trim().is_empty() {
        bail!("pasted {provider} auth.json has an empty access_token");
    }
    if refresh_token.trim().is_empty() {
        bail!("pasted {provider} auth.json has an empty refresh_token");
    }

    let expires_at_rfc3339 = normalise_expires_at(&expires_raw).with_context(|| {
        format!("pasted {provider} auth.json has an unparseable expires_at value: {expires_raw}")
    })?;

    Ok(PastedOauthAuth {
        refresh_token,
        initial_access_token: access_token,
        expires_at_rfc3339,
    })
}

/// Normalise an `expires_at` value to RFC 3339.
///
/// Accepts:
///
///   - RFC 3339 / ISO 8601 strings (passed through after validation).
///   - Seconds-since-epoch as a number (Codex CLI shape).
///   - Milliseconds-since-epoch as a number (Claude Code shape; the
///     research file shows Anthropic's wire format uses ms).
fn normalise_expires_at(value: &serde_json::Value) -> Result<String> {
    if let Some(s) = value.as_str() {
        let parsed = chrono::DateTime::parse_from_rfc3339(s)
            .with_context(|| format!("not an RFC 3339 timestamp: {s}"))?;
        return Ok(parsed.to_rfc3339());
    }

    let n = value
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("expected string or integer, got {value:?}"))?;

    // The boundary between "seconds" and "milliseconds" is whether the
    // value fits in a sane future-time-as-seconds window. ~10^11 covers
    // every plausible timestamp until year 5138; anything larger must
    // be milliseconds (Claude Code) — Anthropic's wire format uses
    // milliseconds-since-epoch per the research file.
    let (secs, nanos) = if n.abs() < 100_000_000_000 {
        (n, 0_u32)
    } else {
        let secs = n / 1_000;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "millisecond remainder is bounded to 0..1000 so the cast is exact"
        )]
        let nanos = ((n % 1_000).unsigned_abs() as u32) * 1_000_000;
        (secs, nanos)
    };

    chrono::DateTime::from_timestamp(secs, nanos)
        .map(|dt| dt.to_rfc3339())
        .ok_or_else(|| anyhow::anyhow!("timestamp out of range: {n}"))
}

/// Environment variables emitted into the `phala deploy` env file when a
/// provider is in `oauth_subscription` mode.
///
/// Naming follows the `GM_<PROVIDER>_OAUTH_*` shape the task description
/// pins so a future Phase B (native OAuth in-CVM) reuses the same env
/// surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OauthEnvVars {
    pub refresh_token_var: &'static str,
    pub refresh_token: String,
    pub initial_access_token_var: &'static str,
    pub initial_access_token: String,
    pub expires_at_var: &'static str,
    pub expires_at_rfc3339: String,
}

impl OauthEnvVars {
    /// Build the sealed env-var bundle for `provider`, consuming `auth`.
    #[must_use]
    pub fn for_provider(provider: OauthProvider, auth: PastedOauthAuth) -> Self {
        let (refresh, initial, expires) = match provider {
            OauthProvider::Openai => (
                "GM_OPENAI_OAUTH_REFRESH_TOKEN",
                "GM_OPENAI_OAUTH_INITIAL_ACCESS_TOKEN",
                "GM_OPENAI_OAUTH_EXPIRES_AT",
            ),
            OauthProvider::Anthropic => (
                "GM_ANTHROPIC_OAUTH_REFRESH_TOKEN",
                "GM_ANTHROPIC_OAUTH_INITIAL_ACCESS_TOKEN",
                "GM_ANTHROPIC_OAUTH_EXPIRES_AT",
            ),
        };
        Self {
            refresh_token_var: refresh,
            refresh_token: auth.refresh_token,
            initial_access_token_var: initial,
            initial_access_token: auth.initial_access_token,
            expires_at_var: expires,
            expires_at_rfc3339: auth.expires_at_rfc3339,
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    fn anth(token: &str, refresh: &str, expires: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "accessToken": token,
            "refreshToken": refresh,
            "expiresAt": expires,
        })
    }

    #[test]
    fn parses_flat_claude_code_credentials() {
        // ~/.claude/.credentials.json shape: flat camelCase, ms-since-epoch.
        let body = serde_json::to_vec(&anth("at", "rt", &serde_json::json!(1_900_000_000_000_i64)))
            .unwrap();
        let parsed = parse_pasted_auth_json(&body, OauthProvider::Anthropic).unwrap();
        assert_eq!(parsed.initial_access_token, "at");
        assert_eq!(parsed.refresh_token, "rt");
        assert!(
            parsed.expires_at_rfc3339.starts_with("2030-"),
            "got: {}",
            parsed.expires_at_rfc3339
        );
    }

    #[test]
    fn parses_flat_codex_credentials() {
        // Codex CLI shape: flat snake_case, seconds-since-epoch.
        let body = serde_json::to_vec(&serde_json::json!({
            "access_token": "at-codex",
            "refresh_token": "rt-codex",
            "expires_at": 1_900_000_000_i64,
        }))
        .unwrap();
        let parsed = parse_pasted_auth_json(&body, OauthProvider::Openai).unwrap();
        assert_eq!(parsed.initial_access_token, "at-codex");
        assert_eq!(parsed.refresh_token, "rt-codex");
        assert!(parsed.expires_at_rfc3339.starts_with("2030-"));
    }

    #[test]
    fn parses_nested_hermes_auth_json() {
        // Hermes auth.json shape: nested `openai-codex` block alongside
        // an unrelated `anthropic` block. Selecting Openai must read the
        // openai-codex block and ignore the anthropic one.
        let body = serde_json::to_vec(&serde_json::json!({
            "openai-codex": {
                "access_token": "at-nested",
                "refresh_token": "rt-nested",
                "expires_at": "2030-01-01T00:00:00Z",
            },
            "anthropic": {
                "accessToken": "wrong",
                "refreshToken": "wrong",
                "expiresAt": 1_900_000_000_000_i64,
            },
        }))
        .unwrap();
        let parsed = parse_pasted_auth_json(&body, OauthProvider::Openai).unwrap();
        assert_eq!(parsed.initial_access_token, "at-nested");
        assert_eq!(parsed.refresh_token, "rt-nested");
    }

    #[test]
    fn parses_codex_cli_stock_auth_json() {
        // ~/.codex/auth.json wraps credentials under `tokens`, alongside
        // an unrelated `OPENAI_API_KEY` field. The operator pastes the
        // file unmodified.
        let body = serde_json::to_vec(&serde_json::json!({
            "OPENAI_API_KEY": "sk-unrelated",
            "tokens": {
                "access_token": "at-codex-stock",
                "refresh_token": "rt-codex-stock",
                "expires_at": 1_900_000_000_i64,
            },
        }))
        .unwrap();
        let parsed = parse_pasted_auth_json(&body, OauthProvider::Openai).unwrap();
        assert_eq!(parsed.initial_access_token, "at-codex-stock");
        assert_eq!(parsed.refresh_token, "rt-codex-stock");
    }

    #[test]
    fn parses_claude_code_stock_credentials_json() {
        // ~/.claude/.credentials.json wraps credentials under
        // `claudeAiOauth` with camelCase + ms-since-epoch.
        let body = serde_json::to_vec(&serde_json::json!({
            "claudeAiOauth": {
                "accessToken": "at-claude-stock",
                "refreshToken": "rt-claude-stock",
                "expiresAt": 1_900_000_000_000_i64,
                "scopes": ["user:inference"],
            },
        }))
        .unwrap();
        let parsed = parse_pasted_auth_json(&body, OauthProvider::Anthropic).unwrap();
        assert_eq!(parsed.initial_access_token, "at-claude-stock");
        assert_eq!(parsed.refresh_token, "rt-claude-stock");
    }

    #[test]
    fn nested_hermes_block_beats_codex_tokens_wrapper() {
        // Defence in depth: if a file carries BOTH the Hermes nested
        // block and the Codex `tokens` wrapper, the explicit
        // provider-named block wins.
        let body = serde_json::to_vec(&serde_json::json!({
            "openai-codex": {
                "access_token": "at-hermes",
                "refresh_token": "rt-hermes",
                "expires_at": 1_900_000_000_i64,
            },
            "tokens": {
                "access_token": "at-codex",
                "refresh_token": "rt-codex",
                "expires_at": 1_800_000_000_i64,
            },
        }))
        .unwrap();
        let parsed = parse_pasted_auth_json(&body, OauthProvider::Openai).unwrap();
        assert_eq!(parsed.initial_access_token, "at-hermes");
    }

    #[test]
    fn missing_refresh_token_is_rejected() {
        let body = serde_json::to_vec(&serde_json::json!({
            "access_token": "at",
            "expires_at": 1_900_000_000_i64,
        }))
        .unwrap();
        let err = parse_pasted_auth_json(&body, OauthProvider::Openai).unwrap_err();
        assert!(err.to_string().contains("refresh_token"), "got: {err}");
    }

    #[test]
    fn empty_access_token_is_rejected() {
        let body = serde_json::to_vec(&serde_json::json!({
            "access_token": "  ",
            "refresh_token": "rt",
            "expires_at": 1_900_000_000_i64,
        }))
        .unwrap();
        let err = parse_pasted_auth_json(&body, OauthProvider::Openai).unwrap_err();
        assert!(err.to_string().contains("empty access_token"), "got: {err}");
    }

    #[test]
    fn unparseable_expires_at_is_rejected() {
        let body = serde_json::to_vec(&serde_json::json!({
            "access_token": "at",
            "refresh_token": "rt",
            "expires_at": "not-a-timestamp",
        }))
        .unwrap();
        let err = parse_pasted_auth_json(&body, OauthProvider::Openai).unwrap_err();
        assert!(err.to_string().contains("expires_at"), "got: {err}");
    }

    #[test]
    fn env_var_names_match_phase_b_shape() {
        let auth = || PastedOauthAuth {
            refresh_token: "r".to_owned(),
            initial_access_token: "a".to_owned(),
            expires_at_rfc3339: "2030-01-01T00:00:00+00:00".to_owned(),
        };
        let envs = OauthEnvVars::for_provider(OauthProvider::Anthropic, auth());
        assert_eq!(envs.refresh_token_var, "GM_ANTHROPIC_OAUTH_REFRESH_TOKEN");
        assert_eq!(
            envs.initial_access_token_var,
            "GM_ANTHROPIC_OAUTH_INITIAL_ACCESS_TOKEN"
        );
        assert_eq!(envs.expires_at_var, "GM_ANTHROPIC_OAUTH_EXPIRES_AT");

        let envs = OauthEnvVars::for_provider(OauthProvider::Openai, auth());
        assert_eq!(envs.refresh_token_var, "GM_OPENAI_OAUTH_REFRESH_TOKEN");
        assert_eq!(
            envs.initial_access_token_var,
            "GM_OPENAI_OAUTH_INITIAL_ACCESS_TOKEN"
        );
        assert_eq!(envs.expires_at_var, "GM_OPENAI_OAUTH_EXPIRES_AT");
    }
}
