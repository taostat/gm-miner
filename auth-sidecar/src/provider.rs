//! Per-provider OAuth refresh-endpoint shape.
//!
//! The endpoints, client IDs, and request encodings come from
//! `docs/research/oauth-subscription-prior-art.md` — the Hermes /
//! `OpenClaw` research that documented the published wire shapes for
//! `ChatGPT` Plus / Codex and Claude Pro/Max subscription OAuth.
//!
//! Reused here verbatim — gm-miner consumes the same OAuth provider
//! surface as Hermes; if the upstream changes the wire shape, both
//! tools break at once and the fix lands here.

use serde::Serialize;
use std::fmt;

/// Which provider a refresh task targets.
///
/// Selects the OAuth refresh endpoint, the client ID, and the request
/// encoding (form vs. JSON — the providers diverge).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum OauthProvider {
    /// `ChatGPT` Plus / `OpenAI` Codex subscription.
    Openai,
    /// Claude Pro / Claude Max (Anthropic) subscription.
    Anthropic,
}

impl OauthProvider {
    /// Lowercase wire identifier used on the sidecar's HTTP path
    /// (`GET /token/{provider}`) and as the Prometheus `provider`
    /// label value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
        }
    }

    /// Parse a wire identifier from a path / label.
    ///
    /// Named `from_wire_str` rather than `from_str` so it does not
    /// shadow `std::str::FromStr::from_str` — the standard `FromStr`
    /// returns `Result`, not `Option`, and the rename makes the
    /// difference visible at every call site.
    #[must_use]
    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "openai" => Some(Self::Openai),
            "anthropic" => Some(Self::Anthropic),
            _ => None,
        }
    }

    /// Every provider variant — used to iterate the worker spawn-list.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[Self::Openai, Self::Anthropic]
    }

    /// The OAuth refresh-endpoint shape for this provider.
    #[must_use]
    pub fn endpoints(self) -> ProviderEndpoints {
        match self {
            Self::Openai => ProviderEndpoints {
                provider: self,
                refresh_url: "https://auth.openai.com/oauth/token",
                client_id: "app_EMoamEEZ73f0CkXaXp7hrann",
                encoding: RefreshEncoding::Form,
            },
            Self::Anthropic => ProviderEndpoints {
                provider: self,
                refresh_url: "https://console.anthropic.com/v1/oauth/token",
                client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
                encoding: RefreshEncoding::Json,
            },
        }
    }
}

impl fmt::Display for OauthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Concrete wire shape for one provider's refresh exchange.
///
/// Borrowed strings — every value is a compile-time constant.
#[derive(Debug, Clone, Copy)]
pub struct ProviderEndpoints {
    pub provider: OauthProvider,
    pub refresh_url: &'static str,
    pub client_id: &'static str,
    pub encoding: RefreshEncoding,
}

/// How the refresh request body is encoded.
///
/// `Openai`'s token endpoint accepts `application/x-www-form-urlencoded`;
/// Anthropic's accepts `application/json`. The research file documents
/// the divergence — we mirror it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshEncoding {
    Form,
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_round_trips_via_as_str() {
        for p in OauthProvider::all() {
            let s = p.as_str();
            assert_eq!(OauthProvider::from_wire_str(s), Some(*p));
        }
    }

    #[test]
    fn from_wire_str_rejects_unknown() {
        assert!(OauthProvider::from_wire_str("gemini").is_none());
        assert!(OauthProvider::from_wire_str("").is_none());
    }

    #[test]
    fn endpoints_match_research_file() {
        let openai = OauthProvider::Openai.endpoints();
        assert_eq!(openai.refresh_url, "https://auth.openai.com/oauth/token");
        assert_eq!(openai.client_id, "app_EMoamEEZ73f0CkXaXp7hrann");
        assert_eq!(openai.encoding, RefreshEncoding::Form);

        let anthropic = OauthProvider::Anthropic.endpoints();
        assert_eq!(
            anthropic.refresh_url,
            "https://console.anthropic.com/v1/oauth/token"
        );
        assert_eq!(anthropic.client_id, "9d1c250a-e61b-44d9-88ed-5944d1962f5e");
        assert_eq!(anthropic.encoding, RefreshEncoding::Json);
    }
}
