//! Types shared between CLI commands and tests.

use serde::{Deserialize, Serialize};

/// Provider identifier — must match the canonical enum in product.json.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Anthropic,
    OpenAI,
    Gemini,
}

impl Provider {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAI => "openai",
            Self::Gemini => "gemini",
        }
    }
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Provider {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "anthropic" => Ok(Self::Anthropic),
            "openai" => Ok(Self::OpenAI),
            "gemini" => Ok(Self::Gemini),
            other => anyhow::bail!(
                "unknown provider {other:?} — must be one of: anthropic, openai, gemini"
            ),
        }
    }
}

/// Per-dimension miner price block, all values in picodollars/Mtok as strings.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MinerPriceBlock {
    pub input_per_mtok_pdollars: String,
    pub output_per_mtok_pdollars: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_per_mtok_pdollars: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_write_5m_per_mtok_pdollars: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_write_1h_per_mtok_pdollars: Option<String>,
}

/// A product entry returned by GET /products.
#[derive(Debug, Clone, Deserialize)]
pub struct Product {
    pub provider: String,
    pub model: String,
    pub status: String,
}

/// Response from GET /miners/me (status endpoint).
#[derive(Debug, Deserialize)]
pub struct MinerStatus {
    pub hotkey: String,
    pub status: String,
    pub last_attestation_at: Option<String>,
    pub image_compose_hash: Option<String>,
    pub products: Vec<ProductOfferStatus>,
}

/// Per-product eligibility in the status response.
#[derive(Debug, Deserialize)]
pub struct ProductOfferStatus {
    pub provider: String,
    pub model: String,
    pub is_offered: bool,
    pub is_eligible: bool,
    pub miner_price: Option<MinerPriceBlock>,
}
