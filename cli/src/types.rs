//! Types shared between CLI commands and tests.
//!
//! Wire shapes mirror the registry's pct-discount API
//! (see registry/openapi.json in the gm repo, post-PR-C):
//!
//! * `POST /miners/products` body = `{provider, model, discount_bp}` —
//!   pct-discount replaced the old per-dimension `miner_price` block.
//! * `GET /products`  → `ProductCatalogResponse`.
//! * `GET /miners/me` → `MinerStatusResponse`.

use serde::{Deserialize, Serialize};

/// Provider identifier — must match the canonical enum in product.json.
///
/// `Benchmark` exists so a serde decode of any payload that mentions the
/// registry's `benchmark` provider does not fail. It is intentionally not
/// declarable via the CLI: see [`FromStr`] (rejects the literal "benchmark")
/// and [`filter_catalog`](crate) (drops benchmark rows from fan-out
/// discovery as a defence in depth — today the registry omits the entry
/// from `GET /products` entirely, but the CLI must not regress if that
/// changes).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Anthropic,
    OpenAI,
    Gemini,
    Chutes,
    Benchmark,
}

impl Provider {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAI => "openai",
            Self::Gemini => "gemini",
            Self::Chutes => "chutes",
            Self::Benchmark => "benchmark",
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

    /// Parse a `--provider` CLI value. `benchmark` is intentionally
    /// rejected here even though `Provider::Benchmark` is a valid serde
    /// variant: the registry's benchmark pool is auto-synthesized from
    /// every routable miner (see `docs/plans/admission-benchmark.md`),
    /// has no product-catalog row, and `declare_product` 404s on any
    /// attempt to declare it. Failing at the CLI parser surfaces the
    /// error before any registry round-trip.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "anthropic" => Ok(Self::Anthropic),
            "openai" => Ok(Self::OpenAI),
            "gemini" => Ok(Self::Gemini),
            "chutes" => Ok(Self::Chutes),
            "benchmark" => anyhow::bail!(
                "provider \"benchmark\" is not declarable — every gm miner serves \
                 the benchmark pool automatically; see docs/plans/admission-benchmark.md"
            ),
            other => anyhow::bail!(
                "unknown provider {other:?} — must be one of: anthropic, openai, gemini, chutes"
            ),
        }
    }
}

/// One entry in the registry product catalog (`GET /products`).
///
/// `retail_price` carries the two anchor dimensions the CLI needs to show
/// the miner the effective per-Mtok rate they'll receive after applying
/// their declared discount. Other retail fields are intentionally
/// ignored — the CLI doesn't bill, the gateway does.
#[derive(Debug, Clone, Deserialize)]
pub struct Product {
    pub provider: Provider,
    pub model: String,
    pub status: String,
    pub retail_price: RetailPrice,
}

/// Per-product retail price block returned by `GET /products`. The CLI
/// only deserialises the `dimensions` sub-block; modifiers + surcharges
/// stay on the wire and are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct RetailPrice {
    pub dimensions: RetailDimensions,
}

/// The two anchor per-Mtok dimensions every product carries. Used to
/// render the effective miner payout per request.
#[derive(Debug, Clone, Deserialize)]
pub struct RetailDimensions {
    pub input_per_mtok_ndollars: u64,
    pub output_per_mtok_ndollars: u64,
}

/// Wrapper response shape returned by `GET /products` (`ProductCatalogResponse`).
#[derive(Debug, Clone, Deserialize)]
pub struct ProductCatalogResponse {
    pub products: Vec<Product>,
}

/// Response from `GET /miners/me` (`MinerStatusResponse`).
#[derive(Debug, Deserialize)]
pub struct MinerStatus {
    pub hotkey: String,
    pub status: String,
    pub last_attestation_at: Option<String>,
    pub image_compose_hash: Option<String>,
    pub products: Vec<ProductOfferStatus>,
}

/// Per-product eligibility entry in `MinerStatus`.
///
/// The registry only includes rows for products the miner has actually
/// declared an offer for (`GET /miners/me` joins `MinerProductOffer` with
/// `Product`), so `discount_bp` is always populated in practice. The
/// `Option` is a forward-compatibility hedge against the `OpenAPI` schema,
/// which marks the field nullable.
#[derive(Debug, Deserialize)]
pub struct ProductOfferStatus {
    pub provider: String,
    pub model: String,
    pub is_offered: bool,
    pub is_eligible: bool,
    pub discount_bp: Option<u32>,
}

/// Body of `POST /miners/products` (`ProductDeclarationRequest`).
///
/// `discount_bp` is a basis-point discount off retail applied uniformly to
/// every dimension; range `[0, 9990]` (the upper cap leaves the miner with
/// strictly positive revenue). See `docs/plans/miner-pct-discount-pricing.md`
/// §3.1 in the gm repo for the math.
#[derive(Debug, Clone, Serialize)]
pub struct ProductDeclarationRequest<'a> {
    pub provider: &'a str,
    pub model: &'a str,
    pub discount_bp: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_model: Option<&'a str>,
}

/// Body of `POST /miners/{hotkey}/workers` (`WorkerCreateRequest`).
///
/// The same shape `POST /miners/register` accepts for the first worker —
/// the per-worker `node_secret` becomes the worker's `x-gm-node-key`
/// credential the registry serves to the gateway.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerCreateRequest<'a> {
    pub endpoint: &'a str,
    pub attestation_endpoint: &'a str,
    pub compose_hash: &'a str,
    pub os_image_hash: &'a str,
    /// `None` omits the field; the registry's schema marks it nullable. A
    /// `worker add` always carries the freshly-generated per-worker secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_secret: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<&'a str>,
}

/// Response from `POST /miners/{hotkey}/workers` (`WorkerCreateResponse`).
#[derive(Debug, Deserialize)]
pub struct WorkerCreateResponse {
    pub worker_id: String,
    pub miner_hotkey: String,
    pub status: String,
}

/// One worker in the `GET /miners/{hotkey}/workers` response (`WorkerEntry`).
#[derive(Debug, Deserialize)]
pub struct WorkerEntry {
    pub worker_id: String,
    pub endpoint: String,
    pub status: String,
    pub last_attestation_at: Option<String>,
}

/// Response from `GET /miners/{hotkey}/workers` (`WorkerListResponse`).
#[derive(Debug, Deserialize)]
pub struct WorkerListResponse {
    pub workers: Vec<WorkerEntry>,
}
