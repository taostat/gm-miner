//! Tests for the pct-discount declare-product wire shape and the
//! `RegistryClient` POST path used by `gmcli declare-product` and
//! `gmcli declare-products`.
//!
//! Covers:
//!   * `ProductDeclarationRequest` serialises to the exact
//!     `{provider, model, discount_bp}` body the registry's pct-discount API
//!     expects (no `miner_price`, no extra fields).
//!   * `ProductCatalogResponse` deserialises the new wrapper shape returned
//!     by `GET /products` (`{products: [...], generated_at: ...}`).
//!   * `Provider::Benchmark` round-trips through serde so a benchmark
//!     catalog entry does not break a fan-out discovery call.
//!   * A wiremock-backed `RegistryClient::post` round-trip verifies that
//!     the body actually put on the wire matches the typed shape and that
//!     a 200 response is propagated as success.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]

use std::str::FromStr;

use gm_miner_cli::{
    client::RegistryClient,
    config::{Config, NetworkEntry, TokenEntry},
    types::{ProductCatalogResponse, ProductDeclarationRequest, Provider},
};
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

// ── Pure serialization tests ─────────────────────────────────────────────────

#[test]
fn declaration_request_serialises_to_pct_discount_shape() {
    let body = serde_json::to_value(ProductDeclarationRequest {
        provider: Provider::Anthropic.as_str(),
        model: "claude-sonnet-4-6",
        discount_bp: 500,
    })
    .unwrap();

    assert_eq!(
        body,
        serde_json::json!({
            "provider": "anthropic",
            "model": "claude-sonnet-4-6",
            "discount_bp": 500,
        }),
        "post-PR-C wire shape: {{provider, model, discount_bp}}, no `miner_price`"
    );
}

#[test]
fn declaration_request_zero_discount_is_quote_at_retail() {
    // discount_bp=0 means "quote at retail" — the lower bound of the
    // registry's [0, 9990] range. Must serialise as the integer 0, not
    // be omitted, so the registry treats the field as present.
    let body = serde_json::to_value(ProductDeclarationRequest {
        provider: "openai",
        model: "gpt-5.5",
        discount_bp: 0,
    })
    .unwrap();

    let map = body.as_object().expect("body is a JSON object");
    assert!(map.contains_key("discount_bp"));
    assert_eq!(map["discount_bp"], serde_json::json!(0));
}

#[test]
fn declaration_request_max_discount_at_cap() {
    // The registry's upper cap is 9990 inclusive (see
    // ProductDeclarationRequest in registry/openapi.json).
    let body = serde_json::to_value(ProductDeclarationRequest {
        provider: "gemini",
        model: "gemini-2.5-pro",
        discount_bp: 9990,
    })
    .unwrap();
    assert_eq!(body["discount_bp"], serde_json::json!(9990));
}

#[test]
fn provider_benchmark_deserialises_but_cli_rejects_it() {
    // serde must accept "benchmark" — otherwise any GET that mentions
    // the registry's benchmark provider would fail to decode and break
    // fan-out discovery.
    let p: Provider = serde_json::from_value(serde_json::json!("benchmark")).unwrap();
    assert_eq!(p, Provider::Benchmark);
    assert_eq!(p.as_str(), "benchmark");
    assert_eq!(
        serde_json::to_value(&p).unwrap(),
        serde_json::json!("benchmark")
    );

    // FromStr drives clap's `--provider` parser. Declaring against the
    // benchmark pool is invalid (the registry has no catalog row for it
    // and would 404), so the CLI parser must fail closed and explain why.
    let err = Provider::from_str("benchmark").unwrap_err().to_string();
    assert!(
        err.contains("not declarable") && err.contains("benchmark"),
        "error must name the rejection reason; got: {err}"
    );
}

#[test]
fn product_catalog_response_parses_wrapper_shape() {
    // GET /products returns ProductCatalogResponse, NOT a bare array —
    // matches the new OpenAPI schema (registry/openapi.json post-PR-C).
    let retail = serde_json::json!({
        "dimensions": {
            "input_per_mtok_ndollars": 3_000_000_000_u64,
            "output_per_mtok_ndollars": 15_000_000_000_u64,
        }
    });
    let body = serde_json::json!({
        "products": [
            {"provider": "anthropic", "model": "claude-sonnet-4-6", "status": "active",
             "retail_price": retail},
            {"provider": "openai", "model": "gpt-5.5", "status": "active",
             "retail_price": retail},
            {"provider": "gemini", "model": "gemini-1.0", "status": "deprecated",
             "retail_price": retail},
        ],
        "generated_at": "2026-06-05T10:00:00Z",
    });
    let parsed: ProductCatalogResponse = serde_json::from_value(body).unwrap();
    assert_eq!(parsed.products.len(), 3);
    assert_eq!(parsed.products[0].provider, Provider::Anthropic);
    assert_eq!(parsed.products[0].model, "claude-sonnet-4-6");
    assert_eq!(parsed.products[2].status, "deprecated");
}

#[test]
fn provider_unknown_yields_actionable_error() {
    let err = Provider::from_str("cohere").unwrap_err();
    assert!(
        err.to_string().contains("unknown provider"),
        "error must name the failure mode; got: {err}"
    );
}

// ── Wire round-trip with wiremock ────────────────────────────────────────────

/// Build a `Config` whose active-network entry points at the wiremock server
/// and carries an access token so `RegistryClient::post` is allowed through.
fn config_for(server: &MockServer) -> Config {
    let mut networks = std::collections::HashMap::new();
    networks.insert(
        "testnet".to_owned(),
        NetworkEntry {
            api_url: Some(server.uri()),
            tokens: Some(TokenEntry {
                access_token: Some("test-token".to_owned()),
                refresh_token: None,
                token_expires_at: None,
            }),
            workers: Vec::new(),
            legacy_node_secret: None,
            registered_hotkey: None,
        },
    );

    Config {
        active_network: Some("testnet".to_owned()),
        provider_keys: None,
        phala_api_key: None,
        api_url_override: None,
        networks,
    }
}

#[tokio::test]
async fn post_miners_products_puts_exact_pct_discount_body_on_the_wire() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/miners/products"))
        .and(header("authorization", "Bearer test-token"))
        .and(body_json(serde_json::json!({
            "provider": "anthropic",
            "model": "claude-sonnet-4-6",
            "discount_bp": 500,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "miner_hotkey": "5HK…",
            "provider": "anthropic",
            "model": "claude-sonnet-4-6",
            "miner_price_id": "01HFQXYZ…",
            "is_offered": true,
            "is_eligible": false,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let body = serde_json::to_value(ProductDeclarationRequest {
        provider: "anthropic",
        model: "claude-sonnet-4-6",
        discount_bp: 500,
    })
    .unwrap();

    let mut client = RegistryClient::new(config_for(&server));
    let resp = client
        .post("/miners/products", &body)
        .await
        .expect("POST must reach the mock");
    assert!(resp.status().is_success(), "registry returns 200");

    // wiremock auto-verifies the .expect(1) on drop; if the body shape
    // did not match, the mock would never have responded and the request
    // would fail — so reaching here proves the wire shape is exact.
}

#[tokio::test]
async fn post_miners_products_propagates_registry_error_body() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/miners/products"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "detail": "product not found"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let body = serde_json::to_value(ProductDeclarationRequest {
        provider: "openai",
        model: "gpt-does-not-exist",
        discount_bp: 100,
    })
    .unwrap();

    let mut client = RegistryClient::new(config_for(&server));
    let resp = client.post("/miners/products", &body).await.unwrap();
    assert_eq!(resp.status(), 404);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        json.get("detail").and_then(|v| v.as_str()),
        Some("product not found"),
        "registry error body must be readable so the CLI can surface its detail"
    );
}
