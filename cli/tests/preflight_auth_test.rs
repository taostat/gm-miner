//! Tests for `RegistryClient::preflight_auth`, the cheap auth probe that
//! `gm-miner deploy` runs before any CVM work.
//!
//! Failure paths verified:
//!   - access token absent → "not logged in" (no HTTP call)
//!   - server returns 401  → "authentication expired"
//!
//! Pass paths verified:
//!   - 200 OK
//!   - 404 (miner not yet registered) — auth itself works, this is not
//!     a preflight failure since `gm-miner deploy` is about to register.
//!
//! These guard against a regression where the deploy command runs the
//! whole pipeline and only fails at the trailing `register-image` call.

#![expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]

use gm_miner_cli::{
    client::RegistryClient,
    config::{Config, NetworkEntry, TokenEntry},
};
use std::collections::HashMap;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

fn config_with(api_url: &str, token: Option<&str>) -> Config {
    let mut networks = HashMap::new();
    networks.insert(
        "mainnet".to_owned(),
        NetworkEntry {
            api_url: Some(api_url.to_owned()),
            tokens: token.map(|t| TokenEntry {
                access_token: Some(t.to_owned()),
                refresh_token: None,
                token_expires_at: None,
            }),
            ..Default::default()
        },
    );
    Config {
        networks,
        active_network: Some("mainnet".to_owned()),
        provider_keys: None,
    }
}

/// Render the full anyhow error chain to a string so tests can match on
/// the underlying cause regardless of how many `.context(...)` wrappers
/// sit on top.
fn full_chain(err: &anyhow::Error) -> String {
    let mut out = String::new();
    for cause in err.chain() {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&cause.to_string());
    }
    out
}

/// Forgetting `gm-miner login` is the most common operator mistake. The
/// preflight must surface a clear "not logged in" before any CVM bytes
/// move.
#[tokio::test]
async fn preflight_errors_when_token_absent() {
    let cfg = config_with("https://registry.example.com", None);
    let mut client = RegistryClient::new(cfg);

    let err = client
        .preflight_auth()
        .await
        .expect_err("missing token must error");
    let chain = full_chain(&err);
    assert!(
        chain.contains("not logged in") || chain.to_lowercase().contains("login"),
        "error chain must direct operator to run `gm-miner login`; got: {chain}"
    );
}

/// A stale or revoked token must surface as "authentication expired"
/// before deploy starts.
#[tokio::test]
async fn preflight_errors_on_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/miners/me"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let cfg = config_with(&server.uri(), Some("stale-token"));
    let mut client = RegistryClient::new(cfg);

    let err = client.preflight_auth().await.expect_err("401 must error");
    let chain = full_chain(&err);
    assert!(
        chain.contains("authentication expired") || chain.to_lowercase().contains("login"),
        "error chain must indicate auth expired; got: {chain}"
    );
}

/// 200 OK means the token works and the miner is already registered.
/// Preflight must not error.
#[tokio::test]
async fn preflight_passes_on_200() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/miners/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;

    let cfg = config_with(&server.uri(), Some("good-token"));
    let mut client = RegistryClient::new(cfg);

    client.preflight_auth().await.expect("200 must succeed");
}

/// 404 means the token works but the miner has never registered — that's
/// the normal state on the very first `gm-miner deploy`. Preflight must
/// allow this through so the deploy can proceed and register the miner.
#[tokio::test]
async fn preflight_passes_on_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/miners/me"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;

    let cfg = config_with(&server.uri(), Some("good-token"));
    let mut client = RegistryClient::new(cfg);

    client
        .preflight_auth()
        .await
        .expect("404 (miner not registered) must not block deploy");
}
