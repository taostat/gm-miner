//! Tests for `RegistryClient::preflight_auth`, the cheap auth probe that
//! `gmcli deploy` runs before any CVM work.
//!
//! Failure paths verified:
//!   - access token absent → "not logged in" (no HTTP call)
//!   - server returns 401  → "authentication expired"
//!
//! Pass paths verified:
//!   - 200 OK
//!   - 404 (miner not yet registered) — auth itself works, this is not
//!     a preflight failure since `gmcli deploy` is about to register.
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
    config_with_expiry(api_url, token, None)
}

/// Like [`config_with`] but also sets `token_expires_at` (an RFC3339
/// string) on the stored token entry.
fn config_with_expiry(api_url: &str, token: Option<&str>, expires_at: Option<String>) -> Config {
    let mut networks = HashMap::new();
    networks.insert(
        "mainnet".to_owned(),
        NetworkEntry {
            api_url: Some(api_url.to_owned()),
            tokens: token.map(|t| TokenEntry {
                access_token: Some(t.to_owned()),
                token_expires_at: expires_at,
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    Config {
        networks,
        active_network: Some("mainnet".to_owned()),
        provider_keys: None,
        phala_api_key: None,
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

/// Forgetting `gmcli login` is the most common operator mistake. The
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
        "error chain must direct operator to run `gmcli login`; got: {chain}"
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
/// the normal state on the very first `gmcli deploy`. Preflight must
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

// ── Token-expiry preflight ───────────────────────────────────────────────────
//
// A `gmcli deploy` does many minutes of CVM work before its trailing
// `register-image` call. A token that is valid at preflight but expires
// mid-deploy must be caught up front, not after the irreversible CVM work.

/// A stored token whose `token_expires_at` is already in the past must be
/// rejected by the preflight without any HTTP round-trip.
#[tokio::test]
async fn preflight_errors_when_token_already_expired() {
    let past = "2000-01-01T00:00:00Z".to_owned();
    // No mock server: if the preflight made an HTTP call it would fail with
    // a connection error, not the expiry error we assert on below.
    let cfg = config_with_expiry("http://127.0.0.1:1", Some("expired-token"), Some(past));
    let mut client = RegistryClient::new(cfg);

    let err = client
        .preflight_auth()
        .await
        .expect_err("an expired token must fail the preflight");
    let chain = full_chain(&err);
    assert!(
        chain.contains("expired") && chain.to_lowercase().contains("login"),
        "error must say the token expired and direct to `gmcli login`; got: {chain}"
    );
}

/// A token that is technically still valid but expires within the deploy
/// margin must also be rejected — it would lapse mid-deploy.
#[tokio::test]
async fn preflight_errors_when_token_near_expiry() {
    // 60s from now — inside the 300s margin.
    let soon = (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
    let cfg = config_with_expiry("http://127.0.0.1:1", Some("soon-token"), Some(soon));
    let mut client = RegistryClient::new(cfg);

    let err = client
        .preflight_auth()
        .await
        .expect_err("a near-expiry token must fail the preflight");
    let chain = full_chain(&err);
    assert!(
        chain.contains("expired") || chain.to_lowercase().contains("login"),
        "error must direct the operator to re-login; got: {chain}"
    );
}

/// An unparseable `token_expires_at` is treated as expired — better to
/// force a re-login than to trust a corrupt timestamp.
#[tokio::test]
async fn preflight_errors_on_corrupt_expiry_timestamp() {
    let cfg = config_with_expiry(
        "http://127.0.0.1:1",
        Some("token"),
        Some("not-a-timestamp".to_owned()),
    );
    let mut client = RegistryClient::new(cfg);

    let err = client
        .preflight_auth()
        .await
        .expect_err("a corrupt expiry must fail the preflight");
    let chain = full_chain(&err);
    assert!(
        chain.to_lowercase().contains("login"),
        "error must direct the operator to re-login; got: {chain}"
    );
}

/// A token whose `token_expires_at` is comfortably in the future must pass
/// the expiry check and proceed to the normal HTTP probe.
#[tokio::test]
async fn preflight_passes_when_token_not_near_expiry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/miners/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;

    let later = (chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
    let cfg = config_with_expiry(&server.uri(), Some("fresh-token"), Some(later));
    let mut client = RegistryClient::new(cfg);

    client
        .preflight_auth()
        .await
        .expect("a token valid well past the deploy window must pass");
}
