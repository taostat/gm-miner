//! Tests for the anonymous registry Bearer challenge/token flow that
//! `gmcli deploy` uses to classify a miner image as publicly pullable or
//! private (which decides whether pull credentials must be supplied).
//!
//! [`fetch_anonymous_token`] is the network-touching core of that flow: it
//! exchanges a parsed `WWW-Authenticate: Bearer` challenge for an anonymous
//! token at the registry's token endpoint. The public/private verdict turns
//! on its result:
//!   - a token in `token` or `access_token` → exchange succeeded (the caller
//!     retries the manifest and can still see a public image),
//!   - `401`/`403` from the token endpoint → anonymous pull denied (private),
//!   - any other non-success status → surfaced as an error so the operator
//!     sees the real failure rather than a silent "treat as public".
//!
//! Driven against a wiremock token endpoint so no real registry is needed.

#![expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]

use gm_miner_cli::{
    client::build_http_client,
    deploy::{fetch_anonymous_token, BearerChallenge},
};
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

/// A challenge whose `realm` points at `server`'s `/token` endpoint.
fn challenge_for(server: &MockServer) -> BearerChallenge {
    BearerChallenge {
        realm: format!("{}/token", server.uri()),
        service: "registry.example.com".to_owned(),
        scope: Some("repository:owner/gm-miner:pull".to_owned()),
    }
}

/// A `200` carrying the token under the standard `token` key resolves to that
/// token — the public-image path: the caller retries the manifest with it.
#[tokio::test]
async fn token_under_token_key_is_returned() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .and(query_param("service", "registry.example.com"))
        .and(query_param("scope", "repository:owner/gm-miner:pull"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "anon-abc123"
        })))
        .mount(&server)
        .await;

    let client = build_http_client().expect("build http client");
    let token = fetch_anonymous_token(&client, &challenge_for(&server))
        .await
        .expect("token exchange should succeed");
    assert_eq!(token.as_deref(), Some("anon-abc123"));
}

/// Docker Hub returns the token under `access_token` rather than `token`; the
/// flow must accept either spelling, else a Docker Hub public image would be
/// misclassified as private.
#[tokio::test]
async fn token_under_access_token_key_is_returned() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "anon-xyz789"
        })))
        .mount(&server)
        .await;

    let client = build_http_client().expect("build http client");
    let token = fetch_anonymous_token(&client, &challenge_for(&server))
        .await
        .expect("token exchange should succeed");
    assert_eq!(token.as_deref(), Some("anon-xyz789"));
}

/// A `200` whose token field is an empty string is treated as no token — an
/// empty bearer would not authenticate the retry, so the image is private.
#[tokio::test]
async fn empty_token_string_is_none() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": ""
        })))
        .mount(&server)
        .await;

    let client = build_http_client().expect("build http client");
    let token = fetch_anonymous_token(&client, &challenge_for(&server))
        .await
        .expect("token exchange should succeed");
    assert!(
        token.is_none(),
        "an empty token string must classify the image as private"
    );
}

/// A `401` from the token endpoint means anonymous pull is denied: the image
/// is private, signalled by `Ok(None)` (not an error).
#[tokio::test]
async fn token_endpoint_401_means_private() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let client = build_http_client().expect("build http client");
    let token = fetch_anonymous_token(&client, &challenge_for(&server))
        .await
        .expect("a denied anonymous request is not an error");
    assert!(token.is_none(), "401 from the token endpoint means private");
}

/// A `403` is likewise an anonymous-pull denial (private), not an error.
#[tokio::test]
async fn token_endpoint_403_means_private() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let client = build_http_client().expect("build http client");
    let token = fetch_anonymous_token(&client, &challenge_for(&server))
        .await
        .expect("a denied anonymous request is not an error");
    assert!(token.is_none(), "403 from the token endpoint means private");
}

/// Any other non-success status (here a `500`) is surfaced as an error rather
/// than silently classified, so the operator sees the real registry failure.
#[tokio::test]
async fn token_endpoint_500_is_an_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = build_http_client().expect("build http client");
    let err = fetch_anonymous_token(&client, &challenge_for(&server))
        .await
        .expect_err("a 500 from the token endpoint must surface as an error");
    let msg = err.to_string();
    assert!(
        msg.contains("token exchange") && msg.contains("500"),
        "error should name the token exchange and the status: {msg}"
    );
}

/// A challenge with no `scope` (some registries omit it on the manifest
/// challenge) still exchanges, and the request carries `service` but no
/// `scope` query parameter — a stray `scope=` could be rejected by a strict
/// token endpoint. Asserted against the actually-received request, since
/// `query_param` only checks presence and would pass even if `scope` leaked.
#[tokio::test]
async fn missing_scope_omits_the_scope_param() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "anon-noscope"
        })))
        .mount(&server)
        .await;

    let challenge = BearerChallenge {
        realm: format!("{}/token", server.uri()),
        service: "registry.example.com".to_owned(),
        scope: None,
    };
    let client = build_http_client().expect("build http client");
    let token = fetch_anonymous_token(&client, &challenge)
        .await
        .expect("token exchange should succeed without a scope");
    assert_eq!(token.as_deref(), Some("anon-noscope"));

    let requests = server
        .received_requests()
        .await
        .expect("recorded requests available");
    let request = requests.first().expect("exactly one token request");
    let params: Vec<(String, String)> = request
        .url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert!(
        params
            .iter()
            .any(|(k, v)| k == "service" && v == "registry.example.com"),
        "service must be sent: {params:?}"
    );
    assert!(
        params.iter().all(|(k, _)| k != "scope"),
        "no scope param must be sent when the challenge has no scope: {params:?}"
    );
}
