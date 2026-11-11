//! OAuth requests must not follow redirects, which can forward credentials.

#![expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]

use gm_miner_cli::auth;
use wiremock::{
    matchers::{any, body_string_contains, method, path},
    Mock, MockServer, ResponseTemplate,
};

async fn redirect_servers(status: u16, endpoint: &str) -> (MockServer, MockServer) {
    let source = MockServer::start().await;
    let destination = MockServer::start().await;
    // The source uses 127.0.0.1; localhost exercises a different host as well
    // as a different port without sending credentials outside loopback.
    let destination_url = format!("http://localhost:{}/receiver", destination.address().port());

    Mock::given(method("POST"))
        .and(path(endpoint))
        .respond_with(
            ResponseTemplate::new(status)
                .insert_header("Location", destination_url)
                // A retryable OAuth error must not override a redirect status.
                .set_body_json(serde_json::json!({"error": "authorization_pending"})),
        )
        // An unexpected retry gets 404, making the regression fail promptly.
        .up_to_n_times(1)
        .expect(1)
        .mount(&source)
        .await;

    // A followed redirect returns a valid OAuth response, so an error alone
    // cannot accidentally pass the regression because the sink returned 404.
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "redirected-access-token",
            "device_code": "redirected-device-code",
            "user_code": "ABCD-1234",
            "verification_uri": "https://auth.example.com/device",
            "interval": 0,
            "expires_in": 900,
        })))
        .mount(&destination)
        .await;

    (source, destination)
}

async fn assert_destination_not_contacted(destination: &MockServer, status: u16) {
    let requests = destination
        .received_requests()
        .await
        .expect("mock records requests");
    assert!(
        requests.is_empty(),
        "OAuth {status} redirect forwarded a request to another origin: {requests:?}"
    );
}

async fn assert_refresh_redirect_blocked(status: u16) {
    let (source, destination) = redirect_servers(status, "/token").await;

    let result = auth::refresh_token(
        &format!("{}/token", source.uri()),
        "gm-miner-cli",
        "stored-refresh-token",
    )
    .await;

    let requests = source
        .received_requests()
        .await
        .expect("mock records requests");
    assert_eq!(requests.len(), 1, "a redirect must not trigger a retry");
    let body = std::str::from_utf8(&requests[0].body).expect("form body is UTF-8");
    assert!(body.contains("refresh_token=stored-refresh-token"));
    assert!(body.contains("grant_type=refresh_token"));
    assert_destination_not_contacted(&destination, status).await;
    let error = result.expect_err("a redirect must be an error, not refresh rejection");
    assert!(error.to_string().contains(&status.to_string()));
}

#[tokio::test]
async fn refresh_does_not_forward_credentials_on_307() {
    assert_refresh_redirect_blocked(307).await;
}

#[tokio::test]
async fn refresh_does_not_forward_credentials_on_308() {
    assert_refresh_redirect_blocked(308).await;
}

#[tokio::test]
async fn device_authorization_does_not_follow_redirects() {
    for status in [301, 302, 303, 307, 308] {
        let (source, destination) = redirect_servers(status, "/device/code").await;

        let result = auth::device_login(
            &format!("{}/device/code", source.uri()),
            &format!("{}/token", source.uri()),
            "gm-miner-cli",
            &["openid".to_owned()],
            false,
        )
        .await;

        assert_destination_not_contacted(&destination, status).await;
        let error = result.expect_err("a device authorization redirect must fail");
        assert!(error.to_string().contains(&status.to_string()));
    }
}

#[tokio::test]
async fn device_token_poll_does_not_follow_redirects() {
    for status in [301, 302, 303, 307, 308] {
        let (source, destination) = redirect_servers(status, "/token").await;
        Mock::given(method("POST"))
            .and(path("/device/code"))
            .and(body_string_contains("gm-miner-cli"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "stored-device-code",
                "user_code": "ABCD-1234",
                "verification_uri": "https://auth.example.com/device",
                "interval": 0,
                "expires_in": 900,
            })))
            .expect(1)
            .mount(&source)
            .await;

        let result = auth::device_login(
            &format!("{}/device/code", source.uri()),
            &format!("{}/token", source.uri()),
            "gm-miner-cli",
            &["openid".to_owned()],
            false,
        )
        .await;

        assert_destination_not_contacted(&destination, status).await;
        let error = result.expect_err("a device token redirect must fail");
        let requests = source
            .received_requests()
            .await
            .expect("mock records requests");
        assert_eq!(
            requests.len(),
            2,
            "device authorization and one token poll must be the only requests"
        );
        assert!(error.to_string().contains(&status.to_string()));
    }
}
