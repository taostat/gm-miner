//! Channel commands through the real binary, using the inbox's wiremock pattern.

#![expect(clippy::expect_used, reason = "test assertions")]

use std::process::{Output, Stdio};

use serde_json::{json, Value};
use tokio::io::AsyncWriteExt as _;
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

const PATH: &str = "/miners/me/notifications";
const CONFIRM: &str = "/miners/me/notifications/confirm";
const URL: &str = "tgram://secret-token-avoid-echo/private-chat";
const CODE: &str = "012345";

fn channel(verified: bool) -> Value {
    json!({
        "configured": true,
        "channel": "telegram",
        "destination_fingerprint": "telegram:aabbccddeeffaabb",
        "digest_enabled": false,
        "verified": verified,
        "pending": !verified,
        "code_expires_at": if verified { Value::Null } else { json!("2026-10-05T10:15:00Z") },
        "last_success_at": null,
        "consecutive_failures": 0,
        "auto_disabled": false,
    })
}

fn config(dir: &tempfile::TempDir, api_url: &str, token: Option<&str>) {
    let mut entry = json!({"api_url": api_url});
    if let Some(token) = token {
        entry["tokens"] =
            json!({"access_token": token, "token_expires_at": "2999-01-01T00:00:00Z"});
    }
    std::fs::write(
        dir.path().join("config.json"),
        serde_json::to_vec(&json!({"active_network": "testnet", "networks": {"testnet": entry}}))
            .expect("serialize config"),
    )
    .expect("write config");
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

async fn run_in(dir: &tempfile::TempDir, args: &[&str], input: &[u8], log: &str) -> Output {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_gmcli"))
        .kill_on_drop(true)
        .env("GMCLI_CONFIG_DIR", dir.path())
        .env_remove("GM_REGISTRY_URL")
        .env("RUST_LOG", log)
        .args(["notifications"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn CLI");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(input)
        .await
        .expect("write stdin");
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait_with_output())
        .await
        .expect("CLI must terminate")
        .expect("run CLI");
    for text in [stdout(&output), stderr(&output)] {
        assert!(!text.contains(URL), "destination leaked: {text}");
        assert!(
            !text.contains("secret-token-avoid-echo"),
            "URL token leaked: {text}"
        );
        assert!(!text.contains(CODE), "code leaked: {text}");
    }
    for entry in std::fs::read_dir(dir.path()).expect("config directory") {
        let bytes = std::fs::read(entry.expect("entry").path()).expect("read config file");
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(URL), "destination persisted");
        assert!(!text.contains(CODE), "code persisted");
    }
    output
}

async fn run(api_url: &str, token: Option<&str>, args: &[&str], input: &[u8]) -> Output {
    let dir = tempfile::tempdir().expect("temporary config");
    config(&dir, api_url, token);
    run_in(&dir, args, input, "warn").await
}

async fn respond(server: &MockServer, verb: &str, route: &str, response: ResponseTemplate) {
    Mock::given(method(verb))
        .and(path(route))
        .and(header("authorization", "Bearer miner-token"))
        .respond_with(response)
        .expect(1)
        .mount(server)
        .await;
}

fn commands() -> [(&'static str, &'static str, Vec<&'static str>); 4] {
    [
        ("PUT", PATH, vec!["set", URL]),
        ("POST", CONFIRM, vec!["confirm", CODE]),
        ("GET", PATH, vec!["status"]),
        ("DELETE", PATH, vec!["off"]),
    ]
}

#[tokio::test]
async fn set_sends_the_url_and_digest_with_miner_auth_and_prints_the_exact_next_command() {
    for digest in [false, true] {
        let server = MockServer::start().await;
        let mut status = channel(false);
        status["digest_enabled"] = json!(digest);
        Mock::given(method("PUT"))
            .and(path(PATH))
            .and(header("authorization", "Bearer miner-token"))
            .and(body_json(
                json!({"destination": URL, "digest_enabled": digest}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(status))
            .expect(1)
            .mount(&server)
            .await;
        let mut args = vec!["set", URL];
        if digest {
            args.push("--digest");
        }
        let output = run(&server.uri(), Some("miner-token"), &args, b"").await;
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout(&output), "A confirmation code was sent to your channel on testnet.\nNext: gmcli notifications confirm <code>\n");
    }
}

#[tokio::test]
async fn set_reads_stdin_and_strips_only_trailing_line_endings() {
    let server = MockServer::start().await;
    let mut status = channel(false);
    status["digest_enabled"] = json!(true);
    Mock::given(method("PUT"))
        .and(path(PATH))
        .and(body_json(
            json!({"destination": URL, "digest_enabled": true}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(status))
        .expect(1)
        .mount(&server)
        .await;
    let output = run(
        &server.uri(),
        Some("miner-token"),
        &["set", "-", "--digest"],
        format!("{URL}\r\n").as_bytes(),
    )
    .await;
    assert!(output.status.success(), "{}", stderr(&output));
}

#[tokio::test]
async fn invalid_stdin_and_empty_or_oversized_arguments_fail_before_requests() {
    let server = MockServer::start().await;
    for input in [
        vec![],
        vec![0xff],
        vec![b'a'; 9000],
        format!("{URL}\nsecond-url").into_bytes(),
    ] {
        let output = run(&server.uri(), None, &["set", "-"], &input).await;
        assert_eq!(output.status.code(), Some(1));
        assert!(!stderr(&output).contains("not logged in"));
    }
    for input in [
        String::new(),
        "a".repeat(2049),
        format!("{URL}\nsecond-url"),
    ] {
        let output = run(&server.uri(), None, &["set", &input], b"").await;
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains("1-2048 characters"));
    }
    assert!(server
        .received_requests()
        .await
        .expect("requests")
        .is_empty());
}

#[tokio::test]
async fn rejected_destinations_report_the_server_error_and_reason_without_echoing_input() {
    for (status, error, reason) in [
        (400, "destination_rejected", "address_blocked"),
        (400, "invalid_request", "channel_not_allowed"),
        (422, "code_not_delivered", "send_failed"),
        (400, "new_error", "new_reason"),
    ] {
        let server = MockServer::start().await;
        respond(
            &server,
            "PUT",
            PATH,
            ResponseTemplate::new(status).set_body_json(json!({
                "error": error, "reason": reason,
                "message": "Please check the channel settings.\u{1b}[2J",
                "input": URL, "errors": [{"input": URL}]
            })),
        )
        .await;
        let output = run(&server.uri(), Some("miner-token"), &["set", URL], b"").await;
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(stdout(&output), "");
        let err = stderr(&output);
        assert!(err.contains(error) && err.contains(reason), "{err}");
        assert!(err.contains("Please check the channel settings."), "{err}");
        assert!(!err.contains('\u{1b}'), "{err}");
        if status == 422 {
            assert!(
                err.contains("pending") && err.contains("five-minute cooldown"),
                "{err}"
            );
        }
    }
}

#[tokio::test]
async fn cooldown_reports_retry_after_seconds() {
    for (header, seconds) in [
        ("237", 237),
        ("301", 301),
        ("000123", 123),
        ("0", 0),
        ("18446744073709551615", u64::MAX),
    ] {
        let server = MockServer::start().await;
        respond(
            &server,
            "PUT",
            PATH,
            ResponseTemplate::new(429)
                .insert_header("Retry-After", header)
                .set_body_json(json!({"error": "code_cooldown"})),
        )
        .await;
        let output = run(&server.uri(), Some("miner-token"), &["set", URL], b"").await;
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains(&format!(
            "Retry in {seconds} seconds (Retry-After: {seconds})"
        )));
        assert!(stderr(&output).contains("code_cooldown"));
    }
}

#[tokio::test]
async fn missing_or_invalid_retry_after_is_not_echoed_or_invented() {
    for value in [
        None,
        Some(URL),
        Some("18446744073709551616"),
        Some("Wed, 21 Oct 2026 07:28:00 GMT"),
    ] {
        let server = MockServer::start().await;
        let mut response =
            ResponseTemplate::new(429).set_body_json(json!({"error": "code_cooldown"}));
        if let Some(value) = value {
            response = response.insert_header("Retry-After", value);
        }
        respond(&server, "PUT", PATH, response).await;
        let output = run(&server.uri(), Some("miner-token"), &["set", URL], b"").await;
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains("did not provide a valid Retry-After"));
    }
}

#[tokio::test]
async fn confirm_preserves_leading_zeroes_in_the_body_and_prints_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(CONFIRM))
        .and(header("authorization", "Bearer miner-token"))
        .and(body_json(json!({"code": CODE})))
        .respond_with(ResponseTemplate::new(200).set_body_json(channel(true)))
        .expect(1)
        .mount(&server)
        .await;
    let output = run(&server.uri(), Some("miner-token"), &["confirm", CODE], b"").await;
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "Notification channel verified on testnet.\n"
    );
}

#[tokio::test]
async fn confirm_checks_six_ascii_digits_before_authentication() {
    let server = MockServer::start().await;
    for code in [
        "",
        "12345",
        "1234567",
        "abcdef",
        "１２３４５６",
        "12 345",
        URL,
    ] {
        let output = run(&server.uri(), None, &["confirm", code], b"").await;
        assert_eq!(output.status.code(), Some(1));
        assert!(
            stderr(&output).contains("exactly 6 digits"),
            "{}",
            stderr(&output)
        );
    }
    assert!(server
        .received_requests()
        .await
        .expect("requests")
        .is_empty());
}

#[tokio::test]
async fn an_incorrect_code_reports_attempts_and_the_retry_command() {
    for attempts in [None, Some(0), Some(4), Some(5)] {
        let server = MockServer::start().await;
        respond(
            &server,
            "POST",
            CONFIRM,
            ResponseTemplate::new(400)
                .set_body_json(json!({"error": "code_invalid", "attempts_remaining": attempts})),
        )
        .await;
        let output = run(&server.uri(), Some("miner-token"), &["confirm", CODE], b"").await;
        assert_eq!(output.status.code(), Some(1));
        let expected = attempts.map_or_else(
            || "Check the latest code".to_owned(),
            |count| format!("{count} attempts remaining"),
        );
        assert!(stderr(&output).contains(&expected));
        assert!(stderr(&output).contains("gmcli notifications confirm <code>"));
        assert!(stderr(&output).contains("code_invalid"));
    }
}

#[tokio::test]
async fn expired_and_exhausted_codes_explain_how_to_request_a_new_one() {
    for (error, expected) in [("code_expired", "expired"), ("code_exhausted", "exhausted")] {
        let server = MockServer::start().await;
        respond(
            &server,
            "POST",
            CONFIRM,
            ResponseTemplate::new(400).set_body_json(json!({"error": error})),
        )
        .await;
        let output = run(&server.uri(), Some("miner-token"), &["confirm", CODE], b"").await;
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains(expected));
        assert!(stderr(&output).contains(error));
        assert!(stderr(&output).contains("gmcli notifications set <apprise-url>"));
    }
}

#[tokio::test]
async fn already_verified_reports_conflict_with_the_status_command() {
    let server = MockServer::start().await;
    respond(
        &server,
        "POST",
        CONFIRM,
        ResponseTemplate::new(409).set_body_json(json!({"error": "already_verified"})),
    )
    .await;
    let output = run(&server.uri(), Some("miner-token"), &["confirm", CODE], b"").await;
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("already verified"));
    assert!(stderr(&output).contains("already_verified"));
    assert!(stderr(&output).contains("gmcli notifications status"));
}

#[tokio::test]
async fn concurrent_subscription_change_explains_how_to_retry() {
    let server = MockServer::start().await;
    respond(
        &server,
        "PUT",
        PATH,
        ResponseTemplate::new(409).set_body_json(json!({
            "error": "subscription_changed", "reason": "replaced",
            "message": "The channel was replaced during verification."
        })),
    )
    .await;
    let output = run(&server.uri(), Some("miner-token"), &["set", URL], b"").await;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout(&output), "");
    for expected in [
        "subscription_changed",
        "replaced",
        "The channel was replaced during verification.",
        "gmcli notifications status",
        "gmcli notifications set <apprise-url>",
    ] {
        assert!(stderr(&output).contains(expected), "missing {expected}");
    }
}

#[tokio::test]
async fn status_displays_pending_expiry_fingerprint_and_health() {
    let server = MockServer::start().await;
    respond(
        &server,
        "GET",
        PATH,
        ResponseTemplate::new(200).set_body_json(channel(false)),
    )
    .await;
    let output = run(&server.uri(), Some("miner-token"), &["status"], b"").await;
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "Notification channel on testnet:\n  Channel: telegram\n  Fingerprint: telegram:aabbccddeeffaabb\n  Verified: no\n  Pending: yes\n  Code expires (UTC): 2026-10-05T10:15:00Z\n  Digest enabled: no\n  Last success (UTC): none\n  Consecutive failures: 0\n  Auto-disabled: no\n");
}

#[tokio::test]
async fn status_shows_verified_channels_that_have_been_auto_disabled() {
    let server = MockServer::start().await;
    let mut body = channel(true);
    body["auto_disabled"] = json!(true);
    body["consecutive_failures"] = json!(105);
    body["digest_enabled"] = json!(true);
    body["last_success_at"] = json!("2026-10-05T11:00:00+01:00");
    respond(
        &server,
        "GET",
        PATH,
        ResponseTemplate::new(200).set_body_json(body),
    )
    .await;
    let output = run(&server.uri(), Some("miner-token"), &["status"], b"").await;
    assert!(output.status.success(), "{}", stderr(&output));
    for expected in [
        "Verified: yes",
        "Pending: no",
        "Code expires (UTC): none",
        "Digest enabled: yes",
        "Last success (UTC): 2026-10-05T10:00:00Z",
        "Consecutive failures: 105",
        "Auto-disabled: yes",
    ] {
        assert!(stdout(&output).contains(expected), "missing {expected}");
    }
}

#[tokio::test]
async fn status_without_a_channel_explains_how_to_set_one() {
    let server = MockServer::start().await;
    respond(
        &server,
        "GET",
        PATH,
        ResponseTemplate::new(404).set_body_json(json!({"error": "no_subscription"})),
    )
    .await;
    let output = run(&server.uri(), Some("miner-token"), &["status"], b"").await;
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("No channel set on testnet"));
    assert!(stdout(&output).contains("gmcli notifications set <apprise-url>"));
}

#[tokio::test]
async fn confirm_without_a_channel_explains_how_to_set_one() {
    let server = MockServer::start().await;
    respond(
        &server,
        "POST",
        CONFIRM,
        ResponseTemplate::new(404).set_body_json(json!({"error": "no_subscription"})),
    )
    .await;
    let output = run(&server.uri(), Some("miner-token"), &["confirm", CODE], b"").await;
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("No channel set"));
    assert!(stderr(&output).contains("no_subscription"));
    assert!(stderr(&output).contains("gmcli notifications set <apprise-url>"));
}

#[tokio::test]
async fn off_confirms_removal_or_that_nothing_was_set() {
    for (response, expected) in [
        (
            ResponseTemplate::new(204),
            "Notification channel removed on testnet.\n",
        ),
        (
            ResponseTemplate::new(404).set_body_json(json!({"error": "no_subscription"})),
            "No channel was set on testnet; nothing to remove.\n",
        ),
    ] {
        let server = MockServer::start().await;
        respond(&server, "DELETE", PATH, response).await;
        let output = run(&server.uri(), Some("miner-token"), &["off"], b"").await;
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout(&output), expected);
    }
}

#[tokio::test]
async fn route_404_means_notifications_are_switched_off_for_every_command() {
    for (verb, route, args) in commands() {
        let server = MockServer::start().await;
        respond(
            &server,
            verb,
            route,
            ResponseTemplate::new(404).set_body_json(json!({"detail": "Not Found"})),
        )
        .await;
        let output = run(&server.uri(), Some("miner-token"), &args, b"").await;
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains("Notifications are switched off on testnet"));
    }
}

#[tokio::test]
async fn service_failures_have_clear_messages_for_every_command() {
    for (status, error, expected) in [
        (
            502,
            "notifier_unavailable",
            "temporarily unavailable; retry later",
        ),
        (
            503,
            "notifier_not_configured",
            "not configured on testnet; contact the network operator",
        ),
    ] {
        for (verb, route, args) in commands() {
            let server = MockServer::start().await;
            respond(
                &server,
                verb,
                route,
                ResponseTemplate::new(status).set_body_json(json!({"error": error})),
            )
            .await;
            let output = run(&server.uri(), Some("miner-token"), &args, b"").await;
            assert_eq!(output.status.code(), Some(1));
            assert_eq!(stdout(&output), "");
            assert!(stderr(&output).contains(expected), "{}", stderr(&output));
            assert!(stderr(&output).contains(error));
        }
    }
}

#[tokio::test]
async fn all_commands_use_existing_missing_and_expired_login_errors() {
    for (verb, route, args) in commands() {
        let server = MockServer::start().await;
        let missing = run(&server.uri(), None, &args, b"").await;
        assert_eq!(missing.status.code(), Some(1));
        assert!(stderr(&missing).contains("not logged in"));
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
        respond(
            &server,
            verb,
            route,
            ResponseTemplate::new(401).set_body_json(json!({"input": URL})),
        )
        .await;
        let expired = run(&server.uri(), Some("miner-token"), &args, b"").await;
        assert_eq!(expired.status.code(), Some(1));
        assert!(stderr(&expired).contains("authentication expired"));
    }
}

#[tokio::test]
async fn an_unreachable_registry_names_the_network_and_remedy_for_every_command() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let uri = format!("http://{}", listener.local_addr().expect("address"));
    drop(listener);
    for (_, _, args) in commands() {
        let output = run(&uri, Some("miner-token"), &args, b"").await;
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains(&format!("could not reach the testnet registry at {uri}")));
        assert!(stderr(&output).contains("--api-url"));
    }
}

#[tokio::test]
async fn refresh_failure_retries_without_sending_the_channel_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/auth/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code_url": format!("{}/device", server.uri()),
            "token_url": format!("{}/token", server.uri()),
            "client_id": "gm-miner-cli", "scopes": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "unused-token", "expires_in": "invalid-expiry"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "0")
                .set_body_string("temporarily unavailable"),
        )
        .with_priority(1)
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().expect("config directory");
    std::fs::write(
        dir.path().join("config.json"),
        serde_json::to_vec(&json!({
            "active_network": "testnet",
            "networks": {"testnet": {
                "api_url": server.uri(),
                "tokens": {"access_token": "expired-token", "refresh_token": "stored-refresh",
                    "token_expires_at": "2000-01-01T00:00:00Z"}
            }}
        }))
        .expect("serialize"),
    )
    .expect("config");
    let before = std::fs::read(dir.path().join("config.json")).expect("original config");
    let output = run_in(&dir, &["set", URL], b"", "warn").await;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("retrying the refresh"));
    assert!(stderr(&output).contains("parse refresh token response"));
    assert_eq!(
        std::fs::read(dir.path().join("config.json")).expect("config"),
        before
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 3);
}

#[tokio::test]
async fn channel_auth_falls_back_to_device_login_when_refresh_is_missing_or_rejected() {
    for rejected_refresh in [false, true] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_code_url": format!("{}/device", server.uri()),
                "token_url": format!("{}/token", server.uri()),
                "client_id": "gm-miner-cli", "scopes": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant", "message": "Refresh token expired"
            })))
            .expect(u64::from(rejected_refresh))
            .mount(&server)
            .await;
        // Prove the binary enters the shared device flow without opening a
        // real browser. A failed device request must leave the channel alone.
        Mock::given(method("POST"))
            .and(path("/device"))
            .respond_with(ResponseTemplate::new(500).set_body_string("authentication unavailable"))
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().expect("config directory");
        let mut tokens = json!({
            "access_token": "expired-token", "token_expires_at": "2000-01-01T00:00:00Z"
        });
        if rejected_refresh {
            tokens["refresh_token"] = json!("stored-refresh");
        }
        std::fs::write(
            dir.path().join("config.json"),
            serde_json::to_vec(&json!({
                "active_network": "testnet",
                "networks": {"testnet": {"api_url": server.uri(), "tokens": tokens}}
            }))
            .expect("serialize"),
        )
        .expect("config");
        let before = std::fs::read(dir.path().join("config.json")).expect("original config");
        let output = run_in(&dir, &["confirm", CODE], b"", "warn").await;
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(stdout(&output), "");
        assert!(stderr(&output).contains("authentication unavailable"));
        assert_eq!(
            std::fs::read(dir.path().join("config.json")).expect("config"),
            before
        );
        assert!(stderr(&output).contains("re-authenticating"));
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 2 + usize::from(rejected_refresh));
        assert!(requests
            .iter()
            .all(|request| matches!(request.url.path(), "/auth/config" | "/token" | "/device")));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn channel_commands_resume_after_device_login_and_save_only_auth_tokens() {
    for (verb, route, args) in commands() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().expect("config directory");
        // open treats this as a missing file, so no real browser is launched.
        let verification_uri = dir.path().join("missing-verification-page");
        Mock::given(method("GET"))
            .and(path("/auth/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_code_url": format!("{}/device", server.uri()),
                "token_url": format!("{}/token", server.uri()),
                "client_id": "gm-miner-cli", "scopes": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/device"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_code": "device-authorization", "user_code": "BROWSER-LOGIN",
                "verification_uri": verification_uri, "interval": 0, "expires_in": 60
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(wiremock::matchers::body_string_contains(
                "device_code=device-authorization",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "miner-token", "refresh_token": "device-refresh",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let response = if verb == "DELETE" {
            ResponseTemplate::new(204)
        } else {
            ResponseTemplate::new(200).set_body_json(channel(verb != "PUT"))
        };
        respond(&server, verb, route, response).await;
        std::fs::write(
            dir.path().join("config.json"),
            serde_json::to_vec(&json!({
                "active_network": "testnet",
                "networks": {"testnet": {"api_url": server.uri(), "tokens": {
                    "access_token": "expired-token", "token_expires_at": "2000-01-01T00:00:00Z"
                }}}
            }))
            .expect("serialize"),
        )
        .expect("config");
        let output = run_in(&dir, &args, b"", "trace").await;
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert!(stdout(&output).contains("Code: BROWSER-LOGIN"));
        assert!(stdout(&output).contains(&verification_uri.display().to_string()));
        assert!(stdout(&output).contains("testnet"));
        let saved: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("config.json")).expect("config"))
                .expect("parse");
        assert_eq!(
            saved["networks"]["testnet"]["tokens"]["access_token"],
            "miner-token"
        );
        assert_eq!(
            saved["networks"]["testnet"]["tokens"]["refresh_token"],
            "device-refresh"
        );
        assert_eq!(server.received_requests().await.expect("requests").len(), 4);
    }
}

#[tokio::test]
async fn channel_auth_refreshes_and_persists_rotated_tokens_before_sending_secrets() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/auth/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code_url": format!("{}/device", server.uri()),
            "token_url": format!("{}/token", server.uri()),
            "client_id": "gm-miner-cli", "scopes": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(wiremock::matchers::body_string_contains(
            "refresh_token=stored-refresh",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "fresh-token", "refresh_token": "rotated-refresh",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(PATH))
        .and(header("authorization", "Bearer fresh-token"))
        .and(body_json(
            json!({"destination": URL, "digest_enabled": false}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(channel(false)))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().expect("config directory");
    std::fs::write(
        dir.path().join("config.json"),
        serde_json::to_vec(&json!({
            "active_network": "testnet",
            "networks": {"testnet": {"api_url": server.uri(), "tokens": {
                "access_token": "expired-token", "refresh_token": "stored-refresh",
                "token_expires_at": "2000-01-01T00:00:00Z"
            }}}
        }))
        .expect("serialize"),
    )
    .expect("config");
    let output = run_in(&dir, &["set", URL], b"", "trace").await;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stderr(&output), "Access token refreshed.\n");
    assert!(stdout(&output).contains("A confirmation code was sent"));
    let saved: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("config.json")).expect("config"))
            .expect("parse");
    assert_eq!(
        saved["networks"]["testnet"]["tokens"]["access_token"],
        "fresh-token"
    );
    assert_eq!(
        saved["networks"]["testnet"]["tokens"]["refresh_token"],
        "rotated-refresh"
    );
    assert_eq!(saved["networks"]["testnet"]["api_url"], server.uri());
    assert_eq!(server.received_requests().await.expect("requests").len(), 3);
}

#[tokio::test]
async fn malformed_errors_do_not_echo_raw_bodies() {
    for (verb, route, args) in commands() {
        let server = MockServer::start().await;
        respond(
            &server,
            verb,
            route,
            ResponseTemplate::new(500).set_body_string(format!("{URL} {CODE}")),
        )
        .await;
        let output = run(&server.uri(), Some("miner-token"), &args, b"").await;
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(stdout(&output), "");
        assert!(stderr(&output).contains("500 Internal Server Error"));
    }
}

#[tokio::test]
async fn malformed_status_fails_without_echoing_response_values() {
    let server = MockServer::start().await;
    respond(
        &server,
        "GET",
        PATH,
        ResponseTemplate::new(200).set_body_json(json!({"channel": URL, "code": CODE})),
    )
    .await;
    let output = run(&server.uri(), Some("miner-token"), &["status"], b"").await;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("invalid notification channel status"));
}

#[tokio::test]
async fn success_responses_cannot_echo_the_destination_or_emit_terminal_controls() {
    for (verb, route, args) in commands().into_iter().take(3) {
        let server = MockServer::start().await;
        let mut body = channel(verb == "POST");
        body["destination"] = json!(URL);
        body["code"] = json!(CODE);
        body["channel"] = json!("future-channel\u{1b}[2J");
        body["destination_fingerprint"] = json!("future:fingerprint\u{202e}");
        respond(
            &server,
            verb,
            route,
            ResponseTemplate::new(200).set_body_json(body),
        )
        .await;
        let output = run(&server.uri(), Some("miner-token"), &args, b"").await;
        assert_eq!(output.status.code(), Some(0));
        assert!(!stdout(&output).contains('\u{1b}'));
        assert!(!stdout(&output).contains('\u{202e}'));
    }
}

#[tokio::test]
async fn unexpected_success_codes_are_not_success() {
    for (verb, route, args) in commands() {
        let server = MockServer::start().await;
        respond(
            &server,
            verb,
            route,
            ResponseTemplate::new(202).set_body_json(channel(false)),
        )
        .await;
        let output = run(&server.uri(), Some("miner-token"), &args, b"").await;
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(stdout(&output), "");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn set_reads_a_url_from_terminal_stdin() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path(PATH))
        .and(body_json(
            json!({"destination": URL, "digest_enabled": false}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(channel(false)))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().expect("config directory");
    config(&dir, &server.uri(), Some("miner-token"));
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new("python3")
            .env("GMCLI_CONFIG_DIR", dir.path())
            .env_remove("GM_REGISTRY_URL")
            .env("RUST_LOG", "warn")
            .args([
                "-c",
                r"
import os, pty, subprocess, sys, termios
master, slave = pty.openpty()
settings = termios.tcgetattr(slave)
settings[3] &= ~termios.ECHO
termios.tcsetattr(slave, termios.TCSANOW, settings)
assert os.isatty(slave)
child = subprocess.Popen([sys.argv[1], 'notifications', 'set', '-'], stdin=slave)
os.close(slave)
os.write(master, sys.argv[2].encode() + b'\n\x04')
try:
    sys.exit(child.wait(timeout=5))
finally:
    if child.poll() is None:
        child.kill()
        child.wait()
    os.close(master)
",
                env!("CARGO_BIN_EXE_gmcli"),
                URL,
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("terminal input must finish")
    .expect("run CLI through PTY");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains("A confirmation code was sent"));
    for text in [stdout(&output), stderr(&output)] {
        assert!(!text.contains(URL));
        assert!(!text.contains("secret-token-avoid-echo"));
    }
}

#[tokio::test]
async fn help_describes_stdin_and_short_channel_examples() {
    let output = run("http://127.0.0.1:1", None, &["set", "--help"], b"").await;
    assert!(output.status.success());
    let text = stdout(&output);
    for expected in [
        "stdin",
        "shell history",
        "https://discord.com/api/webhooks/id/token",
        "tgram://token/chat_id",
        "slack://",
        "--digest",
        "jsons://example.com/webhook",
        "digest delivery is not enabled in v1",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
}

#[tokio::test]
async fn explicit_network_sticks_and_api_url_overrides_remain_ephemeral() {
    let testnet = MockServer::start().await;
    let mainnet = MockServer::start().await;
    let override_server = MockServer::start().await;
    let dir = tempfile::tempdir().expect("config directory");
    let entry = |url: String, token: &str| json!({"api_url": url, "tokens": {"access_token": token, "token_expires_at": "2999-01-01T00:00:00Z"}});
    std::fs::write(dir.path().join("config.json"), serde_json::to_vec(&json!({
        "active_network": "testnet",
        "networks": {"testnet": entry(testnet.uri(), "test-token"), "mainnet": entry(mainnet.uri(), "main-token")}
    })).expect("serialize")).expect("config");
    for (verb, route, mut args) in commands() {
        let response = if verb == "DELETE" {
            ResponseTemplate::new(204)
        } else {
            ResponseTemplate::new(200).set_body_json(channel(verb != "PUT"))
        };
        Mock::given(method(verb))
            .and(path(route))
            .and(header("authorization", "Bearer main-token"))
            .respond_with(response)
            .expect(1)
            .mount(&mainnet)
            .await;
        if verb == "PUT" {
            args.extend(["--network", "mainnet"]);
        }
        let output = run_in(&dir, &args, b"", "warn").await;
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(stdout(&output).contains("mainnet"));
    }
    Mock::given(method("GET"))
        .and(path(PATH))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(channel(true)))
        .expect(1)
        .mount(&override_server)
        .await;
    let output = run_in(
        &dir,
        &["status", "--testnet", "--api-url", &override_server.uri()],
        b"",
        "warn",
    )
    .await;
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("testnet"));
    let saved: Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("config.json")).expect("read config"),
    )
    .expect("parse");
    assert_eq!(saved["active_network"], "testnet");
    assert_eq!(saved["networks"]["testnet"]["api_url"], testnet.uri());
    assert!(testnet
        .received_requests()
        .await
        .expect("requests")
        .is_empty());
}

#[tokio::test]
async fn stdin_rejects_blank_input_and_extra_lines() {
    let server = MockServer::start().await;
    for input in [
        format!("{URL}{}second-url", "\n".repeat(8200)),
        "   \n".to_owned(),
        format!("{URL}\n\n"),
    ] {
        let output = run(&server.uri(), None, &["set", "-"], input.as_bytes()).await;
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains("1-2048 characters"));
    }
    assert!(server
        .received_requests()
        .await
        .expect("requests")
        .is_empty());
}

#[tokio::test]
async fn redirects_are_not_followed_and_never_report_success() {
    let target = MockServer::start().await;
    for (verb, route, args) in commands() {
        for status in [301, 302, 307, 308] {
            let server = MockServer::start().await;
            respond(
                &server,
                verb,
                route,
                ResponseTemplate::new(status).insert_header(
                    "Location",
                    format!("{}/secret-token-avoid-echo/{CODE}", target.uri()),
                ),
            )
            .await;
            let dir = tempfile::tempdir().expect("config directory");
            config(&dir, &server.uri(), Some("miner-token"));
            let output = run_in(&dir, &args, b"", "warn").await;
            assert_eq!(output.status.code(), Some(1));
            assert_eq!(stdout(&output), "");
        }
    }
    assert!(target
        .received_requests()
        .await
        .expect("requests")
        .is_empty());
}

#[tokio::test]
async fn ambiguous_not_found_is_not_a_successful_status_or_removal() {
    for (verb, route, args) in commands().into_iter().skip(2) {
        let server = MockServer::start().await;
        respond(
            &server,
            verb,
            route,
            ResponseTemplate::new(404).set_body_json(json!({"error": "not_found"})),
        )
        .await;
        let output = run(&server.uri(), Some("miner-token"), &args, b"").await;
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(stdout(&output), "");
    }
}

#[tokio::test]
async fn trace_logging_does_not_print_channel_secrets() {
    for (verb, route, args) in commands() {
        let server = MockServer::start().await;
        let mut body = channel(verb != "PUT");
        body["destination"] = json!(URL);
        body["code"] = json!(CODE);
        let response = if verb == "DELETE" {
            ResponseTemplate::new(204)
        } else {
            ResponseTemplate::new(200).set_body_json(body)
        };
        respond(&server, verb, route, response).await;
        let dir = tempfile::tempdir().expect("config directory");
        config(&dir, &server.uri(), Some("miner-token"));
        let output = run_in(&dir, &args, b"", "trace").await;
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stderr(&output), "");
        assert!(stdout(&output).contains("TRACE") || stdout(&output).contains("DEBUG"));
    }
}

#[test]
fn stdin_accepts_eof_lf_crlf_and_the_unicode_character_limit() {
    use gm_miner_cli::notifications::channel::read_destination;
    for suffix in ["", "\n", "\r\n"] {
        for destination in [URL.to_owned(), "💬".repeat(2048)] {
            let input = format!("{destination}{suffix}");
            assert_eq!(
                read_destination("-".to_owned(), input.as_bytes()).expect("valid input"),
                destination
            );
        }
    }
}
