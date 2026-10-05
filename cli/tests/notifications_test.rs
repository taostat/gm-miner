//! Drive `gmcli notifications list` through the binary against a mock registry.

#![expect(
    clippy::expect_used,
    reason = "test assertions panic on unexpected values"
)]

use std::process::Output;

use serde_json::{json, Value};
use wiremock::{
    matchers::{header, method, path, query_param, query_param_is_missing},
    Mock, MockServer, ResponseTemplate,
};

const PATH: &str = "/miners/me/notifications/messages";
const HOTKEY: &str = "5InboxMiner";

fn entry(id: u64, text: &str) -> Value {
    json!({
        "id": id,
        "occurred_at": format!("2026-10-01T12:{:02}:00Z", id % 60),
        "event_type": "worker.suspended",
        "reason_code": "attestation_failed",
        "human_text": text,
        "subject_type": "worker",
        "subject_id": format!("wkr-{id}"),
        "delivered": false,
    })
}

fn page(ids: &[u64], next_before: Option<u64>) -> Value {
    let notifications: Vec<Value> = ids
        .iter()
        .map(|id| entry(*id, &format!("Worker wkr-{id} was suspended.")))
        .collect();
    json!({"hotkey": HOTKEY, "notifications": notifications, "next_before": next_before})
}

fn write_config(dir: &tempfile::TempDir, api_url: &str, token: Option<&str>) {
    let mut entry = json!({"api_url": api_url});
    if let Some(token) = token {
        entry["tokens"] = json!({
            "access_token": token, "token_expires_at": "2999-01-01T00:00:00Z"
        });
    }
    let config = json!({"active_network": "testnet", "networks": {"testnet": entry}});
    std::fs::write(
        dir.path().join("config.json"),
        serde_json::to_vec(&config).expect("serialize test config"),
    )
    .expect("write test config");
}

async fn run(api_url: &str, token: Option<&str>, args: &[&str]) -> Output {
    let dir = tempfile::tempdir().expect("temporary CLI configuration");
    write_config(&dir, api_url, token);
    tokio::process::Command::new(env!("CARGO_BIN_EXE_gmcli"))
        .kill_on_drop(true)
        .env("GMCLI_CONFIG_DIR", dir.path())
        .env_remove("GM_REGISTRY_URL")
        .args(["notifications", "list"])
        .args(args)
        .output()
        .await
        .expect("run CLI binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[tokio::test]
async fn lists_newest_first_with_the_miners_token_and_default_limit() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(PATH))
        .and(header("authorization", "Bearer miner-token"))
        .and(query_param("limit", "20"))
        .and(query_param_is_missing("before"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(&[12, 11], None)))
        .expect(1)
        .mount(&server)
        .await;

    let output = run(&server.uri(), Some("miner-token"), &[]).await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "2026-10-01T12:12:00Z  worker.suspended (attestation_failed)  [worker wkr-12]\n  \
         Worker wkr-12 was suspended.\n\
         \n\
         2026-10-01T12:11:00Z  worker.suspended (attestation_failed)  [worker wkr-11]\n  \
         Worker wkr-11 was suspended.\n"
    );
}

#[tokio::test]
async fn before_and_limit_reach_the_registry_and_the_next_cursor_is_printed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(PATH))
        .and(query_param("limit", "2"))
        .and(query_param("before", "40"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(&[39, 38], Some(38))))
        .expect(1)
        .mount(&server)
        .await;

    let output = run(
        &server.uri(),
        Some("t"),
        &["--limit", "2", "--before", "40"],
    )
    .await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).ends_with("\nOlder notifications: gmcli notifications list --before 38\n"),
        "{}",
        stdout(&output)
    );
}

#[tokio::test]
async fn the_largest_registry_cursor_is_accepted() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(PATH))
        .and(query_param("before", "9223372036854775807"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(&[], None)))
        .expect(1)
        .mount(&server)
        .await;

    let output = run(
        &server.uri(),
        Some("t"),
        &["--before", "9223372036854775807"],
    )
    .await;
    assert!(output.status.success(), "{}", stderr(&output));
}

#[tokio::test]
async fn long_text_is_wrapped_under_its_heading() {
    let server = MockServer::start().await;
    let text = "word ".repeat(40);
    Mock::given(method("GET"))
        .and(path(PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hotkey": HOTKEY, "notifications": [entry(1, text.trim())], "next_before": null
        })))
        .mount(&server)
        .await;

    let output = run(&server.uri(), Some("t"), &[]).await;

    let body = stdout(&output);
    let text_lines: Vec<&str> = body.lines().skip(1).collect();
    assert!(text_lines.len() > 1, "{body}");
    assert!(
        text_lines
            .iter()
            .all(|line| line.starts_with("  ") && line.len() <= 78),
        "{body}"
    );
}

#[tokio::test]
async fn all_follows_the_cursor_to_the_last_page() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(PATH))
        .and(query_param("limit", "100"))
        .and(query_param_is_missing("before"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(&[5, 4], Some(4))))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(PATH))
        .and(query_param("limit", "100"))
        .and(query_param("before", "4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(&[3], None)))
        .expect(1)
        .mount(&server)
        .await;

    let output = run(&server.uri(), Some("t"), &["--all"]).await;

    assert!(output.status.success(), "{}", stderr(&output));
    let body = stdout(&output);
    let ids: Vec<&str> = body
        .lines()
        .filter_map(|line| line.split("[worker ").nth(1))
        .collect();
    assert_eq!(ids, ["wkr-5]", "wkr-4]", "wkr-3]"], "{body}");
    assert!(!body.contains("Older notifications"), "{body}");
}

#[tokio::test]
async fn all_stops_at_the_cap_and_names_where_to_continue() {
    let server = MockServer::start().await;
    for start in (1..=11_u64).map(|n| 2_000 - (n - 1) * 100) {
        let ids: Vec<u64> = (0..100).map(|i| start - i).collect();
        let last = *ids.last().expect("non-empty page");
        let mock = Mock::given(method("GET")).and(path(PATH));
        let mock = if start == 2_000 {
            mock.and(query_param_is_missing("before"))
        } else {
            mock.and(query_param("before", (start + 1).to_string()))
        };
        mock.respond_with(ResponseTemplate::new(200).set_body_json(page(&ids, Some(last))))
            .mount(&server)
            .await;
    }

    let output = run(&server.uri(), Some("t"), &["--all"]).await;

    assert!(output.status.success(), "{}", stderr(&output));
    let body = stdout(&output);
    assert_eq!(body.matches("[worker wkr-").count(), 1_000, "{body}");
    assert!(
        body.ends_with("\nOlder notifications: gmcli notifications list --before 1001\n"),
        "{body}"
    );
    assert_eq!(
        server.received_requests().await.expect("requests").len(),
        10
    );
}

#[tokio::test]
async fn an_empty_inbox_says_so() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(&[], None)))
        .mount(&server)
        .await;

    let output = run(&server.uri(), Some("t"), &[]).await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        format!("No notifications for {HOTKEY} on testnet.\n")
    );
}

#[tokio::test]
async fn an_expired_login_says_to_log_in_again() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(PATH))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let output = run(&server.uri(), Some("t"), &[]).await;

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("run `gmcli login` again"),
        "{}",
        stderr(&output)
    );
}

#[tokio::test]
async fn no_login_says_to_log_in_without_calling_the_registry() {
    let server = MockServer::start().await;

    let output = run(&server.uri(), None, &[]).await;

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not logged in"),
        "{}",
        stderr(&output)
    );
    assert!(server
        .received_requests()
        .await
        .expect("requests")
        .is_empty());
}

#[tokio::test]
async fn an_unreachable_registry_names_the_url_and_the_fix() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);

    let output = run(&url, Some("t"), &[]).await;

    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(
        err.contains(&format!("could not reach the testnet registry at {url}")),
        "{err}"
    );
    assert!(err.contains("--api-url"), "{err}");
}

#[tokio::test]
async fn a_registry_without_the_inbox_says_so() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(PATH))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"detail": "Not Found"})))
        .mount(&server)
        .await;

    let output = run(&server.uri(), Some("t"), &[]).await;

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("does not serve the notifications inbox yet"),
        "{}",
        stderr(&output)
    );
}

#[tokio::test]
async fn any_other_failure_reports_the_status_and_the_registry_detail() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(PATH))
        .respond_with(
            ResponseTemplate::new(426).set_body_json(json!({"detail": "upgrade gmcli to 0.9"})),
        )
        .mount(&server)
        .await;

    let output = run(&server.uri(), Some("t"), &[]).await;

    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(err.contains("426 Upgrade Required"), "{err}");
    assert!(err.contains("upgrade gmcli to 0.9"), "{err}");
}

#[tokio::test]
async fn out_of_range_paging_is_refused_before_any_request() {
    let server = MockServer::start().await;

    for args in [
        &["--limit", "0"][..],
        &["--limit", "101"],
        &["--before", "0"],
        &["--before", "9223372036854775808"],
        &["--before", "18446744073709551615"],
        &["--all", "--limit", "5"],
        &["--all", "--before", "5"],
    ] {
        let output = run(&server.uri(), Some("t"), args).await;
        assert!(!output.status.success(), "{args:?} should be refused");
        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    }
    assert!(server
        .received_requests()
        .await
        .expect("requests")
        .is_empty());
}

#[tokio::test]
async fn registry_text_cannot_emit_terminal_controls() {
    let server = MockServer::start().await;
    let attack = "\u{1b}]52;c;c2VjcmV0\u{7}\u{9b}2J\r\u{8}\u{202e}";
    let mut notification = entry(1, &format!("first\n{attack}\nlast"));
    for field in ["event_type", "reason_code", "subject_type", "subject_id"] {
        notification[field] = json!(attack);
    }
    Mock::given(method("GET"))
        .and(path(PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hotkey": HOTKEY, "notifications": [notification], "next_before": null
        })))
        .mount(&server)
        .await;

    let output = run(&server.uri(), Some("t"), &[]).await;
    assert!(output.status.success(), "{}", stderr(&output));
    let body = stdout(&output);
    assert!(
        body.chars().all(|c| !c.is_control() || c == '\n'),
        "{body:?}"
    );
    assert!(!body.contains('\u{202e}'), "{body:?}");
    assert!(body.contains("  first\n"), "{body:?}");
    assert!(body.contains("  last\n"), "{body:?}");
}

#[tokio::test]
async fn empty_inbox_and_errors_escape_registry_controls() {
    for response in [
        ResponseTemplate::new(200).set_body_json(json!({
            "hotkey": "miner\u{1b}[2J\u{7}", "notifications": [], "next_before": null
        })),
        ResponseTemplate::new(500).set_body_json(json!({"detail": "oops\u{1b}[2J\u{7}"})),
        ResponseTemplate::new(502).set_body_string("oops\u{9b}2J\u{7}"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(PATH))
            .respond_with(response)
            .mount(&server)
            .await;
        let output = run(&server.uri(), Some("t"), &[]).await;
        for text in [stdout(&output), stderr(&output)] {
            assert!(
                text.chars().all(|c| !c.is_control() || c == '\n'),
                "{text:?}"
            );
        }
    }
}

#[tokio::test]
async fn invalid_pages_fail_without_looping_or_printing_partial_results() {
    let oversized: Vec<u64> = (1..=101).rev().collect();
    for invalid in [
        page(&[], Some(8)),
        page(&[9, 8], Some(10)),
        page(&[9, 8], Some(7)),
        page(&[9, 8], Some(0)),
        page(&[8, 9], None),
        page(&[9, 9], None),
        page(&[0], None),
        page(&[u64::MAX], None),
        page(&[1_u64 << 63], Some(1_u64 << 63)),
        page(&oversized, None),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(invalid.clone()))
            .mount(&server)
            .await;
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run(&server.uri(), Some("t"), &["--all"]),
        )
        .await
        .expect("invalid paging must terminate");
        assert!(!output.status.success(), "accepted {invalid}");
        assert_eq!(stdout(&output), "");
        assert!(
            stderr(&output).contains("invalid notifications page"),
            "{}",
            stderr(&output)
        );
        assert_eq!(server.received_requests().await.expect("requests").len(), 1);
    }
}

#[tokio::test]
async fn a_repeated_page_fails_instead_of_filling_the_cap_with_duplicates() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(&[9, 8], Some(8))))
        .mount(&server)
        .await;
    let output = run(&server.uri(), Some("t"), &["--all"]).await;
    assert!(!output.status.success());
    assert_eq!(stdout(&output), "");
    assert!(
        stderr(&output).contains("invalid notifications page"),
        "{}",
        stderr(&output)
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 2);
}

#[tokio::test]
async fn all_truncates_an_uneven_last_page_without_skipping_the_continuation() {
    let server = MockServer::start().await;
    // Short first page leaves 999 slots; the eleventh page must be truncated.
    Mock::given(method("GET"))
        .and(path(PATH))
        .and(query_param_is_missing("before"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(&[2000], Some(2000))))
        .mount(&server)
        .await;
    for start in (0..10).map(|n| 1999 - n * 100) {
        let ids: Vec<u64> = (0..100).map(|i| start - i).collect();
        Mock::given(method("GET"))
            .and(path(PATH))
            .and(query_param("before", (start + 1).to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(page(
                &ids,
                if start == 1099 {
                    None
                } else {
                    Some(start - 99)
                },
            )))
            .mount(&server)
            .await;
    }
    let output = run(&server.uri(), Some("t"), &["--all"]).await;
    assert!(output.status.success(), "{}", stderr(&output));
    let body = stdout(&output);
    assert_eq!(body.matches("[worker wkr-").count(), 1000);
    assert!(
        body.ends_with("\nOlder notifications: gmcli notifications list --before 1001\n"),
        "{body}"
    );
    assert_eq!(
        server.received_requests().await.expect("requests").len(),
        11
    );
}

#[tokio::test]
async fn malformed_success_responses_and_later_page_errors_fail_cleanly() {
    for response in [
        ResponseTemplate::new(200).set_body_string("not JSON"),
        ResponseTemplate::new(200).set_body_json(json!({"notifications": []})),
        ResponseTemplate::new(401),
        ResponseTemplate::new(503).set_body_json(json!({"detail": "retry later"})),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(PATH))
            .and(query_param_is_missing("before"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page(&[2], Some(2))))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(PATH))
            .and(query_param("before", "2"))
            .respond_with(response)
            .mount(&server)
            .await;
        let output = run(&server.uri(), Some("t"), &["--all"]).await;
        assert!(!output.status.success());
        assert_eq!(stdout(&output), "");
        assert!(!stderr(&output).contains("panicked"), "{}", stderr(&output));
        assert_eq!(server.received_requests().await.expect("requests").len(), 2);
    }
}
