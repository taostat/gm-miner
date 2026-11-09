//! `gmcli worker list` end to end: the real binary against a mock registry,
//! checking the image line each worker gets from `GET /image-versions`.

#![expect(clippy::expect_used, reason = "test fixture setup must succeed")]

use std::process::{Command, Output};

use serde_json::{json, Value};
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

const HOTKEY: &str = "5HK";

fn hash(prefix: &str) -> String {
    format!("{prefix}{}", "0".repeat(64 - prefix.len()))
}

fn version(compose: &str, tag: &str, status: &str, grace: Option<u64>) -> Value {
    json!({
        "git_tag": tag,
        "compose_hash": compose,
        "os_image_hash": hash("b"),
        "status": status,
        "deprecation_end_epoch": grace,
        "notes": null,
        "created_at": "2026-11-01T00:00:00Z",
    })
}

/// The registry's full roster: one row in each standing.
fn roster() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({"versions": [
        version(&hash("a22"), "v0.5.22", "supported", None),
        version(&hash("a21"), "v0.5.21", "deprecated", Some(26_273)),
        version(&hash("a11"), "v0.5.11", "revoked", None),
    ]}))
}

/// Run `gmcli worker list` for one worker reporting `compose`, with the
/// registry answering `/image-versions?status=all` with `versions`.
async fn worker_list(compose: Option<&str>, versions: ResponseTemplate) -> Output {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/miners/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hotkey": HOTKEY, "status": "active", "products": [],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/miners/{HOTKEY}/workers")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "workers": [{
                "worker_id": "01JWORKER",
                "endpoint": "https://w1.example.org",
                "status": "active",
                "image_compose_hash": compose,
                "last_attestation_at": "2026-11-09T00:00:00Z",
            }],
            "consecutive_ok_required": 2,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/image-versions"))
        .and(query_param("status", "all"))
        .respond_with(versions)
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("isolated config");
    let config = json!({
        "active_network": "testnet",
        "networks": {"testnet": {
            "api_url": server.uri(),
            "tokens": {"access_token": "test-token"},
        }},
    });
    std::fs::write(dir.path().join("config.json"), config.to_string()).expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_gmcli"))
        .args(["worker", "list"])
        .current_dir(dir.path())
        .env_clear()
        .env("GMCLI_CONFIG_DIR", dir.path())
        .output()
        .expect("run gmcli worker list");
    server.verify().await;
    output
}

/// The command succeeded, listed the worker, and gave it exactly `image`.
fn assert_image_line(output: &Output, image: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("1 worker(s) total."), "{stdout}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.contains(&format!("  image           : {image}").as_str()),
        "expected image line `{image}` in:\n{stdout}"
    );
}

#[tokio::test]
async fn a_supported_image_is_named_by_its_release() {
    let output = worker_list(Some(&hash("a22")), roster()).await;
    assert_image_line(&output, "v0.5.22 (supported)");
}

#[tokio::test]
async fn a_deprecated_image_shows_its_grace_epoch() {
    let output = worker_list(Some(&hash("a21")), roster()).await;
    assert_image_line(&output, "v0.5.21 (deprecated — grace ends epoch 26273)");
}

#[tokio::test]
async fn a_revoked_image_says_so() {
    let output = worker_list(Some(&hash("a11")), roster()).await;
    assert_image_line(&output, "v0.5.11 (revoked)");
}

#[tokio::test]
async fn an_image_off_the_roster_shows_its_short_compose_hash() {
    let output = worker_list(Some(&hash("deadbeef1234")), roster()).await;
    assert_image_line(&output, "unknown image (compose deadbeef1234)");
}

#[tokio::test]
async fn a_worker_without_a_compose_hash_is_not_reported_yet() {
    let output = worker_list(None, roster()).await;
    assert_image_line(&output, "not reported yet");
}

#[tokio::test]
async fn a_failed_version_lookup_still_lists_the_workers() {
    let output = worker_list(
        Some(&hash("a22")),
        ResponseTemplate::new(503).set_body_string("down"),
    )
    .await;
    assert_image_line(&output, "compose a22000000000 (version lookup failed)");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning: could not look up image versions"),
        "{stderr}"
    );
}
