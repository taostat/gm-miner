//! Integration tests for the `gm-miner deploy` hash-verification flow.
//!
//! Uses wiremock to mock the registry `/image-versions` endpoint and a
//! stub `DstackClient` to simulate the dstack-cloud deploy step, so no
//! real network or toolchain is needed.
//!
//! Key test: mismatched hashes cause `verify_hashes` to return an error
//! (which `cmd_deploy` propagates as an exit-1-equivalent `Err`).

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]

use gm_miner_cli::{
    config::{Config, ProviderKeys},
    deploy::{
        fetch_supported_versions, render_compose, select_version, verify_hashes, DstackClient,
        DstackDeployResult, ImageVersion, COMPOSE_TEMPLATE,
    },
};
use std::collections::HashMap;
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

// ── Stub DstackClient ─────────────────────────────────────────────────────────

/// A test double for `DstackClient` that returns pre-canned hashes without
/// touching the filesystem or calling any external process.
struct StubDstack {
    compose_sha256: String,
    os_image_hash: String,
}

impl StubDstack {
    fn matching(compose: &str, os: &str) -> Self {
        Self {
            compose_sha256: compose.to_owned(),
            os_image_hash: os.to_owned(),
        }
    }
}

impl DstackClient for StubDstack {
    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
    ) -> anyhow::Result<DstackDeployResult> {
        Ok(DstackDeployResult {
            compose_sha256: self.compose_sha256.clone(),
            os_image_hash: self.os_image_hash.clone(),
        })
    }
}

/// A stub that always returns an error (simulates a deploy failure).
struct FailingDstack;

impl DstackClient for FailingDstack {
    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
    ) -> anyhow::Result<DstackDeployResult> {
        anyhow::bail!("dstack-cloud deploy exited with status 1");
    }
}

/// Build an `ImageVersionsResponse` JSON body with one version.
fn versions_body(compose_hash: &str, os_image_hash: &str) -> serde_json::Value {
    serde_json::json!({
        "versions": [{
            "compose_hash": compose_hash,
            "os_image_hash": os_image_hash,
            "status": "supported",
            "notes": "test version",
            "created_at": "2025-05-01T12:00:00Z"
        }]
    })
}

// ── Core verification tests ───────────────────────────────────────────────────

/// The central trust guarantee: if dstack returns hashes that do NOT match the
/// registry-approved version, `verify_hashes` must return an `Err`.
/// This causes `cmd_deploy` to refuse to register and exit with a non-zero code.
#[test]
fn mismatched_hashes_produce_error() {
    let approved = ImageVersion {
        compose_hash: "approved-compose-hash".to_owned(),
        os_image_hash: "approved-os-hash".to_owned(),
        status: "supported".to_owned(),
        notes: None,
        created_at: "2025-01-01T00:00:00Z".to_owned(),
    };

    // Dstack returns DIFFERENT hashes (simulates a tampered deploy).
    let actual = DstackDeployResult {
        compose_sha256: "TAMPERED-compose-hash".to_owned(),
        os_image_hash: "TAMPERED-os-hash".to_owned(),
    };

    let err =
        verify_hashes(&actual, &approved).expect_err("mismatched hashes must produce an error");

    let msg = err.to_string();
    assert!(
        msg.contains("HASH MISMATCH"),
        "error must say HASH MISMATCH; got: {msg}"
    );
    assert!(
        msg.contains("compose_hash"),
        "error must mention compose_hash; got: {msg}"
    );
    assert!(
        msg.contains("os_image_hash"),
        "error must mention os_image_hash; got: {msg}"
    );
    // Must include the expected and actual values for actionability.
    assert!(msg.contains("approved-compose-hash"));
    assert!(msg.contains("TAMPERED-compose-hash"));
}

/// When only the compose hash is wrong, the error must call that out precisely.
#[test]
fn compose_mismatch_error_is_specific() {
    let approved = ImageVersion {
        compose_hash: "correct-compose".to_owned(),
        os_image_hash: "correct-os".to_owned(),
        status: "supported".to_owned(),
        notes: None,
        created_at: "2025-01-01T00:00:00Z".to_owned(),
    };
    let actual = DstackDeployResult {
        compose_sha256: "wrong-compose".to_owned(),
        os_image_hash: "correct-os".to_owned(),
    };

    let err = verify_hashes(&actual, &approved).expect_err("must fail");
    let msg = err.to_string();
    assert!(msg.contains("compose_hash"));
    // os_image_hash is fine — should not appear in the diff.
    assert!(
        !msg.contains("  os_image_hash\n"),
        "os_image_hash section should not appear when it matches; got:\n{msg}"
    );
}

/// When only the OS hash is wrong, the error must call that out precisely.
#[test]
fn os_hash_mismatch_error_is_specific() {
    let approved = ImageVersion {
        compose_hash: "correct-compose".to_owned(),
        os_image_hash: "correct-os".to_owned(),
        status: "supported".to_owned(),
        notes: None,
        created_at: "2025-01-01T00:00:00Z".to_owned(),
    };
    let actual = DstackDeployResult {
        compose_sha256: "correct-compose".to_owned(),
        os_image_hash: "wrong-os".to_owned(),
    };

    let err = verify_hashes(&actual, &approved).expect_err("must fail");
    let msg = err.to_string();
    assert!(msg.contains("os_image_hash"));
    assert!(
        !msg.contains("  compose_hash\n"),
        "compose_hash section should not appear when it matches; got:\n{msg}"
    );
}

/// Matched hashes must succeed (no error).
#[test]
fn matched_hashes_succeed() {
    let approved = ImageVersion {
        compose_hash: "abc123".to_owned(),
        os_image_hash: "def456".to_owned(),
        status: "supported".to_owned(),
        notes: None,
        created_at: "2025-01-01T00:00:00Z".to_owned(),
    };
    let actual = DstackDeployResult {
        compose_sha256: "abc123".to_owned(),
        os_image_hash: "def456".to_owned(),
    };
    assert!(verify_hashes(&actual, &approved).is_ok());
}

// ── Full deploy flow (with mock registry + stub dstack) ───────────────────────

/// Happy path: matched hashes → verification passes → `cmd_deploy` would
/// proceed to registration.  We test the verify step in isolation here
/// (registration requires a live registry client, which is tested elsewhere).
#[tokio::test]
async fn deploy_flow_matched_hashes_calls_verify_ok() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/image-versions"))
        .and(query_param("status", "supported"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(versions_body("expected-compose", "expected-os")),
        )
        .mount(&server)
        .await;

    let versions = fetch_supported_versions(&server.uri()).await.unwrap();
    let approved = select_version(&versions, None).unwrap();

    let stub = StubDstack::matching("expected-compose", "expected-os");
    let keys = ProviderKeys {
        anthropic: Some("key".to_owned()),
        openai: None,
        google: None,
    };
    let rendered = render_compose(COMPOSE_TEMPLATE, "reg.example.com/app@sha256:abc").unwrap();
    let actual = stub.deploy(&rendered, &keys).unwrap();

    assert!(verify_hashes(&actual, approved).is_ok());
}

/// Mismatch path: dstack returns different hashes → verify fails → deploy
/// refuses to register.
#[tokio::test]
async fn deploy_flow_mismatched_hashes_causes_verify_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/image-versions"))
        .and(query_param("status", "supported"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(versions_body("registry-compose", "registry-os")),
        )
        .mount(&server)
        .await;

    let versions = fetch_supported_versions(&server.uri()).await.unwrap();
    let approved = select_version(&versions, None).unwrap();

    // dstack returns DIFFERENT hashes — simulates a tampered or stale build.
    let stub = StubDstack::matching("different-compose", "different-os");
    let keys = ProviderKeys {
        anthropic: Some("key".to_owned()),
        openai: None,
        google: None,
    };
    let rendered = render_compose(COMPOSE_TEMPLATE, "reg.example.com/app@sha256:abc").unwrap();
    let actual = stub.deploy(&rendered, &keys).unwrap();

    let err =
        verify_hashes(&actual, approved).expect_err("mismatched hashes must produce an error");
    assert!(err.to_string().contains("HASH MISMATCH"));
}

// ── No provider keys → early-exit error ──────────────────────────────────────

#[test]
fn deploy_errors_when_no_provider_keys_set() {
    let cfg = Config {
        networks: HashMap::new(),
        active_network: Some("mainnet".to_string()),
        provider_keys: None, // no keys configured
    };

    // Replicate the exact check from `cmd_deploy`.
    let result = cfg
        .provider_keys
        .as_ref()
        .filter(|k| k.any_set())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no provider keys; run `gm-miner set-api-keys \
                 --anthropic <key>` (and/or --openai / --google) first"
            )
        });

    let err = result.expect_err("should error with no keys");
    assert!(err.to_string().contains("no provider keys"));
    assert!(err.to_string().contains("set-api-keys"));
}

#[test]
fn deploy_errors_when_provider_keys_all_none() {
    let cfg = Config {
        networks: HashMap::new(),
        active_network: Some("mainnet".to_string()),
        provider_keys: Some(ProviderKeys {
            anthropic: None,
            openai: None,
            google: None,
        }),
    };

    let result = cfg
        .provider_keys
        .as_ref()
        .filter(|k| k.any_set())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no provider keys; run `gm-miner set-api-keys \
                 --anthropic <key>` (and/or --openai / --google) first"
            )
        });

    let err = result.expect_err("should error with all-None keys");
    assert!(err.to_string().contains("no provider keys"));
}

// ── Registry 404 surfaces as actionable error ─────────────────────────────────

#[tokio::test]
async fn registry_404_returns_clear_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/image-versions"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let err = fetch_supported_versions(&server.uri())
        .await
        .expect_err("404 must produce an error");

    assert!(
        err.to_string().contains("404"),
        "error must mention 404; got: {err}"
    );
    assert!(
        err.to_string().contains("newer than the registry"),
        "error must explain the cause; got: {err}"
    );
}

// ── Dstack deploy failure surfaces as error ───────────────────────────────────

#[test]
fn dstack_failure_surfaces_as_error() {
    let keys = ProviderKeys {
        anthropic: Some("key".to_owned()),
        openai: None,
        google: None,
    };
    let err = FailingDstack
        .deploy("compose-content", &keys)
        .expect_err("failing dstack must produce an error");
    assert!(err.to_string().contains("dstack-cloud deploy exited"));
}

// ── Version selection with multiple supported versions ────────────────────────

#[tokio::test]
async fn newest_version_selected_by_default() {
    let server = MockServer::start().await;

    let body = serde_json::json!({
        "versions": [
            {
                "compose_hash": "old-compose",
                "os_image_hash": "old-os",
                "status": "supported",
                "notes": "v1",
                "created_at": "2025-01-01T00:00:00Z"
            },
            {
                "compose_hash": "new-compose",
                "os_image_hash": "new-os",
                "status": "supported",
                "notes": "v2",
                "created_at": "2025-06-01T00:00:00Z"
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/image-versions"))
        .and(query_param("status", "supported"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let versions = fetch_supported_versions(&server.uri()).await.unwrap();
    let selected = select_version(&versions, None).unwrap();
    assert_eq!(
        selected.compose_hash, "new-compose",
        "newest must be selected by default"
    );
}

#[tokio::test]
async fn pinned_version_selected_when_requested() {
    let server = MockServer::start().await;

    let body = serde_json::json!({
        "versions": [
            {
                "compose_hash": "new-compose",
                "os_image_hash": "new-os",
                "status": "supported",
                "notes": "v2",
                "created_at": "2025-06-01T00:00:00Z"
            },
            {
                "compose_hash": "old-compose",
                "os_image_hash": "old-os",
                "status": "supported",
                "notes": "v1",
                "created_at": "2025-01-01T00:00:00Z"
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/image-versions"))
        .and(query_param("status", "supported"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let versions = fetch_supported_versions(&server.uri()).await.unwrap();
    // Pin to version 2 (older one, 1-based index in newest-first list).
    let selected = select_version(&versions, Some(2)).unwrap();
    assert_eq!(selected.compose_hash, "old-compose");
}
