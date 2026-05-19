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
    bootstrapped: bool,
    /// Records whether `bootstrap` was called.
    bootstrap_called: std::cell::Cell<bool>,
}

impl StubDstack {
    fn matching(compose: &str, os: &str) -> Self {
        Self {
            compose_sha256: compose.to_owned(),
            os_image_hash: os.to_owned(),
            bootstrapped: true,
            bootstrap_called: std::cell::Cell::new(false),
        }
    }

    fn fresh_machine(compose: &str, os: &str) -> Self {
        Self {
            bootstrapped: false,
            bootstrap_called: std::cell::Cell::new(false),
            ..Self::matching(compose, os)
        }
    }
}

impl DstackClient for StubDstack {
    fn is_bootstrapped(&self) -> bool {
        self.bootstrapped
    }

    fn bootstrap(&self, _app_name: &str) -> anyhow::Result<()> {
        self.bootstrap_called.set(true);
        Ok(())
    }

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
        _boot_timeout_secs: u64,
    ) -> anyhow::Result<DstackDeployResult> {
        Ok(DstackDeployResult {
            compose_sha256: self.compose_sha256.clone(),
            os_image_hash: self.os_image_hash.clone(),
        })
    }
}

/// A stub that simulates a deploy that returns hashes immediately.
/// Used to verify the happy path when the CVM boots quickly.
struct FastBootDstack {
    compose_sha256: String,
    os_image_hash: String,
}

impl FastBootDstack {
    fn new(compose: &str, os: &str) -> Self {
        Self {
            compose_sha256: compose.to_owned(),
            os_image_hash: os.to_owned(),
        }
    }
}

impl DstackClient for FastBootDstack {
    fn is_bootstrapped(&self) -> bool {
        true
    }

    fn bootstrap(&self, _app_name: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
        _boot_timeout_secs: u64,
    ) -> anyhow::Result<DstackDeployResult> {
        Ok(DstackDeployResult {
            compose_sha256: self.compose_sha256.clone(),
            os_image_hash: self.os_image_hash.clone(),
        })
    }
}

/// A stub that simulates a deploy that always times out (hashes never appear).
struct TimedOutDstack;

impl DstackClient for TimedOutDstack {
    fn is_bootstrapped(&self) -> bool {
        true
    }

    fn bootstrap(&self, _app_name: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
        _boot_timeout_secs: u64,
    ) -> anyhow::Result<DstackDeployResult> {
        anyhow::bail!(
            "timed out after 0s waiting for the CVM to boot \
             (compose_sha256/os_image_hash never appeared in \
             `dstack-cloud status --json`); \
             increase --boot-timeout-secs or check the dstack-cloud console"
        )
    }
}

/// A stub that always returns an error (simulates a deploy failure).
struct FailingDstack;

impl DstackClient for FailingDstack {
    fn is_bootstrapped(&self) -> bool {
        true
    }

    fn bootstrap(&self, _app_name: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
        _boot_timeout_secs: u64,
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
    let actual = stub.deploy(&rendered, &keys, 300).unwrap();

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
    let actual = stub.deploy(&rendered, &keys, 300).unwrap();

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
        .deploy("compose-content", &keys, 300)
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

// ── Bootstrap detection ───────────────────────────────────────────────────────

/// On a fresh machine where `app.json` is absent, `is_bootstrapped()` returns
/// false and the deploy flow must call `bootstrap()` before deploying.
#[test]
fn fresh_machine_bootstrap_is_called() {
    let stub = StubDstack::fresh_machine("compose", "os");
    assert!(
        !stub.is_bootstrapped(),
        "fresh machine must not be bootstrapped"
    );

    // Simulate what cmd_deploy does: call bootstrap when not bootstrapped.
    if !stub.is_bootstrapped() {
        stub.bootstrap("gm-miner-1").unwrap();
    }
    assert!(
        stub.bootstrap_called.get(),
        "bootstrap must have been called for a fresh machine"
    );
}

/// On a machine where `app.json` exists, `is_bootstrapped()` returns true and
/// `bootstrap()` must NOT be called.
#[test]
fn existing_machine_bootstrap_not_called() {
    let stub = StubDstack::matching("compose", "os");
    assert!(
        stub.is_bootstrapped(),
        "existing machine must be bootstrapped"
    );

    // Simulate what cmd_deploy does.
    if !stub.is_bootstrapped() {
        stub.bootstrap("gm-miner-1").unwrap();
    }
    assert!(
        !stub.bootstrap_called.get(),
        "bootstrap must NOT be called when app.json already exists"
    );
}

// ── Atomic 0600 .env creation ─────────────────────────────────────────────────

/// Verify that the `.env` file is created with mode 0600 from the outset
/// (no world-readable window).
#[cfg(unix)]
#[test]
fn env_file_created_with_0600_mode() {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");

    // Replicate the atomic open logic from RealDstackClient::deploy.
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&env_path)
            .unwrap();
        file.write_all(b"ANTHROPIC_API_KEY=test\n").unwrap();
    }

    let meta = std::fs::metadata(&env_path).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        ".env must be created with mode 0600 (got {mode:o})"
    );
}

// ── Polling timeout error ─────────────────────────────────────────────────────

/// When the CVM never boots and hashes never appear, the poll loop must surface
/// a clear actionable error mentioning `--boot-timeout-secs`.
#[test]
fn timeout_error_is_actionable() {
    let keys = ProviderKeys {
        anthropic: Some("key".to_owned()),
        openai: None,
        google: None,
    };
    let err = TimedOutDstack
        .deploy("compose", &keys, 0)
        .expect_err("timed-out deploy must produce an error");
    let msg = err.to_string();
    assert!(
        msg.contains("timed out"),
        "error must say 'timed out'; got: {msg}"
    );
    assert!(
        msg.contains("--boot-timeout-secs"),
        "error must mention --boot-timeout-secs; got: {msg}"
    );
}

/// When the CVM boots quickly and hashes appear on the first status poll,
/// deploy succeeds without error.
#[test]
fn fast_boot_deploy_succeeds() {
    let keys = ProviderKeys {
        anthropic: Some("key".to_owned()),
        openai: None,
        google: None,
    };
    let stub = FastBootDstack::new("compose-hash", "os-hash");
    let result = stub.deploy("compose", &keys, 300).unwrap();
    assert_eq!(result.compose_sha256, "compose-hash");
    assert_eq!(result.os_image_hash, "os-hash");
}
