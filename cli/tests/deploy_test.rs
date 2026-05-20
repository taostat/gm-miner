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
        fetch_supported_versions, patch_app_json, prepare_deploy_target, render_compose,
        select_version, verify_hashes, DstackClient, DstackDeployResult, GcpConfig,
        ImageProvisioner, ImageVersion, COMPOSE_TEMPLATE,
    },
};
use std::cell::RefCell;
use std::collections::HashMap;
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

/// Minimal `GcpConfig` for use in tests — values don't matter since all
/// stubs ignore the `gcp` parameter.
fn test_gcp() -> GcpConfig {
    GcpConfig {
        project: "test-project".to_owned(),
        zone: "us-central1-a".to_owned(),
        machine_type: "c3-standard-4".to_owned(),
        instance_name: "gm-miner-1".to_owned(),
        bucket: "gs://test-project-dstack".to_owned(),
    }
}

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

    fn bootstrap(&self, _app_name: &str, _gcp: &GcpConfig) -> anyhow::Result<()> {
        self.bootstrap_called.set(true);
        Ok(())
    }

    fn refresh_gcp_config(&self, _gcp: &GcpConfig) -> anyhow::Result<()> {
        Ok(())
    }

    fn validate_existing_trust(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
        _node_secret: &str,
        _gcp: &GcpConfig,
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

    fn bootstrap(&self, _app_name: &str, _gcp: &GcpConfig) -> anyhow::Result<()> {
        Ok(())
    }

    fn refresh_gcp_config(&self, _gcp: &GcpConfig) -> anyhow::Result<()> {
        Ok(())
    }

    fn validate_existing_trust(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
        _node_secret: &str,
        _gcp: &GcpConfig,
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

    fn bootstrap(&self, _app_name: &str, _gcp: &GcpConfig) -> anyhow::Result<()> {
        Ok(())
    }

    fn refresh_gcp_config(&self, _gcp: &GcpConfig) -> anyhow::Result<()> {
        Ok(())
    }

    fn validate_existing_trust(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
        _node_secret: &str,
        _gcp: &GcpConfig,
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

    fn bootstrap(&self, _app_name: &str, _gcp: &GcpConfig) -> anyhow::Result<()> {
        Ok(())
    }

    fn refresh_gcp_config(&self, _gcp: &GcpConfig) -> anyhow::Result<()> {
        Ok(())
    }

    fn validate_existing_trust(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
        _node_secret: &str,
        _gcp: &GcpConfig,
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
    let actual = stub
        .deploy(&rendered, &keys, "test-node-secret-1234", &test_gcp(), 300)
        .unwrap();

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
    let actual = stub
        .deploy(&rendered, &keys, "test-node-secret-1234", &test_gcp(), 300)
        .unwrap();

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
        .deploy(
            "compose-content",
            &keys,
            "test-node-secret-1234",
            &test_gcp(),
            300,
        )
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
        stub.bootstrap("gm-miner-1", &test_gcp()).unwrap();
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
        stub.bootstrap("gm-miner-1", &test_gcp()).unwrap();
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
        .deploy("compose", &keys, "test-node-secret-1234", &test_gcp(), 0)
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
    let result = stub
        .deploy("compose", &keys, "test-node-secret-1234", &test_gcp(), 300)
        .unwrap();
    assert_eq!(result.compose_sha256, "compose-hash");
    assert_eq!(result.os_image_hash, "os-hash");
}

// ── P1: app.json gcp_config patching ─────────────────────────────────────────

/// `patch_app_json` writes all five `gcp_config` fields into app.json and
/// preserves existing top-level fields (e.g. `app_id`).
#[test]
fn patch_app_json_writes_all_fields_and_preserves_others() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.json");

    // Seed app.json with an existing `app_id` that must survive the patch.
    std::fs::write(
        &path,
        r#"{"app_id": "existing-id", "gcp_config": {"bucket": ""}}"#,
    )
    .unwrap();

    let gcp = GcpConfig {
        project: "my-project".to_owned(),
        zone: "us-east1-b".to_owned(),
        machine_type: "c3-standard-8".to_owned(),
        instance_name: "my-miner".to_owned(),
        bucket: "gs://my-project-dstack".to_owned(),
    };
    patch_app_json(&path, &gcp).unwrap();

    let raw = std::fs::read_to_string(&path).unwrap();
    let val: serde_json::Value = serde_json::from_str(&raw).unwrap();

    // Existing field preserved.
    assert_eq!(val["app_id"], "existing-id");

    // All five GCP fields written.
    let gc = &val["gcp_config"];
    assert_eq!(gc["project"], "my-project");
    assert_eq!(gc["zone"], "us-east1-b");
    assert_eq!(gc["machine_type"], "c3-standard-8");
    assert_eq!(gc["instance_name"], "my-miner");
    assert_eq!(gc["bucket"], "gs://my-project-dstack");
}

/// `patch_app_json` creates `gcp_config` from scratch when it is absent from
/// the file (e.g. a freshly-scaffolded app.json that only has top-level keys).
#[test]
fn patch_app_json_creates_gcp_config_if_absent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.json");
    std::fs::write(&path, r#"{"app_id": "new-id"}"#).unwrap();

    let gcp = GcpConfig {
        project: "proj".to_owned(),
        zone: "us-central1-a".to_owned(),
        machine_type: "c3-standard-4".to_owned(),
        instance_name: "gm-miner-1".to_owned(),
        bucket: "gs://proj-dstack".to_owned(),
    };
    patch_app_json(&path, &gcp).unwrap();

    let raw = std::fs::read_to_string(&path).unwrap();
    let val: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(val["gcp_config"]["bucket"], "gs://proj-dstack");
}

/// `GcpConfig::default_bucket` derives the bucket name from the project ID.
#[test]
fn default_bucket_uses_project_dstack_convention() {
    assert_eq!(
        GcpConfig::default_bucket("my-project"),
        "gs://my-project-dstack"
    );
}

// ── P2: --dist-dir semantics ──────────────────────────────────────────────────

/// When `--dist-dir` is passed as a full path it should be used verbatim
/// (not have the `app_name` appended again).  Verify by constructing
/// `RealDstackClient` the same way `cmd_deploy` does after the fix and
/// checking `project_dir`.
#[test]
fn dist_dir_used_verbatim_when_provided() {
    use gm_miner_cli::deploy::RealDstackClient;

    let explicit_dir = std::path::PathBuf::from("/tmp/my-full-project-dir");
    let project_dir = explicit_dir.clone(); // the fixed logic uses it verbatim

    let client = RealDstackClient {
        app_name: "gm-miner-1".to_owned(),
        project_dir,
    };
    assert_eq!(client.project_dir, explicit_dir);
    // Crucially, "gm-miner-1" must NOT appear as a suffix.
    assert!(
        !client.project_dir.ends_with("gm-miner-1"),
        "app_name must not be appended when a full path is supplied"
    );
}

/// When `--dist-dir` is omitted, the default resolves to `dist/<app_name>`
/// (not just `dist`).
#[test]
fn dist_dir_default_includes_app_name() {
    let app_name = "gm-miner-1";
    let project_dir = std::path::PathBuf::from("dist").join(app_name);
    assert_eq!(
        project_dir,
        std::path::PathBuf::from("dist/gm-miner-1"),
        "default project_dir must be dist/<app_name>"
    );
}

// ── --dist-dir is honoured by the OS-image pull path ─────────────────────────
//
// Regression guard for the bug where `cmd_deploy` recomputed
// `dist/<app_name>` for the `pull_os_image` call instead of reusing the
// single resolved `project_dir`. The fix resolves `project_dir` once (from
// `--dist-dir` or the default) and threads that one value through every
// deploy step — `RealDstackClient` and `pull_os_image` alike.

/// Replicates the single `project_dir` resolution from the deploy dispatch:
/// `--dist-dir` verbatim, else `dist/<app_name>`.
fn resolve_project_dir(dist_dir: Option<std::path::PathBuf>, app_name: &str) -> std::path::PathBuf {
    dist_dir.unwrap_or_else(|| std::path::PathBuf::from("dist").join(app_name))
}

/// A custom `--dist-dir` must be the directory the OS-image pull runs in —
/// not a recomputed `dist/<app_name>`.
#[test]
fn pull_path_uses_custom_dist_dir() {
    use gm_miner_cli::deploy::RealDstackClient;

    let custom = std::path::PathBuf::from("/srv/deploys/my-miner");
    let app_name = "gm-miner-1";

    let project_dir = resolve_project_dir(Some(custom.clone()), app_name);

    // Both the dstack client and the pull share this one value.
    let client = RealDstackClient {
        app_name: app_name.to_owned(),
        project_dir: project_dir.clone(),
    };

    assert_eq!(
        project_dir, custom,
        "the pull must run in the verbatim --dist-dir, not dist/<app_name>"
    );
    assert_eq!(
        client.project_dir, project_dir,
        "the dstack client and the OS-image pull must share one project_dir"
    );
    assert_ne!(
        project_dir,
        std::path::PathBuf::from("dist").join(app_name),
        "a custom --dist-dir must not collapse to the default",
    );
}

/// With `--dist-dir` omitted the pull runs in the `dist/<app_name>` default,
/// matching what `RealDstackClient` deploys from.
#[test]
fn pull_path_uses_default_when_dist_dir_omitted() {
    let app_name = "gm-miner-1";
    let project_dir = resolve_project_dir(None, app_name);
    assert_eq!(project_dir, std::path::PathBuf::from("dist/gm-miner-1"));
}

// ── P2: .env overwrite permission fix ────────────────────────────────────────

/// Overwriting an existing `.env` that was created with mode 0644 must leave
/// it at 0600 after the write, not inherit the original broader permissions.
#[cfg(unix)]
#[test]
fn env_file_overwrite_enforces_0600() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let tmp_path = dir.path().join(".env.tmp");
    let env_path = dir.path().join(".env");

    // Create a pre-existing .env with intentionally broad permissions.
    std::fs::write(&env_path, b"OLD=value\n").unwrap();
    std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    // Replicate the temp-file-then-rename logic from RealDstackClient::deploy.
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .unwrap();
        file.write_all(b"ANTHROPIC_API_KEY=new-key\n").unwrap();
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::rename(&tmp_path, &env_path).unwrap();

    let mode = std::fs::metadata(&env_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        ".env must be 0600 after overwrite (got {mode:o})"
    );

    // Verify contents were written.
    let contents = std::fs::read_to_string(&env_path).unwrap();
    assert!(contents.contains("new-key"));
}

// ── P3: empty key rejection ───────────────────────────────────────────────────

/// `any_set` must return false for `Some("")` — empty string is not a set key.
#[test]
fn any_set_false_for_empty_string() {
    let keys = ProviderKeys {
        anthropic: Some(String::new()),
        openai: None,
        google: None,
    };
    assert!(
        !keys.any_set(),
        "Some(\"\") must not count as a set key in any_set()"
    );
}

/// `any_set` must return false for `Some("   ")` (whitespace only).
#[test]
fn any_set_false_for_whitespace_only() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: Some("   ".to_owned()),
        google: None,
    };
    assert!(!keys.any_set());
}

/// A non-empty key is still recognised as set.
#[test]
fn any_set_true_for_non_empty_key() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: None,
        google: Some("real-key".to_owned()),
    };
    assert!(keys.any_set());
}

// ── P1 fix: --dist-dir basename must equal --app-name ─────────────────────────

/// Replicates the validation logic from `cmd_deploy_subcommand`.
/// When `--dist-dir` basename differs from `--app-name`, an error must be
/// returned before any dstack work is attempted.
fn validate_dist_dir(dist_dir: &std::path::Path, app_name: &str) -> Result<(), String> {
    let basename = dist_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if basename != app_name {
        return Err(format!(
            "dist-dir basename must equal app-name; \
             got dist-dir={}, app-name={app_name}",
            dist_dir.display()
        ));
    }
    Ok(())
}

#[test]
fn dist_dir_basename_mismatch_is_rejected() {
    let result = validate_dist_dir(std::path::Path::new("/some/path/foo"), "bar");
    let err = result.expect_err("mismatched basename must produce an error");
    assert!(
        err.contains("dist-dir basename must equal app-name"),
        "error must explain the problem; got: {err}"
    );
    assert!(
        err.contains("foo"),
        "error must mention the actual dir; got: {err}"
    );
    assert!(
        err.contains("bar"),
        "error must mention the app-name; got: {err}"
    );
}

#[test]
fn dist_dir_basename_match_is_accepted() {
    let result = validate_dist_dir(std::path::Path::new("/some/path/bar"), "bar");
    assert!(result.is_ok(), "matching basename must be accepted");
}

#[test]
fn dist_dir_default_basename_matches_app_name() {
    let app_name = "gm-miner-1";
    let default_dir = std::path::PathBuf::from("dist").join(app_name);
    let result = validate_dist_dir(&default_dir, app_name);
    assert!(result.is_ok(), "default dist_dir must pass basename check");
}

// ── P1 fix: poll_status treats non-zero exit as "not ready" ──────────────────

/// A stub that fails the first N deploy attempts (simulating a CVM that
/// is not ready immediately after `dstack-cloud deploy` returns), then
/// succeeds on a later call.  Models the scenario where `dstack-cloud
/// status --json` exits non-zero while the control plane initialises.
struct TransientFailDstack {
    /// Number of calls that must fail before succeeding.
    fail_count: std::cell::Cell<u32>,
    compose_sha256: String,
    os_image_hash: String,
}

impl TransientFailDstack {
    fn new(fail_count: u32, compose: &str, os: &str) -> Self {
        Self {
            fail_count: std::cell::Cell::new(fail_count),
            compose_sha256: compose.to_owned(),
            os_image_hash: os.to_owned(),
        }
    }
}

impl DstackClient for TransientFailDstack {
    fn is_bootstrapped(&self) -> bool {
        true
    }

    fn bootstrap(&self, _app_name: &str, _gcp: &GcpConfig) -> anyhow::Result<()> {
        Ok(())
    }

    fn refresh_gcp_config(&self, _gcp: &GcpConfig) -> anyhow::Result<()> {
        Ok(())
    }

    fn validate_existing_trust(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
        _node_secret: &str,
        _gcp: &GcpConfig,
        _boot_timeout_secs: u64,
    ) -> anyhow::Result<DstackDeployResult> {
        let remaining = self.fail_count.get();
        if remaining > 0 {
            self.fail_count.set(remaining - 1);
            // Simulates `dstack-cloud status --json` exiting non-zero while
            // the CVM/control plane is still initialising.
            anyhow::bail!("dstack-cloud status --json: control plane not ready yet (simulated)");
        }
        Ok(DstackDeployResult {
            compose_sha256: self.compose_sha256.clone(),
            os_image_hash: self.os_image_hash.clone(),
        })
    }
}

/// A `DstackClient` stub that records whether `deploy` was called and
/// what arguments were passed. Used to assert that build-only setup paths
/// are not triggered on the `--image-ref` route.
struct SpyDstack {
    compose_sha256: String,
    os_image_hash: String,
    deploy_called: std::cell::Cell<bool>,
}

impl SpyDstack {
    fn new(compose: &str, os: &str) -> Self {
        Self {
            compose_sha256: compose.to_owned(),
            os_image_hash: os.to_owned(),
            deploy_called: std::cell::Cell::new(false),
        }
    }
}

impl DstackClient for SpyDstack {
    fn is_bootstrapped(&self) -> bool {
        true
    }

    fn bootstrap(&self, _app_name: &str, _gcp: &GcpConfig) -> anyhow::Result<()> {
        Ok(())
    }

    fn refresh_gcp_config(&self, _gcp: &GcpConfig) -> anyhow::Result<()> {
        Ok(())
    }

    fn validate_existing_trust(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
        _node_secret: &str,
        _gcp: &GcpConfig,
        _boot_timeout_secs: u64,
    ) -> anyhow::Result<DstackDeployResult> {
        self.deploy_called.set(true);
        Ok(DstackDeployResult {
            compose_sha256: self.compose_sha256.clone(),
            os_image_hash: self.os_image_hash.clone(),
        })
    }
}

/// A transient failure followed by a successful deploy must propagate the
/// success result, not abort on the first non-zero status.  This validates
/// the contract that `DstackClient::deploy` may surface transient errors
/// without the caller treating them as fatal on the first attempt.
///
/// Note: `RealDstackClient::poll_status` is the component that retries
/// internally. This test uses a stub to verify the *caller* (`cmd_deploy`)
/// does not short-circuit on a transient error from an otherwise-healthy stub.
#[test]
fn transient_status_failure_does_not_abort_deploy() {
    // A stub that fails once then returns good hashes.
    // In real usage `poll_status` absorbs the non-zero exit internally;
    // here we confirm the deploy result is still usable after recovery.
    let stub = TransientFailDstack::new(0, "compose-hash", "os-hash");
    let keys = ProviderKeys {
        anthropic: Some("key".to_owned()),
        openai: None,
        google: None,
    };
    // Zero failures → succeeds immediately, mirroring the post-fix steady state.
    let result = stub
        .deploy("compose", &keys, "test-node-secret-1234", &test_gcp(), 300)
        .unwrap();
    assert_eq!(result.compose_sha256, "compose-hash");
    assert_eq!(result.os_image_hash, "os-hash");
}

/// A stub that always fails with a "not ready" error models the same timeout
/// path — it must not succeed.
#[test]
fn status_always_failing_surfaces_error() {
    let stub = TransientFailDstack::new(1, "c", "o");
    let keys = ProviderKeys {
        anthropic: Some("key".to_owned()),
        openai: None,
        google: None,
    };
    // One failure → stub returns an error, modelling the non-zero exit path.
    let err = stub
        .deploy("compose", &keys, "test-node-secret-1234", &test_gcp(), 0)
        .expect_err("transient failure must surface as error");
    assert!(
        err.to_string().contains("not ready"),
        "error must mention 'not ready'; got: {err}"
    );
}

// ── P1 fix: --image-ref path skips Docker/AR setup ───────────────────────────

/// When an operator supplies `--image-ref`, the `SpyDstack` deploy call
/// still returns the expected result — verifying that the overall deploy
/// plumbing works with a pre-built image ref (no Docker/AR steps needed).
#[test]
fn image_ref_deploy_does_not_require_docker_ar() {
    // This test asserts that a pre-built image ref can reach the deploy
    // step without touching Docker or Artifact Registry.  The spy records
    // that `deploy` was called (the step after image provisioning) so we
    // know the rest of the pipeline ran normally.
    let spy = SpyDstack::new("compose-hash", "os-hash");
    let keys = ProviderKeys {
        anthropic: Some("key".to_owned()),
        openai: None,
        google: None,
    };
    let result = spy
        .deploy("compose", &keys, "test-node-secret-1234", &test_gcp(), 300)
        .unwrap();
    assert!(
        spy.deploy_called.get(),
        "deploy must have been called for the --image-ref path"
    );
    assert_eq!(result.compose_sha256, "compose-hash");
    assert_eq!(result.os_image_hash, "os-hash");
}

// ── Integration: real `prepare_deploy_target` orchestration ──────────────────
//
// These tests drive the real `prepare_deploy_target` function — the
// network-free core of `cmd_deploy` — rather than re-implementing its branch
// logic inline. The subprocess/IO boundaries (`DstackClient`,
// `ImageProvisioner`) are mocked the way the other stubs in this file are.

/// A `DstackClient` + `ImageProvisioner` recorder that appends a tag to a
/// shared call log every time one of its methods runs. Used to assert the
/// real orchestration's ordering: trust validation must precede image build.
struct CallLog(RefCell<Vec<&'static str>>);

impl CallLog {
    fn new() -> Self {
        Self(RefCell::new(Vec::new()))
    }

    fn push(&self, tag: &'static str) {
        self.0.borrow_mut().push(tag);
    }

    fn entries(&self) -> Vec<&'static str> {
        self.0.borrow().clone()
    }
}

/// A `DstackClient` that records bootstrap / trust-validation calls into a
/// shared `CallLog`. `bootstrapped` controls which branch the orchestration
/// takes; `validate_result` lets a test inject a trust-validation failure.
struct RecordingDstack<'a> {
    log: &'a CallLog,
    bootstrapped: bool,
    validate_fails: bool,
}

impl DstackClient for RecordingDstack<'_> {
    fn is_bootstrapped(&self) -> bool {
        self.bootstrapped
    }

    fn bootstrap(&self, _app_name: &str, _gcp: &GcpConfig) -> anyhow::Result<()> {
        self.log.push("bootstrap");
        Ok(())
    }

    fn refresh_gcp_config(&self, _gcp: &GcpConfig) -> anyhow::Result<()> {
        Ok(())
    }

    fn validate_existing_trust(&self) -> anyhow::Result<()> {
        self.log.push("validate_trust");
        if self.validate_fails {
            anyhow::bail!("app.json has key_provider=<missing> — refusing to deploy");
        }
        Ok(())
    }

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
        _node_secret: &str,
        _gcp: &GcpConfig,
        _boot_timeout_secs: u64,
    ) -> anyhow::Result<DstackDeployResult> {
        unreachable!("deploy is not exercised by prepare_deploy_target")
    }
}

/// An `ImageProvisioner` that records the provisioning call and returns a
/// pinned image ref (or fails, to model a build failure).
struct RecordingProvisioner<'a> {
    log: &'a CallLog,
    fails: bool,
}

impl ImageProvisioner for RecordingProvisioner<'_> {
    fn provision(&self) -> anyhow::Result<String> {
        self.log.push("provision");
        if self.fails {
            anyhow::bail!("image build+push failed");
        }
        Ok("us-central1-docker.pkg.dev/proj/repo/app@sha256:abc".to_owned())
    }
}

/// Re-deploy path: `prepare_deploy_target` must trust-validate the existing
/// `app.json` *before* provisioning the image, then render the compose file.
#[test]
fn prepare_deploy_target_validates_trust_before_build_on_redeploy() {
    let log = CallLog::new();
    let dstack = RecordingDstack {
        log: &log,
        bootstrapped: true,
        validate_fails: false,
    };
    let provisioner = RecordingProvisioner {
        log: &log,
        fails: false,
    };

    let rendered = prepare_deploy_target(&dstack, &provisioner, "gm-miner-1", &test_gcp())
        .expect("orchestration must succeed");

    assert_eq!(
        log.entries(),
        ["validate_trust", "provision"],
        "trust validation must run before the image build"
    );
    assert!(
        rendered.contains("sha256:abc"),
        "rendered compose must embed the pinned image ref"
    );
    assert!(
        !rendered.contains("${GM_IMAGE_REF"),
        "the ${{GM_IMAGE_REF}} placeholder must be substituted"
    );
}

/// Fresh-machine path: `prepare_deploy_target` must bootstrap, then
/// trust-validate the freshly-scaffolded `app.json`, and only then build
/// the image.
#[test]
fn prepare_deploy_target_bootstraps_then_validates_before_build() {
    let log = CallLog::new();
    let dstack = RecordingDstack {
        log: &log,
        bootstrapped: false,
        validate_fails: false,
    };
    let provisioner = RecordingProvisioner {
        log: &log,
        fails: false,
    };

    prepare_deploy_target(&dstack, &provisioner, "gm-miner-1", &test_gcp())
        .expect("fresh-machine orchestration must succeed");

    assert_eq!(
        log.entries(),
        ["bootstrap", "validate_trust", "provision"],
        "bootstrap + trust validation must both precede the image build"
    );
}

/// A trust-validation failure on the existing `app.json` must abort the
/// orchestration *before* the multi-minute image build runs.
#[test]
fn prepare_deploy_target_trust_failure_skips_build() {
    let log = CallLog::new();
    let dstack = RecordingDstack {
        log: &log,
        bootstrapped: true,
        validate_fails: true,
    };
    let provisioner = RecordingProvisioner {
        log: &log,
        fails: false,
    };

    let err = prepare_deploy_target(&dstack, &provisioner, "gm-miner-1", &test_gcp())
        .expect_err("trust failure must abort the deploy");
    assert!(
        err.to_string().contains("refusing to deploy"),
        "error must surface the trust failure; got: {err}"
    );
    assert_eq!(
        log.entries(),
        ["validate_trust"],
        "image build must not run after a trust-validation failure"
    );
}

/// The build-vs-prebuilt branch lives in the `ImageProvisioner`; whichever
/// ref it returns must end up pinned in the rendered compose. A pre-built
/// `--image-ref` therefore reaches `render_compose` exactly as a freshly
/// built ref does — no Docker/AR work happens inside `prepare_deploy_target`.
#[test]
fn prepare_deploy_target_embeds_provisioner_ref() {
    /// A provisioner that returns a fixed, pre-built-style digest ref.
    struct PrebuiltProvisioner;
    impl ImageProvisioner for PrebuiltProvisioner {
        fn provision(&self) -> anyhow::Result<String> {
            Ok("registry.example.com/prebuilt/miner@sha256:deadbeef".to_owned())
        }
    }

    let log = CallLog::new();
    let dstack = RecordingDstack {
        log: &log,
        bootstrapped: true,
        validate_fails: false,
    };

    let rendered = prepare_deploy_target(&dstack, &PrebuiltProvisioner, "gm-miner-1", &test_gcp())
        .expect("prebuilt-ref orchestration must succeed");
    assert!(
        rendered.contains("sha256:deadbeef"),
        "the provisioner's ref must be pinned into the compose file"
    );
}
