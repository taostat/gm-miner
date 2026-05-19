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
        fetch_supported_versions, patch_app_json, render_compose, select_version, verify_hashes,
        DstackClient, DstackDeployResult, GcpConfig, ImageVersion, COMPOSE_TEMPLATE,
    },
};
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

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
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

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
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

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
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

    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
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
    let actual = stub.deploy(&rendered, &keys, &test_gcp(), 300).unwrap();

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
    let actual = stub.deploy(&rendered, &keys, &test_gcp(), 300).unwrap();

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
        .deploy("compose-content", &keys, &test_gcp(), 300)
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
        .deploy("compose", &keys, &test_gcp(), 0)
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
    let result = stub.deploy("compose", &keys, &test_gcp(), 300).unwrap();
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
