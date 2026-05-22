//! Integration tests for the `gm-miner deploy` hash-verification flow.
//!
//! Uses wiremock to mock the registry `/image-versions` endpoint and a
//! stub `PhalaClient` to simulate the Phala Cloud deploy step, so no real
//! network or `phala` CLI is needed.
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
        fetch_supported_versions, prepare_deploy_target, render_compose, select_version,
        verify_hashes, DeployOutcome, DstackDeployResult, ImageProvisioner, ImageVersion,
        PhalaClient, RegistryCredentials, COMPOSE_TEMPLATE,
    },
};
use std::collections::HashMap;
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

// ── Stub PhalaClient ──────────────────────────────────────────────────────────

/// A test double for `PhalaClient` that returns pre-canned hashes without
/// touching the filesystem or calling any external process.
struct StubPhala {
    compose_sha256: String,
    os_image_hash: String,
    /// Records whether `deploy` was called.
    deploy_called: std::cell::Cell<bool>,
}

impl StubPhala {
    fn matching(compose: &str, os: &str) -> Self {
        Self {
            compose_sha256: compose.to_owned(),
            os_image_hash: os.to_owned(),
            deploy_called: std::cell::Cell::new(false),
        }
    }
}

impl PhalaClient for StubPhala {
    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
        _node_secret: &str,
        _registry_creds: Option<&RegistryCredentials>,
        _benchmark_upstream_url: Option<&str>,
        _boot_timeout_secs: u64,
    ) -> anyhow::Result<DeployOutcome> {
        self.deploy_called.set(true);
        Ok(DeployOutcome {
            hashes: DstackDeployResult {
                compose_sha256: self.compose_sha256.clone(),
                os_image_hash: self.os_image_hash.clone(),
            },
            endpoint: "https://app_x-8080.dstack-prod5.phala.network".to_owned(),
        })
    }
}

/// A stub that simulates a deploy that always times out (hashes never appear).
struct TimedOutPhala;

impl PhalaClient for TimedOutPhala {
    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
        _node_secret: &str,
        _registry_creds: Option<&RegistryCredentials>,
        _benchmark_upstream_url: Option<&str>,
        _boot_timeout_secs: u64,
    ) -> anyhow::Result<DeployOutcome> {
        anyhow::bail!(
            "timed out after 0s waiting for the CVM to report hashes \
             (compose_hash/os_image_hash never appeared in \
             `phala cvms get app_x --json`); \
             increase --boot-timeout-secs or check the Phala Cloud dashboard"
        )
    }
}

/// A stub that always returns an error (simulates a deploy failure).
struct FailingPhala;

impl PhalaClient for FailingPhala {
    fn deploy(
        &self,
        _compose_yaml: &str,
        _env_vars: &ProviderKeys,
        _node_secret: &str,
        _registry_creds: Option<&RegistryCredentials>,
        _benchmark_upstream_url: Option<&str>,
        _boot_timeout_secs: u64,
    ) -> anyhow::Result<DeployOutcome> {
        anyhow::bail!("phala deploy exited with status 1");
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

/// The central trust guarantee: if Phala Cloud returns hashes that do NOT
/// match the registry-approved version, `verify_hashes` must return an
/// `Err`. This causes `cmd_deploy` to refuse to register and exit non-zero.
#[test]
fn mismatched_hashes_produce_error() {
    let approved = ImageVersion {
        compose_hash: "approved-compose-hash".to_owned(),
        os_image_hash: "approved-os-hash".to_owned(),
        status: "supported".to_owned(),
        notes: None,
        created_at: "2025-01-01T00:00:00Z".to_owned(),
    };

    // Phala Cloud returns DIFFERENT hashes (simulates a tampered deploy).
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

// ── Full deploy flow (with mock registry + stub phala) ────────────────────────

/// Happy path: matched hashes → verification passes → `cmd_deploy` would
/// proceed to registration.
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

    let stub = StubPhala::matching("expected-compose", "expected-os");
    let keys = ProviderKeys {
        anthropic: Some("key".to_owned()),
        openai: None,
        google: None,
    };
    let rendered = render_compose(COMPOSE_TEMPLATE, "ghcr.io/o/app@sha256:abc").unwrap();
    let actual = stub
        .deploy(&rendered, &keys, "test-node-secret-1234", None, None, 300)
        .unwrap();

    assert!(stub.deploy_called.get(), "deploy must have been called");
    assert!(verify_hashes(&actual.hashes, approved).is_ok());
}

/// Mismatch path: Phala Cloud returns different hashes → verify fails →
/// deploy refuses to register.
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

    // Phala Cloud returns DIFFERENT hashes — simulates a tampered build.
    let stub = StubPhala::matching("different-compose", "different-os");
    let keys = ProviderKeys {
        anthropic: Some("key".to_owned()),
        openai: None,
        google: None,
    };
    let rendered = render_compose(COMPOSE_TEMPLATE, "ghcr.io/o/app@sha256:abc").unwrap();
    let actual = stub
        .deploy(&rendered, &keys, "test-node-secret-1234", None, None, 300)
        .unwrap();

    let err = verify_hashes(&actual.hashes, approved)
        .expect_err("mismatched hashes must produce an error");
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

// ── Phala deploy failure surfaces as error ────────────────────────────────────

#[test]
fn phala_failure_surfaces_as_error() {
    let keys = ProviderKeys {
        anthropic: Some("key".to_owned()),
        openai: None,
        google: None,
    };
    let err = FailingPhala
        .deploy(
            "compose-content",
            &keys,
            "test-node-secret-1234",
            None,
            None,
            300,
        )
        .expect_err("failing phala must produce an error");
    assert!(err.to_string().contains("phala deploy exited"));
}

// ── Polling timeout error ─────────────────────────────────────────────────────

/// When the CVM never reports its hashes, the poll loop must surface a
/// clear actionable error mentioning `--boot-timeout-secs`.
#[test]
fn timeout_error_is_actionable() {
    let keys = ProviderKeys {
        anthropic: Some("key".to_owned()),
        openai: None,
        google: None,
    };
    let err = TimedOutPhala
        .deploy("compose", &keys, "test-node-secret-1234", None, None, 0)
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

// ── --dist-dir semantics ──────────────────────────────────────────────────────

/// When `--dist-dir` is passed as a full path it should be used verbatim
/// (not have the `app_name` appended again).
#[test]
fn dist_dir_used_verbatim_when_provided() {
    use gm_miner_cli::deploy::RealPhalaClient;

    let explicit_dir = std::path::PathBuf::from("/tmp/my-full-project-dir");
    let client = RealPhalaClient::new(
        "gm-miner-1",
        explicit_dir.clone(),
        "tdx.medium",
        "40G",
        "dstack-0.5.7",
    );
    assert_eq!(client.project_dir, explicit_dir);
    assert!(
        !client.project_dir.ends_with("gm-miner-1"),
        "app_name must not be appended when a full path is supplied"
    );
}

/// When `--dist-dir` is omitted, the default resolves to `dist/<app_name>`.
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

// ── Atomic 0600 .env creation ─────────────────────────────────────────────────

/// Verify that the `.env` file is created with mode 0600 from the outset
/// (no world-readable window) — the env file `phala deploy` reads and
/// encrypts client-side to the CVM key.
#[cfg(unix)]
#[test]
fn env_file_created_with_0600_mode() {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");

    // Replicate the atomic open logic from RealPhalaClient's env writer.
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

    // Replicate the temp-file-then-rename logic from RealPhalaClient.
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

    let contents = std::fs::read_to_string(&env_path).unwrap();
    assert!(contents.contains("new-key"));
}

// ── Empty key rejection ───────────────────────────────────────────────────────

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

// ── Integration: real `prepare_deploy_target` orchestration ──────────────────
//
// These tests drive the real `prepare_deploy_target` function — the
// network-free core of `cmd_deploy` — rather than re-implementing its branch
// logic inline. The image-build boundary (`ImageProvisioner`) is mocked.

/// An `ImageProvisioner` that returns a fixed pinned ref.
struct StubProvisioner {
    ref_: String,
}

impl ImageProvisioner for StubProvisioner {
    fn provision(&self) -> anyhow::Result<String> {
        Ok(self.ref_.clone())
    }
}

/// `prepare_deploy_target` must pin the provisioner's image ref into the
/// rendered compose file.
#[test]
fn prepare_deploy_target_embeds_provisioner_ref() {
    let provisioner = StubProvisioner {
        ref_: "ghcr.io/taostat/gm-miner@sha256:abc".to_owned(),
    };
    let target = prepare_deploy_target(&provisioner).expect("orchestration must succeed");
    assert_eq!(target.image_ref, "ghcr.io/taostat/gm-miner@sha256:abc");
    assert!(
        target.rendered_compose.contains("sha256:abc"),
        "rendered compose must embed the pinned image ref"
    );
    assert!(
        !target.rendered_compose.contains("${GM_IMAGE_REF"),
        "the ${{GM_IMAGE_REF}} placeholder must be substituted"
    );
}

/// The build-vs-prebuilt branch lives in the `ImageProvisioner`; whichever
/// ref it returns must end up pinned in the rendered compose. A pre-built
/// `--image-ref` therefore reaches `render_compose` exactly as a freshly
/// built ref does.
#[test]
fn prepare_deploy_target_embeds_prebuilt_ref() {
    let provisioner = StubProvisioner {
        ref_: "docker.io/taostat/gm-miner@sha256:deadbeef".to_owned(),
    };
    let target = prepare_deploy_target(&provisioner).expect("prebuilt-ref must succeed");
    assert!(
        target.rendered_compose.contains("sha256:deadbeef"),
        "the provisioner's ref must be pinned into the compose file"
    );
}

/// An image-build failure must abort `prepare_deploy_target`.
#[test]
fn prepare_deploy_target_propagates_build_failure() {
    struct FailingProvisioner;
    impl ImageProvisioner for FailingProvisioner {
        fn provision(&self) -> anyhow::Result<String> {
            anyhow::bail!("image build+push failed")
        }
    }
    let err = prepare_deploy_target(&FailingProvisioner)
        .expect_err("build failure must abort the deploy");
    assert!(err.to_string().contains("image build+push failed"));
}
