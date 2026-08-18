#![cfg(unix)]
#![expect(
    clippy::expect_used,
    reason = "integration tests intentionally fail hard on unexpected command output"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate must live under repo root")
        .to_owned()
}

fn executable(path: &Path, body: &str) {
    fs::write(path, body).expect("write mock executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .expect("make mock executable runnable");
}

fn run_start(
    preflight_exit: u8,
    runtime_exit: Option<u8>,
    envoy_exit: Option<u8>,
) -> (Output, PathBuf) {
    let temp = tempfile::tempdir().expect("temp runtime");
    let root = temp.keep();
    let bin = root.join("bin");
    let markers = root.join("markers");
    fs::create_dir_all(&bin).expect("create mock bin");
    fs::create_dir_all(&markers).expect("create marker dir");

    executable(&bin.join("gm-miner-ratls"), "#!/usr/bin/env bash\nexit 0\n");
    executable(
        &bin.join("gm-miner-attestd"),
        "#!/usr/bin/env bash\ntouch \"${GM_TEST_MARKERS}/attestd\"\nexec sleep 30\n",
    );
    executable(
        &bin.join("gm-near-verify-proxy"),
        r#"#!/usr/bin/env bash
if [[ "${1:-}" == "--verify-once" ]]; then
  touch "${GM_TEST_MARKERS}/near-preflight"
  exit "${GM_TEST_PREFLIGHT_EXIT}"
fi
touch "${GM_TEST_MARKERS}/near-runtime"
if [[ -n "${GM_TEST_RUNTIME_EXIT:-}" ]]; then
  exit "${GM_TEST_RUNTIME_EXIT}"
fi
exec sleep 30
"#,
    );
    executable(
        &bin.join("envoy"),
        r#"#!/usr/bin/env bash
touch "${GM_TEST_MARKERS}/envoy"
if [[ -n "${GM_TEST_ENVOY_EXIT:-}" ]]; then
  exit "${GM_TEST_ENVOY_EXIT}"
fi
exec sleep 30
"#,
    );

    let rendered = root.join("envoy.yaml");
    let mut command = Command::new("bash");
    command
        .arg(repo_root().join("image/start.sh"))
        .env_clear()
        .env("PATH", format!("{}:/bin:/usr/bin", bin.display()))
        .env("GM_TEST_MARKERS", &markers)
        .env("GM_TEST_PREFLIGHT_EXIT", preflight_exit.to_string())
        .env(
            "GM_ENVOY_TEMPLATE_PATH",
            repo_root().join("image/envoy.yaml"),
        )
        .env("GM_RENDERED_CONFIG", rendered)
        .env("GM_NETWORK", "testnet")
        .env("NEAR_API_KEY", "test-key");
    if let Some(exit) = runtime_exit {
        command.env("GM_TEST_RUNTIME_EXIT", exit.to_string());
    }
    if let Some(exit) = envoy_exit {
        command.env("GM_TEST_ENVOY_EXIT", exit.to_string());
    }
    let output = command.output().expect("run start.sh with mocked services");
    (output, markers)
}

#[test]
fn failed_near_readiness_prevents_every_serving_process() {
    let (output, markers) = run_start(42, None, None);
    assert_eq!(output.status.code(), Some(42));
    assert!(markers.join("near-preflight").exists());
    assert!(!markers.join("near-runtime").exists());
    assert!(!markers.join("attestd").exists());
    assert!(!markers.join("envoy").exists());
}

#[test]
fn envoy_starts_only_after_near_readiness_and_runtime_start() {
    let (output, markers) = run_start(0, None, Some(17));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(17), "{stderr}");
    assert!(markers.join("near-preflight").exists());
    assert!(markers.join("near-runtime").exists());
    assert!(markers.join("attestd").exists());
    assert!(markers.join("envoy").exists());
}

#[test]
fn near_proxy_exit_brings_down_the_container() {
    let (output, markers) = run_start(0, Some(23), None);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(23), "{stderr}");
    assert!(markers.join("near-runtime").exists());
    assert!(
        stderr.contains("NEAR verification proxy exited"),
        "{stderr}"
    );
}
