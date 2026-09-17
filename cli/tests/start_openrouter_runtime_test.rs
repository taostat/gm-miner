#![cfg(unix)]
#![expect(clippy::expect_used, reason = "runtime fixtures fail on unexpected IO")]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

fn executable(path: &Path, body: &str) {
    fs::write(path, body).expect("write executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod");
}

fn entrypoint_command(root: &Path, markers: &Path) -> Command {
    let mut command = Command::new("bash");
    command
        .arg(root.join("image/start.sh"))
        .env_clear()
        .env(
            "PATH",
            format!("{}:/bin:/usr/bin", markers.join("bin").display()),
        )
        .env("MARKERS", markers)
        .env("GM_NETWORK", "testnet")
        .env("GM_ENVOY_TEMPLATE_PATH", root.join("image/envoy.yaml"))
        .env("GM_RENDERED_CONFIG", markers.join("envoy.yaml"))
        .env("GMCLI_BIN", env!("CARGO_BIN_EXE_gmcli"))
        .env("GM_NODE_SECRET", "test-node-secret-0001")
        .env("OPENROUTER_API_KEY", "sk-or-v1-test");
    command
}

fn fixture() -> (&'static Path, tempfile::TempDir) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root");
    let temp = tempfile::tempdir().expect("runtime fixture");
    fs::create_dir(temp.path().join("bin")).expect("bin directory");
    executable(
        &temp.path().join("bin/gm-miner-ratls"),
        "#!/bin/bash\nexit 0\n",
    );
    (root, temp)
}

/// An account that kept the canary prompt must not reach the render step, let
/// alone Envoy: the gate exists to keep buyer prompts off a logging account,
/// and a data plane that starts first has already forwarded one.
#[test]
fn a_retaining_account_never_renders_or_starts_the_data_plane() {
    let (root, temp) = fixture();
    executable(
        &temp.path().join("bin/gm-miner-attestd"),
        r#"#!/bin/bash
if [[ "${1:-}" == "--verify-openrouter-once" ]]; then
  touch "${MARKERS}/retention-gate"
  exit 19
fi
touch "${MARKERS}/attestd"
exec sleep 30
"#,
    );
    executable(
        &temp.path().join("bin/envoy"),
        "#!/bin/bash\ntouch \"${MARKERS}/envoy\"\nexit 0\n",
    );
    let output = entrypoint_command(root, temp.path())
        .output()
        .expect("run entrypoint with stub services");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(19), "{stderr}");
    assert!(
        temp.path().join("retention-gate").exists(),
        "the gate must run: {stderr}"
    );
    assert!(!temp.path().join("attestd").exists(), "{stderr}");
    assert!(!temp.path().join("envoy").exists(), "{stderr}");
    assert!(
        !temp.path().join("envoy.yaml").exists(),
        "the gate must fail closed before the config is rendered: {stderr}"
    );
}

/// The one-shot gate proves the account at startup; the serving attestd
/// re-proves it before it binds and keeps re-proving on a timer. Envoy waits
/// for that second proof, so a key that passes the one-shot and then fails on
/// the serving path still never carries buyer traffic.
#[test]
fn the_data_plane_waits_for_the_serving_retention_gate() {
    let (root, temp) = fixture();
    executable(
        &temp.path().join("bin/gm-miner-attestd"),
        r#"#!/bin/bash
if [[ "${1:-}" == "--verify-openrouter-once" ]]; then exit 0; fi
if [[ "${1:-}" == "--check-ready" ]]; then
  [[ -e "${MARKERS}/ready" ]]
  exit $?
fi
sleep 0.3
touch "${MARKERS}/ready"
for ((attempt = 0; attempt < 100; attempt++)); do
  if [[ -e "${MARKERS}/envoy" ]]; then exit 23; fi
  sleep 0.1
done
exit 24
"#,
    );
    executable(
        &temp.path().join("bin/envoy"),
        r#"#!/bin/bash
if [[ ! -e "${MARKERS}/ready" ]]; then touch "${MARKERS}/early"; fi
touch "${MARKERS}/envoy"
trap 'exit 0' TERM
while true; do sleep 0.1; done
"#,
    );
    let output = entrypoint_command(root, temp.path())
        .output()
        .expect("run entrypoint with stub services");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !temp.path().join("early").exists(),
        "data plane started before the serving gate answered ready: {stderr}"
    );
    assert!(
        temp.path().join("envoy").exists(),
        "a verified account must end up serving: {stderr}"
    );
}
