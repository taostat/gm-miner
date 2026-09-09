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

fn cloud_start(fail_before_ready: bool) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root");
    let temp = tempfile::tempdir().expect("runtime fixture");
    let bin = temp.path().join("bin");
    fs::create_dir(&bin).expect("bin directory");
    executable(&bin.join("gm-miner-ratls"), "#!/bin/bash\nexit 0\n");
    executable(
        &bin.join("gm-miner-attestd"),
        r#"#!/bin/bash
if [[ "${1:-}" == "--verify-azure-once" ]]; then exit 0; fi
if [[ "${1:-}" == "--check-ready" ]]; then
  [[ -e "${MARKERS}/ready" ]]
  exit $?
fi
sleep 0.3
if [[ "${FAIL_READY}" == 1 ]]; then exit 23; fi
touch "${MARKERS}/ready"
for ((attempt = 0; attempt < 100; attempt++)); do
  if [[ -e "${MARKERS}/gm-cloud-hop" && -e "${MARKERS}/envoy" ]]; then exit 23; fi
  sleep 0.1
done
exit 24
"#,
    );
    for service in ["gm-cloud-hop", "envoy"] {
        executable(
            &bin.join(service),
            r#"#!/bin/bash
if [[ "${1:-}" == "--validate-config" ]]; then exit 0; fi
if [[ ! -e "${MARKERS}/ready" ]]; then touch "${MARKERS}/early"; fi
touch "${MARKERS}/${0##*/}"
trap 'touch "${MARKERS}/${0##*/}-stopped"; exit 0' TERM
while true; do sleep 0.1; done
"#,
        );
    }
    let output = Command::new("bash")
        .arg(root.join("image/start.sh"))
        .env_clear()
        .env("PATH", format!("{}:/bin:/usr/bin", bin.display()))
        .env("MARKERS", temp.path())
        .env("FAIL_READY", if fail_before_ready { "1" } else { "0" })
        .env("GM_NETWORK", "testnet")
        .env("GM_ENVOY_TEMPLATE_PATH", root.join("image/envoy.yaml"))
        .env("GM_RENDERED_CONFIG", temp.path().join("envoy.yaml"))
        .env("GMCLI_BIN", env!("CARGO_BIN_EXE_gmcli"))
        .env("GM_NODE_SECRET", "test-node-secret-0001")
        .env("OPENAI_UPSTREAM", "azure")
        .env("AZURE_OPENAI_ENDPOINT", "https://acct.openai.azure.com")
        .env("AZURE_OPENAI_API_KEY", "azure-key")
        .env("AZURE_OPENAI_DEPLOYMENTS", "gpt-5.5=azure-gpt55")
        .output()
        .expect("run entrypoint with stub services");
    assert!(
        !output.status.success(),
        "attestd exit must stop entrypoint"
    );
    assert!(
        !temp.path().join("early").exists(),
        "data plane started before readiness"
    );
    for service in ["gm-cloud-hop", "envoy"] {
        assert_eq!(
            temp.path().join(service).exists(),
            !fail_before_ready,
            "{service}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if !fail_before_ready {
            assert!(
                temp.path().join(format!("{service}-stopped")).exists(),
                "{service} must die with attestd"
            );
        }
    }
}

#[test]
fn cloud_data_plane_waits_for_serving_gate_and_dies_with_attestd() {
    cloud_start(false);
}

#[test]
fn failed_serving_gate_never_starts_cloud_data_plane() {
    cloud_start(true);
}
