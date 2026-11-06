//! Verify an unsupported Phala CLI stops deploy before authentication.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "test fixture setup must succeed")]

use std::{os::unix::fs::PermissionsExt as _, process::Command};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

async fn registry_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kms-roots"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "roots": [{
                "kms_contract_id": "registry-default",
                "is_default": true,
                "allowed_until": null
            }]
        })))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn outdated_phala_cli_stops_deploy_before_authentication() {
    let dir = tempfile::tempdir().expect("isolated config and executable directory");
    let server = registry_server().await;
    let executable = dir.path().join("phala");
    let calls = dir.path().join("calls");
    std::fs::write(
        &executable,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$TEST_PHALA_CALLS\"\n\
         if [ \"$1\" = \"--version\" ]; then printf 'v1.1.18\\n'; exit 0; fi\n\
         exit 1\n",
    )
    .expect("write stub phala");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("make stub executable");

    let output = Command::new(env!("CARGO_BIN_EXE_gmcli"))
        .args(["deploy", "--api-url", &server.uri()])
        .env_clear()
        .env("PATH", dir.path())
        .env("GMCLI_CONFIG_DIR", dir.path())
        .env("TEST_PHALA_CALLS", &calls)
        .output()
        .expect("run deploy with an outdated Phala CLI");

    assert!(!output.status.success(), "an outdated CLI must stop deploy");
    let calls = std::fs::read_to_string(calls).expect("read Phala calls");
    assert_eq!(calls.lines().collect::<Vec<_>>(), ["--version"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("1.1.19"),
        "must explain the minimum: {stderr}"
    );
    assert!(
        stderr.contains("v1.1.18"),
        "must include the observed phala --version output: {stderr}"
    );
    assert!(
        stderr.contains("npm install -g phala"),
        "must use the dependency install hint: {stderr}"
    );
}

#[tokio::test]
async fn phala_version_tempdir_failure_is_not_reported_as_missing_from_path() {
    let dir = tempfile::tempdir().expect("isolated config and executable directory");
    let server = registry_server().await;
    let missing_temp = dir.path().join("no-such-temp-directory");

    let output = Command::new(env!("CARGO_BIN_EXE_gmcli"))
        .args(["deploy", "--api-url", &server.uri()])
        .env_clear()
        .env("PATH", dir.path())
        .env("TMPDIR", &missing_temp)
        .env("GMCLI_CONFIG_DIR", dir.path())
        .output()
        .expect("run deploy with an unusable temp directory");

    assert!(!output.status.success(), "tempdir failure must stop deploy");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("create isolated working directory to check phala version"),
        "must report the temporary-directory error: {stderr}"
    );
    assert!(
        !stderr.contains("not found on PATH"),
        "must not describe a setup failure as a missing executable: {stderr}"
    );
}
