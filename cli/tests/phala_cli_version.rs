//! Verify an unsupported Phala CLI stops deploy before authentication.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "test fixture setup must succeed")]

use std::{os::unix::fs::PermissionsExt as _, process::Command};

#[test]
fn outdated_phala_cli_stops_deploy_before_authentication() {
    let dir = tempfile::tempdir().expect("isolated config and executable directory");
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
        .args(["deploy"])
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
        stderr.contains("npm install -g phala"),
        "must use the dependency install hint: {stderr}"
    );
}

#[test]
fn temp_directory_failure_is_not_reported_as_missing_phala() {
    let dir = tempfile::tempdir().expect("isolated config and executable directory");
    let executable = dir.path().join("phala");
    std::fs::write(&executable, "#!/bin/sh\nprintf 'v1.1.19\\n'\n").expect("write stub phala");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("make stub executable");

    let output = Command::new(env!("CARGO_BIN_EXE_gmcli"))
        .args(["deploy"])
        .env_clear()
        .env("PATH", dir.path())
        .env("GMCLI_CONFIG_DIR", dir.path())
        .env("TMPDIR", dir.path().join("missing-tmp"))
        .output()
        .expect("run deploy without a usable temporary directory");

    assert!(
        !output.status.success(),
        "deploy cannot check phala without a temp dir"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("temporary directory"),
        "must name the temp-directory failure: {stderr}"
    );
    assert!(
        !stderr.contains("not found on PATH") && !stderr.contains("is not installed"),
        "an installed phala must not be reported missing: {stderr}"
    );
}
