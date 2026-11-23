//! Run the bundled pre-launch script with isolated commands and environment.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "test fixture setup must succeed")]

use std::{os::unix::fs::PermissionsExt as _, process::Command};

const PRELAUNCH_SCRIPT: &str = include_str!("../../dstack/prelaunch.sh");

fn stub_commands(dir: &std::path::Path) {
    for (name, script) in [
        (
            "docker",
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"$TEST_DOCKER_CALLS\"\n\
             if [ \"$1\" = info ]; then exit 0; fi\n\
             if [ \"$1\" = login ]; then cat >/dev/null; fi\n\
             exit 0\n",
        ),
        ("dstack-util", "#!/bin/sh\nexit 0\n"),
        ("jq", "#!/bin/sh\nexit 0\n"),
        ("curl", "#!/bin/sh\nexit 0\n"),
    ] {
        let executable = dir.join(name);
        std::fs::write(&executable, script).expect("write command stub");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("make command stub executable");
    }
}

fn run_script(dir: &std::path::Path, credentials: bool) -> (std::process::Output, String) {
    let stubs = dir.join("bin");
    std::fs::create_dir(&stubs).expect("create stub directory");
    stub_commands(&stubs);
    let calls = dir.join("docker-calls");

    let mut command = Command::new("bash");
    command
        .args(["-e", "-u", "-o", "pipefail", "-c", PRELAUNCH_SCRIPT])
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", stubs.display()))
        .env("HOME", dir)
        .env("TEST_DOCKER_CALLS", &calls);
    if credentials {
        command
            .env("DSTACK_DOCKER_USERNAME", "miner-user")
            .env("DSTACK_DOCKER_PASSWORD", "miner-password")
            .env("DSTACK_DOCKER_REGISTRY", "docker.io");
    }

    let output = command.output().expect("run pre-launch script");
    let docker_calls = std::fs::read_to_string(calls).expect("read docker calls");
    (output, docker_calls)
}

#[test]
fn empty_environment_reaches_completion() {
    let dir = tempfile::tempdir().expect("isolated script environment");
    let (output, docker_calls) = run_script(dir.path(), false);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "script failed: {stdout}");
    assert!(stdout.contains("Script execution completed"), "{stdout}");
    assert!(docker_calls.contains("image prune -af"));
    assert!(docker_calls.contains("volume prune -f"));
}

#[test]
fn registry_credentials_reach_completion() {
    let dir = tempfile::tempdir().expect("isolated script environment");
    let (output, docker_calls) = run_script(dir.path(), true);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "script failed: {stdout}");
    assert!(stdout.contains("Script execution completed"), "{stdout}");
    assert!(docker_calls.contains("login -u miner-user --password-stdin docker.io"));
    assert!(docker_calls.contains("image prune -af"));
}
