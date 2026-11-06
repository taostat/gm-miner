//! Verify Phala subprocesses cannot inherit a caller's project configuration.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "test fixture setup must succeed")]

use std::{os::unix::fs::PermissionsExt as _, path::PathBuf};

use gm_miner_cli::deploy::phala_command;

struct RestoreCurrentDir(PathBuf);

impl Drop for RestoreCurrentDir {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.0);
    }
}

#[test]
fn caller_phala_toml_is_not_visible_to_phala() {
    let original_dir = std::env::current_dir().expect("read original cwd");
    let caller_dir = tempfile::tempdir().expect("caller project directory");
    std::fs::write(
        caller_dir.path().join("phala.toml"),
        "id = 'existing-cvm'\n",
    )
    .expect("write caller Phala config");
    let bin_dir = tempfile::tempdir().expect("fake Phala executable directory");
    let executable = bin_dir.path().join("phala");
    std::fs::write(
        &executable,
        "#!/bin/sh\n[ ! -f phala.toml ] || exit 41\npwd\n",
    )
    .expect("write fake Phala executable");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("make fake Phala executable");

    let _restore = RestoreCurrentDir(original_dir);
    std::env::set_current_dir(caller_dir.path()).expect("use caller project directory");
    let mut command = phala_command(None).expect("create isolated Phala command");
    let phala_dir = PathBuf::from(
        command
            .get_current_dir()
            .expect("Phala command must have an explicit working directory"),
    )
    .canonicalize()
    .expect("canonicalize Phala working directory");
    assert_ne!(
        phala_dir,
        caller_dir
            .path()
            .canonicalize()
            .expect("canonicalize caller directory")
    );

    let output = command
        .env("PATH", bin_dir.path())
        .arg("--version")
        .output()
        .expect("spawn fake Phala CLI");
    assert!(
        output.status.success(),
        "caller phala.toml reached Phala: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        phala_dir.to_string_lossy().as_ref()
    );
}
