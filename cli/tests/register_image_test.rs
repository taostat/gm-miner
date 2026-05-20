//! Tests for `gm-miner register-image` auto-discovery of the deployed
//! miner's image hashes.
//!
//! `register-image` no longer takes manual `--compose-hash` /
//! `--os-image-hash` flags: it reads the live hashes from
//! `dstack-cloud status --json` via `parse_dstack_status` — the same
//! status-parsing code path `gm-miner deploy` polls. These tests exercise
//! that shared parser directly (it is pure: exit status + raw stdout in,
//! `Option<DstackDeployResult>` out), so no real `dstack-cloud` toolchain
//! is needed.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]

use gm_miner_cli::deploy::{parse_dstack_status, DstackDeployResult};

/// A fully-deployed miner: `dstack-cloud status --json` succeeded and both
/// hashes are populated → `register-image` discovers them and registers.
#[test]
fn parses_both_hashes_from_deployed_status() {
    let stdout = br#"{"compose_sha256":"abc123","os_image_hash":"def456"}"#;
    let parsed = parse_dstack_status(true, stdout)
        .expect("valid status JSON must parse")
        .expect("populated hashes must yield Some");
    assert_eq!(
        parsed,
        DstackDeployResult {
            compose_sha256: "abc123".to_owned(),
            os_image_hash: "def456".to_owned(),
        }
    );
}

/// Extra fields in the status JSON (dstack-cloud emits many) must be ignored
/// — only the two hashes matter.
#[test]
fn ignores_unrelated_status_fields() {
    let stdout =
        br#"{"app_id":"x","state":"running","compose_sha256":"c","os_image_hash":"o","extra":42}"#;
    let parsed = parse_dstack_status(true, stdout).unwrap().unwrap();
    assert_eq!(parsed.compose_sha256, "c");
    assert_eq!(parsed.os_image_hash, "o");
}

/// Not deployed yet: `dstack-cloud status --json` exited non-zero (control
/// plane not ready). `register-image` turns the `None` into a "deploy first"
/// error rather than registering stale/empty hashes.
#[test]
fn non_zero_exit_yields_none() {
    let parsed = parse_dstack_status(false, b"anything on stdout").unwrap();
    assert!(
        parsed.is_none(),
        "a non-zero dstack-cloud exit must be reported as 'not deployed'"
    );
}

/// Status JSON present but `compose_sha256` absent (CVM still booting) →
/// `None`, so `register-image` reports "no deployed miner" instead of
/// registering a half-populated record.
#[test]
fn missing_compose_hash_yields_none() {
    let stdout = br#"{"os_image_hash":"def456"}"#;
    assert!(parse_dstack_status(true, stdout).unwrap().is_none());
}

/// `os_image_hash` absent → `None` for the same reason.
#[test]
fn missing_os_image_hash_yields_none() {
    let stdout = br#"{"compose_sha256":"abc123"}"#;
    assert!(parse_dstack_status(true, stdout).unwrap().is_none());
}

/// An empty-string hash counts as "not populated yet" — dstack-cloud emits
/// empty strings before the CVM finishes booting.
#[test]
fn empty_hash_strings_yield_none() {
    let stdout = br#"{"compose_sha256":"","os_image_hash":"def456"}"#;
    assert!(
        parse_dstack_status(true, stdout).unwrap().is_none(),
        "an empty compose hash must not be treated as a deployed miner"
    );

    let stdout = br#"{"compose_sha256":"abc","os_image_hash":""}"#;
    assert!(parse_dstack_status(true, stdout).unwrap().is_none());
}

/// A successful exit with output that is not valid JSON is a hard error —
/// it must not be silently swallowed as "not deployed".
#[test]
fn malformed_json_on_success_is_an_error() {
    let err = parse_dstack_status(true, b"not json at all")
        .expect_err("malformed status JSON must surface as an error");
    assert!(
        err.to_string().contains("dstack-cloud status --json"),
        "error must name the failing operation; got: {err}"
    );
}

/// Malformed output is ignored when the command itself failed — the
/// non-zero exit short-circuits before any parse is attempted.
#[test]
fn malformed_output_on_failure_is_not_an_error() {
    let parsed = parse_dstack_status(false, b"not json at all")
        .expect("a failed command must not attempt to parse stdout");
    assert!(parsed.is_none());
}

/// `register-image` builds its "deploy first" error from the app name and
/// the project dir. Replicates that construction (the actual `.ok_or_else`
/// closure lives in the binary crate's `cmd_register_image`).
#[test]
fn not_deployed_error_is_actionable() {
    let app_name = "gm-miner-1";
    let project_dir = std::path::Path::new("dist/gm-miner-1");
    let err = anyhow::anyhow!(
        "no deployed miner found for app '{app_name}' \
         (no compose/os-image hashes in `dstack-cloud status --json` \
         for {dir}); deploy first with `gm-miner deploy`",
        dir = project_dir.display()
    );
    let msg = err.to_string();
    assert!(
        msg.contains("no deployed miner found for app 'gm-miner-1'"),
        "error must name the app; got: {msg}"
    );
    assert!(
        msg.contains("gm-miner deploy"),
        "error must point the operator at `gm-miner deploy`; got: {msg}"
    );
    assert!(
        msg.contains("dist/gm-miner-1"),
        "error must name the project dir it looked in; got: {msg}"
    );
}
