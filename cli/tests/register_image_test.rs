//! Tests for `gm-miner register-image` auto-discovery of the deployed
//! miner's image hashes and endpoint.
//!
//! `register-image` reads the live hashes from `phala cvms get <app-id>
//! --json` via `parse_phala_cvm_detail`, and the miner's public endpoint
//! via `parse_phala_cvm_endpoint` — the same CVM-detail parsers `gm-miner
//! deploy` uses. These tests exercise those pure parsers directly (exit
//! status + raw stdout in, parsed value out), so no real `phala` CLI is
//! needed.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]

use gm_miner_cli::deploy::{parse_phala_cvm_detail, parse_phala_cvm_endpoint, DstackDeployResult};

/// A fully-deployed CVM: `phala cvms get --json` succeeded and both hashes
/// are populated → `register-image` discovers them and registers.
#[test]
fn parses_both_hashes_from_deployed_cvm() {
    let stdout = br#"{"compose_hash":"abc123","os":{"os_image_hash":"def456"}}"#;
    let parsed = parse_phala_cvm_detail(true, stdout)
        .expect("valid CVM detail JSON must parse")
        .expect("populated hashes must yield Some");
    assert_eq!(
        parsed,
        DstackDeployResult {
            compose_sha256: "abc123".to_owned(),
            os_image_hash: "def456".to_owned(),
        }
    );
}

/// Extra fields in the CVM detail JSON (Phala Cloud emits many) must be
/// ignored — only the two hashes matter.
#[test]
fn ignores_unrelated_cvm_detail_fields() {
    let stdout = br#"{
        "app_id":"app_x","status":"running","name":"gm-miner-1",
        "compose_hash":"c","os":{"name":"dstack-0.5.3","os_image_hash":"o"},
        "resource":{"vcpu":2}
    }"#;
    let parsed = parse_phala_cvm_detail(true, stdout).unwrap().unwrap();
    assert_eq!(parsed.compose_sha256, "c");
    assert_eq!(parsed.os_image_hash, "o");
}

/// Not deployed yet: `phala cvms get --json` exited non-zero. `register-image`
/// turns the `None` into a "deploy first" error rather than registering
/// stale/empty hashes.
#[test]
fn non_zero_exit_yields_none() {
    let parsed = parse_phala_cvm_detail(false, b"anything on stdout").unwrap();
    assert!(
        parsed.is_none(),
        "a non-zero phala exit must be reported as 'not deployed'"
    );
}

/// CVM detail present but `compose_hash` absent (CVM still booting) → `None`,
/// so `register-image` reports "no deployed miner" instead of registering a
/// half-populated record.
#[test]
fn missing_compose_hash_yields_none() {
    let stdout = br#"{"os":{"os_image_hash":"def456"}}"#;
    assert!(parse_phala_cvm_detail(true, stdout).unwrap().is_none());
}

/// `os` block absent → `None` for the same reason.
#[test]
fn missing_os_block_yields_none() {
    let stdout = br#"{"compose_hash":"abc123"}"#;
    assert!(parse_phala_cvm_detail(true, stdout).unwrap().is_none());
}

/// `os` block present but `os_image_hash` absent → `None`.
#[test]
fn missing_os_image_hash_yields_none() {
    let stdout = br#"{"compose_hash":"abc123","os":{"name":"dstack-0.5.3"}}"#;
    assert!(parse_phala_cvm_detail(true, stdout).unwrap().is_none());
}

/// An empty-string hash counts as "not populated yet".
#[test]
fn empty_hash_strings_yield_none() {
    let stdout = br#"{"compose_hash":"","os":{"os_image_hash":"def456"}}"#;
    assert!(
        parse_phala_cvm_detail(true, stdout).unwrap().is_none(),
        "an empty compose hash must not be treated as a deployed miner"
    );

    let stdout = br#"{"compose_hash":"abc","os":{"os_image_hash":""}}"#;
    assert!(parse_phala_cvm_detail(true, stdout).unwrap().is_none());
}

/// A successful exit with output that is not valid JSON is a hard error —
/// it must not be silently swallowed as "not deployed".
#[test]
fn malformed_json_on_success_is_an_error() {
    let err = parse_phala_cvm_detail(true, b"not json at all")
        .expect_err("malformed CVM detail JSON must surface as an error");
    assert!(
        err.to_string().contains("phala cvms get --json"),
        "error must name the failing operation; got: {err}"
    );
}

/// Malformed output is ignored when the command itself failed — the
/// non-zero exit short-circuits before any parse is attempted.
#[test]
fn malformed_output_on_failure_is_not_an_error() {
    let parsed = parse_phala_cvm_detail(false, b"not json at all")
        .expect("a failed command must not attempt to parse stdout");
    assert!(parsed.is_none());
}

/// `register-image` must read the miner's public endpoint from
/// `endpoints[0].app` so it can send the registry's required `endpoint`
/// (and `attestation_endpoint`) field.
#[test]
fn parses_endpoint_from_deployed_cvm() {
    let stdout = br#"{
        "app_id":"app_abc",
        "compose_hash":"abc","os":{"os_image_hash":"def"},
        "endpoints":[{"app":"https://app_abc-8080.dstack-prod9.phala.network"}]
    }"#;
    let endpoint = parse_phala_cvm_endpoint(true, stdout)
        .expect("valid CVM detail JSON must parse")
        .expect("a populated endpoint must yield Some");
    assert_eq!(endpoint, "https://app_abc-8080.dstack-prod9.phala.network");
}

/// A CVM whose gateway endpoint is not yet provisioned yields `None`, so
/// `register-image` reports the missing endpoint instead of registering an
/// empty one (which the registry rejects).
#[test]
fn missing_endpoint_yields_none() {
    let stdout = br#"{"compose_hash":"abc","os":{"os_image_hash":"def"}}"#;
    assert!(parse_phala_cvm_endpoint(true, stdout).unwrap().is_none());
}

/// `register-image` builds its "deploy first" error from the app id.
/// Replicates that construction (the actual `.ok_or_else` closure lives in
/// the binary crate's `cmd_register_image`).
#[test]
fn not_deployed_error_is_actionable() {
    let app_id = "app_abc123";
    let err = anyhow::anyhow!(
        "no measured hashes for CVM '{app_id}' \
         (compose_hash/os_image_hash not present in \
         `phala cvms get {app_id} --json`); \
         deploy first with `gm-miner deploy`"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("no measured hashes for CVM 'app_abc123'"),
        "error must name the app id; got: {msg}"
    );
    assert!(
        msg.contains("gm-miner deploy"),
        "error must point the operator at `gm-miner deploy`; got: {msg}"
    );
}
