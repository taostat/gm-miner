//! Measured-hash normalization and verification against the registry
//! allow-list.

use anyhow::{bail, Result};

use crate::deploy::version::ImageVersion;

/// Result returned after a successful Phala Cloud deploy + status poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DstackDeployResult {
    /// Canonical compose hash measured by the CVM (RTMR3-derived). Read
    /// from `phala cvms get <app-id> --json`.
    pub compose_sha256: String,
    /// OS image hash reported for the CVM.
    pub os_image_hash: String,
}

/// Everything `gmcli deploy` needs back from a Phala Cloud deploy: the
/// CVM's measured hashes (verified against the registry allow-list) and
/// the CVM's public endpoint (sent to the registry on registration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployOutcome {
    /// Measured `compose_hash` + `os_image_hash` for the CVM.
    pub hashes: DstackDeployResult,
    /// The CVM's public RA-TLS data-plane endpoint — the dstack
    /// TLS-passthrough (`s`-suffix) form of `endpoints[0].app`, e.g.
    /// `https://<app-id>-8080s.dstack-<node>.phala.network`. Registered
    /// with the registry so the gateway connects to the URL on which
    /// the miner's RA-TLS certificate is actually presented.
    pub endpoint: String,
    /// The Phala Cloud `app_id` of the deployed CVM, read from the
    /// CVM-detail document. Persisted in the worker's `WorkerRecord` so
    /// `worker remove` can tell the operator which CVM to `phala cvms
    /// delete`.
    pub app_id: String,
}

/// Normalize a hash to the registry's canonical form: lowercase, with any
/// `sha256:` prefix stripped. Phala Cloud may report a hash uppercased or
/// `sha256:`-prefixed; the registry's `POST /miners/register` only accepts
/// `^[0-9a-f]{64}$`, so the hash must be normalized before it is both
/// verified and sent onward.
#[must_use]
pub fn normalize_hash(hash: &str) -> String {
    let lowered = hash.to_lowercase();
    match lowered.strip_prefix("sha256:") {
        Some(stripped) => stripped.to_owned(),
        None => lowered,
    }
}

/// Verify that the actual hashes from Phala Cloud match the
/// registry-approved version, returning the normalized actual hashes.
///
/// Both sides are normalized (lowercased, `sha256:` prefix stripped) before
/// comparison. The returned [`DstackDeployResult`] holds the normalized
/// values so the loud verification check and the subsequent registration
/// operate on the exact same hash.
///
/// # Errors
/// Returns a loud, actionable error if either hash does not match.
pub fn verify_hashes(
    actual: &DstackDeployResult,
    approved: &ImageVersion,
) -> Result<DstackDeployResult> {
    let normalized = DstackDeployResult {
        compose_sha256: normalize_hash(&actual.compose_sha256),
        os_image_hash: normalize_hash(&actual.os_image_hash),
    };
    let compose_match = normalized.compose_sha256 == normalize_hash(&approved.compose_hash);
    let os_match = normalized.os_image_hash == normalize_hash(&approved.os_image_hash);

    if compose_match && os_match {
        return Ok(normalized);
    }

    let mut msg = String::from("HASH MISMATCH — deployment is suspect; refusing to register.\n\n");

    if !compose_match {
        msg.push_str("  compose_hash\n    expected (registry): ");
        msg.push_str(&approved.compose_hash);
        msg.push_str("\n    actual (phala):      ");
        msg.push_str(&actual.compose_sha256);
        msg.push_str("\n\n");
    }
    if !os_match {
        msg.push_str("  os_image_hash\n    expected (registry): ");
        msg.push_str(&approved.os_image_hash);
        msg.push_str("\n    actual (phala):      ");
        msg.push_str(&actual.os_image_hash);
        msg.push_str("\n\n");
    }
    msg.push_str(
        "If you believe this is a legitimate new build, wait for the registry to \
         publish a new approved version and retry.",
    );

    bail!("{msg}");
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    fn approved(compose: &str, os: &str) -> ImageVersion {
        ImageVersion {
            compose_hash: compose.to_owned(),
            os_image_hash: os.to_owned(),
            status: "supported".to_owned(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_owned(),
            image_ref: None,
        }
    }

    #[test]
    fn verify_hashes_passes_on_match() {
        let actual = DstackDeployResult {
            compose_sha256: "abc123".to_string(),
            os_image_hash: "def456".to_string(),
        };
        let verified =
            verify_hashes(&actual, &approved("abc123", "def456")).expect("hashes should match");
        assert_eq!(verified.compose_sha256, "abc123");
        assert_eq!(verified.os_image_hash, "def456");
    }

    #[test]
    fn verify_hashes_case_insensitive() {
        let actual = DstackDeployResult {
            compose_sha256: "ABC123".to_string(),
            os_image_hash: "DEF456".to_string(),
        };
        let verified =
            verify_hashes(&actual, &approved("abc123", "def456")).expect("hashes should match");
        assert_eq!(verified.compose_sha256, "abc123");
        assert_eq!(verified.os_image_hash, "def456");
    }

    #[test]
    fn verify_hashes_strips_sha256_prefix() {
        // Phala Cloud may report a `sha256:`-prefixed or uppercased hash;
        // the registry only accepts bare lowercase hex. The returned hashes
        // must be normalized so registration uses the value that was
        // actually verified.
        let actual = DstackDeployResult {
            compose_sha256: "sha256:ABC123".to_string(),
            os_image_hash: "SHA256:DEF456".to_string(),
        };
        let verified =
            verify_hashes(&actual, &approved("abc123", "def456")).expect("hashes should match");
        assert_eq!(verified.compose_sha256, "abc123");
        assert_eq!(verified.os_image_hash, "def456");
    }

    #[test]
    fn normalize_hash_lowercases_and_strips_prefix() {
        assert_eq!(normalize_hash("ABCDEF"), "abcdef");
        assert_eq!(normalize_hash("sha256:ABCDEF"), "abcdef");
        assert_eq!(normalize_hash("SHA256:abcdef"), "abcdef");
        assert_eq!(normalize_hash("abcdef"), "abcdef");
    }

    #[test]
    fn verify_hashes_fails_on_compose_mismatch() {
        let actual = DstackDeployResult {
            compose_sha256: "WRONG".to_string(),
            os_image_hash: "def456".to_string(),
        };
        let err = verify_hashes(&actual, &approved("abc123", "def456")).unwrap_err();
        assert!(err.to_string().contains("compose_hash"));
        assert!(err.to_string().contains("HASH MISMATCH"));
    }

    #[test]
    fn verify_hashes_fails_on_os_mismatch() {
        let actual = DstackDeployResult {
            compose_sha256: "abc123".to_string(),
            os_image_hash: "WRONG".to_string(),
        };
        let err = verify_hashes(&actual, &approved("abc123", "def456")).unwrap_err();
        assert!(err.to_string().contains("os_image_hash"));
        assert!(err.to_string().contains("HASH MISMATCH"));
    }

    #[test]
    fn verify_hashes_fails_on_both_mismatch() {
        let actual = DstackDeployResult {
            compose_sha256: "W1".to_string(),
            os_image_hash: "W2".to_string(),
        };
        let err = verify_hashes(&actual, &approved("abc123", "def456")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("compose_hash"));
        assert!(msg.contains("os_image_hash"));
    }
}
