//! Compute the 64-byte `report_data` value bound into the TDX quote.
//!
//! Per `gm/docs/contracts/gateway-attestation-info.md`:
//! `report_data = SHA-512(pubkey || caller_nonce)`.
//!
//! TDX `report_data` is exactly 64 bytes; SHA-512 fits naturally. The
//! gm registry's verifier (`registry/src/gm_registry/attestation/`)
//! recomputes the same hash and verifies it against the value embedded
//! in the quote. The gm gateway's attestation surface uses the
//! identical helper — the two services stay byte-for-byte consistent.

use sha2::{Digest, Sha512};

/// Compute `report_data = SHA-512(pubkey_bytes || nonce_bytes)`. Both
/// sides are decoded from base64 by callers; this helper takes raw
/// bytes so the encoding dance is not re-implemented per call site.
#[must_use]
pub fn compute_report_data(pubkey_bytes: &[u8], nonce_bytes: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(pubkey_bytes);
    hasher.update(nonce_bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine;

    #[test]
    fn report_data_is_64_bytes() {
        let out = compute_report_data(&[1u8; 32], &[2u8; 32]);
        assert_eq!(out.len(), 64);
    }

    #[test]
    fn report_data_changes_with_nonce() {
        let pk = [7u8; 32];
        let a = compute_report_data(&pk, b"nonce-a");
        let b = compute_report_data(&pk, b"nonce-b");
        assert_ne!(a, b);
    }

    #[test]
    fn report_data_changes_with_pubkey() {
        let nonce = [11u8; 32];
        let a = compute_report_data(&[1u8; 32], &nonce);
        let b = compute_report_data(&[2u8; 32], &nonce);
        assert_ne!(a, b);
    }

    #[test]
    fn report_data_matches_independent_sha512() {
        // Pin the binding algorithm by recomputing it independently with
        // the same crate. Catches drift if the helper ever changes
        // (e.g. someone swaps the hasher update order).
        let pubkey = [0x42u8; 32];
        let nonce = [0xAAu8; 32];
        let got = compute_report_data(&pubkey, &nonce);
        let mut h = Sha512::new();
        h.update(pubkey);
        h.update(nonce);
        let expected: [u8; 64] = h.finalize().into();
        assert_eq!(got, expected);
    }

    #[test]
    fn report_data_base64_roundtrip() {
        // Pin the wire encoding: base64 STANDARD (not base64url). The
        // 64-byte output encodes to exactly 88 base64 chars.
        let out = compute_report_data(&[5u8; 32], &[6u8; 32]);
        let encoded = BASE64_STANDARD.encode(out);
        assert_eq!(encoded.len(), 88);
        let decoded = BASE64_STANDARD.decode(&encoded).unwrap();
        assert_eq!(decoded.as_slice(), &out);
    }
}
