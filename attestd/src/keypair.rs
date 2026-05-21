//! ed25519 keypair bootstrap, TEE-bound in production.
//!
//! The miner's attestation server holds one ed25519 keypair per
//! container instance. The pubkey is published in `GET /attestation/info`
//! and bound into the TDX quote's `report_data`; the registry verifies
//! that binding.
//!
//! In production the secret is derived from a dstack-KMS sealed key via
//! the guest agent's `get_key` endpoint (`/var/run/dstack.sock`). The
//! dstack-KMS releases the key only inside an attested CVM and only for
//! this `app_id` + `compose_hash`, so a container replacement (crash,
//! redeploy of the same image) regenerates the same key bytes.
//!
//! The signing key is held inside an `Arc<SigningKey>` and never
//! exposed as raw bytes through the public API. This mirrors the gm
//! gateway's `gateway/src/attestation/keypair.rs`.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use dstack_sdk::dstack_client::DstackClient;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::provider::AttestationError;

/// dstack `get_key` namespace for the miner attestation keypair.
const KEY_PATH: &str = "miner-attestation";

/// ed25519 keypair bootstrapped at attestation-server startup. Cheaply
/// cloneable — the secret is wrapped in an `Arc` so the bootstrap and
/// the request handler share a single allocation.
#[derive(Clone)]
pub struct SigningKeypair {
    inner: Arc<SigningKey>,
}

impl std::fmt::Debug for SigningKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the private key. The pubkey is safe.
        f.debug_struct("SigningKeypair")
            .field("pubkey_b64", &self.public_b64())
            .finish()
    }
}

impl SigningKeypair {
    /// Bootstrap the keypair from the dstack guest agent.
    ///
    /// Opens a connection to the dstack guest agent socket (default
    /// `/var/run/dstack.sock`, overridable via the `dstack_socket`
    /// parameter or the `DSTACK_SIMULATOR_ENDPOINT` env var). `get_key`
    /// returns a hex-encoded secret bound to `(app_id, compose_hash,
    /// path, purpose)`; the miner uses a single key per `miner_id`.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::DstackKey`] when the guest agent is
    /// unreachable, returns an error, hands back a key that is not
    /// valid hex, or returns fewer than 32 secret bytes. The caller
    /// fails fast — the container exits and the runtime restarts it.
    pub async fn bootstrap(
        miner_id: &str,
        dstack_socket: Option<&str>,
    ) -> Result<Self, AttestationError> {
        let client = DstackClient::new(dstack_socket);
        let response = client
            .get_key(Some(KEY_PATH.to_owned()), Some(miner_id.to_owned()))
            .await
            .map_err(|e| AttestationError::DstackKey(e.to_string()))?;
        let key_bytes = response
            .decode_key()
            .map_err(|e| AttestationError::DstackKey(format!("decode hex: {e}")))?;
        if key_bytes.len() < 32 {
            return Err(AttestationError::DstackKey(format!(
                "expected at least 32 secret bytes from dstack, got {}",
                key_bytes.len()
            )));
        }
        let secret: [u8; 32] = key_bytes[..32]
            .try_into()
            .map_err(|_| AttestationError::DstackKey("slice into 32 bytes".to_owned()))?;
        Ok(Self::from_secret_bytes(secret))
    }

    /// Construct a deterministic keypair from `miner_id` without a
    /// dstack call. Used only by tests and by `cargo build` paths that
    /// have no TDX socket; never reached on a deployed miner.
    #[must_use]
    pub fn deterministic(miner_id: &str) -> Self {
        let mut h = Sha256::new();
        h.update(b"gm-miner-attestd-test");
        h.update(miner_id.as_bytes());
        let secret: [u8; 32] = h.finalize().into();
        Self::from_secret_bytes(secret)
    }

    /// Construct from explicit 32 secret bytes.
    #[must_use]
    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        Self {
            inner: Arc::new(SigningKey::from_bytes(&secret)),
        }
    }

    /// Raw 32-byte ed25519 public key.
    #[must_use]
    pub fn public_bytes(&self) -> [u8; 32] {
        self.inner.verifying_key().to_bytes()
    }

    /// Base64 (STANDARD, not URL-safe) encoded public key. This is the
    /// `gateway_pubkey` field on the wire — the registry reads that key
    /// name verbatim (see the registry control loop's `attestation`
    /// checker), so the field name is shared with the gateway contract.
    #[must_use]
    pub fn public_b64(&self) -> String {
        BASE64_STANDARD.encode(self.public_bytes())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn deterministic_keypair_is_stable_per_miner_id() {
        let a = SigningKeypair::deterministic("miner-1");
        let b = SigningKeypair::deterministic("miner-1");
        assert_eq!(a.public_b64(), b.public_b64());
        assert_eq!(a.public_bytes(), b.public_bytes());
    }

    #[test]
    fn deterministic_keypair_distinct_per_miner_id() {
        let a = SigningKeypair::deterministic("miner-1");
        let b = SigningKeypair::deterministic("miner-2");
        assert_ne!(a.public_b64(), b.public_b64());
    }

    #[test]
    fn pubkey_is_32_bytes_b64() {
        let kp = SigningKeypair::deterministic("miner-1");
        let decoded = BASE64_STANDARD.decode(kp.public_b64()).unwrap();
        assert_eq!(decoded.len(), 32);
    }
}
