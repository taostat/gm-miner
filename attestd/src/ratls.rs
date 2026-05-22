//! RA-TLS data-plane certificate provisioning.
//!
//! The miner's Envoy data plane on `:8080` terminates TLS with a
//! certificate minted by **dstack's native RA-TLS facility** — the
//! guest agent's `GetTlsKey` RPC. This module is the thin container-
//! start bootstrap that calls that RPC and writes the resulting
//! key/cert PEM files to disk for Envoy's `DownstreamTlsContext`.
//!
//! # What dstack provides
//!
//! `DstackClient::get_tls_key(TlsKeyConfig { usage_ra_tls: true, .. })`
//! makes the guest agent, inside the CVM:
//!
//! 1. Generate a fresh P-256 key pair (random per call — not the
//!    KMS-sealed app key; an ephemeral data-plane key).
//! 2. Take a fresh Intel TDX quote whose `report_data` commits to that
//!    key: `report_data = SHA-512("ratls-cert:" || pubkey_der)` where
//!    `pubkey_der` is the cert's DER `SubjectPublicKeyInfo`.
//! 3. Issue an X.509 leaf certificate carrying the quote (and the CVM
//!    event log) in the dstack RA-TLS extension, OID
//!    `1.3.6.1.4.1.62397.1.8` (`PHALA_RATLS_ATTESTATION`).
//!
//! The RPC returns the PKCS#8 private key (PEM) and the certificate
//! chain (PEM, leaf first). No quote handling, no `report_data`
//! arithmetic and no X.509 minting happens in this process — the guest
//! agent owns the entire ceremony. We only place the files where Envoy
//! reads them.
//!
//! # What a verifier (the gateway) must check
//!
//! On connecting to the miner's `:8080` the gateway must, once per
//! connection:
//!
//! 1. Parse the leaf cert, read the `1.3.6.1.4.1.62397.1.8` extension,
//!    decode the dstack `VersionedAttestation` (which carries the TDX
//!    quote and event log).
//! 2. Verify the quote with `dcap-qvl` — the same audited path the
//!    registry control loop already uses.
//! 3. Recompute `SHA-512("ratls-cert:" || leaf_spki_der)` and check it
//!    equals the quote's `report_data`. This binds the TLS key to the
//!    quote: a stolen cert cannot be re-keyed.
//! 4. Replay the event log to RTMR3 and confirm the `compose_hash`
//!    maps to an approved `ImageVersion`.
//!
//! The dstack `ra-tls` crate's `attestation::from_der` performs steps
//! 1 and 3; `dcap-qvl` performs step 2.

use std::path::{Path, PathBuf};

use dstack_sdk::dstack_client::{DstackClient, TlsKeyConfig};
use thiserror::Error;
use tokio::fs;

/// `0o600` — owner read/write only. The RA-TLS private key is a
/// credential; the cert is public but kept beside the key with the
/// same restrictive mode for simplicity.
const KEY_FILE_MODE: u32 = 0o600;

/// Certificate subject Common Name. Informational only — the gateway
/// trusts the cert via the embedded quote, not via a CA or a hostname
/// match, so the CN carries the miner identity for human-readable
/// `openssl x509` inspection rather than for verification.
const CERT_SUBJECT_PREFIX: &str = "gm-miner-ratls";

/// Errors from RA-TLS certificate provisioning.
#[derive(Debug, Error)]
pub enum RatlsError {
    /// The dstack guest agent's `GetTlsKey` RPC failed or was
    /// unreachable.
    #[error("dstack get_tls_key failed: {0}")]
    DstackTlsKey(String),
    /// The guest agent returned an empty certificate chain — it cannot
    /// be used as a TLS leaf.
    #[error("dstack get_tls_key returned an empty certificate chain")]
    EmptyCertChain,
    /// Writing a PEM artifact to disk failed.
    #[error("write {path}: {source}")]
    Write {
        /// The artifact path the write targeted.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
}

/// Where the provisioned RA-TLS PEM artifacts are written. Envoy's
/// `DownstreamTlsContext` references these exact paths.
#[derive(Debug, Clone)]
pub struct RatlsPaths {
    /// PEM private key (PKCS#8) path.
    pub key: PathBuf,
    /// PEM certificate chain (leaf first) path.
    pub cert: PathBuf,
}

/// Mint the miner's data-plane RA-TLS certificate via dstack and write
/// the key/cert PEM files for Envoy.
///
/// Calls `DstackClient::get_tls_key` with `usage_ra_tls = true` and
/// `usage_server_auth = true` (the miner data plane is a TLS *server*),
/// then writes the returned private key and the joined certificate
/// chain to `paths`.
///
/// `miner_id` is folded into the certificate subject CN so a manual
/// `openssl x509 -in cert.pem -noout -subject` names the miner; it does
/// not affect the attestation binding.
///
/// # Errors
///
/// Returns [`RatlsError::DstackTlsKey`] when the guest agent is
/// unreachable or the RPC fails, [`RatlsError::EmptyCertChain`] when
/// the chain comes back empty, and [`RatlsError::Write`] when a PEM
/// artifact cannot be written. The caller fails fast — the container
/// exits and the runtime restarts it.
pub async fn provision(
    miner_id: &str,
    dstack_socket: Option<&str>,
    paths: &RatlsPaths,
) -> Result<(), RatlsError> {
    let client = DstackClient::new(dstack_socket);
    let config = TlsKeyConfig::builder()
        .subject(format!("{CERT_SUBJECT_PREFIX}/{miner_id}"))
        .usage_ra_tls(true)
        .usage_server_auth(true)
        .usage_client_auth(false)
        .build();
    let response = client
        .get_tls_key(config)
        .await
        .map_err(|e| RatlsError::DstackTlsKey(e.to_string()))?;

    if response.certificate_chain.is_empty() {
        return Err(RatlsError::EmptyCertChain);
    }
    // dstack returns each PEM block already newline-terminated; joining
    // with an empty separator yields a valid concatenated PEM bundle
    // (leaf first, then any intermediates) which Envoy accepts as a
    // certificate chain.
    let cert_pem = response.certificate_chain.join("");

    write_artifact(&paths.key, response.key.as_bytes()).await?;
    write_artifact(&paths.cert, cert_pem.as_bytes()).await?;
    Ok(())
}

/// Write a PEM artifact with `0o600` permissions, creating the parent
/// directory if needed.
async fn write_artifact(path: &Path, contents: &[u8]) -> Result<(), RatlsError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .await
                .map_err(|source| RatlsError::Write {
                    path: parent.to_path_buf(),
                    source,
                })?;
        }
    }
    fs::write(path, contents)
        .await
        .map_err(|source| RatlsError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    set_mode(path, KEY_FILE_MODE).await
}

/// Restrict a written artifact to `mode`.
#[cfg(unix)]
async fn set_mode(path: &Path, mode: u32) -> Result<(), RatlsError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .await
        .map_err(|source| RatlsError::Write {
            path: path.to_path_buf(),
            source,
        })
}

/// Non-Unix builds (developer machines) skip the `chmod`; the miner
/// only ever runs on the Linux CVM image.
#[cfg(not(unix))]
async fn set_mode(_path: &Path, _mode: u32) -> Result<(), RatlsError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[tokio::test]
    async fn write_artifact_creates_parent_and_restricts_mode() {
        let dir = std::env::temp_dir().join(format!("gm-ratls-test-{}", std::process::id()));
        let path = dir.join("nested").join("key.pem");
        write_artifact(&path, b"-----BEGIN-----\n")
            .await
            .expect("write artifact");
        assert_eq!(fs::read(&path).await.unwrap(), b"-----BEGIN-----\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).await.unwrap().permissions().mode();
            assert_eq!(mode & 0o777, KEY_FILE_MODE);
        }
        fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn write_artifact_overwrites_existing() {
        let dir = std::env::temp_dir().join(format!("gm-ratls-ow-{}", std::process::id()));
        let path = dir.join("cert.pem");
        write_artifact(&path, b"first").await.expect("first write");
        write_artifact(&path, b"second")
            .await
            .expect("second write");
        assert_eq!(fs::read(&path).await.unwrap(), b"second");
        fs::remove_dir_all(&dir).await.ok();
    }
}
