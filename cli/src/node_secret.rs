//! Node-secret generation for the miner.
//!
//! Mechanism 1 of `docs/plans/attestation-and-identity.md`: the miner
//! sets a secret for its node, hands it to the registry at registration,
//! and bakes it into the container's env where envoy enforces it as the
//! `x-gm-node-key` header. The secret is generated once on the first
//! `gm-miner deploy` and persisted in the CLI config so re-deploys reuse
//! the same value.

use anyhow::{Context, Result};

use crate::config;

/// Length in bytes of the random material behind a node secret. 32 bytes
/// (256 bits) is well past any brute-force concern for a pre-shared
/// credential; hex-encoded it is a 64-character string.
const SECRET_BYTES: usize = 32;

/// Generate a fresh node secret: 32 random bytes, lowercase hex-encoded.
///
/// Reads the operating system CSPRNG directly (`/dev/urandom` on Unix) so
/// the CLI needs no extra crypto dependency. The 64-char hex string sits
/// inside the registry's `node_secret` length bounds (16–128).
///
/// # Errors
/// Returns an error if the OS random source cannot be read.
pub fn generate() -> Result<String> {
    let bytes = os_random_bytes()?;
    let mut hex = String::with_capacity(SECRET_BYTES * 2);
    for byte in bytes {
        // `write!` to a String is infallible; format the byte as two
        // lowercase hex digits.
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    Ok(hex)
}

#[cfg(unix)]
fn os_random_bytes() -> Result<[u8; SECRET_BYTES]> {
    use std::io::Read as _;

    let mut buf = [0u8; SECRET_BYTES];
    let mut urandom = std::fs::File::open("/dev/urandom").context("open /dev/urandom")?;
    urandom
        .read_exact(&mut buf)
        .context("read random bytes from /dev/urandom")?;
    Ok(buf)
}

#[cfg(not(unix))]
fn os_random_bytes() -> Result<[u8; SECRET_BYTES]> {
    anyhow::bail!("node-secret generation requires a Unix host (/dev/urandom)")
}

/// Resolve the node secret for `network` from the persisted CLI config,
/// or generate a fresh one and persist it under that network.
///
/// The secret is scoped per network (mainnet / testnet) so two
/// deployments from the same config get distinct values. It must be
/// stable across re-deploys — what envoy enforces, what the registry
/// stores, and what the gateway presents all have to agree — so it is
/// generated exactly once per network. `network` is the resolved active
/// network name (the caller passes the same value `load_config` uses, so
/// the secret lands under the network the deploy actually targets).
/// Returns `(secret, freshly_generated)` so the caller can report which
/// path ran.
///
/// # Errors
/// Returns an error if the config cannot be loaded, the OS random source
/// cannot be read, or the config cannot be saved.
pub fn resolve_persisted(network: &str) -> Result<(String, bool)> {
    let mut cfg = config::load().context("load gm-miner config")?;
    cfg.active_network = Some(network.to_owned());
    if let Some(existing) = cfg
        .active_network_entry()
        .and_then(|n| n.node_secret.as_deref())
    {
        if !existing.trim().is_empty() {
            return Ok((existing.to_owned(), false));
        }
    }
    let secret = generate().context("generate node secret")?;
    cfg.active_entry_mut().node_secret = Some(secret.clone());
    config::save(&cfg).context("persist node secret to gm-miner config")?;
    Ok((secret, true))
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_64_hex_chars() {
        let secret = generate().expect("generate node secret");
        assert_eq!(secret.len(), SECRET_BYTES * 2);
        assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(secret.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn generate_is_not_constant() {
        // Two consecutive draws must differ — a constant secret would be
        // a catastrophic failure of the CSPRNG read.
        let a = generate().expect("first secret");
        let b = generate().expect("second secret");
        assert_ne!(a, b);
    }
}
