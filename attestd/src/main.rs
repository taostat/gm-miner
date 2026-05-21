//! gm miner attestation server binary.
//!
//! Bootstraps a TEE-bound ed25519 keypair from the dstack guest agent,
//! then serves `GET /attestation/info` on a loopback address. Envoy
//! (the miner's data plane) routes that single path here; the registry
//! probes it through Envoy's public `:8080` port.
//!
//! Configuration (environment):
//!
//! * `GM_MINER_ID` — identity slug, lowercase alphanumeric + hyphens,
//!   <=64 chars. Default `gm-miner`.
//! * `GM_ATTESTD_BIND_ADDR` — bind address. Default `127.0.0.1:8081`.
//! * `DSTACK_SOCKET` — dstack guest agent socket override. Default
//!   `/var/run/dstack.sock` (handled by the SDK).
//!
//! A failure to reach dstack at startup is fatal: the process exits
//! non-zero and the container runtime restarts it, the same fail-fast
//! posture the gm gateway uses.

#![forbid(unsafe_code)]

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use axum::routing::get;
use axum::Router;
use gm_miner_attestd::info::AppState;
use gm_miner_attestd::{attestation_info, DstackAttestationProvider, SigningKeypair};

/// Default identity slug when `GM_MINER_ID` is unset.
const DEFAULT_MINER_ID: &str = "gm-miner";
/// Default bind address. Loopback only — Envoy reaches it in-container;
/// nothing external should hit the attestation server directly.
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8081";

#[tokio::main]
async fn main() -> Result<()> {
    // Log to stderr, not stdout: the container entrypoint (start.sh)
    // also logs to stderr, so a single stream keeps attestd's and the
    // entrypoint's lines correctly interleaved in `phala cvms logs`,
    // and an anyhow fatal-error printout (also stderr) lands in order.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let miner_id = std::env::var("GM_MINER_ID").unwrap_or_else(|_| DEFAULT_MINER_ID.to_owned());
    validate_miner_id(&miner_id)?;
    let bind_addr =
        std::env::var("GM_ATTESTD_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_owned());
    let dstack_socket = std::env::var("DSTACK_SOCKET").ok();
    tracing::info!(
        miner_id = %miner_id,
        bind_addr = %bind_addr,
        dstack_socket = dstack_socket.as_deref().unwrap_or("<sdk default>"),
        "attestd starting",
    );

    // TEE-bound signing keypair. Derived from the dstack-KMS sealed key;
    // a redeploy of the same image yields the same pubkey. Each dstack
    // step is logged before it runs so a hang or a kill mid-bootstrap
    // is visible in the container log.
    tracing::info!("bootstrapping attestation keypair from dstack get_key");
    let keypair = SigningKeypair::bootstrap(&miner_id, dstack_socket.as_deref())
        .await
        .context("bootstrap miner attestation keypair from dstack")?;
    tracing::info!(
        miner_pubkey = %keypair.public_b64(),
        "attestation keypair bootstrapped",
    );

    // Fetch the static CVM attestation fields once at startup.
    tracing::info!("fetching static CVM fields from dstack info");
    let provider: AppState = Arc::new(
        DstackAttestationProvider::bootstrap(miner_id.clone(), keypair, dstack_socket)
            .await
            .context("bootstrap dstack attestation provider")?,
    );

    let app = Router::new()
        .route("/attestation/info", get(attestation_info))
        .with_state(provider);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("bind attestation server to {bind_addr}"))?;
    tracing::info!(bind_addr = %bind_addr, "miner attestation server listening");
    axum::serve(listener, app)
        .await
        .context("attestation server terminated")?;
    Ok(())
}

/// Validate the miner identity slug: lowercase alphanumeric + hyphens,
/// non-empty, <=64 chars. Mirrors the gm gateway's `gateway_id` rule so
/// the shared `AttestationInfo` shape carries a consistent identifier.
fn validate_miner_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("GM_MINER_ID must not be empty");
    }
    if id.len() > 64 {
        bail!("GM_MINER_ID must be <=64 characters, got {}", id.len());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("GM_MINER_ID must be lowercase alphanumeric or hyphens: {id:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn rejects_empty_miner_id() {
        assert!(validate_miner_id("").is_err());
    }

    #[test]
    fn rejects_uppercase_miner_id() {
        assert!(validate_miner_id("GM-Miner-1").is_err());
    }

    #[test]
    fn rejects_overlong_miner_id() {
        assert!(validate_miner_id(&"a".repeat(65)).is_err());
    }

    #[test]
    fn accepts_canonical_miner_id() {
        assert!(validate_miner_id("gm-testnet-miner").is_ok());
    }
}
