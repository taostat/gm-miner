//! gm miner RA-TLS certificate provisioner.
//!
//! A one-shot container-start step: mints the miner's data-plane TLS
//! certificate via dstack's native RA-TLS facility (the guest agent's
//! `GetTlsKey` RPC) and writes the key/cert PEM files Envoy's
//! `DownstreamTlsContext` references. `image/start.sh` runs this
//! before launching Envoy; on success it exits 0 and Envoy starts, on
//! failure it exits non-zero and the container restarts.
//!
//! The minted certificate carries a fresh Intel TDX quote in the
//! dstack RA-TLS extension (OID `1.3.6.1.4.1.62397.1.8`); the quote's
//! `report_data` commits to the certificate public key. The gateway
//! verifies that binding when it opens a TLS connection to the miner.
//! See `gm_miner_attestd::ratls` for the full format description.
//!
//! The output paths are fixed: Envoy's `image/envoy.yaml` hard-codes
//! `/tmp/gm-ratls/{cert,key}.pem`, and that config is part of the
//! attestation-measured image, so the paths are not operator-tunable —
//! they are a build-time contract between this binary and Envoy.
//!
//! Configuration (environment):
//!
//! * `GM_MINER_ID` — identity slug folded into the certificate
//!   subject CN. Default `gm-miner`.
//! * `DSTACK_SOCKET` — dstack guest agent socket override. Default is
//!   the SDK's socket-path search (`/var/run/dstack.sock` first).

#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::{Context, Result};
use gm_miner_attestd::{provision_ratls, validate_miner_id, RatlsPaths};

/// Default identity slug when `GM_MINER_ID` is unset. Matches the
/// attestation server's default so both name the miner identically.
const DEFAULT_MINER_ID: &str = "gm-miner";
/// PEM private-key output path. Must match `image/envoy.yaml`.
const KEY_PATH: &str = "/tmp/gm-ratls/key.pem";
/// PEM certificate-chain output path. Must match `image/envoy.yaml`.
const CERT_PATH: &str = "/tmp/gm-ratls/cert.pem";

#[tokio::main]
async fn main() -> Result<()> {
    // Log to stderr so the provisioner's lines interleave correctly
    // with start.sh's `[start]` lines in `phala cvms logs`.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let miner_id = std::env::var("GM_MINER_ID").unwrap_or_else(|_| DEFAULT_MINER_ID.to_owned());
    validate_miner_id(&miner_id).map_err(|e| anyhow::anyhow!(e))?;
    let paths = RatlsPaths {
        key: PathBuf::from(KEY_PATH),
        cert: PathBuf::from(CERT_PATH),
    };
    let dstack_socket = std::env::var("DSTACK_SOCKET").ok();

    tracing::info!(
        miner_id = %miner_id,
        key_path = KEY_PATH,
        cert_path = CERT_PATH,
        dstack_socket = dstack_socket.as_deref().unwrap_or("<sdk default>"),
        "minting data-plane RA-TLS cert via dstack get_tls_key",
    );
    provision_ratls(&miner_id, dstack_socket.as_deref(), &paths)
        .await
        .context("provision miner data-plane RA-TLS certificate from dstack")?;
    tracing::info!("RA-TLS certificate provisioned — Envoy can start");
    Ok(())
}
