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

use anyhow::{Context, Result};
use axum::routing::get;
use axum::Router;
use gm_miner_attestd::azure_verify;
use gm_miner_attestd::info::AppState;
use gm_miner_attestd::{
    attestation_info, validate_miner_id, DstackAttestationProvider, SigningKeypair,
};
use tokio::sync::oneshot;

/// Default identity slug when `GM_MINER_ID` is unset.
const DEFAULT_MINER_ID: &str = "gm-miner";
/// Default bind address. Loopback only — Envoy reaches it in-container;
/// nothing external should hit the attestation server directly.
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8081";
const VERIFY_AZURE_ONCE_ARG: &str = "--verify-azure-once";

/// True when either upstream selector routes through an Azure account whose
/// owner-capture controls `attestd` must verify before the data plane serves.
fn env_selects_azure() -> bool {
    let selected = |name: &str, value: &str| {
        std::env::var(name).unwrap_or_else(|_| "direct".to_owned()) == value
    };
    selected("OPENAI_UPSTREAM", "azure") || selected("ANTHROPIC_UPSTREAM", "foundry")
}

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

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args == [VERIFY_AZURE_ONCE_ARG] {
        tracing::info!("running one-shot Azure owner-capture verification");
        azure_verify::verify_azure_config_from_env()
            .await
            .context("Azure owner-capture verification failed")?;
        return Ok(());
    }
    if !args.is_empty() {
        anyhow::bail!("unknown argument(s): {}", args.join(" "));
    }

    let miner_id = std::env::var("GM_MINER_ID").unwrap_or_else(|_| DEFAULT_MINER_ID.to_owned());
    validate_miner_id(&miner_id).map_err(|e| anyhow::anyhow!(e))?;
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

    // Every Azure-backed upstream this worker routes through: Azure OpenAI
    // (`OPENAI_UPSTREAM=azure`) and Claude on Microsoft Foundry
    // (`ANTHROPIC_UPSTREAM=foundry`). Either may be configured, or both.
    let azure_upstream = env_selects_azure();
    if azure_upstream {
        tracing::info!("verifying Azure owner-capture controls");
        if let Err(err) = azure_verify::verify_azure_config_from_env().await {
            anyhow::bail!("Azure owner-capture verification failed: {err:#}");
        }
    }

    let app = Router::new()
        .route("/attestation/info", get(attestation_info))
        .with_state(provider);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("bind attestation server to {bind_addr}"))?;
    tracing::info!(bind_addr = %bind_addr, "miner attestation server listening");

    let (_periodic_azure_verify_task, azure_shutdown_rx) = if azure_upstream {
        let (fatal_shutdown_tx, fatal_shutdown_rx) = oneshot::channel();
        let task = azure_verify::spawn_periodic_azure_verification_from_env(fatal_shutdown_tx)
            .context("start periodic Azure owner-capture verification")?;
        (task, Some(fatal_shutdown_rx))
    } else {
        (None, None)
    };

    if let Some(azure_shutdown_rx) = azure_shutdown_rx {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let reason = azure_shutdown_rx.await.unwrap_or_else(|_| {
                    "periodic Azure owner-capture verification task ended".to_owned()
                });
                tracing::error!(
                    reason = %reason,
                    "stopping attestd after Azure owner-capture verification failure",
                );
            })
            .await
            .context("attestation server terminated")?;
        anyhow::bail!("attestd stopped after periodic Azure owner-capture verification failure");
    }

    axum::serve(listener, app)
        .await
        .context("attestation server terminated")?;
    Ok(())
}
