//! gm miner capability check service.
//!
//! Exposes three authenticated endpoints, one per upstream provider:
//!   GET /capability/anthropic
//!   GET /capability/openai
//!   GET /capability/gemini
//!
//! Each endpoint verifies the corresponding env var is set, calls the
//! upstream's free `/models` (or equivalent) endpoint, and returns the
//! model list. The registry calls these on its 10-minute control-loop
//! cadence to decide whether a miner-product offer is currently eligible.
//!
//! Also exposes:
//!   GET /health   — unauthenticated liveness probe
//!   GET /metrics  — Prometheus text format (public read-only port)
//!
//! Contract: docs/contracts/miner-capability.md

#![forbid(unsafe_code)]

use gm_miner_capability::{metrics, routes};

use anyhow::Context;
use clap::Parser;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;

/// Capability check service arguments.
#[derive(Parser, Debug)]
#[command(
    name = "gm-miner-capability",
    about = "gm miner capability check service",
    version
)]
pub struct Args {
    /// Port for the capability / health endpoints (authenticated).
    #[arg(long, env = "CAPABILITY_PORT", default_value = "8443")]
    pub port: u16,

    /// Port for the Prometheus metrics endpoint (public, read-only).
    #[arg(long, env = "METRICS_PORT", default_value = "9090")]
    pub metrics_port: u16,

    /// Bearer token the registry presents. Derived from the `NodeSecret`
    /// rotation pattern (BLAKE2b-hashed). If unset, capability endpoints
    /// reject all requests with 401.
    #[arg(long, env = "CAPABILITY_BEARER_TOKEN")]
    pub bearer_token: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "gm_miner_capability=info,warn".into()),
        )
        .init();

    let args = Args::parse();

    // Shared metrics registry.
    let registry = metrics::build_registry();

    // Spawn the metrics server on its own port.
    let metrics_addr: SocketAddr = format!("0.0.0.0:{}", args.metrics_port).parse()?;
    let metrics_router = routes::metrics_router(registry.clone());
    let metrics_listener = TcpListener::bind(metrics_addr)
        .await
        .with_context(|| format!("bind metrics port {}", args.metrics_port))?;
    info!("metrics listening on {metrics_addr}");
    tokio::spawn(async move {
        #[expect(
            clippy::expect_used,
            reason = "metrics server runs for the process lifetime; failure is fatal"
        )]
        axum::serve(metrics_listener, metrics_router)
            .await
            .expect("metrics server error");
    });

    // Capability + health server.
    let cap_addr: SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let bearer = args.bearer_token.clone();
    let cap_router = routes::capability_router(bearer, registry);
    let cap_listener = TcpListener::bind(cap_addr)
        .await
        .with_context(|| format!("bind capability port {}", args.port))?;
    info!("capability service listening on {cap_addr}");

    axum::serve(cap_listener, cap_router).await?;
    Ok(())
}
