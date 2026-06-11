//! gm miner OAuth-subscription refresh sidecar binary.
//!
//! Bootstrap order:
//!
//! 1. Initialise tracing (stderr — same stream `attestd` and `start.sh`
//!    write to so `phala cvms logs` shows interleaved lines in order).
//! 2. Read sealed `GM_<PROVIDER>_OAUTH_*` env vars into the per-provider
//!    config bundle.
//! 3. Build the metrics registry and seed every enabled provider's
//!    series so the scrape never has missing entries.
//! 4. Build the in-memory token cache, seeded with the initial access
//!    token + expiry the operator pasted at deploy.
//! 5. Spawn one refresh worker per enabled provider.
//! 6. Bind the two HTTP listeners (token endpoint + metrics endpoint).
//! 7. Wait for SIGTERM, flip the cancellation token, give the workers
//!    a moment to drain, then exit.
//!
//! A sidecar with zero enabled providers stays up — Envoy will 503 on
//! every OAuth provider's route, the same as if the worker pool had
//! marked everything unhealthy.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use gm_miner_auth_sidecar::{
    config::SidecarConfig,
    metrics::Metrics,
    server::{build_metrics_router, build_token_router, MetricsAppState, TokenAppState},
    state::{ProviderState, StateRegistry},
    worker::{run_provider_worker, RetryPolicy},
};
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cfg = SidecarConfig::from_env().context("read sidecar env config")?;
    tracing::info!(
        enabled_providers = cfg.providers.len(),
        token_bind_addr = %cfg.token_bind_addr,
        metrics_bind_addr = %cfg.metrics_bind_addr,
        "gm-miner auth sidecar starting",
    );

    let metrics = Metrics::new().context("init prometheus metrics")?;
    metrics.touch_build_info();

    let mut states = Vec::with_capacity(cfg.providers.len());
    for p in &cfg.providers {
        states.push(ProviderState::new(
            p.provider,
            p.initial_access_token.clone(),
            p.initial_expires_at,
        ));
    }
    let registry = Arc::new(StateRegistry::from_states(states));

    let http_client = reqwest::Client::builder()
        // Cap the connection pool — only two providers, low traffic.
        .pool_max_idle_per_host(4)
        // Honour a per-request timeout in `refresh_once`; this is the
        // connect-level default.
        .connect_timeout(Duration::from_secs(10))
        .build()
        .context("build reqwest client")?;

    let cancel = CancellationToken::new();
    let policy = RetryPolicy::default();

    // Spawn one refresh task per enabled provider. Each task owns its
    // own state cell + a clone of the metrics registry.
    let mut worker_handles = Vec::new();
    for provider_cfg in &cfg.providers {
        let cell = registry
            .get(provider_cfg.provider)
            .context("state registry missing seeded provider")?
            .clone();
        let h = tokio::spawn(run_provider_worker(
            http_client.clone(),
            provider_cfg.provider,
            provider_cfg.refresh_token.clone(),
            cell,
            metrics.clone(),
            policy,
            cancel.clone(),
        ));
        worker_handles.push(h);
    }

    // Two HTTP servers — one per port.
    let token_listener = tokio::net::TcpListener::bind(&cfg.token_bind_addr)
        .await
        .with_context(|| format!("bind token endpoint to {}", cfg.token_bind_addr))?;
    let metrics_listener = tokio::net::TcpListener::bind(&cfg.metrics_bind_addr)
        .await
        .with_context(|| format!("bind metrics endpoint to {}", cfg.metrics_bind_addr))?;

    let token_app = build_token_router(TokenAppState {
        registry: registry.clone(),
    });
    let metrics_app = build_metrics_router(MetricsAppState {
        metrics: metrics.clone(),
    });

    let token_cancel = cancel.clone();
    let token_server = tokio::spawn(async move {
        let res = axum::serve(token_listener, token_app)
            .with_graceful_shutdown(async move { token_cancel.cancelled().await })
            .await;
        if let Err(e) = res {
            tracing::error!(error = %e, "token http server terminated");
        }
    });
    let metrics_cancel = cancel.clone();
    let metrics_server = tokio::spawn(async move {
        let res = axum::serve(metrics_listener, metrics_app)
            .with_graceful_shutdown(async move { metrics_cancel.cancelled().await })
            .await;
        if let Err(e) = res {
            tracing::error!(error = %e, "metrics http server terminated");
        }
    });

    tracing::info!("gm-miner auth sidecar listeners up");

    wait_for_shutdown_signal().await;
    tracing::info!("shutdown signal received; draining workers and HTTP servers");
    cancel.cancel();

    // Give workers up to 5s to wake from their sleeps. Envoy stops
    // forwarding well before we do (start.sh sends SIGTERM to envoy
    // first), so the sidecar can take its time.
    let drain = Duration::from_secs(5);
    let _ = tokio::time::timeout(drain, async {
        for h in worker_handles {
            let _ = h.await;
        }
    })
    .await;
    let _ = token_server.await;
    let _ = metrics_server.await;

    tracing::info!("gm-miner auth sidecar exited cleanly");
    Ok(())
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}

/// Wait for SIGTERM (the container runtime's stop signal) or SIGINT
/// (interactive ctrl-c, useful when debugging on a bare host).
async fn wait_for_shutdown_signal() {
    let term = signal(SignalKind::terminate());
    let int = signal(SignalKind::interrupt());
    match (term, int) {
        (Ok(mut term), Ok(mut int)) => {
            tokio::select! {
                _ = term.recv() => tracing::info!("SIGTERM received"),
                _ = int.recv() => tracing::info!("SIGINT received"),
            }
        }
        // If signal installation itself fails (rare — only on platforms
        // tokio's signal driver doesn't support), fall through to
        // letting tokio::signal::ctrl_c handle the wait.
        _ => {
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::error!(error = %e, "signal handler init failed; sleeping forever");
                std::future::pending::<()>().await;
            }
        }
    }
}
