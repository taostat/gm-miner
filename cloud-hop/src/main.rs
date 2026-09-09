//! Entrypoint for the loopback-only measured cloud model hop.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use gm_cloud_hop::{serve, CloudHopConfig};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

const BIND_ADDR: &str = "127.0.0.1:8083";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "cloud hop stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = CloudHopConfig::from_env()?;
    if std::env::args()
        .skip(1)
        .any(|arg| arg == "--validate-config")
    {
        tracing::info!(
            azure_models = config
                .azure_openai
                .as_ref()
                .map_or(0, gm_cloud_hop::DeploymentMap::len),
            foundry_models = config
                .foundry
                .as_ref()
                .map_or(0, gm_cloud_hop::DeploymentMap::len),
            max_request_bytes = config.max_request_bytes,
            "cloud hop configuration validated"
        );
        return Ok(());
    }
    if !config.has_enabled_provider() {
        return Err("cloud hop requires Azure OpenAI or Foundry to be selected".into());
    }
    let listener = TcpListener::bind(BIND_ADDR).await?;
    tracing::info!(
        bind_addr = BIND_ADDR,
        egress_addr = "127.0.0.1:8084",
        max_request_bytes = config.max_request_bytes,
        max_buffered_bytes = config.max_buffered_bytes,
        max_concurrency = config.max_concurrency,
        timeout = ?config.timeout,
        "cloud hop listening"
    );
    serve(listener, config).await?;
    Ok(())
}
