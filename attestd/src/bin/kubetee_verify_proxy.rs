use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::routing::{any, get};
use axum::Router;
use gm_miner_attestd::kubetee_verify::{
    error_response, KubeteeVerifier, BIND_ADDR, HOST_NAME, TARGETS,
};
use gm_miner_attestd::upstream_proxy::option_value;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "KubeTEE verification proxy failed");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("install rustls ring provider"))?;
    let verifier = Arc::new(KubeteeVerifier::new()?);
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.iter().any(|argument| argument == "--verify-once") {
        return verify_once(&verifier, option_value(&arguments, "--model")?).await;
    }
    let address: SocketAddr = BIND_ADDR
        .parse()
        .context("parse KubeTEE proxy bind address")?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .context("bind KubeTEE verification proxy")?;
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/models", get(models))
        .fallback(any(proxy))
        .with_state(verifier);
    info!(
        bind_addr = BIND_ADDR,
        "KubeTEE verification proxy listening"
    );
    axum::serve(listener, app)
        .await
        .context("serve KubeTEE verification proxy")
}

/// Attest `llm.kubetee.ai` once, sending no inference. The quote is per
/// host, not per model, so `--model` only checks the id is a compiled target.
async fn verify_once(verifier: &KubeteeVerifier, model: Option<&str>) -> Result<()> {
    if let Some(model) = model {
        anyhow::ensure!(
            TARGETS.contains(&model),
            "--model is not in the compiled KubeTEE target allowlist"
        );
    }
    let attested = verifier
        .preflight()
        .await
        .with_context(|| format!("verify KubeTEE endpoint {HOST_NAME}"))?;
    info!(
        host = HOST_NAME,
        peer = %attested.peer,
        pod = attested.pod,
        "KubeTEE endpoint attestation verified"
    );
    Ok(())
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn models(
    State(verifier): State<Arc<KubeteeVerifier>>,
    request: Request<Body>,
) -> Response<Body> {
    verifier
        .models(request)
        .await
        .unwrap_or_else(|error| error_response(&error))
}

async fn proxy(
    State(verifier): State<Arc<KubeteeVerifier>>,
    request: Request<Body>,
) -> Response<Body> {
    verifier
        .forward(request)
        .await
        .unwrap_or_else(|error| error_response(&error))
}
