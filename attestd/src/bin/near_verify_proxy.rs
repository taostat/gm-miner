use std::net::SocketAddr;
use std::process::ExitCode;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::routing::{any, get};
use axum::{Json, Router};
use gm_miner_attestd::near_verify::{error_response, NearVerifier, TARGETS};
use tracing::info;
use tracing_subscriber::EnvFilter;

const BIND_ADDR: &str = "127.0.0.1:8082";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "NEAR verification proxy failed");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("install rustls ring provider"))?;
    let verifier = NearVerifier::new()?;
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.iter().any(|argument| argument == "--verify-once") {
        let selected_model = option_value(&arguments, "--model")?;
        let connect_ip = option_value(&arguments, "--connect-ip")?
            .map(str::parse)
            .transpose()
            .context("parse --connect-ip")?;
        for target in TARGETS
            .into_iter()
            .filter(|target| selected_model.is_none_or(|model| target.model == model))
        {
            let result = match connect_ip {
                Some(ip) => verifier.preflight_at(target, ip).await,
                None => verifier.preflight(target).await,
            };
            result.with_context(|| {
                format!(
                    "verify NEAR endpoint {}{}",
                    target.host,
                    connect_ip.map_or_else(String::new, |ip| format!(" via {ip}"))
                )
            })?;
            info!(
                model = target.model,
                host = target.host,
                connect_ip = ?connect_ip,
                "NEAR endpoint attestation verified"
            );
        }
        if selected_model.is_some()
            && !TARGETS
                .iter()
                .any(|target| Some(target.model) == selected_model)
        {
            anyhow::bail!("--model is not in the compiled NEAR target allowlist");
        }
        return Ok(());
    }

    let address: SocketAddr = BIND_ADDR.parse().context("parse NEAR proxy bind address")?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .context("bind NEAR verification proxy")?;
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/models", get(models))
        .fallback(any(proxy))
        .with_state(verifier);
    info!(bind_addr = BIND_ADDR, "NEAR verification proxy listening");
    axum::serve(listener, app)
        .await
        .context("serve NEAR verification proxy")
}

fn option_value<'a>(arguments: &'a [String], option: &str) -> Result<Option<&'a str>> {
    let Some(index) = arguments.iter().position(|argument| argument == option) else {
        return Ok(None);
    };
    arguments
        .get(index + 1)
        .map(String::as_str)
        .map(Some)
        .with_context(|| format!("{option} requires a value"))
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn models() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "object": "list",
        "data": TARGETS.map(|target| serde_json::json!({
            "id": target.model,
            "object": "model",
            "owned_by": "near",
        })),
    }))
}

async fn proxy(State(verifier): State<NearVerifier>, request: Request<Body>) -> Response<Body> {
    verifier
        .forward(request)
        .await
        .unwrap_or_else(|error| error_response(&error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_capability_catalog_lists_every_closed_target() {
        let Json(catalog) = models().await;
        let expected = TARGETS
            .map(|target| {
                serde_json::json!({
                    "id": target.model,
                    "object": "model",
                    "owned_by": "near",
                })
            })
            .to_vec();
        assert_eq!(catalog["data"], serde_json::Value::Array(expected));
    }
}
