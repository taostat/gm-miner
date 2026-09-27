//! Plumbing shared by the verifiers that attest an upstream TLS connection
//! and then forward inference on it: connecting, bounded attestation
//! retries, header hygiene and the 502 every refusal becomes.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::body::{Body, Bytes};
use axum::http::header::{CONNECTION, TRANSFER_ENCODING, UPGRADE};
use axum::http::{HeaderMap, HeaderName, Response, StatusCode};
use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::{lookup_host, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;
use tracing::warn;

/// How many times an attestation is attempted before the request fails.
pub const ATTESTATION_ATTEMPTS: usize = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// One HTTP/1.1 connection over TLS to an upstream, with the leaf
/// certificate the server presented on it.
pub struct UpstreamConnection {
    pub sender: SendRequest<Body>,
    pub driver: JoinHandle<Result<(), hyper::Error>>,
    pub leaf: CertificateDer<'static>,
    pub peer: SocketAddr,
}

/// Open one TLS connection to `host` and start HTTP/1.1 on it.
///
/// `address` pins the TCP peer; without it `host` is resolved on port 443
/// and `attempt` rotates through the sorted addresses, so a retry reaches a
/// different peer when there is one. TLS SNI is always `host`.
///
/// # Errors
///
/// Returns an error when resolution, TCP, the TLS handshake or the HTTP/1.1
/// handshake fails, or the server presents no certificate.
pub async fn connect(
    tls: &TlsConnector,
    provider: &str,
    host: &str,
    address: Option<SocketAddr>,
    attempt: usize,
) -> Result<UpstreamConnection> {
    let address = if let Some(address) = address {
        address
    } else {
        let mut addresses = lookup_host((host, 443))
            .await
            .with_context(|| format!("resolve {host}"))?
            .collect::<Vec<_>>();
        addresses.sort_unstable();
        addresses.dedup();
        *addresses
            .get(attempt % addresses.len().max(1))
            .with_context(|| format!("{host} resolved to no addresses"))?
    };
    let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .with_context(|| format!("{provider} TCP connect timed out"))?
        .with_context(|| format!("connect to {host} via {address}"))?;
    let peer = tcp
        .peer_addr()
        .with_context(|| format!("read {provider} peer address for {host}"))?;
    let server_name = ServerName::try_from(host.to_owned())
        .with_context(|| format!("invalid {provider} TLS server name"))?;
    let stream = timeout(CONNECT_TIMEOUT, tls.connect(server_name, tcp))
        .await
        .with_context(|| format!("{provider} TLS handshake timed out"))?
        .with_context(|| format!("complete {provider} TLS handshake"))?;
    let leaf = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .with_context(|| format!("{provider} TLS peer sent no certificate"))?
        .clone()
        .into_owned();
    let (sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .with_context(|| format!("start HTTP/1.1 over {provider} TLS"))?;
    Ok(UpstreamConnection {
        sender,
        driver: tokio::spawn(connection),
        leaf,
        peer,
    })
}

/// Run `operation` up to [`ATTESTATION_ATTEMPTS`] times with a short
/// backoff, returning the first success or every failure joined.
///
/// Only attestation (before any inference leaves) may be retried this way.
///
/// # Errors
///
/// Returns an error naming every attempt's failure when none succeeds.
pub async fn retry_attestation<T, Operation, Attempt>(
    provider: &str,
    mut operation: Operation,
) -> Result<T>
where
    Operation: FnMut() -> Attempt,
    Attempt: Future<Output = Result<T>>,
{
    let mut failures = Vec::with_capacity(ATTESTATION_ATTEMPTS);
    for attempt in 1..=ATTESTATION_ATTEMPTS {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                warn!(
                    provider,
                    attempt,
                    max_attempts = ATTESTATION_ATTEMPTS,
                    will_retry = attempt < ATTESTATION_ATTEMPTS,
                    error = %format!("{error:#}"),
                    "upstream attestation attempt failed"
                );
                failures.push(format!("attempt {attempt}: {error:#}"));
            }
        }
        if attempt < ATTESTATION_ATTEMPTS {
            sleep(Duration::from_millis(100 * attempt as u64)).await;
        }
    }
    bail!(
        "{provider} attestation failed after {ATTESTATION_ATTEMPTS} attempts: {}",
        failures.join("; ")
    )
}

/// Remove the connection-scoped headers a proxy must not forward.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for header in [
        &CONNECTION,
        &TRANSFER_ENCODING,
        &UPGRADE,
        &HeaderName::from_static("keep-alive"),
        &HeaderName::from_static("proxy-authenticate"),
        &HeaderName::from_static("proxy-authorization"),
    ] {
        headers.remove(header);
    }
}

/// Wait briefly for a connection whose sender was dropped to close.
///
/// # Errors
///
/// Returns an error when the connection task ended with an error.
pub async fn finish_connection(
    provider: &str,
    connection: JoinHandle<Result<(), hyper::Error>>,
) -> Result<()> {
    match timeout(Duration::from_secs(2), connection).await {
        Ok(joined) => joined
            .with_context(|| format!("join {provider} HTTP connection"))?
            .with_context(|| format!("{provider} HTTP connection")),
        Err(_) => Ok(()),
    }
}

/// The 502 a verifier answers with when it refuses a request. The body
/// names only the provider: it must never carry a provider-drain phrase
/// (see `image/envoy/README.md`).
pub fn error_response(provider: &str, error: &anyhow::Error) -> Response<Body> {
    warn!(provider, error = %format!("{error:#}"), "attestation proxy rejected request");
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"error": format!("{provider} upstream attestation failed")})
                .to_string(),
        ))
        .unwrap_or_else(|_| Response::new(Body::from(Bytes::new())))
}

/// The value following `option` on a command line, if the option is present.
///
/// # Errors
///
/// Returns an error when the option is the last argument.
pub fn option_value<'a>(arguments: &'a [String], option: &str) -> Result<Option<&'a str>> {
    let Some(index) = arguments.iter().position(|argument| argument == option) else {
        return Ok(None);
    };
    arguments
        .get(index + 1)
        .map(String::as_str)
        .map(Some)
        .with_context(|| format!("{option} requires a value"))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test values are known to be valid")]
mod tests {
    use super::*;

    #[test]
    fn option_value_requires_a_following_argument() {
        let arguments = vec!["--model".to_owned()];
        assert!(option_value(&arguments, "--model").is_err());
        assert_eq!(option_value(&arguments, "--other").unwrap(), None);
    }
}
