use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::body::{Body, Bytes};
use axum::http::header::{CONNECTION, HOST, TRANSFER_ENCODING, UPGRADE};
use axum::http::{HeaderMap, HeaderName, Method, Request, Response, StatusCode, Uri};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use dcap_qvl::collateral::CollateralClient;
use dcap_qvl::quote::Report;
use dcap_qvl::verify::VerifiedReport;
use http_body_util::{BodyExt as _, Limited};
use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use rand::RngCore as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tokio::net::{lookup_host, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;
use tracing::warn;
use x509_parser::parse_x509_certificate;

pub const SELECTOR_HEADER: &str = "x-gm-upstream-model";
const ATTESTATION_LIMIT: usize = 2 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const ATTESTATION_TIMEOUT: Duration = Duration::from_secs(120);
const NRAS_TIMEOUT: Duration = Duration::from_secs(60);
const NRAS_URL: &str = "https://nras.attestation.nvidia.com/v3/attest/gpu";
const ATTESTATION_ATTEMPTS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NearTarget {
    pub model: &'static str,
    pub host: &'static str,
}

pub const TARGETS: [NearTarget; 2] = [
    NearTarget {
        model: "zai-org/GLM-5.1-FP8",
        host: "glm-5-1.completions.near.ai",
    },
    NearTarget {
        model: "Qwen/Qwen3.6-27B-FP8",
        host: "qwen3-6-27b.completions.near.ai",
    },
];

#[must_use]
pub fn target_for_model(model: &str) -> Option<NearTarget> {
    TARGETS.iter().copied().find(|target| target.model == model)
}

#[derive(Debug, Deserialize)]
struct NearAttestation {
    model_name: String,
    signing_address: String,
    signing_algo: String,
    request_nonce: String,
    intel_quote: String,
    nvidia_payload: String,
    tls_cert_fingerprint: String,
    info: AttestationInfo,
}

#[derive(Debug, Deserialize)]
struct AttestationInfo {
    tcb_info: Value,
}

#[derive(Debug, Deserialize)]
struct AppCompose {
    docker_compose_file: String,
}

#[derive(Clone, Copy, Debug)]
struct AttestedFields<'a> {
    report_data: &'a [u8; 64],
    mr_config_id: &'a [u8; 48],
}

#[derive(Debug)]
struct AttestationOnlyServerVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}

impl AttestationOnlyServerVerifier {
    fn new() -> Self {
        Self {
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for AttestationOnlyServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[derive(Clone)]
pub struct NearVerifier {
    tls: TlsConnector,
    collateral: CollateralClient,
    nras: reqwest::Client,
}

impl fmt::Debug for NearVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NearVerifier")
            .finish_non_exhaustive()
    }
}

impl NearVerifier {
    /// Build the TLS, Intel collateral, and NVIDIA verification clients.
    ///
    /// # Errors
    ///
    /// Returns an error when a verification client cannot be configured.
    pub fn new() -> Result<Self> {
        let tls_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AttestationOnlyServerVerifier::new()))
            .with_no_client_auth();
        let nras = reqwest::Client::builder()
            .timeout(NRAS_TIMEOUT)
            .https_only(true)
            .build()
            .context("build NVIDIA attestation client")?;
        Ok(Self {
            tls: TlsConnector::from(Arc::new(tls_config)),
            collateral: CollateralClient::from_env().context("build DCAP collateral client")?,
            nras,
        })
    }

    /// Verify one configured endpoint without forwarding inference.
    ///
    /// # Errors
    ///
    /// Returns an error for any connection or attestation failure.
    pub async fn preflight(&self, target: NearTarget) -> Result<()> {
        let (sender, connection, _, _) = self.connect_and_attest(target).await?;
        drop(sender);
        finish_connection(connection).await
    }

    /// Verify one configured endpoint while pinning the TCP connection to an
    /// operator-selected IP. This is diagnostic-only: TLS SNI, HTTP Host, the
    /// model allowlist, and every attestation binding still use the compiled
    /// target identity.
    ///
    /// # Errors
    ///
    /// Returns an error for any connection or attestation failure.
    pub async fn preflight_at(&self, target: NearTarget, ip: IpAddr) -> Result<()> {
        let (sender, connection, _, _) = self.connect_and_attest_once(target, Some(ip), 0).await?;
        drop(sender);
        finish_connection(connection).await
    }

    /// Attest the selected endpoint and forward on that same TLS connection.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported requests or any attestation/upstream
    /// failure. No inference is sent when attestation fails.
    pub async fn forward(&self, request: Request<Body>) -> Result<Response<Body>> {
        validate_request(&request)?;
        let selector = request
            .headers()
            .get(SELECTOR_HEADER)
            .context("missing NEAR model selector")?
            .to_str()
            .context("NEAR model selector is not valid ASCII")?;
        let target = target_for_model(selector).context("unsupported NEAR model selector")?;
        let (mut sender, connection, _, _) = self.connect_and_attest(target).await?;

        let upstream_request = upstream_request(request, target)?;
        let response = timeout(ATTESTATION_TIMEOUT, sender.send_request(upstream_request))
            .await
            .context("NEAR inference timed out")?
            .context("send NEAR inference on attested TLS connection")?;
        let (parts, body) = response.into_parts();
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                warn!(%error, "NEAR upstream connection ended with an error");
            }
        });
        Ok(Response::from_parts(parts, Body::new(body)))
    }

    async fn connect_and_attest(
        &self,
        target: NearTarget,
    ) -> Result<(
        SendRequest<Body>,
        JoinHandle<Result<(), hyper::Error>>,
        [u8; 32],
        SocketAddr,
    )> {
        let mut attempt = 0;
        retry_attestation(|| {
            let current_attempt = attempt;
            attempt += 1;
            self.connect_and_attest_once(target, None, current_attempt)
        })
        .await
    }

    async fn connect_and_attest_once(
        &self,
        target: NearTarget,
        ip: Option<IpAddr>,
        attempt: usize,
    ) -> Result<(
        SendRequest<Body>,
        JoinHandle<Result<(), hyper::Error>>,
        [u8; 32],
        SocketAddr,
    )> {
        let (mut sender, connection, live_spki, peer) = self.connect(target, ip, attempt).await?;
        if let Err(error) = self.attest(&mut sender, target, &live_spki).await {
            connection.abort();
            return Err(error).with_context(|| format!("attest {} via {peer}", target.host));
        }
        Ok((sender, connection, live_spki, peer))
    }

    async fn connect(
        &self,
        target: NearTarget,
        ip: Option<IpAddr>,
        attempt: usize,
    ) -> Result<(
        SendRequest<Body>,
        JoinHandle<Result<(), hyper::Error>>,
        [u8; 32],
        SocketAddr,
    )> {
        let address = if let Some(ip) = ip {
            SocketAddr::new(ip, 443)
        } else {
            let mut addresses = lookup_host((target.host, 443))
                .await
                .with_context(|| format!("resolve {}", target.host))?
                .collect::<Vec<_>>();
            addresses.sort_unstable();
            addresses.dedup();
            *addresses
                .get(attempt % addresses.len().max(1))
                .with_context(|| format!("{} resolved to no addresses", target.host))?
        };
        let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
            .await
            .context("NEAR TCP connect timed out")?
            .with_context(|| format!("connect to {} via {address}", target.host))?;
        let peer = tcp
            .peer_addr()
            .with_context(|| format!("read NEAR peer address for {}", target.host))?;
        let server_name = ServerName::try_from(target.host)
            .context("invalid NEAR TLS server name")?
            .to_owned();
        let tls = timeout(CONNECT_TIMEOUT, self.tls.connect(server_name, tcp))
            .await
            .context("NEAR TLS handshake timed out")?
            .context("complete NEAR TLS handshake")?;
        let peer_certificate = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .context("NEAR TLS peer sent no certificate")?;
        let live_spki = spki_sha256(peer_certificate.as_ref())?;
        let (sender, connection) = http1::handshake(TokioIo::new(tls))
            .await
            .context("start HTTP/1.1 over NEAR TLS")?;
        let connection = tokio::spawn(connection);
        Ok((sender, connection, live_spki, peer))
    }

    async fn attest(
        &self,
        sender: &mut SendRequest<Body>,
        target: NearTarget,
        live_spki: &[u8; 32],
    ) -> Result<()> {
        let nonce = random_nonce();
        let uri: Uri = format!(
            "/v1/attestation/report?include_tls_fingerprint=true&signing_algo=ed25519&nonce={}",
            hex::encode(nonce)
        )
        .parse()
        .context("build NEAR attestation URI")?;
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(HOST, target.host)
            .body(Body::empty())
            .context("build NEAR attestation request")?;
        let response = timeout(ATTESTATION_TIMEOUT, sender.send_request(request))
            .await
            .context("NEAR attestation request timed out")?
            .context("send NEAR attestation request")?;
        if response.status() != StatusCode::OK {
            bail!("NEAR attestation endpoint returned {}", response.status());
        }
        let body = Limited::new(response.into_body(), ATTESTATION_LIMIT)
            .collect()
            .await
            .map_err(|error| anyhow::anyhow!("read NEAR attestation response: {error}"))?
            .to_bytes();
        let attestation: NearAttestation =
            serde_json::from_slice(&body).context("decode NEAR attestation response")?;
        let raw_quote = hex::decode(&attestation.intel_quote).context("decode NEAR TDX quote")?;
        let verified = self
            .collateral
            .fetch_and_verify(&raw_quote)
            .await
            .context("verify NEAR TDX quote against Intel collateral")?;
        let fields = attested_fields(&verified)?;
        verify_identity(&attestation, target, &nonce, live_spki, fields)?;
        self.verify_gpu(&attestation, &nonce).await
    }

    async fn verify_gpu(&self, attestation: &NearAttestation, nonce: &[u8; 32]) -> Result<()> {
        let payload: Value =
            serde_json::from_str(&attestation.nvidia_payload).context("decode NVIDIA evidence")?;
        let payload_nonce = payload
            .get("nonce")
            .and_then(Value::as_str)
            .context("NVIDIA evidence has no nonce")?;
        if !payload_nonce.eq_ignore_ascii_case(&hex::encode(nonce)) {
            bail!("NVIDIA evidence nonce does not match the fresh TDX nonce");
        }
        let response: Value = self
            .nras
            .post(NRAS_URL)
            .json(&payload)
            .send()
            .await
            .context("submit GPU evidence to NVIDIA NRAS")?
            .error_for_status()
            .context("NVIDIA NRAS rejected GPU evidence")?
            .json()
            .await
            .context("decode NVIDIA NRAS verdict")?;
        verify_nras_response(&response)
    }
}

async fn retry_attestation<T, Operation, Attempt>(mut operation: Operation) -> Result<T>
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
                    attempt,
                    max_attempts = ATTESTATION_ATTEMPTS,
                    will_retry = attempt < ATTESTATION_ATTEMPTS,
                    error = %format!("{error:#}"),
                    "NEAR attestation attempt failed"
                );
                failures.push(format!("attempt {attempt}: {error:#}"));
            }
        }
        if attempt < ATTESTATION_ATTEMPTS {
            sleep(Duration::from_millis(100 * attempt as u64)).await;
        }
    }
    bail!(
        "NEAR attestation failed after {ATTESTATION_ATTEMPTS} attempts: {}",
        failures.join("; ")
    )
}

fn verify_nras_response(response: &Value) -> Result<()> {
    let token = response
        .as_array()
        .and_then(|outer| outer.first())
        .and_then(Value::as_array)
        .and_then(|entry| entry.get(1))
        .and_then(Value::as_str)
        .context("NVIDIA NRAS response has no verdict token")?;
    let payload_segment = token
        .split('.')
        .nth(1)
        .context("NVIDIA NRAS verdict is not a JWT")?;
    let verdict_bytes = URL_SAFE_NO_PAD
        .decode(payload_segment)
        .context("decode NVIDIA NRAS verdict payload")?;
    let verdict: Value =
        serde_json::from_slice(&verdict_bytes).context("parse NVIDIA NRAS verdict payload")?;
    if verdict
        .get("x-nvidia-overall-att-result")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("NVIDIA NRAS did not return a successful GPU attestation verdict");
    }
    Ok(())
}

fn validate_request(request: &Request<Body>) -> Result<()> {
    if request.method() != Method::POST || request.uri().path() != "/v1/chat/completions" {
        bail!("NEAR proxy accepts only POST /v1/chat/completions");
    }
    Ok(())
}

fn upstream_request(mut request: Request<Body>, target: NearTarget) -> Result<Request<Body>> {
    request.headers_mut().remove(SELECTOR_HEADER);
    strip_hop_by_hop(request.headers_mut());
    request.headers_mut().insert(
        HOST,
        target.host.parse().context("encode NEAR Host header")?,
    );
    let path = request.uri().path_and_query().map_or(
        "/v1/chat/completions",
        axum::http::uri::PathAndQuery::as_str,
    );
    *request.uri_mut() = path.parse().context("encode NEAR upstream URI")?;
    Ok(request)
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
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

fn random_nonce() -> [u8; 32] {
    let mut nonce = [0_u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

fn spki_sha256(certificate_der: &[u8]) -> Result<[u8; 32]> {
    let (_, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|error| anyhow::anyhow!("parse NEAR TLS certificate: {error}"))?;
    Ok(Sha256::digest(certificate.public_key().raw).into())
}

fn attested_fields(report: &VerifiedReport) -> Result<AttestedFields<'_>> {
    if report.status != "UpToDate" {
        bail!(
            "NEAR TDX status is {}, expected UpToDate (platform={}, qe={}, advisories={:?})",
            report.status,
            report.platform_status.status,
            report.qe_status.status,
            report.advisory_ids
        );
    }
    let td = match &report.report {
        Report::TD10(td) => td,
        Report::TD15(td) => &td.base,
        Report::SgxEnclave(_) => bail!("NEAR attestation is SGX, expected TDX"),
    };
    Ok(AttestedFields {
        report_data: &td.report_data,
        mr_config_id: &td.mr_config_id,
    })
}

fn verify_identity(
    attestation: &NearAttestation,
    target: NearTarget,
    nonce: &[u8; 32],
    live_spki: &[u8; 32],
    fields: AttestedFields<'_>,
) -> Result<()> {
    if attestation.model_name != target.model {
        bail!("attested model does not match the selected NEAR model");
    }
    if attestation.signing_algo != "ed25519" {
        bail!("NEAR attestation did not use the requested ed25519 signing key");
    }
    if !attestation
        .request_nonce
        .eq_ignore_ascii_case(&hex::encode(nonce))
    {
        bail!("NEAR attestation response nonce is stale or mismatched");
    }
    let attested_spki: [u8; 32] = hex::decode(&attestation.tls_cert_fingerprint)
        .context("decode attested TLS fingerprint")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("attested TLS fingerprint is not 32 bytes"))?;
    if attested_spki != *live_spki {
        bail!("live NEAR TLS key does not match the attested fingerprint");
    }
    let signing_key: [u8; 32] = hex::decode(&attestation.signing_address)
        .context("decode attested ed25519 signing key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("attested ed25519 signing key is not 32 bytes"))?;
    let mut binding = Sha256::new();
    binding.update(signing_key);
    binding.update(live_spki);
    let expected_binding: [u8; 32] = binding.finalize().into();
    if fields.report_data[..32] != expected_binding || fields.report_data[32..] != *nonce {
        bail!("TDX report_data does not bind the signing key, live TLS key, and fresh nonce");
    }
    verify_compose_binding(attestation, fields.mr_config_id)
}

fn verify_compose_binding(attestation: &NearAttestation, mr_config_id: &[u8; 48]) -> Result<()> {
    let tcb_info = match &attestation.info.tcb_info {
        Value::Object(_) => attestation.info.tcb_info.clone(),
        Value::String(encoded) => serde_json::from_str(encoded).context("decode TCB info")?,
        _ => bail!("NEAR attestation TCB info has an invalid shape"),
    };
    let app_compose = tcb_info
        .get("app_compose")
        .and_then(Value::as_str)
        .context("NEAR attestation has no app_compose")?;
    let compose: AppCompose = serde_json::from_str(app_compose).context("decode app_compose")?;
    if compose.docker_compose_file.trim().is_empty() {
        bail!("NEAR attested compose file is empty");
    }
    let compose_hash: [u8; 32] = Sha256::digest(app_compose.as_bytes()).into();
    if mr_config_id[0] != 1 || mr_config_id[1..33] != compose_hash {
        bail!("NEAR app_compose does not match the verified TDX mr_config_id");
    }
    Ok(())
}

async fn finish_connection(connection: JoinHandle<Result<(), hyper::Error>>) -> Result<()> {
    match timeout(Duration::from_secs(2), connection).await {
        Ok(joined) => joined
            .context("join NEAR HTTP connection")?
            .context("NEAR HTTP connection"),
        Err(_) => Ok(()),
    }
}

pub fn error_response(error: &anyhow::Error) -> Response<Body> {
    warn!(error = %format!("{error:#}"), "NEAR attestation proxy rejected request");
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"error": "NEAR upstream attestation failed"}).to_string(),
        ))
        .unwrap_or_else(|_| Response::new(Body::from(Bytes::new())))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test fixtures intentionally fail hard on malformed local values"
)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn attestation(nonce: [u8; 32], spki: [u8; 32], model: &str) -> NearAttestation {
        let signing_key = [7_u8; 32];
        let app_compose = serde_json::json!({"docker_compose_file": "services: {}"}).to_string();
        NearAttestation {
            model_name: model.to_owned(),
            signing_address: hex::encode(signing_key),
            signing_algo: "ed25519".to_owned(),
            request_nonce: hex::encode(nonce),
            intel_quote: String::new(),
            nvidia_payload: serde_json::json!({"nonce": hex::encode(nonce)}).to_string(),
            tls_cert_fingerprint: hex::encode(spki),
            info: AttestationInfo {
                tcb_info: serde_json::json!({"app_compose": app_compose}),
            },
        }
    }

    fn fields(
        attestation: &NearAttestation,
        nonce: [u8; 32],
        spki: [u8; 32],
    ) -> ([u8; 64], [u8; 48]) {
        let signing_key = hex::decode(&attestation.signing_address).unwrap();
        let binding = Sha256::digest([signing_key.as_slice(), spki.as_slice()].concat());
        let mut report_data = [0_u8; 64];
        report_data[..32].copy_from_slice(&binding);
        report_data[32..].copy_from_slice(&nonce);
        let app_compose = attestation.info.tcb_info["app_compose"].as_str().unwrap();
        let mut mr_config = [0_u8; 48];
        mr_config[0] = 1;
        mr_config[1..33].copy_from_slice(&Sha256::digest(app_compose.as_bytes()));
        (report_data, mr_config)
    }

    fn verifies(attestation: &NearAttestation, nonce: [u8; 32], spki: [u8; 32]) -> Result<()> {
        let (report_data, mr_config_id) = fields(attestation, nonce, spki);
        verify_identity(
            attestation,
            TARGETS[0],
            &nonce,
            &spki,
            AttestedFields {
                report_data: &report_data,
                mr_config_id: &mr_config_id,
            },
        )
    }

    #[test]
    fn exact_attested_identity_passes() {
        let nonce = [1_u8; 32];
        let spki = [2_u8; 32];
        verifies(&attestation(nonce, spki, TARGETS[0].model), nonce, spki).unwrap();
    }

    #[test]
    fn unknown_selector_has_no_network_target() {
        assert!(target_for_model("attacker/model").is_none());
    }

    #[test]
    fn model_substitution_fails_closed() {
        let nonce = [1_u8; 32];
        let spki = [2_u8; 32];
        let error = verifies(&attestation(nonce, spki, TARGETS[1].model), nonce, spki).unwrap_err();
        assert!(error.to_string().contains("attested model"));
    }

    #[test]
    fn different_live_tls_peer_fails_closed() {
        let nonce = [1_u8; 32];
        let attested_spki = [2_u8; 32];
        let error = verifies(
            &attestation(nonce, attested_spki, TARGETS[0].model),
            nonce,
            [3_u8; 32],
        )
        .unwrap_err();
        assert!(error.to_string().contains("live NEAR TLS key"));
    }

    #[test]
    fn stale_nonce_fails_closed() {
        let nonce = [1_u8; 32];
        let spki = [2_u8; 32];
        let error = verifies(
            &attestation([9_u8; 32], spki, TARGETS[0].model),
            nonce,
            spki,
        )
        .unwrap_err();
        assert!(error.to_string().contains("nonce is stale"));
    }

    #[test]
    fn report_data_substitution_fails_closed() {
        let nonce = [1_u8; 32];
        let spki = [2_u8; 32];
        let attestation = attestation(nonce, spki, TARGETS[0].model);
        let (mut report_data, mr_config_id) = fields(&attestation, nonce, spki);
        report_data[0] ^= 1;
        let error = verify_identity(
            &attestation,
            TARGETS[0],
            &nonce,
            &spki,
            AttestedFields {
                report_data: &report_data,
                mr_config_id: &mr_config_id,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("report_data"));
    }

    #[test]
    fn compose_measurement_substitution_fails_closed() {
        let nonce = [1_u8; 32];
        let spki = [2_u8; 32];
        let attestation = attestation(nonce, spki, TARGETS[0].model);
        let (report_data, mut mr_config_id) = fields(&attestation, nonce, spki);
        mr_config_id[1] ^= 1;
        let error = verify_identity(
            &attestation,
            TARGETS[0],
            &nonce,
            &spki,
            AttestedFields {
                report_data: &report_data,
                mr_config_id: &mr_config_id,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("app_compose"));
    }

    #[test]
    fn selector_is_removed_before_upstream() {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/chat/completions")
            .header(SELECTOR_HEADER, TARGETS[0].model)
            .body(Body::empty())
            .unwrap();
        let request = upstream_request(request, TARGETS[0]).unwrap();
        assert!(!request.headers().contains_key(SELECTOR_HEADER));
        assert_eq!(request.headers()[HOST], TARGETS[0].host);
    }

    #[test]
    fn any_other_path_or_method_is_rejected() {
        for (method, path) in [
            (Method::GET, "/v1/chat/completions"),
            (Method::POST, "/v1/models"),
            (Method::POST, "/attacker"),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            assert!(validate_request(&request).is_err());
        }
    }

    fn nras_response(result: &Value) -> Value {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(result).unwrap());
        serde_json::json!([["JWT", format!("header.{payload}.signature")]])
    }

    #[test]
    fn nras_boolean_success_is_required() {
        assert!(verify_nras_response(&nras_response(
            &serde_json::json!({"x-nvidia-overall-att-result": true})
        ))
        .is_ok());
        for result in [
            serde_json::json!({"x-nvidia-overall-att-result": false}),
            serde_json::json!({"x-nvidia-overall-att-result": "success"}),
            serde_json::json!({}),
        ] {
            assert!(verify_nras_response(&nras_response(&result)).is_err());
        }
    }

    #[tokio::test]
    async fn transient_attestation_failure_is_retried_before_inference() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&attempts);
        retry_attestation(|| {
            let attempt = observed.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt < 2 {
                    bail!("transient verifier failure")
                }
                Ok(())
            }
        })
        .await
        .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn attestation_stays_failed_after_bounded_attempts() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&attempts);
        let error = retry_attestation::<(), _, _>(|| {
            observed.fetch_add(1, Ordering::SeqCst);
            async { bail!("persistent verifier failure") }
        })
        .await
        .unwrap_err();
        assert_eq!(attempts.load(Ordering::SeqCst), ATTESTATION_ATTEMPTS);
        assert!(error.to_string().contains("failed after 3 attempts"));
        assert_eq!(
            format!("{error:#}")
                .matches("persistent verifier failure")
                .count(),
            ATTESTATION_ATTEMPTS
        );
    }
}
