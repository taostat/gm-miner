use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::body::{Body, Bytes};
use axum::http::header::HOST;
use axum::http::{Method, Request, Response, StatusCode, Uri};
use dcap_qvl::collateral::CollateralClient;
use http_body_util::{BodyExt as _, Limited};
use hyper::client::conn::http1::SendRequest;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};
use tokio_rustls::TlsConnector;

use crate::attested_pool::{Attested, Lease, Pool};
use crate::tee_evidence::{self, nras};
use crate::upstream_proxy::{self, retry_attestation, strip_hop_by_hop};

pub const SELECTOR_HEADER: &str = "x-gm-upstream-model";
const PROVIDER: &str = "NEAR";
const ATTESTATION_LIMIT: usize = 2 * 1024 * 1024;
const ATTESTATION_TIMEOUT: Duration = Duration::from_secs(120);
// Match the Envoy route timeout: non-streaming inference may not return
// response headers until generation completes.
const INFERENCE_TIMEOUT: Duration = Duration::from_secs(1800);
const NRAS_TIMEOUT: Duration = Duration::from_secs(60);
const NRAS_URL: &str = "https://nras.attestation.nvidia.com/v3/attest/gpu";
const CHAT_COMPLETIONS: &str = "/v1/chat/completions";
const IMAGES_GENERATIONS: &str = "/v1/images/generations";
const READY_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct NearTarget {
    pub model: &'static str,
    pub host: &'static str,
    pub path: &'static str,
}

pub const TARGETS: [NearTarget; 3] = [
    NearTarget {
        model: "Qwen/Qwen3.8-27B",
        host: "qwen3-8-27b.completions.near.ai",
        path: CHAT_COMPLETIONS,
    },
    NearTarget {
        model: "z-ai/glm-5.3-flash",
        host: "glm-5-3-flash.completions.near.ai",
        path: CHAT_COMPLETIONS,
    },
    NearTarget {
        model: "black-forest-labs/FLUX.2-klein-4B",
        host: "flux2-klein.completions.near.ai",
        path: IMAGES_GENERATIONS,
    },
];

fn make_pools() -> HashMap<NearTarget, Arc<Pool>> {
    TARGETS
        .into_iter()
        .map(|target| (target, Arc::new(Pool::default())))
        .collect()
}

#[must_use]
pub fn target_for_model(model: &str) -> Option<NearTarget> {
    TARGETS.iter().copied().find(|target| target.model == model)
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
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
#[cfg_attr(test, derive(serde::Serialize))]
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
    pools: Arc<HashMap<NearTarget, Arc<Pool>>>,
    #[cfg(test)]
    test_factory: Option<Arc<tests::LocalConnectionFactory>>,
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
            collateral: tee_evidence::collateral_client()?,
            nras,
            pools: Arc::new(make_pools()),
            #[cfg(test)]
            test_factory: None,
        })
    }

    /// Verify one configured endpoint without forwarding inference.
    ///
    /// # Errors
    ///
    /// Returns an error for any connection or attestation failure.
    pub async fn preflight(&self, target: NearTarget) -> Result<()> {
        finish_preflight(self.connect_and_attest(target).await?).await
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
        finish_preflight(self.connect_and_attest_once(target, Some(ip), 0).await?).await
    }

    /// Forward on an attested connection, reusing one only for its target host.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported requests or any attestation/upstream
    /// failure. No inference is sent when attestation fails.
    pub async fn forward(&self, request: Request<Body>) -> Result<Response<Body>> {
        let selector = request
            .headers()
            .get(SELECTOR_HEADER)
            .context("missing NEAR model selector")?
            .to_str()
            .context("NEAR model selector is not valid ASCII")?;
        let target = target_for_model(selector).context("unsupported NEAR model selector")?;
        validate_request(&request, target)?;
        let upstream_request = upstream_request(request, target)?;
        let pool = self.pool_for(target)?;
        let mut connection = self.checkout(target, &pool).await?;

        #[cfg(test)]
        if let Some(factory) = &self.test_factory {
            factory.before_inference().await;
        }

        connection.requests += 1;
        let response = match send_inference(&mut connection.sender, upstream_request).await {
            Ok(response) => response,
            Err(InferenceSendError::Unsent { request, source }) => {
                connection.retire();
                let mut retry_connection =
                    self.connect_and_attest(target).await.with_context(|| {
                        format!("freshly attest NEAR connection after unsent request: {source:#}")
                    })?;
                if let Err(error) = wait_for_readiness(&mut retry_connection.sender).await {
                    retry_connection.retire();
                    return Err(error.context("fresh NEAR retry connection is not ready"));
                }
                if !pool.usable(&retry_connection) {
                    retry_connection.retire();
                    bail!("fresh NEAR retry connection expired or closed before inference");
                }
                retry_connection.requests += 1;
                #[cfg(test)]
                if let Some(factory) = &self.test_factory {
                    factory.before_inference().await;
                }
                match send_inference(&mut retry_connection.sender, *request).await {
                    Ok(response) => {
                        connection = retry_connection;
                        response
                    }
                    Err(error) => {
                        retry_connection.retire();
                        return Err(error.into_anyhow().context(format!(
                            "fresh NEAR inference retry after unsent request: {source:#}"
                        )));
                    }
                }
            }
            Err(error) => {
                connection.retire();
                return Err(error.into_anyhow());
            }
        };
        let (parts, body) = response.into_parts();
        let body = Lease::new(Body::new(body), connection, pool);
        Ok(Response::from_parts(parts, Body::new(body)))
    }

    #[must_use]
    pub fn idle_connections(&self, target: NearTarget) -> usize {
        self.pools.get(&target).map_or(0, |pool| pool.idle())
    }

    fn pool_for(&self, target: NearTarget) -> Result<Arc<Pool>> {
        self.pools
            .get(&target)
            .cloned()
            .with_context(|| format!("no NEAR connection pool for {}", target.host))
    }

    async fn checkout(&self, target: NearTarget, pool: &Arc<Pool>) -> Result<Attested> {
        while let Some(mut connection) = pool.take() {
            if wait_for_readiness(&mut connection.sender).await.is_ok() && pool.usable(&connection)
            {
                return Ok(connection);
            }
            connection.retire();
        }
        let mut connection = self.connect_and_attest(target).await?;
        if let Err(error) = wait_for_readiness(&mut connection.sender).await {
            connection.retire();
            return Err(error.context("fresh NEAR connection is not ready"));
        }
        if !pool.usable(&connection) {
            connection.retire();
            bail!("NEAR connection expired or closed before its first request");
        }
        Ok(connection)
    }

    async fn connect_and_attest(&self, target: NearTarget) -> Result<Attested> {
        let mut attempt = 0;
        retry_attestation(PROVIDER, || {
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
    ) -> Result<Attested> {
        let (sender, driver, live_spki, peer) = self.connect(target, ip, attempt).await?;
        let mut connection = Attested {
            sender,
            driver,
            attested_at: Instant::now(),
            idle_since: None,
            expires_at: None,
            requests: 0,
        };
        self.attest(&mut connection.sender, target, &live_spki)
            .await
            .with_context(|| format!("attest {} via {peer}", target.host))?;
        #[cfg(test)]
        if let Some(factory) = &self.test_factory {
            factory.after_attestation().await;
        }
        Ok(connection)
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
        #[cfg(test)]
        if let Some(factory) = &self.test_factory {
            return factory.connect(&self.tls, target, ip).await;
        }

        let connection = upstream_proxy::connect(
            &self.tls,
            PROVIDER,
            target.host,
            ip.map(|ip| SocketAddr::new(ip, 443)),
            attempt,
        )
        .await?;
        let live_spki = tee_evidence::spki_sha256(connection.leaf.as_ref())
            .context("hash NEAR TLS certificate key")?;
        Ok((
            connection.sender,
            connection.driver,
            live_spki,
            connection.peer,
        ))
    }

    async fn attest(
        &self,
        sender: &mut SendRequest<Body>,
        target: NearTarget,
        live_spki: &[u8; 32],
    ) -> Result<()> {
        let nonce = tee_evidence::random_nonce();
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
        let body = fetch_attestation(sender, request).await?;
        let attestation: NearAttestation =
            serde_json::from_slice(&body).context("decode NEAR attestation response")?;
        let raw_quote = hex::decode(&attestation.intel_quote).context("decode NEAR TDX quote")?;
        let (report_data, mr_config_id) = self.quote_fields(&raw_quote).await?;
        let fields = AttestedFields {
            report_data: &report_data,
            mr_config_id: &mr_config_id,
        };
        verify_identity(&attestation, target, &nonce, live_spki, fields)?;
        self.verify_gpu(&attestation, &nonce).await
    }

    async fn quote_fields(&self, raw_quote: &[u8]) -> Result<([u8; 64], [u8; 48])> {
        #[cfg(test)]
        if let Some(factory) = &self.test_factory {
            return factory.quote_fields(raw_quote);
        }

        let claims = tee_evidence::verify_quote(&self.collateral, raw_quote)
            .await
            .context("verify NEAR TDX quote against Intel collateral")?;
        let td = tee_evidence::td_report(&claims.report).context("NEAR attestation")?;
        Ok((td.report_data, td.mr_config_id))
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
        let response = self.gpu_verdict(&payload).await?;
        verify_nras_response(&response)
    }

    async fn gpu_verdict(&self, payload: &Value) -> Result<Value> {
        #[cfg(test)]
        if let Some(factory) = &self.test_factory {
            return Ok(factory.gpu_verdict());
        }

        self.nras
            .post(NRAS_URL)
            .json(payload)
            .send()
            .await
            .context("submit GPU evidence to NVIDIA NRAS")?
            .error_for_status()
            .context("NVIDIA NRAS rejected GPU evidence")?
            .json()
            .await
            .context("decode NVIDIA NRAS verdict")
    }
}

async fn wait_for_readiness(sender: &mut SendRequest<Body>) -> Result<()> {
    timeout(READY_TIMEOUT, sender.ready())
        .await
        .context("NEAR connection readiness timed out")?
        .context("NEAR connection closed before inference")
}

async fn finish_preflight(mut connection: Attested) -> Result<()> {
    // Drop the sender to request graceful shutdown, but keep the driver owned
    // by Attested so a timeout or cancellation still aborts the transport.
    let (placeholder_io, placeholder_peer) = tokio::io::duplex(1);
    let (placeholder_sender, placeholder_driver) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(placeholder_io))
            .await
            .context("prepare NEAR preflight connection shutdown")?;
    drop(placeholder_driver);
    drop(placeholder_peer);
    drop(std::mem::replace(
        &mut connection.sender,
        placeholder_sender,
    ));
    match timeout(Duration::from_secs(2), &mut connection.driver).await {
        Ok(joined) => joined
            .context("join NEAR HTTP connection")?
            .context("NEAR HTTP connection"),
        Err(_) => Ok(()),
    }
}

async fn fetch_attestation(
    sender: &mut SendRequest<Body>,
    request: Request<Body>,
) -> Result<Bytes> {
    // One deadline covers the complete HTTP response. Receiving headers or
    // another body chunk must not reset the attestation budget.
    timeout(ATTESTATION_TIMEOUT, async {
        let response = sender
            .send_request(request)
            .await
            .context("send NEAR attestation request")?;
        if response.status() != StatusCode::OK {
            bail!("NEAR attestation endpoint returned {}", response.status());
        }
        Ok(Limited::new(response.into_body(), ATTESTATION_LIMIT)
            .collect()
            .await
            .map_err(|error| anyhow::anyhow!("read NEAR attestation response: {error}"))?
            .to_bytes())
    })
    .await
    .context("NEAR attestation request timed out")?
}

fn verify_nras_response(response: &Value) -> Result<()> {
    let verdict = nras::unverified_claims(nras::aggregate_token(response)?)?;
    nras::require_overall_success(&verdict)
}

// Runs before the attested connect: a selector on the wrong path must not spend
// a TDX quote and an NRAS round-trip only to be refused at forwarding time.
fn validate_request(request: &Request<Body>, target: NearTarget) -> Result<()> {
    let path = request.uri().path();
    if request.method() != Method::POST || path != target.path {
        bail!(
            "{} is served only at POST {}, not {} {path}",
            target.model,
            target.path,
            request.method()
        );
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
    let path = request
        .uri()
        .path_and_query()
        .map_or(target.path, axum::http::uri::PathAndQuery::as_str);
    *request.uri_mut() = path.parse().context("encode NEAR upstream URI")?;
    Ok(request)
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

/// The 502 the NEAR proxy answers with when it refuses a request.
#[must_use]
pub fn error_response(error: &anyhow::Error) -> Response<Body> {
    upstream_proxy::error_response(PROVIDER, error)
}

enum InferenceSendError {
    /// Hyper returned the request before serializing it onto the connection.
    Unsent {
        request: Box<Request<Body>>,
        source: anyhow::Error,
    },
    Failed(anyhow::Error),
}

impl InferenceSendError {
    fn into_anyhow(self) -> anyhow::Error {
        match self {
            Self::Unsent { source, .. } | Self::Failed(source) => source,
        }
    }
}

// Only a request returned by try_send_request is safe for the caller to retry
// on another connection: Hyper has not started serializing it.
async fn send_inference(
    sender: &mut SendRequest<Body>,
    request: Request<Body>,
) -> std::result::Result<Response<hyper::body::Incoming>, InferenceSendError> {
    match timeout(INFERENCE_TIMEOUT, sender.try_send_request(request)).await {
        Err(_) => Err(InferenceSendError::Failed(anyhow::anyhow!(
            "NEAR inference timed out"
        ))),
        Ok(Ok(response)) => Ok(response),
        Ok(Err(mut error)) => {
            let request = error.take_message();
            let source = anyhow::Error::new(error.into_error())
                .context("send NEAR inference on attested TLS connection");
            match request {
                Some(request) => Err(InferenceSendError::Unsent {
                    request: Box::new(request),
                    source,
                }),
                None => Err(InferenceSendError::Failed(source)),
            }
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test fixtures intentionally fail hard on malformed local values"
)]
mod tests {
    use super::*;
    use crate::attested_pool::{MAX_AGE, MAX_IDLE_AGE};
    use axum::http::header::CONNECTION;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const FLUX_KLEIN_MODEL: &str = "black-forest-labs/FLUX.2-klein-4B";
    const FLUX_KLEIN_HOST: &str = "flux2-klein.completions.near.ai";
    const GLM_53_FLASH_MODEL: &str = "z-ai/glm-5.3-flash";
    const GLM_53_FLASH_HOST: &str = "glm-5-3-flash.completions.near.ai";
    const TEST_LEAF: &[u8] = include_bytes!("../tests/fixtures/kubetee/test_leaf.der");
    const TEST_KEY: &[u8] = include_bytes!("../tests/fixtures/kubetee/test_leaf_key.pk8");

    #[derive(Clone, Copy, Debug, Default)]
    enum EvidenceFault {
        #[default]
        None,
        TlsKey,
        Nonce,
        ReportData,
        Quote,
        GpuNonce,
        GpuVerdict,
    }

    #[derive(Default)]
    struct LocalServerState {
        attestations: AtomicUsize,
        quote_checks: AtomicUsize,
        gpu_checks: AtomicUsize,
        inferences: AtomicUsize,
        fail_next_inference: AtomicBool,
        fail_next_upload: AtomicBool,
        incomplete_next_response: AtomicBool,
        fail_next_body: AtomicBool,
        stall_next_inference: AtomicBool,
        fail_attestation: AtomicBool,
        closes_after_attestation: AtomicBool,
        completed_drivers: AtomicUsize,
        closes_before_inference: std::sync::Mutex<usize>,
        attestation_delay: std::sync::Mutex<Duration>,
        fault: std::sync::Mutex<EvidenceFault>,
        peers: std::sync::Mutex<Vec<Option<IpAddr>>>,
        drivers: std::sync::Mutex<Vec<tokio::task::AbortHandle>>,
        servers: std::sync::Mutex<Vec<tokio::task::AbortHandle>>,
    }

    impl LocalServerState {
        async fn respond(
            &self,
            request: Request<hyper::body::Incoming>,
            target: NearTarget,
            attested: &AtomicBool,
        ) -> std::io::Result<Response<Body>> {
            assert_eq!(request.headers()[HOST], target.host);
            let path = request.uri().path().to_owned();
            let query = request.uri().query().unwrap_or_default().to_owned();
            if path == target.path && self.fail_next_upload.swap(false, Ordering::SeqCst) {
                assert!(attested.load(Ordering::SeqCst));
                let mut body = request.into_body();
                assert_eq!(
                    body.frame().await.unwrap().unwrap().into_data().unwrap(),
                    "partial request"
                );
                return Err(std::io::Error::other("local upload interrupted"));
            }
            let body = request
                .into_body()
                .collect()
                .await
                .map_err(|_| std::io::Error::other("local request body failed"))?
                .to_bytes();
            if path == "/v1/attestation/report" {
                self.attestations.fetch_add(1, Ordering::SeqCst);
                if self.fail_attestation.load(Ordering::SeqCst) {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::empty())
                        .unwrap());
                }
                let delay = *self.attestation_delay.lock().unwrap();
                tokio::time::sleep(delay).await;
                attested.store(true, Ordering::SeqCst);
                return Ok(Response::new(Body::from(evidence_body(
                    self, target, &query,
                ))));
            }

            assert!(attested.load(Ordering::SeqCst));
            assert_eq!(path, target.path);
            assert_eq!(body, "request body");
            self.inferences.fetch_add(1, Ordering::SeqCst);
            if self.stall_next_inference.swap(false, Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            if self.fail_next_inference.swap(false, Ordering::SeqCst) {
                return Err(std::io::Error::other("local inference failed"));
            }
            let fail_body = self.fail_next_body.swap(false, Ordering::SeqCst);
            if self.incomplete_next_response.swap(false, Ordering::SeqCst) || fail_body {
                use futures_util::{stream, StreamExt as _};
                let chunks = stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(
                    b"partial",
                ))])
                .chain(stream::once(async move {
                    if fail_body {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                        Err(std::io::Error::other("local response body failed"))
                    } else {
                        std::future::pending().await
                    }
                }));
                return Ok(Response::new(Body::from_stream(chunks)));
            }
            Ok(Response::new(Body::from("completion")))
        }

        fn record_server(&self, server: &tokio::task::JoinHandle<()>) {
            self.servers.lock().unwrap().push(server.abort_handle());
        }

        async fn close_latest_peer(&self) {
            let server = self.servers.lock().unwrap().last().unwrap().clone();
            let driver = self.drivers.lock().unwrap().last().unwrap().clone();
            server.abort();
            timeout(Duration::from_secs(1), async {
                while !driver.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
    }

    #[derive(Default)]
    pub(super) struct LocalConnectionFactory {
        state: Arc<LocalServerState>,
    }

    // TLS, nonce generation, evidence fetching, identity binding and GPU verdict
    // enforcement use the production path. Only Intel appraisal and the NRAS
    // service use synthetic evidence, keeping these lifecycle tests offline.
    impl LocalConnectionFactory {
        pub(super) async fn before_inference(&self) {
            let close = {
                let mut remaining = self.state.closes_before_inference.lock().unwrap();
                let close = *remaining > 0;
                *remaining = remaining.saturating_sub(1);
                close
            };
            if close {
                self.state.close_latest_peer().await;
            }
        }

        pub(super) async fn after_attestation(&self) {
            if self
                .state
                .closes_after_attestation
                .swap(false, Ordering::SeqCst)
            {
                self.state.close_latest_peer().await;
            }
        }

        pub(super) async fn connect(
            &self,
            tls: &TlsConnector,
            target: NearTarget,
            ip: Option<IpAddr>,
        ) -> Result<(
            SendRequest<Body>,
            JoinHandle<Result<(), hyper::Error>>,
            [u8; 32],
            SocketAddr,
        )> {
            use hyper::service::service_fn;
            use hyper_util::rt::TokioIo;
            use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

            self.state.peers.lock().unwrap().push(ip);
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(TEST_LEAF)],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(TEST_KEY.to_vec())),
                )?;
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

            let state = Arc::clone(&self.state);
            let attested = Arc::new(AtomicBool::new(false));
            let (client, server) = tokio::io::duplex(4096);
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let state = Arc::clone(&state);
                let attested = Arc::clone(&attested);
                async move { state.respond(request, target, &attested).await }
            });
            let server = tokio::spawn(async move {
                let server = acceptor.accept(server).await.unwrap();
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(server), service)
                    .await;
            });
            self.state.record_server(&server);
            let client = tls
                .connect(ServerName::try_from(target.host)?, client)
                .await?;
            let live_spki = tee_evidence::spki_sha256(
                client.get_ref().1.peer_certificates().unwrap()[0].as_ref(),
            )?;
            let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
                .await
                .context("start local NEAR HTTP connection")?;
            let driver_state = Arc::clone(&self.state);
            let driver = tokio::spawn(async move {
                let result = connection.await;
                driver_state
                    .completed_drivers
                    .fetch_add(1, Ordering::SeqCst);
                result
            });
            self.state
                .drivers
                .lock()
                .unwrap()
                .push(driver.abort_handle());
            Ok((
                sender,
                driver,
                live_spki,
                SocketAddr::new(ip.unwrap_or(IpAddr::from([127, 0, 0, 1])), 443),
            ))
        }

        pub(super) fn quote_fields(&self, raw: &[u8]) -> Result<([u8; 64], [u8; 48])> {
            self.state.quote_checks.fetch_add(1, Ordering::SeqCst);
            if matches!(*self.state.fault.lock().unwrap(), EvidenceFault::Quote) {
                bail!("local quote appraisal failed");
            }
            let (report_data, mr_config_id) = raw.split_at(64);
            Ok((report_data.try_into()?, mr_config_id.try_into()?))
        }

        pub(super) fn gpu_verdict(&self) -> Value {
            self.state.gpu_checks.fetch_add(1, Ordering::SeqCst);
            nras_response(&serde_json::json!({
                "x-nvidia-overall-att-result": !matches!(
                    *self.state.fault.lock().unwrap(), EvidenceFault::GpuVerdict
                )
            }))
        }
    }

    fn evidence_body(state: &LocalServerState, target: NearTarget, query: &str) -> Vec<u8> {
        assert!(query.contains("include_tls_fingerprint=true&signing_algo=ed25519"));
        let nonce: [u8; 32] = hex::decode(query.split_once("nonce=").unwrap().1)
            .unwrap()
            .try_into()
            .unwrap();
        let spki = tee_evidence::spki_sha256(TEST_LEAF).unwrap();
        let mut attestation = attestation(nonce, spki, target.model);
        let (mut report_data, mr_config_id) = fields(&attestation, nonce, spki);
        match *state.fault.lock().unwrap() {
            EvidenceFault::TlsKey => attestation.tls_cert_fingerprint = hex::encode([42; 32]),
            EvidenceFault::Nonce => attestation.request_nonce = hex::encode([42; 32]),
            EvidenceFault::ReportData => report_data[0] ^= 1,
            EvidenceFault::GpuNonce => {
                attestation.nvidia_payload =
                    serde_json::json!({"nonce": hex::encode([42; 32])}).to_string();
            }
            EvidenceFault::None | EvidenceFault::Quote | EvidenceFault::GpuVerdict => {}
        }
        attestation.intel_quote =
            hex::encode([report_data.as_slice(), mr_config_id.as_slice()].concat());
        serde_json::to_vec(&attestation).unwrap()
    }

    fn local_verifier() -> (NearVerifier, Arc<LocalServerState>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let factory = Arc::new(LocalConnectionFactory::default());
        let state = Arc::clone(&factory.state);
        let mut verifier = NearVerifier::new().unwrap();
        verifier.test_factory = Some(factory);
        (verifier, state)
    }

    fn inference_request(target: NearTarget) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(target.path)
            .header(SELECTOR_HEADER, target.model)
            .body(Body::from("request body"))
            .unwrap()
    }

    async fn complete_inference(verifier: &NearVerifier, target: NearTarget) {
        let response = verifier.forward(inference_request(target)).await.unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "completion"
        );
    }

    #[tokio::test]
    async fn a_second_inference_reuses_its_target_connection_without_reattesting() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        complete_inference(&verifier, target).await;
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 1);
        assert_eq!(state.quote_checks.load(Ordering::SeqCst), 1);
        assert_eq!(state.gpu_checks.load(Ordering::SeqCst), 1);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 2);
        assert_eq!(verifier.idle_connections(target), 1);
    }

    #[tokio::test]
    async fn each_target_host_uses_its_own_pool() {
        let first = TARGETS[0];
        let second = TARGETS[1];
        let (verifier, state) = local_verifier();
        complete_inference(&verifier, first).await;
        complete_inference(&verifier, second).await;
        complete_inference(&verifier, first).await;
        complete_inference(&verifier, second).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 4);
        assert_eq!(verifier.idle_connections(first), 1);
        assert_eq!(verifier.idle_connections(second), 1);
        let other_model = NearTarget {
            model: second.model,
            ..first
        };
        let other_path = NearTarget {
            path: IMAGES_GENERATIONS,
            ..first
        };
        assert!(verifier.pool_for(other_model).is_err());
        assert!(verifier.pool_for(other_path).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn an_expired_connection_is_reattested_before_inference() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        complete_inference(&verifier, target).await;
        // Keep the connection active so the shorter idle limit cannot make
        // this test pass without enforcing the attestation age.
        let interval = Duration::from_secs(60);
        for _ in 1..MAX_AGE.as_secs() / interval.as_secs() {
            tokio::time::advance(interval).await;
            complete_inference(&verifier, target).await;
            assert_eq!(state.attestations.load(Ordering::SeqCst), 1);
        }
        tokio::time::advance(interval).await;
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
        assert_eq!(state.quote_checks.load(Ordering::SeqCst), 2);
        assert_eq!(state.gpu_checks.load(Ordering::SeqCst), 2);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 11);
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_connection_past_the_limit_is_reattested() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        complete_inference(&verifier, target).await;
        tokio::time::advance(MAX_IDLE_AGE + Duration::from_secs(1)).await;
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_time_starts_after_the_response_is_consumed_and_resets_on_return() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        let response = verifier.forward(inference_request(target)).await.unwrap();
        tokio::time::advance(MAX_IDLE_AGE + Duration::from_secs(1)).await;
        assert_eq!(verifier.idle_connections(target), 0);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "completion"
        );
        complete_inference(&verifier, target).await;
        tokio::time::advance(MAX_IDLE_AGE.checked_sub(Duration::from_secs(1)).unwrap()).await;
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 1);
        tokio::time::advance(MAX_IDLE_AGE).await;
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn a_peer_closed_while_idle_is_reattested_on_checkout() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        complete_inference(&verifier, target).await;
        state.close_latest_peer().await;
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_unsent_inference_retries_once_on_a_fresh_attested_connection() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        complete_inference(&verifier, target).await;
        *state.closes_before_inference.lock().unwrap() = 1;
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
        assert_eq!(state.quote_checks.load(Ordering::SeqCst), 2);
        assert_eq!(state.gpu_checks.load(Ordering::SeqCst), 2);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 2);
        assert_eq!(verifier.idle_connections(target), 1);
    }

    #[tokio::test]
    async fn a_second_unsent_failure_is_not_retried_again() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        complete_inference(&verifier, target).await;
        *state.closes_before_inference.lock().unwrap() = 2;
        assert!(verifier.forward(inference_request(target)).await.is_err());
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
        assert_eq!(state.quote_checks.load(Ordering::SeqCst), 2);
        assert_eq!(state.gpu_checks.load(Ordering::SeqCst), 2);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 1);
        assert_eq!(verifier.idle_connections(target), 0);
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 3);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unsent_retry_requires_successful_fresh_attestation() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        complete_inference(&verifier, target).await;
        *state.closes_before_inference.lock().unwrap() = 1;
        *state.fault.lock().unwrap() = EvidenceFault::GpuVerdict;
        assert!(verifier.forward(inference_request(target)).await.is_err());
        assert_eq!(
            state.attestations.load(Ordering::SeqCst),
            1 + upstream_proxy::ATTESTATION_ATTEMPTS
        );
        assert_eq!(state.inferences.load(Ordering::SeqCst), 1);
        assert_eq!(verifier.idle_connections(target), 0);
        let drivers = state.drivers.lock().unwrap().clone();
        timeout(Duration::from_secs(1), async {
            while drivers.iter().any(|driver| !driver.is_finished()) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn attested_at_starts_with_nonce_bound_attestation() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        let delay = Duration::from_secs(30);
        *state.attestation_delay.lock().unwrap() = delay;
        complete_inference(&verifier, target).await;
        let interval = Duration::from_secs(60);
        for _ in 1..MAX_AGE.as_secs() / interval.as_secs() {
            tokio::time::advance(interval).await;
            complete_inference(&verifier, target).await;
            assert_eq!(state.attestations.load(Ordering::SeqCst), 1);
        }
        tokio::time::advance(interval.checked_sub(delay).unwrap()).await;
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 11);
    }

    #[tokio::test]
    async fn request_limit_forces_a_new_attestation() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        for _ in 0..crate::attested_pool::MAX_REQUESTS {
            complete_inference(&verifier, target).await;
        }
        assert_eq!(state.attestations.load(Ordering::SeqCst), 1);
        assert_eq!(verifier.idle_connections(target), 0);
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 101);
    }

    async fn first_driver_stopped(state: &LocalServerState) {
        let driver = state.drivers.lock().unwrap()[0].clone();
        timeout(Duration::from_secs(1), async {
            while !driver.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_timed_out_inference_retires_its_connection_before_reuse() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        state.stall_next_inference.store(true, Ordering::SeqCst);
        let started = Instant::now();
        let error = verifier
            .forward(inference_request(target))
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "NEAR inference timed out");
        assert_eq!(started.elapsed(), INFERENCE_TIMEOUT);
        assert_eq!(verifier.idle_connections(target), 0);
        first_driver_stopped(&state).await;
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cancelling_an_inference_retires_its_connection() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        state.stall_next_inference.store(true, Ordering::SeqCst);
        let worker = verifier.clone();
        let request = tokio::spawn(async move { worker.forward(inference_request(target)).await });
        timeout(Duration::from_secs(1), async {
            while state.inferences.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert_eq!(verifier.idle_connections(target), 0);
        first_driver_stopped(&state).await;
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cancelling_attestation_closes_the_pending_connection() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        *state.attestation_delay.lock().unwrap() = ATTESTATION_TIMEOUT;
        let worker = verifier.clone();
        let request = tokio::spawn(async move { worker.forward(inference_request(target)).await });
        timeout(Duration::from_secs(1), async {
            while state.attestations.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert_eq!(verifier.idle_connections(target), 0);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 0);
        first_driver_stopped(&state).await;
        *state.attestation_delay.lock().unwrap() = Duration::ZERO;
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_attestation_never_sends_inference_or_enters_the_pool() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        state.fail_attestation.store(true, Ordering::SeqCst);
        assert!(verifier.forward(inference_request(target)).await.is_err());
        assert_eq!(
            state.attestations.load(Ordering::SeqCst),
            upstream_proxy::ATTESTATION_ATTEMPTS
        );
        assert_eq!(state.inferences.load(Ordering::SeqCst), 0);
        assert_eq!(verifier.idle_connections(target), 0);
        state.fail_attestation.store(false, Ordering::SeqCst);
        complete_inference(&verifier, target).await;
        assert_eq!(
            state.attestations.load(Ordering::SeqCst),
            upstream_proxy::ATTESTATION_ATTEMPTS + 1
        );
    }

    #[tokio::test]
    async fn a_consumed_inference_failure_is_not_retried() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        state.fail_next_inference.store(true, Ordering::SeqCst);
        assert!(verifier.forward(inference_request(target)).await.is_err());
        assert_eq!(state.attestations.load(Ordering::SeqCst), 1);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 1);
        assert_eq!(verifier.idle_connections(target), 0);
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_partly_written_request_is_never_retried() {
        use futures_util::{stream, StreamExt as _};

        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        state.fail_next_upload.store(true, Ordering::SeqCst);
        let mut request = inference_request(target);
        *request.body_mut() = Body::from_stream(
            stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(
                b"partial request",
            ))])
            .chain(stream::pending()),
        );
        assert!(timeout(Duration::from_secs(1), verifier.forward(request))
            .await
            .unwrap()
            .is_err());
        assert_eq!(state.attestations.load(Ordering::SeqCst), 1);
        assert_eq!(verifier.idle_connections(target), 0);
        first_driver_stopped(&state).await;
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn rejected_evidence_never_carries_inference_or_enters_the_pool() {
        for fault in [
            EvidenceFault::TlsKey,
            EvidenceFault::Nonce,
            EvidenceFault::ReportData,
            EvidenceFault::Quote,
            EvidenceFault::GpuNonce,
            EvidenceFault::GpuVerdict,
        ] {
            let (verifier, state) = local_verifier();
            *state.fault.lock().unwrap() = fault;
            assert!(
                verifier
                    .forward(inference_request(TARGETS[0]))
                    .await
                    .is_err(),
                "{fault:?}"
            );
            assert_eq!(
                state.attestations.load(Ordering::SeqCst),
                upstream_proxy::ATTESTATION_ATTEMPTS
            );
            assert_eq!(state.inferences.load(Ordering::SeqCst), 0);
            assert_eq!(verifier.idle_connections(TARGETS[0]), 0);
            first_driver_stopped(&state).await;
            *state.fault.lock().unwrap() = EvidenceFault::None;
            complete_inference(&verifier, TARGETS[0]).await;
            assert_eq!(
                state.attestations.load(Ordering::SeqCst),
                upstream_proxy::ATTESTATION_ATTEMPTS + 1
            );
        }
    }

    #[tokio::test]
    async fn a_failed_request_body_discards_its_connection() {
        let (verifier, state) = local_verifier();
        let mut request = inference_request(TARGETS[0]);
        *request.body_mut() = Body::from_stream(futures_util::stream::iter([
            Ok(Bytes::from_static(b"partial request")),
            Err(std::io::Error::other("caller disconnected")),
        ]));
        assert!(verifier.forward(request).await.is_err());
        assert_eq!(verifier.idle_connections(TARGETS[0]), 0);
        first_driver_stopped(&state).await;
        complete_inference(&verifier, TARGETS[0]).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_incomplete_response_body_discards_its_connection() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        state.incomplete_next_response.store(true, Ordering::SeqCst);
        let response = verifier.forward(inference_request(target)).await.unwrap();
        let mut body = response.into_body();
        assert!(body.frame().await.unwrap().unwrap().is_data());
        drop(body);
        assert_eq!(verifier.idle_connections(target), 0);
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_response_body_error_discards_its_connection() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        state.fail_next_body.store(true, Ordering::SeqCst);
        let response = verifier.forward(inference_request(target)).await.unwrap();
        assert!(response.into_body().collect().await.is_err());
        assert_eq!(verifier.idle_connections(target), 0);
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_unread_response_is_not_reused() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        state.incomplete_next_response.store(true, Ordering::SeqCst);
        let response = verifier.forward(inference_request(target)).await.unwrap();
        assert_eq!(verifier.idle_connections(target), 0);
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
        drop(response);
        first_driver_stopped(&state).await;
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn preflight_connections_close_their_drivers_without_pooling() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        verifier.preflight(target).await.unwrap();
        assert_eq!(verifier.idle_connections(target), 0);
        assert_eq!(state.completed_drivers.load(Ordering::SeqCst), 1);
        first_driver_stopped(&state).await;
        verifier
            .preflight_at(target, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(verifier.idle_connections(target), 0);
        assert_eq!(state.completed_drivers.load(Ordering::SeqCst), 2);
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 3);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 1);
        verifier.preflight(target).await.unwrap();
        assert_eq!(state.completed_drivers.load(Ordering::SeqCst), 3);
        verifier
            .preflight_at(target, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(state.completed_drivers.load(Ordering::SeqCst), 4);
        assert_eq!(verifier.idle_connections(target), 1);
        complete_inference(&verifier, target).await;
        assert_eq!(state.attestations.load(Ordering::SeqCst), 5);
        assert_eq!(state.inferences.load(Ordering::SeqCst), 2);
        assert_eq!(
            *state.peers.lock().unwrap(),
            [
                None,
                Some("127.0.0.1".parse().unwrap()),
                None,
                None,
                Some("127.0.0.1".parse().unwrap())
            ]
        );
    }

    struct StalledShutdown {
        io: tokio::io::DuplexStream,
        started: Arc<tokio::sync::Notify>,
    }

    impl tokio::io::AsyncRead for StalledShutdown {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for StalledShutdown {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().io).poll_flush(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.started.notify_one();
            std::task::Poll::Pending
        }
    }

    async fn connection_with_stalled_shutdown(
    ) -> (Attested, tokio::io::DuplexStream, Arc<tokio::sync::Notify>) {
        let (io, peer) = tokio::io::duplex(4096);
        let started = Arc::new(tokio::sync::Notify::new());
        let (sender, driver) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(StalledShutdown {
                io,
                started: Arc::clone(&started),
            }))
            .await
            .unwrap();
        (
            Attested {
                sender,
                driver: tokio::spawn(driver),
                attested_at: Instant::now(),
                idle_since: None,
                expires_at: None,
                requests: 0,
            },
            peer,
            started,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn preflight_shutdown_timeout_closes_the_transport() {
        use tokio::io::AsyncReadExt as _;

        let (connection, mut peer, shutdown_started) = connection_with_stalled_shutdown().await;
        let started = Instant::now();
        finish_preflight(connection).await.unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        timeout(Duration::from_secs(1), shutdown_started.notified())
            .await
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), peer.read(&mut [0]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_preflight_shutdown_closes_the_transport() {
        use tokio::io::AsyncReadExt as _;

        let (connection, mut peer, shutdown_started) = connection_with_stalled_shutdown().await;
        let preflight = tokio::spawn(finish_preflight(connection));
        timeout(Duration::from_secs(1), shutdown_started.notified())
            .await
            .unwrap();
        preflight.abort();
        assert!(preflight.await.unwrap_err().is_cancelled());
        assert_eq!(
            timeout(Duration::from_secs(1), peer.read(&mut [0]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn a_fresh_connection_must_be_ready_before_inference() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        state.closes_after_attestation.store(true, Ordering::SeqCst);

        let error = verifier
            .forward(inference_request(target))
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("fresh NEAR connection is not ready"));
        assert_eq!(state.inferences.load(Ordering::SeqCst), 0);
        assert_eq!(verifier.idle_connections(target), 0);
        first_driver_stopped(&state).await;
    }

    #[tokio::test]
    async fn an_unsent_retry_must_be_ready_before_inference() {
        let target = TARGETS[0];
        let (verifier, state) = local_verifier();
        complete_inference(&verifier, target).await;
        *state.closes_before_inference.lock().unwrap() = 1;
        state.closes_after_attestation.store(true, Ordering::SeqCst);

        let error = verifier
            .forward(inference_request(target))
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("fresh NEAR retry connection is not ready"));
        assert_eq!(state.inferences.load(Ordering::SeqCst), 1);
        assert_eq!(verifier.idle_connections(target), 0);
        first_driver_stopped(&state).await;
    }

    // Real HTTP over an in-memory connection lets Tokio advance simulated
    // time without live TLS/attestation services or wall-clock sleeps.
    async fn delayed_inference(
        target: NearTarget,
        delay: Duration,
    ) -> Result<Response<hyper::body::Incoming>> {
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;

        let (client, server) = tokio::io::duplex(4096);
        let service = service_fn(move |request: Request<hyper::body::Incoming>| async move {
            assert_eq!(request.uri().path(), target.path);
            assert_eq!(request.headers()[HOST], target.host);
            assert!(!request.headers().contains_key(SELECTOR_HEADER));
            assert_eq!(
                request.into_body().collect().await.unwrap().to_bytes(),
                "request body"
            );
            tokio::time::sleep(delay).await;
            Ok::<_, std::convert::Infallible>(Response::new(Body::from("completion")))
        });
        let server = tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(server), service)
                .await
        });
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .unwrap();
        let connection = tokio::spawn(connection);
        let request = Request::builder()
            .method(Method::POST)
            .uri(target.path)
            .header(SELECTOR_HEADER, target.model)
            .body(Body::from("request body"))
            .unwrap();
        let result = send_inference(&mut sender, upstream_request(request, target).unwrap())
            .await
            .map_err(InferenceSendError::into_anyhow);
        // These tests use a complete small body; stop both drivers on error.
        if result.is_err() {
            connection.abort();
            server.abort();
        }
        result
    }

    #[tokio::test(start_paused = true)]
    async fn inference_can_wait_longer_than_the_attestation_deadline() {
        for target in TARGETS {
            let started = tokio::time::Instant::now();
            let response = delayed_inference(target, Duration::from_secs(121))
                .await
                .unwrap();
            assert!(started.elapsed() >= Duration::from_secs(121));
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "completion"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn inference_still_times_out_at_the_route_deadline() {
        let started = tokio::time::Instant::now();
        let error = delayed_inference(TARGETS[0], Duration::from_secs(1801))
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "NEAR inference timed out");
        assert_eq!(started.elapsed(), Duration::from_secs(1800));
    }

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
    fn glm_53_flash_resolves_to_its_chat_target() {
        let target = target_for_model(GLM_53_FLASH_MODEL).unwrap();
        assert_eq!(target.host, GLM_53_FLASH_HOST);
        assert_eq!(target.path, CHAT_COMPLETIONS);

        let request = Request::builder()
            .method(Method::POST)
            .uri(CHAT_COMPLETIONS)
            .body(Body::empty())
            .unwrap();
        let upstream = upstream_request(request, target).unwrap();
        assert_eq!(upstream.headers()[HOST], GLM_53_FLASH_HOST);
        assert_eq!(upstream.uri().path(), CHAT_COMPLETIONS);
    }

    #[test]
    fn glm_53_flash_attestation_for_another_model_fails_closed() {
        let target = target_for_model(GLM_53_FLASH_MODEL).unwrap();
        let nonce = [1_u8; 32];
        let spki = [2_u8; 32];
        let different_model_attestation = attestation(nonce, spki, "z-ai/glm-5.3");
        let (report_data, mr_config_id) = fields(&different_model_attestation, nonce, spki);

        let error = verify_identity(
            &different_model_attestation,
            target,
            &nonce,
            &spki,
            AttestedFields {
                report_data: &report_data,
                mr_config_id: &mr_config_id,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("attested model"));
    }

    #[test]
    fn glm_53_flash_identity_requires_the_attested_tls_key() {
        let target = target_for_model(GLM_53_FLASH_MODEL).unwrap();
        let nonce = [1_u8; 32];
        let attested_spki = [2_u8; 32];
        let attestation = attestation(nonce, attested_spki, target.model);
        let (report_data, mr_config_id) = fields(&attestation, nonce, attested_spki);
        let fields = AttestedFields {
            report_data: &report_data,
            mr_config_id: &mr_config_id,
        };
        verify_identity(&attestation, target, &nonce, &attested_spki, fields).unwrap();

        let error = verify_identity(&attestation, target, &nonce, &[3_u8; 32], fields).unwrap_err();
        assert!(error.to_string().contains("live NEAR TLS key"));
    }

    #[test]
    fn unknown_selector_has_no_network_target() {
        assert!(target_for_model("attacker/model").is_none());
    }

    #[test]
    fn every_qualified_near_target_is_closed_listed() {
        let actual = TARGETS
            .iter()
            .map(|target| (target.model, target.host))
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            vec![
                ("Qwen/Qwen3.8-27B", "qwen3-8-27b.completions.near.ai"),
                (GLM_53_FLASH_MODEL, GLM_53_FLASH_HOST),
                (FLUX_KLEIN_MODEL, FLUX_KLEIN_HOST),
            ]
        );
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
        let flux = target_for_model(FLUX_KLEIN_MODEL).unwrap();
        for (method, path) in [
            (Method::GET, "/v1/chat/completions"),
            (Method::POST, "/v1/models"),
            (Method::POST, "/attacker"),
            (Method::GET, "/v1/images/generations"),
            (Method::POST, "/v1/images/edits"),
            (Method::POST, "/v1/images/variations"),
            (Method::POST, "/v1/images"),
        ] {
            for target in TARGETS {
                let request = Request::builder()
                    .method(&method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap();
                assert!(
                    validate_request(&request, target).is_err(),
                    "{method} {path} must be rejected for {}",
                    target.model
                );
            }
        }
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/images/generations")
            .body(Body::empty())
            .unwrap();
        validate_request(&request, flux).unwrap();
    }

    #[tokio::test]
    async fn a_selector_on_the_wrong_path_is_refused_before_any_connection() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let verifier = NearVerifier::new().unwrap();
        let flux = target_for_model(FLUX_KLEIN_MODEL).unwrap();
        for (path, target) in [(IMAGES_GENERATIONS, TARGETS[0]), (CHAT_COMPLETIONS, flux)] {
            let request = Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(SELECTOR_HEADER, target.model)
                .body(Body::empty())
                .unwrap();
            let error = format!("{:#}", verifier.forward(request).await.unwrap_err());
            assert!(
                error.contains(target.path) && !error.contains("attest"),
                "{} on {path} must be refused without an attested connection, got: {error}",
                target.model
            );
        }
    }

    #[tokio::test]
    async fn images_request_is_forwarded_unread_to_the_flux_host() {
        let body = serde_json::to_vec(&serde_json::json!({
            "model": FLUX_KLEIN_MODEL,
            "prompt": "a lighthouse at dusk",
            "n": 1,
            "size": "1024x1024",
            "response_format": "b64_json",
        }))
        .unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/images/generations")
            .header(SELECTOR_HEADER, FLUX_KLEIN_MODEL)
            .header("content-type", "application/json")
            .header(CONNECTION, "keep-alive")
            .body(Body::from(body.clone()))
            .unwrap();
        let target = target_for_model(FLUX_KLEIN_MODEL).unwrap();
        let upstream = upstream_request(request, target).unwrap();
        assert_eq!(upstream.method(), Method::POST);
        assert_eq!(upstream.uri().path(), "/v1/images/generations");
        assert_eq!(upstream.headers()[HOST], FLUX_KLEIN_HOST);
        assert!(!upstream.headers().contains_key(SELECTOR_HEADER));
        assert!(!upstream.headers().contains_key(CONNECTION));
        assert_eq!(upstream.headers()["content-type"], "application/json");
        let forwarded = upstream.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(forwarded.as_ref(), body.as_slice());
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
        retry_attestation("NEAR", || {
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
        let error = retry_attestation::<(), _, _>("NEAR", || {
            observed.fetch_add(1, Ordering::SeqCst);
            async { bail!("persistent verifier failure") }
        })
        .await
        .unwrap_err();
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            upstream_proxy::ATTESTATION_ATTEMPTS
        );
        assert!(error.to_string().contains("failed after 3 attempts"));
        assert_eq!(
            format!("{error:#}")
                .matches("persistent verifier failure")
                .count(),
            upstream_proxy::ATTESTATION_ATTEMPTS
        );
    }

    // Exercise real HTTP headers and a split body while Tokio advances time.
    async fn attestation_response(
        header_delay: Duration,
        body_delay: Duration,
        status: StatusCode,
        tail: Bytes,
    ) -> Result<Bytes> {
        use futures_util::{stream, StreamExt as _};
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use std::convert::Infallible;

        let (client, server) = tokio::io::duplex(4096);
        let service = service_fn(move |_request: Request<hyper::body::Incoming>| {
            let tail = tail.clone();
            async move {
                tokio::time::sleep(header_delay).await;
                let chunks = stream::once(async { Ok::<_, Infallible>(Bytes::from_static(b"{")) })
                    .chain(stream::once(async move {
                        tokio::time::sleep(body_delay).await;
                        Ok::<_, Infallible>(tail)
                    }));
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(status)
                        .body(Body::from_stream(chunks))
                        .unwrap(),
                )
            }
        });
        let server = tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(server), service)
                .await
        });
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .unwrap();
        let connection = tokio::spawn(connection);
        let request = Request::builder()
            .uri("/v1/attestation/report")
            .header(HOST, TARGETS[0].host)
            .body(Body::empty())
            .unwrap();
        // Bound the test itself so the original unbounded body read fails
        // promptly, rather than hanging the suite.
        let result = timeout(
            Duration::from_secs(121),
            fetch_attestation(&mut sender, request),
        )
        .await;
        connection.abort();
        server.abort();
        result.context("test watchdog expired before attestation deadline")?
    }

    #[tokio::test(start_paused = true)]
    async fn attestation_deadline_covers_headers_and_partial_body_together() {
        // Missing headers, stalled partial body, and individually short phases
        // whose combined duration exceeds 120 seconds must all time out.
        for (header_secs, body_secs) in [(121, 0), (0, 121), (90, 31)] {
            let started = tokio::time::Instant::now();
            let error = attestation_response(
                Duration::from_secs(header_secs),
                Duration::from_secs(body_secs),
                StatusCode::OK,
                Bytes::from_static(b"}"),
            )
            .await
            .unwrap_err();
            assert_eq!(error.to_string(), "NEAR attestation request timed out");
            assert_eq!(started.elapsed(), Duration::from_secs(120));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn attestation_collects_split_body_within_shared_deadline() {
        let body = attestation_response(
            Duration::from_secs(90),
            Duration::from_secs(20),
            StatusCode::OK,
            Bytes::from_static(b"\"ok\":true}"),
        )
        .await
        .unwrap();
        assert_eq!(body, "{\"ok\":true}");
    }

    #[tokio::test(start_paused = true)]
    async fn attestation_rejects_error_status_without_waiting_for_body() {
        let error = attestation_response(
            Duration::ZERO,
            Duration::from_secs(121),
            StatusCode::SERVICE_UNAVAILABLE,
            Bytes::new(),
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("attestation endpoint returned 503"));
    }

    #[tokio::test(start_paused = true)]
    async fn attestation_response_still_has_a_size_limit() {
        let error = attestation_response(
            Duration::ZERO,
            Duration::ZERO,
            StatusCode::OK,
            Bytes::from(vec![b' '; ATTESTATION_LIMIT]),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("read NEAR attestation response"));
    }
}
