use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use axum::body::Body;
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
use sha2::{Digest as _, Sha256, Sha384};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::warn;

use crate::eventlog;
use crate::tee_evidence::{self, nras};
use crate::upstream_proxy::{self, retry_attestation, strip_hop_by_hop};

pub const SELECTOR_HEADER: &str = "x-gm-upstream-model";
const PROVIDER: &str = "NEAR";
const ATTESTATION_LIMIT: usize = 2 * 1024 * 1024;
const ATTESTATION_TIMEOUT: Duration = Duration::from_secs(120);
const NRAS_TIMEOUT: Duration = Duration::from_secs(60);
const NRAS_URL: &str = "https://nras.attestation.nvidia.com/v3/attest/gpu";
const CHAT_COMPLETIONS: &str = "/v1/chat/completions";
const IMAGES_GENERATIONS: &str = "/v1/images/generations";
const DSTACK_RUNTIME_EVENT_TYPE: u32 = 0x0800_0001;
const NEAR_PIN_REVIEW: &str = "NEAR identity pin mismatch; review the provider upgrade using \
    docs/sourcing.md (NEAR attestation enforcement) and deploy a miner with reviewed pins";
const NEAR_APP_ID: &str = "2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b";
const NEAR_OS_IMAGE_HASH: &str = "91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829";
const NEAR_KEY_PROVIDER_INFO: &str = r#"{"name":"kms","id":"3059301306072a8648ce3d020106082a8648ce3d03010703420004394aaed2c745e6a457cb835f7f47423f57ff3ead71b92abff6bdc14d905b319f2e13961b42c50740dae4498d9c51dd7a2e227660c9e5c504083cda06b6c11682"}"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    // Self-reported diagnostic only: neither its presence nor its contents affect acceptance.
    #[serde(default)]
    vm_config: Value,
}

#[derive(Debug, Deserialize)]
struct NearLogEvent {
    imr: usize,
    event_type: u32,
    digest: String,
    event: String,
    event_payload: String,
}

#[derive(Clone, Copy)]
struct NearOsReference {
    os_image_hash: &'static str,
    mrtd: &'static str,
    rtmr0: &'static str,
    rtmr1: &'static str,
    rtmr2: &'static str,
}

// Derive this closed boot reference from the published bundle so its provenance is independently
// reproducible. References are keyed by OS image hash; the measured tuple implicitly covers VM shape.
// The recomputation config comes from the report's self-reported info.vm_config, never a trust input.
// Recomputed from metadata version 0.5.12 with dstack-mr 0.6.1 at Dstack-TEE/dstack
// commit b307d5f85784222789952f72ca2d518e31706921. VM config: 64 vCPUs,
// 2199023255552 bytes RAM, QEMU 9.2.1, pci_hole64_size 1125899906842624, 8 GPUs, 4 NVSwitches,
// hugepages false, hotplug_off true, host_share_mode 9p, OVMF pre202505.
// Bundle: https://github.com/nearai/dstack-images/releases/download/os-image-mr/mr_91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829.tar.gz
// SHA-256(bundle): 9174506ea67da89187f1dbc917dae7582e3bb268e02b151b7f15bc8df1c3a083
const NEAR_OS_REFERENCES: &[NearOsReference] = &[NearOsReference {
    os_image_hash: NEAR_OS_IMAGE_HASH,
    mrtd: "df4d77c857de652bd0fafa343a2026b51071ee03773d076d283abf1a7d36ff91ffa279ee4a617ac664f7e2a2c8d5891b",
    rtmr0: "bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590",
    rtmr1: "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec",
    rtmr2: "bd67ab7554dc27ab03a077bc1447a1a67d0624ff547c4c809a8626f12d6a89712f8ec60e781e99b98208574065d21a71",
}];

#[derive(Debug, Deserialize)]
struct AppCompose {
    docker_compose_file: String,
}

#[derive(Clone, Copy, Debug)]
struct AttestedFields {
    report_data: [u8; 64],
    mr_config_id: [u8; 48],
    mrtd: [u8; 48],
    rtmrs: [eventlog::Register; 4],
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
            collateral: tee_evidence::collateral_client()?,
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
        upstream_proxy::finish_connection(PROVIDER, connection).await
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
        upstream_proxy::finish_connection(PROVIDER, connection).await
    }

    /// Attest the selected endpoint and forward on that same TLS connection.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported requests or any attestation/upstream
    /// failure. No inference is sent when attestation fails.
    pub async fn forward(&self, request: Request<Body>) -> Result<Response<Body>> {
        let target = request_target(&request)?;
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
        let attestation = fetch_attestation(sender, target, &nonce).await?;
        let raw_quote = hex::decode(&attestation.intel_quote).context("decode NEAR TDX quote")?;
        let claims = tee_evidence::verify_quote(&self.collateral, &raw_quote)
            .await
            .context("verify NEAR TDX quote against Intel collateral")?;
        let td = tee_evidence::td_report(&claims.report).context("NEAR attestation")?;
        let fields = AttestedFields {
            report_data: td.report_data,
            mr_config_id: td.mr_config_id,
            mrtd: td.mr_td,
            rtmrs: [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3],
        };
        verify_identity(&attestation, target, &nonce, live_spki, &fields)?;
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

async fn fetch_attestation(
    sender: &mut SendRequest<Body>,
    target: NearTarget,
    nonce: &[u8; 32],
) -> Result<NearAttestation> {
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
    serde_json::from_slice(&body).context("decode NEAR attestation response")
}

fn verify_nras_response(response: &Value) -> Result<()> {
    let verdict = nras::unverified_claims(nras::aggregate_token(response)?)?;
    nras::require_overall_success(&verdict)
}

fn request_target(request: &Request<Body>) -> Result<NearTarget> {
    let selector = request
        .headers()
        .get(SELECTOR_HEADER)
        .context("missing NEAR model selector")?
        .to_str()
        .context("NEAR model selector is not valid ASCII")?;
    let target = target_for_model(selector).context("unsupported NEAR model selector")?;
    validate_request(request, target)?;
    Ok(target)
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
    fields: &AttestedFields,
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
    verify_tls_report_binding(attestation, nonce, live_spki, &fields.report_data)?;
    let tcb_info = decode_tcb_info(attestation)?;
    let compose_hash = verify_compose_binding(&tcb_info, &fields.mr_config_id)?;
    verify_near_application_identity(
        &tcb_info,
        fields,
        &compose_hash,
        &attestation.info.vm_config,
    )
}

fn verify_tls_report_binding(
    attestation: &NearAttestation,
    nonce: &[u8; 32],
    live_spki: &[u8; 32],
    report_data: &[u8; 64],
) -> Result<()> {
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
    if report_data[..32] != expected_binding || report_data[32..] != *nonce {
        bail!("TDX report_data does not bind the signing key, live TLS key, and fresh nonce");
    }
    Ok(())
}

fn decode_tcb_info(attestation: &NearAttestation) -> Result<Value> {
    match &attestation.info.tcb_info {
        Value::Object(_) => Ok(attestation.info.tcb_info.clone()),
        Value::String(encoded) => serde_json::from_str(encoded).context("decode TCB info"),
        _ => bail!("NEAR attestation TCB info has an invalid shape"),
    }
}

fn verify_compose_binding(tcb_info: &Value, mr_config_id: &[u8; 48]) -> Result<[u8; 32]> {
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
    Ok(compose_hash)
}

// These pins establish that NEAR's dstack KMS released NEAR's app keys to this CVM,
// which booted NEAR's approved OS image and compose.
fn verify_near_application_identity(
    tcb_info: &Value,
    fields: &AttestedFields,
    compose_hash: &[u8; 32],
    self_reported_vm_config: &Value,
) -> Result<()> {
    let imr3_events = verified_imr3_events(tcb_info, &fields.rtmrs[3])?;
    let [app_id, compose, os_image, key_provider] = identity_events(&imr3_events)?;

    ensure!(
        hex::encode(event_payload(app_id)?) == NEAR_APP_ID,
        "NEAR app-id event does not identify the pinned inference application; {NEAR_PIN_REVIEW}"
    );
    // No NEAR_PIN_REVIEW here: conflicting quote-bound compose identities signal forgery,
    // not a provider upgrade requiring a new pin.
    ensure!(
        event_payload(compose)?.as_slice() == compose_hash,
        "NEAR compose-hash event does not match the verified TDX mr_config_id"
    );
    let os_image_hash = hex::encode(event_payload(os_image)?);
    verify_near_os_reference(&os_image_hash, fields, self_reported_vm_config)?;
    verify_kms_identity(key_provider)
}

fn verify_kms_identity(key_provider: &NearLogEvent) -> Result<()> {
    let key_provider: Value = serde_json::from_slice(&event_payload(key_provider)?)
        .context("decode NEAR key-provider event payload")?;
    let expected_key_provider: Value = serde_json::from_str(NEAR_KEY_PROVIDER_INFO)
        .context("decode compiled NEAR KMS identity")?;
    ensure!(
        key_provider == expected_key_provider,
        "NEAR key-provider event does not identify the pinned dstack KMS; {NEAR_PIN_REVIEW}"
    );
    Ok(())
}

fn verified_imr3_events(
    tcb_info: &Value,
    quoted_rtmr3: &eventlog::Register,
) -> Result<Vec<NearLogEvent>> {
    let raw_log = tcb_info
        .get("event_log")
        .and_then(Value::as_array)
        .context("NEAR TCB info has no event_log array")?;
    let all_events: Vec<NearLogEvent> =
        serde_json::from_value(Value::Array(raw_log.clone())).context("decode NEAR event log")?;
    let imr3_events = all_events
        .into_iter()
        .filter(|event| event.imr == 3)
        .collect::<Vec<_>>();
    ensure!(
        !imr3_events.is_empty(),
        "NEAR event log has no imr-3 events"
    );
    let replay_events = imr3_events
        .iter()
        .map(verified_eventlog_record)
        .collect::<Result<Vec<_>>>()?;
    let replayed = eventlog::replay(&replay_events)[3];
    ensure!(
        replayed == *quoted_rtmr3,
        "NEAR imr-3 event log does not replay to quote RTMR3 (replayed {}, quote {})",
        hex::encode(replayed),
        hex::encode(quoted_rtmr3)
    );
    Ok(imr3_events)
}

fn identity_events(events: &[NearLogEvent]) -> Result<[&NearLogEvent; 4]> {
    let (app_id_index, app_id) = unique_event(events, "app-id")?;
    let (compose_index, compose) = unique_event(events, "compose-hash")?;
    let (boot_mr_index, _) = unique_event(events, "boot-mr-done")?;
    // Presence proves the guest attested its KMS. Keep it unique and boot-ordered, but do not
    // pin mr_aggregated: it varies with KMS images/instances. The root key pins KMS identity.
    let (mr_kms_index, _) = unique_event(events, "mr-kms")?;
    let (os_image_index, os_image) = unique_event(events, "os-image-hash")?;
    let (key_provider_index, key_provider) = unique_event(events, "key-provider")?;
    let (system_ready_index, _) = unique_event(events, "system-ready")?;
    let indices = [
        app_id_index,
        compose_index,
        boot_mr_index,
        mr_kms_index,
        os_image_index,
        key_provider_index,
        system_ready_index,
    ];
    ensure!(
        indices.windows(2).all(|pair| pair[0] < pair[1]),
        "NEAR identity events are not in the expected dstack boot order"
    );
    Ok([app_id, compose, os_image, key_provider])
}

fn verified_eventlog_record(event: &NearLogEvent) -> Result<eventlog::Event> {
    ensure!(
        event.event_type == DSTACK_RUNTIME_EVENT_TYPE,
        "NEAR RTMR3 event {} has unsupported event type {:#x}",
        event.event,
        event.event_type
    );
    let data = event_payload(event)?;
    let digest: eventlog::Register = hex::decode(&event.digest)
        .with_context(|| format!("decode NEAR {} event digest", event.event))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("NEAR {} event digest is not 48 bytes", event.event))?;
    let mut hasher = Sha384::new();
    hasher.update(event.event_type.to_le_bytes());
    hasher.update(b":");
    hasher.update(event.event.as_bytes());
    hasher.update(b":");
    hasher.update(&data);
    ensure!(
        <[u8; 48]>::from(hasher.finalize()) == digest,
        "NEAR RTMR3 event {} digest does not match its payload",
        event.event
    );
    Ok(eventlog::Event {
        rtmr: 3,
        event_type: event.event_type,
        digest,
        data,
    })
}

fn event_payload(event: &NearLogEvent) -> Result<Vec<u8>> {
    hex::decode(&event.event_payload)
        .with_context(|| format!("decode NEAR {} event payload", event.event))
}

fn unique_event<'a>(events: &'a [NearLogEvent], name: &str) -> Result<(usize, &'a NearLogEvent)> {
    let mut matching = events
        .iter()
        .enumerate()
        .filter(|(_, event)| event.event == name);
    let first = matching
        .next()
        .with_context(|| format!("NEAR event log is missing the required {name} event"))?;
    ensure!(
        matching.next().is_none(),
        "NEAR event log has duplicate {name} events"
    );
    Ok(first)
}

fn verify_near_os_reference(
    os_image_hash: &str,
    fields: &AttestedFields,
    self_reported_vm_config: &Value,
) -> Result<()> {
    let observed = [
        fields.mrtd,
        fields.rtmrs[0],
        fields.rtmrs[1],
        fields.rtmrs[2],
    ];
    let references = NEAR_OS_REFERENCES
        .iter()
        .filter(|reference| reference.os_image_hash == os_image_hash)
        .collect::<Vec<_>>();
    for reference in &references {
        let expected = [
            reference_register(reference.mrtd, "MRTD")?,
            reference_register(reference.rtmr0, "RTMR0")?,
            reference_register(reference.rtmr1, "RTMR1")?,
            reference_register(reference.rtmr2, "RTMR2")?,
        ];
        if observed == expected {
            return Ok(());
        }
    }
    // Format diagnostics only after every reference failed to match. vm_config is self-reported
    // and appears only in this error, which the proxy also logs when rejecting the request.
    let observed_text = format!(
        "MRTD={} RTMR0={} RTMR1={} RTMR2={}",
        hex::encode(observed[0]),
        hex::encode(observed[1]),
        hex::encode(observed[2]),
        hex::encode(observed[3])
    );
    if references.is_empty() {
        bail!(
            "NEAR reports unknown OS image hash {os_image_hash}; quoted boot measurements: \
            {observed_text}; self-reported info.vm_config={self_reported_vm_config}; {NEAR_PIN_REVIEW}"
        );
    }
    let expected_text = references
        .iter()
        .map(|reference| {
            format!(
                "MRTD={} RTMR0={} RTMR1={} RTMR2={}",
                reference.mrtd, reference.rtmr0, reference.rtmr1, reference.rtmr2
            )
        })
        .collect::<Vec<_>>();
    bail!(
        "NEAR OS image hash {os_image_hash} has no approved boot measurement tuple; \
        observed {observed_text}; compiled references: {}; \
        self-reported info.vm_config={self_reported_vm_config}; {NEAR_PIN_REVIEW}",
        expected_text.join("; ")
    )
}

fn reference_register(hex_value: &str, name: &str) -> Result<eventlog::Register> {
    hex::decode(hex_value)
        .with_context(|| format!("decode compiled NEAR {name} reference"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("compiled NEAR {name} reference is not 48 bytes"))
}

/// The 502 the NEAR proxy answers with when it refuses a request.
#[must_use]
pub fn error_response(error: &anyhow::Error) -> Response<Body> {
    upstream_proxy::error_response(PROVIDER, error)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test fixtures intentionally fail hard on malformed local values"
)]
mod tests {
    use super::*;
    use axum::http::header::CONNECTION;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use sha2::Sha384;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const FLUX_KLEIN_MODEL: &str = "black-forest-labs/FLUX.2-klein-4B";
    const FLUX_KLEIN_HOST: &str = "flux2-klein.completions.near.ai";
    const GLM_53_FLASH_MODEL: &str = "z-ai/glm-5.3-flash";
    const GLM_53_FLASH_HOST: &str = "glm-5-3-flash.completions.near.ai";
    const IDENTITY_EVENTS: [&str; 7] = [
        "app-id",
        "compose-hash",
        "boot-mr-done",
        "mr-kms",
        "os-image-hash",
        "key-provider",
        "system-ready",
    ];

    fn near_fixture(name: &str) -> NearAttestation {
        let bytes = match name {
            "glm-5-3-flash" => {
                include_bytes!("../tests/fixtures/near/glm-5-3-flash.json").as_slice()
            }
            "qwen3-8-27b" => include_bytes!("../tests/fixtures/near/qwen3-8-27b.json").as_slice(),
            "flux2-klein" => include_bytes!("../tests/fixtures/near/flux2-klein.json").as_slice(),
            _ => unreachable!(),
        };
        serde_json::from_slice(bytes).unwrap()
    }

    fn fixture_fields(attestation: &NearAttestation) -> AttestedFields {
        let quote_bytes = hex::decode(&attestation.intel_quote).unwrap();
        let quote = dcap_qvl::quote::Quote::parse(&quote_bytes).unwrap();
        let td = tee_evidence::td_report(&quote.report).unwrap();
        AttestedFields {
            report_data: td.report_data,
            mr_config_id: td.mr_config_id,
            mrtd: td.mr_td,
            rtmrs: [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3],
        }
    }

    fn verify_fixture(attestation: &NearAttestation, fields: &AttestedFields) -> Result<()> {
        let nonce: [u8; 32] = hex::decode(&attestation.request_nonce)
            .unwrap()
            .try_into()
            .unwrap();
        let spki: [u8; 32] = hex::decode(&attestation.tls_cert_fingerprint)
            .unwrap()
            .try_into()
            .unwrap();
        let target = target_for_model(&attestation.model_name)
            .context("fixture model is not an allowlisted NEAR target")?;
        verify_identity(attestation, target, &nonce, &spki, fields)
    }

    fn verify_fixture_application_identity(
        attestation: &NearAttestation,
        fields: &AttestedFields,
    ) -> Result<()> {
        let tcb_info = decode_tcb_info(attestation)?;
        let compose_hash = verify_compose_binding(&tcb_info, &fields.mr_config_id)?;
        verify_near_application_identity(
            &tcb_info,
            fields,
            &compose_hash,
            &attestation.info.vm_config,
        )
    }

    fn event_log_mut(attestation: &mut NearAttestation) -> &mut Vec<Value> {
        attestation.info.tcb_info["event_log"]
            .as_array_mut()
            .unwrap()
    }

    fn rewrite_event_payload(attestation: &mut NearAttestation, name: &str, payload: &[u8]) {
        let event = event_log_mut(attestation)
            .iter_mut()
            .find(|event| event["imr"].as_u64() == Some(3) && event["event"] == name)
            .unwrap();
        let event_type = u32::try_from(event["event_type"].as_u64().unwrap()).unwrap();
        let mut preimage = event_type.to_le_bytes().to_vec();
        preimage.extend_from_slice(b":");
        preimage.extend_from_slice(name.as_bytes());
        preimage.extend_from_slice(b":");
        preimage.extend_from_slice(payload);
        event["event_payload"] = Value::String(hex::encode(payload));
        event["digest"] = Value::String(hex::encode(Sha384::digest(preimage)));
    }

    fn replay_fixture_rtmr3(attestation: &NearAttestation) -> eventlog::Register {
        let events = attestation.info.tcb_info["event_log"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| event["imr"].as_u64() == Some(3))
            .map(|event| eventlog::Event {
                rtmr: 3,
                event_type: u32::try_from(event["event_type"].as_u64().unwrap()).unwrap(),
                digest: hex::decode(event["digest"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                data: hex::decode(event["event_payload"].as_str().unwrap()).unwrap(),
            })
            .collect::<Vec<_>>();
        eventlog::replay(&events)[3]
    }

    fn align_fixture_quote_rtmr3(attestation: &NearAttestation, fields: &mut AttestedFields) {
        fields.rtmrs[3] = replay_fixture_rtmr3(attestation);
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
                vm_config: Value::Null,
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
            &AttestedFields {
                report_data,
                mr_config_id,
                mrtd: [0; 48],
                rtmrs: [[0; 48]; 4],
            },
        )
    }

    #[test]
    fn real_near_reports_pass_identity_checks() {
        for name in ["glm-5-3-flash", "qwen3-8-27b", "flux2-klein"] {
            let report = near_fixture(name);
            let fields = fixture_fields(&report);
            verify_fixture_application_identity(&report, &fields).unwrap();
        }
    }

    #[test]
    fn another_app_id_is_rejected_after_event_log_replay() {
        let mut report = near_fixture("qwen3-8-27b");
        rewrite_event_payload(&mut report, "app-id", &[0x99; 20]);
        let mut fields = fixture_fields(&report);
        align_fixture_quote_rtmr3(&report, &mut fields);
        let error = verify_fixture(&report, &fields).unwrap_err();
        assert!(error.to_string().contains("app-id"), "{error:#}");
    }

    #[test]
    fn another_kms_id_is_rejected_after_event_log_replay() {
        let mut report = near_fixture("qwen3-8-27b");
        let event = event_log_mut(&mut report)
            .iter()
            .find(|event| event["imr"].as_u64() == Some(3) && event["event"] == "key-provider")
            .unwrap();
        let mut key_provider: Value =
            serde_json::from_slice(&hex::decode(event["event_payload"].as_str().unwrap()).unwrap())
                .unwrap();
        key_provider["id"] =
            Value::String("3059301306072a8648ce3d020106082a8648ce3d0301070303420000".to_owned());
        let payload = serde_json::to_vec(&key_provider).unwrap();
        rewrite_event_payload(&mut report, "key-provider", &payload);
        let mut fields = fixture_fields(&report);
        align_fixture_quote_rtmr3(&report, &mut fields);
        let error = verify_fixture(&report, &fields).unwrap_err();
        assert!(error.to_string().contains("key-provider"), "{error:#}");
    }

    #[test]
    fn another_mr_kms_measurement_passes_after_event_log_replay() {
        let mut report = near_fixture("qwen3-8-27b");
        rewrite_event_payload(&mut report, "mr-kms", &[0x5A; 32]);
        let mut fields = fixture_fields(&report);
        let error = verify_fixture(&report, &fields).unwrap_err();
        assert!(error.to_string().contains("does not replay"), "{error:#}");
        align_fixture_quote_rtmr3(&report, &mut fields);
        verify_fixture(&report, &fields).unwrap();
    }

    #[test]
    fn an_unknown_os_hash_is_rejected_with_its_measurements() {
        let mut report = near_fixture("qwen3-8-27b");
        rewrite_event_payload(&mut report, "os-image-hash", &[0xA5; 32]);
        let mut fields = fixture_fields(&report);
        align_fixture_quote_rtmr3(&report, &mut fields);
        let error = verify_fixture(&report, &fields).unwrap_err();
        assert!(
            error.to_string().contains(&hex::encode([0xA5; 32])),
            "{error:#}"
        );
        assert!(error.to_string().contains("MRTD"), "{error:#}");
    }

    #[test]
    fn a_mismatched_boot_measurement_tuple_is_rejected() {
        let report = near_fixture("qwen3-8-27b");
        for index in 0..4 {
            let mut fields = fixture_fields(&report);
            let register = match index {
                0 => &mut fields.mrtd,
                _ => &mut fields.rtmrs[index - 1],
            };
            register[0] ^= 1;
            let error = verify_fixture(&report, &fields).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("no approved boot measurement tuple"),
                "register {index}: {error:#}"
            );
        }
    }

    #[test]
    fn os_reference_mismatches_report_and_log_self_reported_vm_config() {
        struct LogWriter(Arc<std::sync::Mutex<Vec<u8>>>);

        impl std::io::Write for LogWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = Arc::clone(&log);
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(move || LogWriter(Arc::clone(&writer)))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            for unknown_os in [false, true] {
                let raw: Value = serde_json::from_slice(include_bytes!(
                    "../tests/fixtures/near/qwen3-8-27b.json"
                ))
                .unwrap();
                let diagnostic =
                    format!("self-reported info.vm_config={}", raw["info"]["vm_config"]);
                let mut report: NearAttestation = serde_json::from_value(raw).unwrap();
                let mut fields = fixture_fields(&report);
                if unknown_os {
                    rewrite_event_payload(&mut report, "os-image-hash", &[0xA5; 32]);
                    align_fixture_quote_rtmr3(&report, &mut fields);
                } else {
                    fields.mrtd[0] ^= 1;
                }
                let error = verify_fixture(&report, &fields).unwrap_err();
                assert!(error.to_string().contains(&diagnostic), "{error:#}");
                log.lock().unwrap().clear();
                let response = error_response(&error);
                assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
                let logged = String::from_utf8(log.lock().unwrap().clone()).unwrap();
                assert!(logged.contains(&diagnostic), "{logged}");
            }
        });
    }

    #[test]
    fn self_reported_vm_config_never_changes_os_reference_acceptance() {
        let original: Value =
            serde_json::from_slice(include_bytes!("../tests/fixtures/near/qwen3-8-27b.json"))
                .unwrap();
        for vm_config in [
            None,
            Some(Value::Null),
            Some(original["info"]["vm_config"].clone()),
            Some(Value::String("not even JSON".into())),
            Some(serde_json::json!({"os_image_hash": "untrusted", "cpu_count": 1})),
        ] {
            let mut raw = original.clone();
            if let Some(config) = vm_config {
                raw["info"]["vm_config"] = config;
            } else {
                raw["info"].as_object_mut().unwrap().remove("vm_config");
            }
            let mut report: NearAttestation = serde_json::from_value(raw).unwrap();
            let fields = fixture_fields(&report);
            verify_fixture(&report, &fields).unwrap();

            let mut mismatched = fields;
            mismatched.mrtd[0] ^= 1;
            let error = verify_fixture(&report, &mismatched).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("no approved boot measurement tuple"),
                "{error:#}"
            );

            rewrite_event_payload(&mut report, "os-image-hash", &[0xA5; 32]);
            let mut unknown = fields;
            align_fixture_quote_rtmr3(&report, &mut unknown);
            let error = verify_fixture(&report, &unknown).unwrap_err();
            assert!(
                error.to_string().contains("unknown OS image hash"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn a_tampered_payload_cannot_replay_to_the_quote_rtmr3() {
        let mut report = near_fixture("qwen3-8-27b");
        rewrite_event_payload(&mut report, "app-id", &[0x99; 20]);
        let fields = fixture_fields(&near_fixture("qwen3-8-27b"));
        let error = verify_fixture(&report, &fields).unwrap_err();
        assert!(error.to_string().contains("RTMR3"), "{error:#}");
    }

    #[test]
    fn a_payload_cannot_be_detached_from_its_extended_digest() {
        let mut report = near_fixture("qwen3-8-27b");
        let event = event_log_mut(&mut report)
            .iter_mut()
            .find(|event| event["imr"].as_u64() == Some(3) && event["event"] == "app-id")
            .unwrap();
        event["event_payload"] = Value::String(hex::encode([0x99; 20]));
        let fields = fixture_fields(&near_fixture("qwen3-8-27b"));
        let error = verify_fixture(&report, &fields).unwrap_err();
        assert!(
            error.to_string().contains("digest does not match"),
            "{error:#}"
        );
    }

    #[test]
    fn missing_identity_or_boot_boundary_events_are_rejected() {
        for name in IDENTITY_EVENTS {
            let mut report = near_fixture("qwen3-8-27b");
            event_log_mut(&mut report).retain(|event| event["event"] != name);
            let mut fields = fixture_fields(&report);
            align_fixture_quote_rtmr3(&report, &mut fields);
            let error = verify_fixture(&report, &fields).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("missing the required {name}")),
                "{error:#}"
            );
        }
    }

    #[test]
    fn duplicate_identity_or_boot_boundary_events_after_system_ready_are_rejected() {
        for name in IDENTITY_EVENTS {
            let mut report = near_fixture("qwen3-8-27b");
            let duplicate = event_log_mut(&mut report)
                .iter()
                .find(|event| event["event"] == name)
                .unwrap()
                .clone();
            event_log_mut(&mut report).push(duplicate);
            let mut fields = fixture_fields(&report);
            align_fixture_quote_rtmr3(&report, &mut fields);
            let error = verify_fixture(&report, &fields).unwrap_err();
            assert!(
                error.to_string().contains(&format!("duplicate {name}")),
                "{error:#}"
            );
        }
    }

    #[test]
    fn compose_hash_event_must_match_mr_config_id() {
        let mut report = near_fixture("qwen3-8-27b");
        rewrite_event_payload(&mut report, "compose-hash", &[0xCC; 32]);
        let mut fields = fixture_fields(&report);
        align_fixture_quote_rtmr3(&report, &mut fields);
        let error = verify_fixture(&report, &fields).unwrap_err();
        assert!(error.to_string().contains("compose-hash"), "{error:#}");
        assert!(!error.to_string().contains(NEAR_PIN_REVIEW), "{error:#}");
    }

    #[test]
    fn unsupported_imr3_event_types_fail_even_with_valid_digests_and_replay() {
        for event_type in [0, 3, 0x0800_0002, u32::MAX] {
            let mut report = near_fixture("qwen3-8-27b");
            let event = event_log_mut(&mut report)
                .iter_mut()
                .find(|event| event["event"] == "app-id")
                .unwrap();
            event["event_type"] = event_type.into();
            rewrite_event_payload(&mut report, "app-id", &hex::decode(NEAR_APP_ID).unwrap());
            let mut fields = fixture_fields(&report);
            align_fixture_quote_rtmr3(&report, &mut fields);
            let error = verify_fixture(&report, &fields).unwrap_err();
            assert!(error.to_string().contains("event type"), "{error:#}");
        }
    }

    #[test]
    fn pin_mismatch_errors_point_to_the_reviewed_upgrade_procedure() {
        for name in ["app-id", "os-image-hash", "key-provider"] {
            let mut report = near_fixture("qwen3-8-27b");
            let payload = if name == "key-provider" {
                br#"{"name":"kms","id":"00"}"#.to_vec()
            } else {
                vec![0; 32]
            };
            rewrite_event_payload(&mut report, name, &payload);
            let mut fields = fixture_fields(&report);
            align_fixture_quote_rtmr3(&report, &mut fields);
            let error = format!("{:#}", verify_fixture(&report, &fields).unwrap_err());
            assert!(error.contains("docs/sourcing.md"), "{name}: {error}");
        }
        let report = near_fixture("qwen3-8-27b");
        let mut fields = fixture_fields(&report);
        fields.mrtd[0] ^= 1;
        let error = format!("{:#}", verify_fixture(&report, &fields).unwrap_err());
        assert!(error.contains("docs/sourcing.md"), "{error}");
    }

    #[test]
    fn identity_events_must_precede_system_ready_in_boot_order() {
        for names in IDENTITY_EVENTS.windows(2) {
            let mut report = near_fixture("qwen3-8-27b");
            let log = event_log_mut(&mut report);
            let first = log
                .iter()
                .position(|event| event["event"] == names[0])
                .unwrap();
            let second = log
                .iter()
                .position(|event| event["event"] == names[1])
                .unwrap();
            log.swap(first, second);
            let mut fields = fixture_fields(&report);
            align_fixture_quote_rtmr3(&report, &mut fields);
            let error = verify_fixture(&report, &fields).unwrap_err();
            assert!(
                error.to_string().contains("boot order"),
                "{names:?}: {error:#}"
            );
        }
    }

    #[test]
    fn every_imr3_payload_and_digest_is_checked_including_unknown_runtime_events() {
        let original = near_fixture("glm-5-3-flash");
        let fields = fixture_fields(&original);
        for (index, event) in original.info.tcb_info["event_log"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            if event["imr"] != 3 {
                continue;
            }
            for field in ["event_payload", "digest"] {
                let mut report = near_fixture("glm-5-3-flash");
                event_log_mut(&mut report)[index][field] = hex::encode([0; 48]).into();
                let error = verify_fixture_application_identity(&report, &fields).unwrap_err();
                assert!(
                    error.to_string().contains("digest does not match"),
                    "{event}: {error:#}"
                );
            }
        }
    }

    #[test]
    fn unknown_runtime_events_are_replayed_after_system_ready() {
        let mut report = near_fixture("glm-5-3-flash");
        let mut fields = fixture_fields(&report);
        rewrite_event_payload(
            &mut report,
            "nearai-replica-report-key-v1",
            b"another runtime value",
        );
        let error = verify_fixture_application_identity(&report, &fields).unwrap_err();
        assert!(error.to_string().contains("does not replay"), "{error:#}");
        align_fixture_quote_rtmr3(&report, &mut fields);
        verify_fixture_application_identity(&report, &fields).unwrap();
    }

    #[test]
    fn self_reported_tcb_fields_cannot_override_quote_or_replayed_events() {
        let mut report = near_fixture("qwen3-8-27b");
        let fields = fixture_fields(&report);
        for field in [
            "mrtd",
            "rtmr0",
            "rtmr1",
            "rtmr2",
            "rtmr3",
            "os_image_hash",
            "compose_hash",
            "app_id",
            "mr_kms",
            "key_provider",
        ] {
            report.info.tcb_info[field] = "untrusted".into();
        }
        verify_fixture(&report, &fields).unwrap();
        rewrite_event_payload(&mut report, "app-id", &[0; 20]);
        report.info.tcb_info["app_id"] = NEAR_APP_ID.into();
        let mut fields = fields;
        align_fixture_quote_rtmr3(&report, &mut fields);
        let error = verify_fixture(&report, &fields).unwrap_err();
        assert!(error.to_string().contains("app-id"), "{error:#}");
    }

    #[test]
    fn identity_events_in_other_registers_cannot_supply_missing_imr3_identity() {
        let mut report = near_fixture("qwen3-8-27b");
        event_log_mut(&mut report)
            .iter_mut()
            .find(|event| event["event"] == "app-id")
            .unwrap()["imr"] = 2.into();
        let mut fields = fixture_fields(&report);
        align_fixture_quote_rtmr3(&report, &mut fields);
        let error = verify_fixture(&report, &fields).unwrap_err();
        assert!(
            error.to_string().contains("missing the required app-id"),
            "{error:#}"
        );
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
            &AttestedFields {
                report_data,
                mr_config_id,
                mrtd: [0; 48],
                rtmrs: [[0; 48]; 4],
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
            &AttestedFields {
                report_data,
                mr_config_id,
                mrtd: [0; 48],
                rtmrs: [[0; 48]; 4],
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
}
