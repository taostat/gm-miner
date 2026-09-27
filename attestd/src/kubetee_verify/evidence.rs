//! The checks on a `KubeTEE` `/v1/attestation` payload, apart from fetching
//! it: the DCAP appraisal, the nonce binding, the event log replay and the
//! TLS-possession proof.

use anyhow::{anyhow, ensure, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use dcap_qvl::policy::QuoteClaims;
use dcap_qvl::quote::TDReport10;
use ring::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
use serde::Deserialize;
use sha2::{Digest as _, Sha256, Sha512};
use tracing::info;
use x509_parser::oid_registry::OID_PKCS1_RSAENCRYPTION;
use x509_parser::parse_x509_certificate;

use crate::eventlog::{self, Register};
use crate::tee_evidence;

const SIGNATURE_ALGORITHM: &str = "RS256";

/// The `GET /v1/attestation` response body.
#[derive(Debug, Deserialize)]
pub struct AttestationPayload {
    pub nonce: String,
    pub quote: String,
    pub cc_eventlog: Option<String>,
    pub tls_possession: Option<TlsPossession>,
    #[serde(default)]
    pub pod: String,
}

/// A signature over the nonce made with the serving certificate's key.
#[derive(Clone, Debug, Deserialize)]
pub struct TlsPossession {
    pub tls_signature: String,
    pub tls_signature_alg: String,
    pub tls_cert_sha256: String,
}

/// The measured registers of the TD that minted a quote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measurements {
    pub mrtd: Register,
    pub mr_config_id: Register,
    pub rtmrs: [Register; 4],
}

impl Measurements {
    fn of(td: &TDReport10) -> Self {
        Self {
            mrtd: td.mr_td,
            mr_config_id: td.mr_config_id,
            rtmrs: [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3],
        }
    }
}

/// Check a verified attestation against the nonce this proxy
/// sent and the certificate of the connection it arrived on.
///
/// `claims` must come from Intel's chain of trust for `payload.quote`.
///
/// # Errors
///
/// Returns an error naming the first check that fails: the echoed nonce,
/// the DCAP appraisal, the nonce binding in `report_data`, the event log
/// replay, or the TLS-possession proof.
pub fn verify_attestation(
    payload: &AttestationPayload,
    nonce: &str,
    leaf: &[u8],
    claims: &QuoteClaims,
    now: u64,
) -> Result<Measurements> {
    ensure!(
        payload.nonce.as_bytes() == nonce.as_bytes(),
        "KubeTEE echoed a different nonce"
    );
    let td = tee_evidence::appraise(claims, now)?;
    verify_report_data(td, nonce)?;
    let measurements = Measurements::of(td);
    let log = payload
        .cc_eventlog
        .as_deref()
        .context("KubeTEE attestation has no cc_eventlog")?;
    verify_event_log(log, &measurements.rtmrs)?;
    let possession = payload
        .tls_possession
        .as_ref()
        .context("KubeTEE attestation has no tls_possession")?;
    verify_tls_possession(possession, nonce, leaf)?;
    Ok(measurements)
}

fn verify_report_data(td: &TDReport10, nonce: &str) -> Result<()> {
    let expected: [u8; 64] = Sha512::digest(nonce.as_bytes()).into();
    ensure!(
        td.report_data == expected,
        "TDX report_data is not SHA-512 of the nonce sent"
    );
    Ok(())
}

fn verify_event_log(log: &str, quoted: &[Register; 4]) -> Result<()> {
    let log = STANDARD.decode(log).context("decode KubeTEE cc_eventlog")?;
    let replayed = eventlog::replay(&eventlog::parse(&log)?);
    for (index, (replayed, quoted)) in replayed.iter().zip(quoted).enumerate() {
        ensure!(
            replayed == quoted,
            "KubeTEE event log does not replay to the quote's RTMR{index}"
        );
    }
    Ok(())
}

/// Check that the TLS-possession proof names this connection's leaf
/// certificate and that its key signed `nonce` (RSASSA-PKCS1-v1_5, SHA-256).
fn verify_tls_possession(possession: &TlsPossession, nonce: &str, leaf: &[u8]) -> Result<()> {
    ensure!(
        possession.tls_signature_alg == SIGNATURE_ALGORITHM,
        "KubeTEE TLS-possession signature is {}, expected {SIGNATURE_ALGORITHM}",
        possession.tls_signature_alg
    );
    let claimed = hex::decode(&possession.tls_cert_sha256)
        .context("decode KubeTEE TLS certificate fingerprint")?;
    ensure!(
        claimed.as_slice() == Sha256::digest(leaf).as_slice(),
        "KubeTEE TLS-possession names a certificate other than this connection's"
    );
    let (_, certificate) = parse_x509_certificate(leaf)
        .map_err(|error| anyhow!("parse KubeTEE TLS certificate: {error}"))?;
    let key = certificate.public_key();
    ensure!(
        key.algorithm.algorithm == OID_PKCS1_RSAENCRYPTION,
        "KubeTEE TLS certificate key is not RSA"
    );
    let signature = STANDARD
        .decode(&possession.tls_signature)
        .context("decode KubeTEE TLS-possession signature")?;
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &key.subject_public_key.data)
        .verify(nonce.as_bytes(), &signature)
        .map_err(|_| anyhow!("KubeTEE TLS-possession signature does not verify"))
}

/// Log the replica and measured registers of a newly attested connection.
pub fn log_attested(pod: &str, measurements: &Measurements) {
    let [rtmr0, rtmr1, rtmr2, rtmr3] = measurements.rtmrs.map(hex::encode);
    info!(
        pod,
        mrtd = hex::encode(measurements.mrtd),
        mr_config_id = hex::encode(measurements.mr_config_id),
        rtmr0,
        rtmr1,
        rtmr2,
        rtmr3,
        "KubeTEE connection attested"
    );
}
