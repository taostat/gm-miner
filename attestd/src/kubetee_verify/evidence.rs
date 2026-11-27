//! The checks on a `KubeTEE` `/v1/attestation` payload, apart from fetching
//! it: the `kubetee.attestation.v2` quote-bound key binding, the DCAP
//! appraisal, the event log replay and the key-possession proof.

use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use dcap_qvl::policy::QuoteClaims;
use dcap_qvl::quote::TDReport10;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED};
use serde::Deserialize;
use serde_json::Value;
use sha2::Digest as _;
use tracing::info;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::eventlog::{self, Register};
use crate::kubetee_verify::binding;
use crate::kubetee_verify::evidence_snp;
use crate::tee_evidence;

/// The `GET /v1/attestation` response body.
#[derive(Clone, Debug, Deserialize)]
pub struct AttestationPayload {
    pub nonce: String,
    /// The Intel TDX quote (base64). `None` on an AMD SEV-SNP gateway, whose
    /// hardware evidence lives in `evidence.snp` instead.
    pub quote: Option<String>,
    pub cc_eventlog: Option<String>,
    pub key_possession: Option<KeyPossession>,
    #[serde(default)]
    pub pod: String,
}

/// Proof that the endpoint holds the per-boot generated key the quote binds:
/// an ECDSA P-256 / SHA-256 signature over the quote-bound 64-byte
/// `report_data`, under the exact DER SPKI the v2 statement names. The
/// signature verifies only under that key — the operator-custodied serving
/// key plays no part in it.
#[derive(Clone, Debug, Deserialize)]
pub struct KeyPossession {
    /// The input class the signature covers: must be `quote_report_data`.
    pub input: String,
    /// The signature algorithm: must be `ecdsa-secp256r1-sha256`.
    pub alg: String,
    /// DER-encoded ECDSA signature, base64.
    pub signature_b64: String,
}

/// The `kubetee.attestation.v2` fields of a response: the served keyset
/// and its canonical-JCS binding statement.
#[derive(Debug, Deserialize)]
pub struct BindingFields {
    pub keyset: Value,
    pub bindings: BindingStatement,
}

#[derive(Debug, Deserialize)]
pub struct BindingStatement {
    pub version: String,
    pub report_data_statement: String,
    pub keyset_digest: String,
}

/// The pre-quote v2 binding gate: parse the served statement, re-derive it
/// field-by-field (anti-downgrade), and recompute the `report_data` the quote
/// must carry. The served keyset is checked against this connection's leaf
/// certificate: it must name the same serving key, be unexpired, and carry the
/// v2 version tag.
pub(crate) struct BindingGuard;

/// Binding fields checked against the serving key and statement. The
/// report data must still be authenticated by the quote before use.
#[derive(Debug)]
pub struct Binding {
    /// The 64-byte `report_data` the quote must carry.
    pub report_data: [u8; 64],
    /// The raw P-256 point of the per-boot key the statement binds (the key
    /// the `key_possession` proof must verify under).
    pub bound_key: Vec<u8>,
    /// UTC deadline of the served keyset.
    pub not_after: DateTime<Utc>,
}

impl Binding {
    /// Recheck after collateral fetching and quote verification, which may
    /// have taken the connection past its keyset's deadline.
    pub(crate) fn ensure_current(&self, now: DateTime<Utc>) -> Result<()> {
        ensure!(
            self.not_after > now,
            "kubetee.attestation.v2 keyset is expired"
        );
        Ok(())
    }
}

impl BindingGuard {
    /// Derive the binding to verify from `body`, or fail closed on any
    /// malformed response, one without both v2 fields, or one that does not
    /// verify.
    ///
    /// # Errors
    ///
    /// Returns an error when the response lacks `keyset` or `bindings`, or
    /// when the statement, keyset, or version check fails.
    pub(crate) fn run(
        body: &[u8],
        nonce: &str,
        leaf: &[u8],
        now: DateTime<Utc>,
    ) -> Result<Binding> {
        let payload = crate::strict_json::parse_unique_json(body)
            .context("decode KubeTEE attestation response")?;
        let keyset_present = payload.get("keyset").is_some();
        let bindings_present = payload.get("bindings").is_some();
        match (keyset_present, bindings_present) {
            (true, true) => {
                let fields: BindingFields = serde_json::from_value(payload)
                    .context("decode kubetee.attestation.v2 binding fields")?;
                ensure!(
                    fields.bindings.version == binding::PURPOSE,
                    "kubetee.attestation.v2 binding has version {}, expected {}",
                    fields.bindings.version,
                    binding::PURPOSE
                );
                let served = &fields.bindings.report_data_statement;
                let digest = &fields.bindings.keyset_digest;
                let not_after = Self::verify_served_keyset(&fields.keyset, digest, leaf)?;
                let (report_data, bound_key) =
                    Self::report_data_and_key_of_statement(served, digest, nonce)?;
                let binding = Binding {
                    report_data,
                    bound_key,
                    not_after,
                };
                binding.ensure_current(now)?;
                Ok(binding)
            }
            (false, false) => {
                bail!("KubeTEE attestation response has no kubetee.attestation.v2 binding")
            }
            _ => bail!("KubeTEE attestation response has half a v2 binding"),
        }
    }

    /// The 64-byte `report_data` a served v2 statement binds and the raw
    /// P-256 point of the key it binds. The statement is parsed, its fields
    /// re-derived into the canonical JCS (anti-downgrade — nothing is trusted
    /// as served), its nonce must be the one sent, and the derivation
    /// consumes exactly those fields.
    fn report_data_and_key_of_statement(
        statement: &str,
        keyset_digest: &str,
        nonce: &str,
    ) -> Result<([u8; 64], Vec<u8>)> {
        let fields: Value =
            serde_json::from_str(statement).context("v2 report_data_statement is not JSON")?;
        let string = |name: &str| -> Result<&str> {
            fields
                .get(name)
                .and_then(Value::as_str)
                .with_context(|| format!("v2 statement missing {name}"))
        };
        let context = string("context")?;
        let stated_digest = string("keyset_digest")?;
        let stated_nonce = binding::normalize_nonce(string("nonce")?)?;
        let pkix_b64url = string("pkix_pubkey_b64url")?;
        ensure!(
            stated_digest == keyset_digest,
            "v2 statement names a different keyset digest"
        );
        ensure!(
            stated_nonce == binding::normalize_nonce(nonce)?,
            "v2 statement names a different nonce"
        );
        let recomputed =
            binding::report_data_statement_v2(stated_digest, &stated_nonce, pkix_b64url, context)?;
        ensure!(
            recomputed == statement,
            "v2 report_data_statement is not the canonical JCS of its fields"
        );
        let pkix = binding::decode_pkix_pubkey(pkix_b64url)?;
        let bound_key = p256_point(&pkix)?;
        let report_data =
            binding::report_data_v2(&pkix, &binding::bytes_from_hex32(&stated_nonce)?, context)?;
        Ok((report_data, bound_key))
    }

    fn verify_served_keyset(
        keyset: &Value,
        stated_digest: &str,
        leaf: &[u8],
    ) -> Result<DateTime<Utc>> {
        let (_, certificate) = parse_x509_certificate(leaf)
            .map_err(|error| anyhow!("parse KubeTEE TLS certificate: {error}"))?;
        let spki = certificate.public_key().raw;
        let recomputed = binding::keyset_digest(keyset)?;
        ensure!(
            recomputed == stated_digest,
            "kubetee.attestation.v2 keyset digest does not match the served keyset"
        );
        let spki_sha256 = hex::encode(sha2::Sha256::digest(spki));
        let matches = keyset
            .get("tls_public_keys")
            .and_then(Value::as_array)
            .is_some_and(|keys| {
                keys.iter().any(|key| {
                    key.get("domain").and_then(Value::as_str) == Some(HOST_DOMAIN)
                        && key.get("spki_sha256").and_then(Value::as_str)
                            == Some(spki_sha256.as_str())
                })
            });
        ensure!(
            matches,
            "kubetee.attestation.v2 keyset does not name this connection's serving key"
        );
        let not_after = keyset
            .get("not_after")
            .and_then(Value::as_str)
            .context("kubetee.attestation.v2 keyset has no not_after")?;
        let expires = DateTime::parse_from_rfc3339(not_after)
            .context("kubetee.attestation.v2 keyset not_after is not RFC 3339")?
            .with_timezone(&Utc);
        let certificate_expires =
            DateTime::from_timestamp(certificate.validity().not_after.timestamp(), 0)
                .context("KubeTEE TLS certificate expiry is outside the supported range")?;
        ensure!(
            expires <= certificate_expires,
            "kubetee.attestation.v2 keyset not_after exceeds the serving certificate expiry"
        );
        Ok(expires)
    }
}

/// The domain the v2 keyset's serving key must name.
const HOST_DOMAIN: &str = "llm.kubetee.ai";

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

/// The measured registers of an attested upstream, whichever TEE produced the
/// hardware evidence: an Intel TDX TD ([`Measurements`]) or an AMD SEV-SNP guest
/// ([`evidence_snp::SnpMeasurements`]).
#[derive(Clone, Debug)]
pub enum TeeMeasurements {
    Tdx(Measurements),
    Snp(evidence_snp::SnpMeasurements),
}

/// Check a verified attestation against the nonce this proxy sent, the
/// `report_data` its v2 binding statement requires, the key-possession proof
/// under the quote-bound key, and the certificate of the connection it
/// arrived on.
///
/// `claims` must come from Intel's chain of trust for `payload.quote`, and
/// `binding` from [`BindingGuard::run`] on the same response (which has
/// already tied the served keyset to `leaf`, this connection's certificate).
///
/// # Errors
///
/// Returns an error naming the first check that fails: the echoed nonce,
/// the DCAP appraisal, the binding in `report_data`, the event log replay,
/// or the key-possession proof.
pub fn verify_attestation(
    payload: &AttestationPayload,
    nonce: &str,
    claims: &QuoteClaims,
    now: u64,
    binding: &Binding,
) -> Result<Measurements> {
    ensure!(
        payload.nonce.as_bytes() == nonce.as_bytes(),
        "KubeTEE echoed a different nonce"
    );
    let td = tee_evidence::appraise(claims, now)?;
    ensure!(
        td.report_data == binding.report_data,
        "TDX report_data is not the kubetee.attestation.v2 binding for the nonce sent"
    );
    let measurements = Measurements::of(td);
    let log = payload
        .cc_eventlog
        .as_deref()
        .context("KubeTEE attestation has no cc_eventlog")?;
    verify_event_log(log, &measurements.rtmrs)?;
    let possession = payload
        .key_possession
        .as_ref()
        .context("KubeTEE attestation has no key_possession")?;
    verify_key_possession(possession, &binding.report_data, &binding.bound_key)?;
    Ok(measurements)
}

/// How a response's hardware evidence is shaped — which TEE produced it and
/// where its signed evidence lives. The `kubetee.attestation.v2` SNP gateway
/// serves `evidence.snp` with a null `quote`; the Intel TDX path serves a
/// base64 `quote`. [`evidence_tee`] fails closed when the `tee` tag and the
/// evidence nodes disagree.
#[derive(Clone, Debug)]
pub(crate) enum EvidenceTee {
    /// AMD SEV-SNP: the signed report + chain live in `evidence.snp`.
    Snp {
        snp: Value,
        quote_report_data: Option<String>,
    },
    /// Intel TDX: a base64 DCAP `quote`.
    Tdx { quote: String },
}

/// Classify a response's hardware evidence from its `tee` / `evidence` /
/// `quote` fields, failing closed on any inconsistency (a `tee` that claims
/// SNP without `evidence.snp`, an `evidence.snp` on a non-SNP `tee`, or a
/// response with neither). This is the only place the two TEE paths diverge.
///
/// # Errors
///
/// Returns an error when the shape is inconsistent or no evidence is present.
pub(crate) fn evidence_tee(root: &Value) -> Result<EvidenceTee> {
    let evidence_node = root.get("evidence");
    let tee = root.get("tee").and_then(Value::as_str).unwrap_or("");
    let snp_node = evidence_node
        .and_then(|e| e.get("snp"))
        .filter(|n| !n.is_null());
    match (tee, snp_node) {
        ("snp", Some(snp)) => {
            let quote_report_data = evidence_node
                .and_then(|e| e.get("quote_report_data"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            Ok(EvidenceTee::Snp {
                snp: snp.clone(),
                quote_report_data,
            })
        }
        ("snp", None) => bail!("KubeTEE tee=snp but evidence.snp is absent"),
        (_, Some(_)) => bail!("KubeTEE evidence.snp present but tee is not snp"),
        (_, None) => {
            let quote = root
                .get("quote")
                .and_then(Value::as_str)
                .filter(|quote| !quote.is_empty())
                .context("KubeTEE attestation has no TDX quote or SNP evidence")?;
            Ok(EvidenceTee::Tdx {
                quote: quote.to_owned(),
            })
        }
    }
}

/// Check an AMD SEV-SNP attestation against the nonce this proxy sent, the
/// `report_data` its v2 binding statement requires, the key-possession proof
/// under the quote-bound key, and the connection's `evidence.snp` hardware
/// evidence.
///
/// `binding` is from [`BindingGuard::run`] on the same response (which has
/// already tied the served keyset to the connection's certificate). The SNP
/// chain is root-anchored to AMD and the report signature checked in
/// [`evidence_snp::verify_snp`].
///
/// # Errors
///
/// Returns an error naming the first check that fails: the echoed nonce, the
/// SNP chain/report appraisal, the binding in `report_data`, or the
/// key-possession proof.
pub fn verify_attestation_snp(
    payload: &AttestationPayload,
    evidence_node: &serde_json::Value,
    quote_report_data: Option<&str>,
    nonce: &str,
    binding: &Binding,
) -> Result<TeeMeasurements> {
    ensure!(
        payload.nonce.as_bytes() == nonce.as_bytes(),
        "KubeTEE echoed a different nonce"
    );
    let snp = evidence_snp::parse_snp(evidence_node)?;
    let measurements = evidence_snp::verify_snp(&snp, quote_report_data)
        .context("AMD SEV-SNP evidence appraisal")?;
    ensure!(
        measurements.report_data == binding.report_data,
        "SNP report_data is not the kubetee.attestation.v2 binding for the nonce sent"
    );
    let possession = payload
        .key_possession
        .as_ref()
        .context("KubeTEE attestation has no key_possession")?;
    verify_key_possession(possession, &binding.report_data, &binding.bound_key)?;
    Ok(TeeMeasurements::Snp(measurements))
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

/// Check that the key-possession proof verifies over the quote-bound 64-byte
/// `report_data` under the **bound** key — the DER SPKI the v2 statement
/// names — not under the TLS serving key. This is what proves the guest
/// generated (and holds) a fresh per-boot key: the signature covers the exact
/// `report_data` the hardware quote commits, and only the key committed by
/// that quote can produce it.
///
/// The proof names `input: "quote_report_data"` and
/// `alg: "ecdsa-secp256r1-sha256"` (ECDSA P-256 / SHA-256, DER encoding —
/// both DER and raw `r||s` encodings are accepted). Any other spelling,
/// a `report_data` of the wrong shape, or a signature under any other key
/// fails closed.
pub(crate) fn verify_key_possession(
    possession: &KeyPossession,
    report_data: &[u8; 64],
    bound_key: &[u8],
) -> Result<()> {
    ensure!(
        possession.input == binding::POSSESSION_INPUT,
        "KubeTEE key-possession input is {}, expected {}",
        possession.input,
        binding::POSSESSION_INPUT
    );
    ensure!(
        possession.alg == binding::POSSESSION_ALG,
        "KubeTEE key-possession signature is {}, expected {}",
        possession.alg,
        binding::POSSESSION_ALG
    );
    let signature = STANDARD
        .decode(&possession.signature_b64)
        .context("decode KubeTEE key-possession signature")?;
    ensure!(
        !signature.is_empty(),
        "KubeTEE key-possession signature is empty"
    );
    // The signature must verify under the key the quote bound (extracted
    // from the statement's `pkix_pubkey_b64url` when the binding was
    // checked). Both DER and raw `r||s` encodings are accepted.
    let algorithms: &[&dyn ring::signature::VerificationAlgorithm] =
        &[&ECDSA_P256_SHA256_ASN1, &ECDSA_P256_SHA256_FIXED];
    algorithms
        .iter()
        .find_map(|algorithm| {
            UnparsedPublicKey::new(*algorithm, bound_key)
                .verify(report_data, &signature)
                .ok()
        })
        .ok_or_else(|| anyhow!("KubeTEE key-possession signature does not verify"))
}

/// The raw uncompressed P-256 point from a DER `SubjectPublicKeyInfo` (the
/// `ecdsa-secp256r1-sha256` key class the possession proof verifies under).
pub(crate) fn p256_point(pkix: &[u8]) -> Result<Vec<u8>> {
    let (_, spki) = SubjectPublicKeyInfo::from_der(pkix)
        .map_err(|error| anyhow!("parse v2 bound SubjectPublicKeyInfo: {error}"))?;
    match spki.parsed() {
        Ok(PublicKey::EC(point)) => {
            ensure!(
                point.data().starts_with(&[0x04]) && point.data().len() == 65,
                "KubeTEE key-possession bound key is not an uncompressed P-256 point"
            );
            Ok(point.data().to_vec())
        }
        _ => bail!("KubeTEE key-possession bound key is not an EC point"),
    }
}

/// Log the replica and measured registers of a newly attested connection.
pub fn log_attested(pod: &str, measurements: &TeeMeasurements) {
    match measurements {
        TeeMeasurements::Tdx(m) => {
            let [rtmr0, rtmr1, rtmr2, rtmr3] = m.rtmrs.map(hex::encode);
            info!(
                pod,
                mrtd = hex::encode(m.mrtd),
                mr_config_id = hex::encode(m.mr_config_id),
                rtmr0,
                rtmr1,
                rtmr2,
                rtmr3,
                "KubeTEE connection attested"
            );
        }
        TeeMeasurements::Snp(m) => {
            info!(
                pod,
                measurement = hex::encode(m.measurement),
                host_data = hex::encode(m.host_data),
                policy = m.policy,
                "KubeTEE connection attested"
            );
        }
    }
}
