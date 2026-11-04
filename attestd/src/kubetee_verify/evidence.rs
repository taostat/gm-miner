//! The checks on a `KubeTEE` `/v1/attestation` payload, apart from fetching
//! it: the `kubetee.attestation.v1` binding, the DCAP appraisal, the event
//! log replay and the TLS-possession proof.

use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use dcap_qvl::policy::QuoteClaims;
use dcap_qvl::quote::TDReport10;
use ring::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tracing::info;
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_PKCS1_RSAENCRYPTION};
use x509_parser::parse_x509_certificate;

use crate::eventlog::{self, Register};
use crate::kubetee_verify::binding;
use crate::tee_evidence;

/// The signature algorithms a TLS-possession proof may name: `ES256` (ECDSA
/// over SHA-256 on P-256 — the per-boot serving key) and `RS256` (RSASSA-
/// PKCS1-v1_5 over SHA-256 — an RSA serving key). The proof is accepted in
/// the encoding the named algorithm implies and fails closed on any other
/// spelling or on a key-type mismatch.
const ES256: &str = "ES256";
const RS256: &str = "RS256";

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

/// The `kubetee.attestation.v1` fields of a response: the served keyset
/// and its binding statement (spec sections 4-5).
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

/// The pre-quote v1 binding gate: hash the exact statement bytes into the
/// `report_data` the quote must carry. The served keyset is checked against
/// this connection's leaf certificate: it must name the same serving key,
/// be unexpired, and carry the v1 version tag.
pub(crate) struct BindingGuard;

/// Binding fields checked against the serving key and statement. The
/// report data must still be authenticated by the quote before use.
#[derive(Debug)]
pub(crate) struct Binding {
    pub report_data: [u8; 64],
    pub not_after: DateTime<Utc>,
}

impl Binding {
    /// Recheck after collateral fetching and quote verification, which may
    /// have taken the connection past its keyset's deadline.
    pub(crate) fn ensure_current(&self, now: DateTime<Utc>) -> Result<()> {
        ensure!(
            self.not_after > now,
            "kubetee.attestation.v1 keyset is expired"
        );
        Ok(())
    }
}

impl BindingGuard {
    /// Derive the binding to verify from `body`, or fail closed on any
    /// malformed response, one without both v1 fields, or one that does not
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
                    .context("decode kubetee.attestation.v1 binding fields")?;
                ensure!(
                    fields.bindings.version == binding::PURPOSE,
                    "kubetee.attestation.v1 binding has version {}, expected {}",
                    fields.bindings.version,
                    binding::PURPOSE
                );
                let not_after = Self::verify_served_keyset(
                    &fields.keyset,
                    &fields.bindings.keyset_digest,
                    leaf,
                )?;
                let report_data = binding::report_data_of_statement(
                    &fields.bindings.report_data_statement,
                    &fields.bindings.keyset_digest,
                    nonce,
                )?;
                let binding = Binding {
                    report_data,
                    not_after,
                };
                binding.ensure_current(now)?;
                Ok(binding)
            }
            (false, false) => {
                bail!("KubeTEE attestation response has no kubetee.attestation.v1 binding")
            }
            _ => bail!("KubeTEE attestation response has half a v1 binding"),
        }
    }

    fn verify_served_keyset(
        keyset: &Value,
        stated_digest: &str,
        leaf: &[u8],
    ) -> Result<DateTime<Utc>> {
        let (_, certificate) = parse_x509_certificate(leaf)
            .map_err(|error| anyhow!("parse KubeTEE TLS certificate: {error}"))?;
        let spki = certificate.public_key().raw;
        let recomputed = binding::recompute_keyset_digest(keyset)?;
        ensure!(
            recomputed == stated_digest,
            "kubetee.attestation.v1 keyset digest does not match the served keyset"
        );
        let spki_sha256 = hex::encode(Sha256::digest(spki));
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
            "kubetee.attestation.v1 keyset does not name this connection's serving key"
        );
        let not_after = keyset
            .get("not_after")
            .and_then(Value::as_str)
            .context("kubetee.attestation.v1 keyset has no not_after")?;
        let expires = DateTime::parse_from_rfc3339(not_after)
            .context("kubetee.attestation.v1 keyset not_after is not RFC 3339")?
            .with_timezone(&Utc);
        let certificate_expires =
            DateTime::from_timestamp(certificate.validity().not_after.timestamp(), 0)
                .context("KubeTEE TLS certificate expiry is outside the supported range")?;
        ensure!(
            expires <= certificate_expires,
            "kubetee.attestation.v1 keyset not_after exceeds the serving certificate expiry"
        );
        Ok(expires)
    }
}

/// The domain the v1 keyset's serving key must name.
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

/// Check a verified attestation against the nonce this proxy sent, the
/// `report_data` its v1 binding statement requires, and the certificate of
/// the connection it arrived on.
///
/// `claims` must come from Intel's chain of trust for `payload.quote`, and
/// `report_data` from [`BindingGuard::run`] on the same response.
///
/// # Errors
///
/// Returns an error naming the first check that fails: the echoed nonce,
/// the DCAP appraisal, the binding in `report_data`, the event log replay,
/// or the TLS-possession proof.
pub fn verify_attestation(
    payload: &AttestationPayload,
    nonce: &str,
    leaf: &[u8],
    claims: &QuoteClaims,
    now: u64,
    report_data: &[u8; 64],
) -> Result<Measurements> {
    ensure!(
        payload.nonce.as_bytes() == nonce.as_bytes(),
        "KubeTEE echoed a different nonce"
    );
    let td = tee_evidence::appraise(claims, now)?;
    ensure!(
        td.report_data == *report_data,
        "TDX report_data is not the kubetee.attestation.v1 binding for the nonce sent"
    );
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
/// certificate and that its key signed `nonce`. The proof names its
/// algorithm (`tls_signature_alg`): `ES256` is ECDSA over SHA-256 with the
/// certificate's P-256 key — raw `r||s` (64 bytes) or ASN.1 DER, both
/// accepted — and `RS256` is RSASSA-PKCS1-v1_5 over SHA-256 with its RSA
/// key. Any other algorithm, or one that does not match the certificate's
/// key type, fails closed.
fn verify_tls_possession(possession: &TlsPossession, nonce: &str, leaf: &[u8]) -> Result<()> {
    let claimed = hex::decode(&possession.tls_cert_sha256)
        .context("decode KubeTEE TLS certificate fingerprint")?;
    ensure!(
        claimed.as_slice() == Sha256::digest(leaf).as_slice(),
        "KubeTEE TLS-possession names a certificate other than this connection's"
    );
    let (_, certificate) = parse_x509_certificate(leaf)
        .map_err(|error| anyhow!("parse KubeTEE TLS certificate: {error}"))?;
    let key = certificate.public_key();
    let signature = STANDARD
        .decode(&possession.tls_signature)
        .context("decode KubeTEE TLS-possession signature")?;
    match possession.tls_signature_alg.as_str() {
        RS256 => {
            ensure!(
                key.algorithm.algorithm == OID_PKCS1_RSAENCRYPTION,
                "KubeTEE TLS-possession signature is RS256 but the certificate key is not RSA"
            );
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &key.subject_public_key.data)
                .verify(nonce.as_bytes(), &signature)
                .map_err(|_| anyhow!("KubeTEE TLS-possession signature does not verify"))
        }
        ES256 => {
            ensure!(
                key.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY
                    && key
                        .algorithm
                        .parameters
                        .as_ref()
                        .and_then(|params| params.as_oid().ok())
                        .is_some_and(|curve| curve == OID_EC_P256),
                "KubeTEE TLS-possession signature is ES256 but the certificate key is not P-256"
            );
            // Both encodings are accepted. DER can also be 64 bytes when
            // its integers are short, so length cannot distinguish them.
            let algorithms: &[&dyn ring::signature::VerificationAlgorithm] =
                &[&ECDSA_P256_SHA256_FIXED, &ECDSA_P256_SHA256_ASN1];
            algorithms
                .iter()
                .find_map(|algorithm| {
                    UnparsedPublicKey::new(*algorithm, &key.subject_public_key.data)
                        .verify(nonce.as_bytes(), &signature)
                        .ok()
                })
                .ok_or_else(|| anyhow!("KubeTEE TLS-possession signature does not verify"))
        }
        other => bail!("KubeTEE TLS-possession signature is {other}, expected {ES256} or {RS256}"),
    }
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

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test fixtures intentionally fail hard on malformed local values"
    )]

    use ring::rand::SystemRandom;
    use ring::signature::{
        EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING,
    };

    use super::*;

    const SESSION_LEAF: &[u8] = include_bytes!("../../tests/fixtures/kubetee/session_leaf.der");
    const EC_SESSION_LEAF: &[u8] =
        include_bytes!("../../tests/fixtures/kubetee/ec_session_leaf.der");
    const EC_SESSION_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/kubetee/ec_session_leaf_key.pk8");
    const FIXTURE_NONCE: &str = "cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a";
    const FIXTURE_KEYSET_DIGEST: &str =
        "sha256:64f6b8c71a0452909b382f5abcaaa6a76ae5b58bf930ff8f78f5074e4a64873d";
    const FIXTURE_STATEMENT: &str = r#"{"keyset_digest":"sha256:64f6b8c71a0452909b382f5abcaaa6a76ae5b58bf930ff8f78f5074e4a64873d","nonce":"cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a","purpose":"kubetee.attestation.v1"}"#;

    const SPKI_SHA256: &str = "3f728244ad1bb95542b14cdbf7f637105dc588f8958c862e4beffc450c000cd3";

    fn fixture_now() -> DateTime<Utc> {
        "2026-10-01T00:00:00Z".parse().unwrap()
    }

    fn v1_keyset(not_after: &str, spki: &str) -> Value {
        serde_json::json!({
            "subject": "kubetee.attestation.v1/llm.kubetee.ai",
            "not_after": not_after,
            "tls_public_keys": [{"domain": "llm.kubetee.ai", "spki_sha256": spki}],
            "signing_keys": [],
            "e2ee_keys": []
        })
    }

    fn statement(digest: &str, nonce: &str) -> String {
        format!("{{\"keyset_digest\":\"{digest}\",\"nonce\":\"{nonce}\",\"purpose\":\"kubetee.attestation.v1\"}}")
    }

    fn fixture_body(keyset: &Value, statement: &str, digest: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "nonce": FIXTURE_NONCE,
            "keyset": keyset,
            "bindings": {"version": "kubetee.attestation.v1", "report_data_statement": statement, "keyset_digest": digest}
        }))
        .unwrap()
    }

    fn self_consistent_body(not_after: &str, spki: &str) -> Vec<u8> {
        let keyset = v1_keyset(not_after, spki);
        let digest = binding::recompute_keyset_digest(&keyset).unwrap();
        let stmt = statement(&digest, FIXTURE_NONCE);
        fixture_body(&keyset, &stmt, &digest)
    }

    #[test]
    fn a_v1_response_binds_the_serving_key() {
        let keyset = v1_keyset("2026-12-01T00:00:00Z", SPKI_SHA256);
        let digest = binding::recompute_keyset_digest(&keyset).unwrap();
        let stmt = statement(&digest, FIXTURE_NONCE);
        let body = fixture_body(&keyset, &stmt, &digest);
        let bound = BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF, fixture_now()).unwrap();
        assert_eq!(
            bound.report_data,
            binding::report_data_of_statement(&stmt, &digest, FIXTURE_NONCE).unwrap()
        );
        assert_eq!(bound.report_data[32..], [0; 32]);
        assert_eq!(
            bound.not_after,
            "2026-12-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn a_response_without_the_v1_binding_fails_closed() {
        let body = br#"{"nonce":"cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a","quote":"","report_data_input":"sha512(nonce)"}"#;
        let error =
            BindingGuard::run(body, FIXTURE_NONCE, SESSION_LEAF, fixture_now()).unwrap_err();
        assert!(format!("{error:#}").contains("no kubetee.attestation.v1 binding"));
    }

    #[test]
    fn a_v1_keyset_for_another_serving_key_fails_closed() {
        let body = self_consistent_body("2026-12-01T00:00:00Z", &"0".repeat(64));
        let error =
            BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF, fixture_now()).unwrap_err();
        assert!(format!("{error:#}").contains("serving key"));
    }

    #[test]
    fn a_v1_keyset_expired_fails_closed() {
        let body = self_consistent_body("2000-01-01T00:00:00Z", SPKI_SHA256);
        let error =
            BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF, fixture_now()).unwrap_err();
        assert!(format!("{error:#}").contains("expired"));
    }

    #[test]
    fn a_v1_binding_expires_at_its_deadline_including_after_verification_work() {
        let deadline = "2026-12-01T00:00:00.123456789Z"
            .parse::<DateTime<Utc>>()
            .unwrap();
        let body = self_consistent_body("2026-12-01T00:00:00.123456789Z", SPKI_SHA256);
        let before = deadline - chrono::Duration::nanoseconds(1);
        let binding = BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF, before).unwrap();
        assert_eq!(binding.not_after, deadline);
        binding.ensure_current(before).unwrap();
        for now in [deadline, deadline + chrono::Duration::nanoseconds(1)] {
            // The same check runs after collateral/quote verification, before
            // a fresh attestation can authorize its first upstream request.
            assert!(binding
                .ensure_current(now)
                .unwrap_err()
                .to_string()
                .contains("expired"));
            assert!(BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF, now)
                .unwrap_err()
                .to_string()
                .contains("expired"));
        }
    }

    #[test]
    fn a_half_v1_response_fails_closed() {
        let body = br#"{"nonce":"cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a","keyset":{}}"#;
        let error =
            BindingGuard::run(body, FIXTURE_NONCE, SESSION_LEAF, fixture_now()).unwrap_err();
        assert!(format!("{error:#}").contains("half a v1 binding"));
    }

    #[test]
    fn the_statement_binding_matches_the_python_builder() {
        let bound = binding::report_data_of_statement(
            FIXTURE_STATEMENT,
            FIXTURE_KEYSET_DIGEST,
            FIXTURE_NONCE,
        )
        .unwrap();
        assert_eq!(
            hex::encode(bound),
            "9e4867826f437965258b4bcf964e603e30d31b662a4f3ef0ffc50cba611633710000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn a_valid_64_byte_der_es256_proof_is_not_misclassified_as_fixed() {
        let leaf = include_bytes!("../../tests/fixtures/kubetee/ec_short_der_leaf.der");
        let signature = include_bytes!("../../tests/fixtures/kubetee/ec_short_der_signature.der");
        assert_eq!(signature.len(), 64);
        let (_, certificate) = parse_x509_certificate(leaf).unwrap();
        // Prove this is a valid DER signature before exercising dispatch.
        UnparsedPublicKey::new(
            &ECDSA_P256_SHA256_ASN1,
            &certificate.public_key().subject_public_key.data,
        )
        .verify(FIXTURE_NONCE.as_bytes(), signature)
        .unwrap();
        let possession = TlsPossession {
            tls_signature: STANDARD.encode(signature),
            tls_signature_alg: ES256.to_owned(),
            tls_cert_sha256: hex::encode(Sha256::digest(leaf)),
        };
        verify_tls_possession(&possession, FIXTURE_NONCE, leaf).unwrap();
        assert!(verify_tls_possession(&possession, "different-nonce", leaf).is_err());
    }

    #[test]
    fn a_keyset_must_not_outlive_its_serving_certificate() {
        let (_, certificate) = parse_x509_certificate(SESSION_LEAF).unwrap();
        let cert_deadline =
            DateTime::from_timestamp(certificate.validity().not_after.timestamp(), 0).unwrap();
        assert_eq!(
            cert_deadline,
            "2026-12-21T10:08:05Z".parse::<DateTime<Utc>>().unwrap()
        );
        for deadline in [cert_deadline - chrono::Duration::seconds(1), cert_deadline] {
            let body = self_consistent_body(&deadline.to_rfc3339(), SPKI_SHA256);
            let binding =
                BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF, fixture_now()).unwrap();
            assert_eq!(binding.not_after, deadline);
        }
        let later = cert_deadline + chrono::Duration::nanoseconds(1);
        let body = self_consistent_body(&later.to_rfc3339(), SPKI_SHA256);
        let error =
            BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF, fixture_now()).unwrap_err();
        assert!(format!("{error:#}").contains("certificate expiry"));
    }

    // Build the digest over serde's last-value-wins interpretation to
    // reproduce ambiguity that is lost before canonicalization.
    fn body_with_raw_keyset(raw: &str) -> Vec<u8> {
        let collapsed: Value = serde_json::from_str(raw).unwrap();
        let digest = binding::recompute_keyset_digest(&collapsed).unwrap();
        let body: Value = serde_json::from_slice(&fixture_body(
            &collapsed,
            &statement(&digest, FIXTURE_NONCE),
            &digest,
        ))
        .unwrap();
        format!("{{\"keyset\":{raw},\"bindings\":{}}}", body["bindings"]).into_bytes()
    }

    #[test]
    fn duplicate_names_in_a_digest_consistent_keyset_fail_closed() {
        let original = v1_keyset("2026-12-01T00:00:00Z", SPKI_SHA256).to_string();
        let variants = [
            original.replace(
                "\"not_after\":",
                "\"not_after\":\"2000-01-01T00:00:00Z\",\"not_after\":",
            ),
            original.replace(
                "\"not_after\":",
                r#""not\u005fafter":"2000-01-01T00:00:00Z","not_after":"#,
            ),
            original.replace("\"domain\":", "\"domain\":\"wrong.example\",\"domain\":"),
            original.replace(
                "\"signing_keys\":[]",
                r#""signing_keys":[{"nested":{"key":"first","key":"last"}}]"#,
            ),
        ];
        for raw in variants {
            let error = BindingGuard::run(
                &body_with_raw_keyset(&raw),
                FIXTURE_NONCE,
                SESSION_LEAF,
                fixture_now(),
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("duplicate object key"));
        }
    }

    #[test]
    fn duplicate_top_level_names_fail_closed_before_the_binding_check() {
        let original = self_consistent_body("2026-12-01T00:00:00Z", SPKI_SHA256);
        let duplicated = format!(
            "{{\"keyset\":{{}},{}",
            std::str::from_utf8(&original)
                .unwrap()
                .strip_prefix('{')
                .unwrap()
        );
        for body in [
            duplicated.as_bytes(),
            br#"{"nonce":"first","nonce":"last"}"#,
            br#"{"unknown":{"name":"first","n\u0061me":"last"}}"#,
        ] {
            let error =
                BindingGuard::run(body, FIXTURE_NONCE, SESSION_LEAF, fixture_now()).unwrap_err();
            assert!(format!("{error:#}").contains("duplicate object key"));
        }
    }

    #[test]
    fn unique_unordered_json_with_whitespace_and_unknown_numbers_still_passes() {
        let keyset = format!(
            r#"{{
            "tls_public_keys": [{{"spki_sha256":"{SPKI_SHA256}", "domain":"llm.kubetee.ai"}}],
            "subject":"kubetee.attestation.v1/llm.kubetee.ai", "signing_keys": [],
            "not_after":"2026-12-01T00:00:00Z", "e2ee_keys": []
        }}"#
        );
        let body = body_with_raw_keyset(&keyset);
        BindingGuard::run(&body, FIXTURE_NONCE, SESSION_LEAF, fixture_now()).unwrap();
        let unknown = r#"{"nonce":"value", "unknown":[-12,1.25,18446744073709551615,true,null,{"name":"value"}],"#;
        let body = format!(
            "{unknown}{}",
            std::str::from_utf8(&body)
                .unwrap()
                .strip_prefix('{')
                .unwrap()
        );
        BindingGuard::run(body.as_bytes(), FIXTURE_NONCE, SESSION_LEAF, fixture_now()).unwrap();
    }

    /// An `ES256` possession proof over the per-boot P-256 key, as
    /// `kubetee_attestation.py` emits it (raw `r||s`) and in the DER
    /// encoding a TLS stack would produce. Both must verify.
    #[test]
    fn an_es256_proof_verifies_in_both_encodings() {
        let rng = SystemRandom::new();
        for algorithm in [
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &ECDSA_P256_SHA256_ASN1_SIGNING,
        ] {
            let key = EcdsaKeyPair::from_pkcs8(algorithm, EC_SESSION_KEY, &rng).unwrap();
            let signature = key.sign(&rng, FIXTURE_NONCE.as_bytes()).unwrap();
            let possession = TlsPossession {
                tls_signature: STANDARD.encode(signature.as_ref()),
                tls_signature_alg: ES256.to_owned(),
                tls_cert_sha256: hex::encode(Sha256::digest(EC_SESSION_LEAF)),
            };
            verify_tls_possession(&possession, FIXTURE_NONCE, EC_SESSION_LEAF).unwrap();
        }
    }

    /// A proof signed by some other P-256 key does not verify against the
    /// certificate it names.
    #[test]
    fn an_es256_proof_from_another_key_fails_closed() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let signature = key.sign(&rng, FIXTURE_NONCE.as_bytes()).unwrap();
        let possession = TlsPossession {
            tls_signature: STANDARD.encode(signature.as_ref()),
            tls_signature_alg: ES256.to_owned(),
            tls_cert_sha256: hex::encode(Sha256::digest(EC_SESSION_LEAF)),
        };
        let error = verify_tls_possession(&possession, FIXTURE_NONCE, EC_SESSION_LEAF).unwrap_err();
        assert!(format!("{error:#}").contains("does not verify"));
    }

    /// `ES256` claimed over an RSA certificate key fails closed on the
    /// key type, before any signature check.
    #[test]
    fn an_es256_claim_over_an_rsa_leaf_fails_closed() {
        let possession = TlsPossession {
            tls_signature: STANDARD.encode([0_u8; 64]),
            tls_signature_alg: ES256.to_owned(),
            tls_cert_sha256: hex::encode(Sha256::digest(SESSION_LEAF)),
        };
        let error = verify_tls_possession(&possession, FIXTURE_NONCE, SESSION_LEAF).unwrap_err();
        assert!(format!("{error:#}").contains("not P-256"));
    }

    /// An algorithm outside the accepted pair fails closed.
    #[test]
    fn an_unnamed_signature_algorithm_fails_closed() {
        let possession = TlsPossession {
            tls_signature: STANDARD.encode([0_u8; 64]),
            tls_signature_alg: "PS256".to_owned(),
            tls_cert_sha256: hex::encode(Sha256::digest(EC_SESSION_LEAF)),
        };
        let error = verify_tls_possession(&possession, FIXTURE_NONCE, EC_SESSION_LEAF).unwrap_err();
        assert!(format!("{error:#}").contains("expected ES256 or RS256"));
    }
}
