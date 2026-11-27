#![expect(
    clippy::unwrap_used,
    reason = "test fixtures intentionally fail hard on malformed local values"
)]
#![expect(
    clippy::panic,
    reason = "test helpers assert the recorded TDX fixture shape"
)]

//! The hardware evidence (quote, collateral, event log) is one live
//! `kubetee.attestation` `GET /v1/attestation` response from `llm.kubetee.ai`
//! (2026-11-04, pod `litellm-5dcbc54579-7rm6g`) and the Intel collateral for
//! its quote. The **binding** is rebuilt as `kubetee.attestation.v2` around a
//! per-boot generated key (the quote's `report_data` is set to that key's
//! binding), since v2 is the only contract this proxy accepts. The end-to-end
//! tests serve that quote from a local TLS server whose certificate chains to
//! a test root and which signs the v2 key-possession proof with its own
//! per-boot key. [`FixtureChain`] is the only substitution on the hardware
//! path.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use dcap_qvl::policy::QuoteClaims;
use dcap_qvl::quote::{EnclaveReport, Report, TDReport10};
use dcap_qvl::tcb_info::TcbStatus;
use http_body_util::{Either, Full};
use hyper::service::service_fn;
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest as _, Sha256};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::binding;
use super::evidence::{verify_attestation, Binding, BindingGuard, KeyPossession, Measurements};
use super::*;

const FIXTURE_NOW: u64 = 1_793_789_636;
/// Within the test leaf's validity, which ends in 2126.
const TEST_KEYSET_NOT_AFTER: &str = "2126-01-01T00:00:00Z";
/// The v2 binding context the gateway mints (`KUBETEE_V2_CONTEXT`).
const CONTEXT: &str = "llm.kubetee.ai/tls-possession";
const ATTESTATION: &[u8] = include_bytes!("../../tests/fixtures/kubetee/attestation.json");
const SESSION_LEAF: &[u8] = include_bytes!("../../tests/fixtures/kubetee/session_leaf.der");
const COLLATERAL: &[u8] = include_bytes!("../../tests/fixtures/kubetee/collateral.json");
const TEST_ROOT: &[u8] = include_bytes!("../../tests/fixtures/kubetee/test_ca.der");
const TEST_LEAF: &[u8] = include_bytes!("../../tests/fixtures/kubetee/test_leaf.der");
const TEST_KEY: &[u8] = include_bytes!("../../tests/fixtures/kubetee/test_leaf_key.pk8");
const FIRST_EVENT: &[u8] = b"data: {\"choices\":[]}\n\n";
const SSE: &str = "data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\ndata: [DONE]\n\n";

/// The fixed DER `SubjectPublicKeyInfo` header for an uncompressed P-256 key
/// (RFC 5480 `id-ecPublicKey` + `prime256v1`), followed by the 65-byte SEC1
/// point. Total DER is 91 bytes.
const P256_SPKI_HEADER: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

fn payload() -> AttestationPayload {
    serde_json::from_slice(ATTESTATION).unwrap()
}

fn fixture_nonce() -> [u8; 32] {
    hex::decode(payload().nonce).unwrap().try_into().unwrap()
}

fn collateral() -> dcap_qvl::QuoteCollateralV3 {
    serde_json::from_slice(COLLATERAL).unwrap()
}

fn quote() -> Vec<u8> {
    STANDARD.decode(payload().quote.unwrap()).unwrap()
}

fn claims() -> QuoteClaims {
    tee_evidence::verify_signature_chain(&quote(), collateral(), FIXTURE_NOW).unwrap()
}

fn td_mut(claims: &mut QuoteClaims) -> &mut TDReport10 {
    match &mut claims.report {
        Report::TD10(td) => td,
        Report::TD15(td) => &mut td.base,
        Report::SgxEnclave(_) => unreachable!("fixture is a TDX quote"),
    }
}

fn fixture_time() -> DateTime<Utc> {
    DateTime::from_timestamp(i64::try_from(FIXTURE_NOW).unwrap(), 0).unwrap()
}

/// A per-boot generated P-256 key, the DER SPKI the quote binds, and its raw
/// uncompressed point.
struct PerBootKey {
    pair: EcdsaKeyPair,
    pkix: Vec<u8>,
    point: Vec<u8>,
}

impl PerBootKey {
    fn generate(alg: &'static ring::signature::EcdsaSigningAlgorithm) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap();
        let point = pair.public_key().as_ref().to_vec();
        let mut pkix = P256_SPKI_HEADER.to_vec();
        pkix.extend_from_slice(&point);
        Self { pair, pkix, point }
    }

    fn es256() -> Self {
        Self::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)
    }

    /// Sign the quote-bound 64-byte `report_data` (DER encoding).
    fn possession(&self, report_data: &[u8; 64]) -> KeyPossession {
        let signature = self.pair.sign(&SystemRandom::new(), report_data).unwrap();
        KeyPossession {
            input: binding::POSSESSION_INPUT.to_owned(),
            alg: binding::POSSESSION_ALG.to_owned(),
            signature_b64: STANDARD.encode(signature.as_ref()),
        }
    }
}

/// The v2 binding inputs and derived artifacts for a nonce and bound key.
struct V2Binding {
    keyset: Value,
    digest: String,
    statement: String,
    report_data: [u8; 64],
    bound_key: Vec<u8>,
    not_after: DateTime<Utc>,
}

fn keyset_for(leaf: &[u8], not_after: &str) -> Value {
    let (_, certificate) = x509_parser::parse_x509_certificate(leaf).unwrap();
    serde_json::json!({
        "subject": format!("{}/{HOST_NAME}", binding::PURPOSE),
        "not_after": not_after,
        "tls_public_keys": [{
            "domain": HOST_NAME,
            "spki_sha256": hex::encode(Sha256::digest(certificate.public_key().raw)),
        }],
        "signing_keys": [],
        "e2ee_keys": [],
    })
}

/// Build a self-consistent v2 binding around `key` for `nonce`, with the
/// `report_data` the quote commits (or the derived one when `None`).
fn v2_binding_with(
    key: &PerBootKey,
    nonce: &str,
    leaf: &[u8],
    not_after: &str,
    report_data: Option<[u8; 64]>,
) -> V2Binding {
    let keyset = keyset_for(leaf, not_after);
    let digest = binding::keyset_digest(&keyset).unwrap();
    let pkix_b64url = URL_SAFE_NO_PAD.encode(&key.pkix);
    let statement =
        binding::report_data_statement_v2(&digest, nonce, &pkix_b64url, CONTEXT).unwrap();
    let raw_nonce = binding::bytes_from_hex32(&binding::normalize_nonce(nonce).unwrap()).unwrap();
    let report_data = match report_data {
        Some(report_data) => report_data,
        None => binding::report_data_v2(&key.pkix, &raw_nonce, CONTEXT).unwrap(),
    };
    V2Binding {
        keyset,
        digest,
        statement,
        report_data,
        bound_key: key.point.clone(),
        not_after: not_after.parse().unwrap(),
    }
}

fn binding_of(v2: &V2Binding) -> Binding {
    Binding {
        report_data: v2.report_data,
        bound_key: v2.bound_key.clone(),
        not_after: v2.not_after,
    }
}

/// The JSON body a v2 response serves for `v2`, with a `key_possession`
/// proof signed by `key` over the quote-bound `report_data`.
fn v2_body(v2: &V2Binding, nonce: &str, possession: Option<KeyPossession>) -> Vec<u8> {
    let mut payload: Value = serde_json::from_slice(ATTESTATION).unwrap();
    payload["nonce"] = Value::from(nonce.to_owned());
    payload["keyset"] = v2.keyset.clone();
    payload["bindings"] = serde_json::json!({
        "version": binding::PURPOSE,
        "report_data_statement": v2.statement,
        "keyset_digest": v2.digest,
    });
    if let Some(possession) = possession {
        payload["key_possession"] = serde_json::json!({
            "input": possession.input,
            "alg": possession.alg,
            "signature_b64": possession.signature_b64,
        });
    } else {
        payload["key_possession"] = Value::Null;
    }
    serde_json::to_vec(&payload).unwrap()
}

/// A v2 attestation payload with a `key_possession` proof under `key`.
fn v2_payload(v2: &V2Binding, key: &PerBootKey, nonce: &str) -> AttestationPayload {
    let body = v2_body(v2, nonce, Some(key.possession(&v2.report_data)));
    serde_json::from_slice(&body).unwrap()
}

/// Verify `payload` against `nonce` and the recorded quote's real chain, with
/// the quote's `report_data` set to `v2`'s binding (the only substitution).
fn verify_with_v2(
    payload: &AttestationPayload,
    nonce: &str,
    v2: &V2Binding,
) -> Result<Measurements> {
    let mut claims = claims();
    td_mut(&mut claims).report_data = v2.report_data;
    verify_attestation(payload, nonce, &claims, FIXTURE_NOW, &binding_of(v2))
}

/// The `Attestation.measurements` field is the TEE-dispatched enum; the
/// fixtures are the recorded Intel TDX evidence, so every attested result is
/// the `Tdx` arm. Panic if that ever changes.
fn tdx(m: &TeeMeasurements) -> &Measurements {
    match m {
        TeeMeasurements::Tdx(t) => t,
        TeeMeasurements::Snp(_) => panic!("expected TDX measurements"),
    }
}

fn failure(result: Result<Measurements>) -> String {
    format!("{:#}", result.unwrap_err())
}

/// The cross-language derivation KAT (shared with `kubetee_binding.py` and
/// `kubetee-attestation-verifier`): the frozen `report_data` for a known
/// `(pkix, nonce, context)` transcript.
#[test]
fn the_v2_report_data_matches_the_cross_language_kat() {
    let pkix = hex::decode(
        "302a300506032b6570032100000102030405060708090a0b0c0d0e0f\
         101112131415161718191a1b1c1d1e1f",
    )
    .unwrap();
    let nonce = [0xaa_u8; 32];
    let rd = binding::report_data_v2(&pkix, &nonce, "kubetee-test-context").unwrap();
    assert_eq!(
        hex::encode(rd),
        "7c7f82da79e64d00bb228bf3bd7075ea31b938759d00162f1f1d83021f245e24\
         eff25929ec5761309dbbc014119dc4c000000000000000000000000000000000"
            .replace(char::is_whitespace, "")
    );
}

/// The end-to-end shape: a v2 response binds the per-boot key and its
/// `key_possession` verifies under that key.
#[test]
fn the_live_hardware_evidence_verifies_offline_under_a_v2_binding() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let payload = v2_payload(&v2, &key, &nonce);
    let measurements = verify_with_v2(&payload, &nonce, &v2).unwrap();
    assert_eq!(measurements.rtmrs[3], [0; 48], "RTMR3 carries no events");
    assert_ne!(measurements.rtmrs[2], [0; 48]);
    // The quote-bound report_data is the v2 derivation.
    assert_eq!(
        v2.report_data[..48],
        binding::report_data_v2(
            &key.pkix,
            &binding::bytes_from_hex32(&nonce).unwrap(),
            CONTEXT
        )
        .unwrap()[..48]
    );
    assert!(v2.report_data[48..].iter().all(|b| *b == 0));
}

#[test]
fn the_binding_binds_the_per_boot_key() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let bound = BindingGuard::run(
        &v2_body(&v2, &nonce, Some(key.possession(&v2.report_data))),
        &nonce,
        TEST_LEAF,
        fixture_time(),
    )
    .unwrap();
    assert_eq!(bound.report_data, v2.report_data);
    assert_eq!(bound.bound_key, key.point);
    assert_eq!(bound.not_after, v2.not_after);
}

#[test]
fn a_response_without_its_v2_fields_fails_closed() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let mut body: Value = serde_json::from_slice(&v2_body(&v2, &nonce, None)).unwrap();
    let fields = body.as_object_mut().unwrap();
    fields.remove("keyset");
    fields.remove("bindings");
    let error = BindingGuard::run(
        &serde_json::to_vec(&body).unwrap(),
        &nonce,
        TEST_LEAF,
        fixture_time(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("no kubetee.attestation.v2 binding"));
}

#[test]
fn a_half_v2_response_fails_closed() {
    let body = br#"{"nonce":"cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a","keyset":{}}"#;
    let error = BindingGuard::run(body, &payload().nonce, TEST_LEAF, fixture_time()).unwrap_err();
    assert!(format!("{error:#}").contains("half a v2 binding"));
}

#[test]
fn a_non_v2_version_fails_closed() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let mut body: Value = serde_json::from_slice(&v2_body(&v2, &nonce, None)).unwrap();
    body["bindings"]["version"] = Value::from("kubetee.attestation.v1");
    let error = BindingGuard::run(
        &serde_json::to_vec(&body).unwrap(),
        &nonce,
        TEST_LEAF,
        fixture_time(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("version"));
}

/// Anti-downgrade: a statement re-serialized outside canonical JCS is not the
/// derivation's fixed point and is rejected.
#[test]
fn a_non_canonical_v2_statement_fails_closed() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    // Shuffle key order + add whitespace: valid JSON, not canonical JCS.
    let reordered = format!(
        r#"{{"purpose":"{}","pkix_pubkey_b64url":"{pkix}","nonce":"{nonce}","keyset_digest":"{digest}","context":"{ctx}"}}"#,
        binding::PURPOSE,
        pkix = URL_SAFE_NO_PAD.encode(&key.pkix),
        digest = v2.digest,
        ctx = CONTEXT,
    );
    let mut body: Value = serde_json::from_slice(&v2_body(&v2, &nonce, None)).unwrap();
    body["bindings"]["report_data_statement"] = Value::from(reordered);
    let error = BindingGuard::run(
        &serde_json::to_vec(&body).unwrap(),
        &nonce,
        TEST_LEAF,
        fixture_time(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("canonical JCS"));
}

#[test]
fn a_statement_bound_to_a_different_key_reproduces_a_different_report_data() {
    let key = PerBootKey::es256();
    let other = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let other_v2 = v2_binding_with(&other, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    assert_ne!(v2.report_data, other_v2.report_data);
    // A possession proof under the other key must not verify against `v2`.
    let payload = v2_payload(&v2, &key, &nonce);
    let mut tampered = payload.clone();
    tampered.key_possession = Some(other.possession(&v2.report_data));
    assert!(failure(verify_with_v2(&tampered, &nonce, &v2)).contains("does not verify"));
}

#[test]
fn a_key_possession_over_a_different_report_data_fails_closed() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let payload = v2_payload(&v2, &key, &nonce);
    // Sign the wrong bytes (another key's report_data) under the right key.
    let other = PerBootKey::es256();
    let wrong = binding::report_data_v2(
        &other.pkix,
        &binding::bytes_from_hex32(&nonce).unwrap(),
        CONTEXT,
    )
    .unwrap();
    let mut tampered = payload.clone();
    tampered.key_possession = Some(key.possession(&wrong));
    assert!(failure(verify_with_v2(&tampered, &nonce, &v2)).contains("does not verify"));
}

#[test]
fn a_missing_key_possession_fails_closed() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let mut payload = v2_payload(&v2, &key, &nonce);
    payload.key_possession = None;
    assert!(failure(verify_with_v2(&payload, &nonce, &v2)).contains("no key_possession"));
}

#[test]
fn a_key_possession_naming_the_wrong_input_or_algorithm_fails_closed() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let payload = v2_payload(&v2, &key, &nonce);

    let mut wrong_input = payload.clone();
    let mut p = key.possession(&v2.report_data);
    p.input = "nonce".to_owned();
    wrong_input.key_possession = Some(p);
    assert!(failure(verify_with_v2(&wrong_input, &nonce, &v2)).contains("input is"));

    let mut wrong_alg = payload.clone();
    let mut p = key.possession(&v2.report_data);
    p.alg = "RS256".to_owned();
    wrong_alg.key_possession = Some(p);
    assert!(failure(verify_with_v2(&wrong_alg, &nonce, &v2)).contains("signature is"));
}

#[test]
fn a_quote_carrying_the_sha512_nonce_construction_fails_the_binding() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let payload = v2_payload(&v2, &key, &nonce);
    let mut claims = claims();
    let mut legacy = [0_u8; 64];
    legacy[..32].copy_from_slice(&Sha256::digest(nonce.as_bytes()));
    td_mut(&mut claims).report_data = legacy;
    let result = verify_attestation(&payload, &nonce, &claims, FIXTURE_NOW, &binding_of(&v2));
    assert!(format!("{:#}", result.unwrap_err()).contains("report_data"));
}

#[test]
fn a_different_echoed_nonce_fails_closed() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let mut payload = v2_payload(&v2, &key, &nonce);
    payload.nonce = hex::encode([7_u8; 32]);
    assert!(failure(verify_with_v2(&payload, &nonce, &v2)).contains("echoed a different nonce"));
}

#[test]
fn an_uppercased_echo_is_not_the_nonce_sent() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let mut payload = v2_payload(&v2, &key, &nonce);
    payload.nonce = nonce.to_uppercase();
    assert!(failure(verify_with_v2(&payload, &nonce, &v2)).contains("echoed a different nonce"));
}

#[test]
fn a_replayed_response_under_a_new_nonce_fails_the_statement() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let body = v2_body(&v2, &nonce, None);
    let fresh = hex::encode([9_u8; 32]);
    let error = BindingGuard::run(&body, &fresh, TEST_LEAF, fixture_time()).unwrap_err();
    assert!(format!("{error:#}").contains("names a different nonce"));
}

#[test]
fn a_served_keyset_for_another_serving_key_fails_closed() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let mut v2 = v2_binding_with(&key, &nonce, SESSION_LEAF, TEST_KEYSET_NOT_AFTER, None);
    // Name a keyset built for a different leaf's key.
    v2.keyset = keyset_for(TEST_LEAF, TEST_KEYSET_NOT_AFTER);
    v2.digest = binding::keyset_digest(&v2.keyset).unwrap();
    let error = BindingGuard::run(
        &v2_body(&v2, &nonce, None),
        &nonce,
        SESSION_LEAF,
        fixture_time(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("serving key"));
}

#[test]
fn an_expired_keyset_fails_closed() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, "2000-01-01T00:00:00Z", None);
    let error = BindingGuard::run(
        &v2_body(&v2, &nonce, None),
        &nonce,
        TEST_LEAF,
        fixture_time(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("expired"));
}

#[test]
fn a_binding_expires_at_its_deadline_including_after_verification_work() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let deadline = "2026-12-01T00:00:00.123456789Z"
        .parse::<DateTime<Utc>>()
        .unwrap();
    let v2 = v2_binding_with(
        &key,
        &nonce,
        TEST_LEAF,
        "2026-12-01T00:00:00.123456789Z",
        None,
    );
    let before = deadline - chrono::Duration::nanoseconds(1);
    let binding =
        BindingGuard::run(&v2_body(&v2, &nonce, None), &nonce, TEST_LEAF, before).unwrap();
    assert_eq!(binding.not_after, deadline);
    binding.ensure_current(before).unwrap();
    for now in [deadline, deadline + chrono::Duration::nanoseconds(1)] {
        assert!(binding
            .ensure_current(now)
            .unwrap_err()
            .to_string()
            .contains("expired"));
        assert!(
            BindingGuard::run(&v2_body(&v2, &nonce, None), &nonce, TEST_LEAF, now)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );
    }
}

#[test]
fn an_sgx_report_fails_closed() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let payload = v2_payload(&v2, &key, &nonce);
    let mut claims = claims();
    claims.report = Report::SgxEnclave(EnclaveReport {
        cpu_svn: [0; 16],
        misc_select: 0,
        reserved1: [0; 28],
        attributes: [0; 16],
        mr_enclave: [0; 32],
        reserved2: [0; 32],
        mr_signer: [0; 32],
        reserved3: [0; 96],
        isv_prod_id: 0,
        isv_svn: 0,
        reserved4: [0; 60],
        report_data: [0; 64],
    });
    let result = verify_attestation(&payload, &nonce, &claims, FIXTURE_NOW, &binding_of(&v2));
    assert!(format!("{:#}", result.unwrap_err()).contains("SGX"));
}

#[test]
fn a_tcb_below_up_to_date_fails_closed() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let payload = v2_payload(&v2, &key, &nonce);
    let mut claims = claims();
    claims.platform.tcb_level.tcb_status = TcbStatus::SWHardeningNeeded;
    td_mut(&mut claims).report_data = v2.report_data;
    let result = verify_attestation(&payload, &nonce, &claims, FIXTURE_NOW, &binding_of(&v2));
    assert!(format!("{:#}", result.unwrap_err()).contains("TCB"));
}

#[test]
fn a_debug_td_fails_closed() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let payload = v2_payload(&v2, &key, &nonce);
    let mut claims = claims();
    td_mut(&mut claims).td_attributes[0] |= 1;
    td_mut(&mut claims).report_data = v2.report_data;
    let result = verify_attestation(&payload, &nonce, &claims, FIXTURE_NOW, &binding_of(&v2));
    assert!(format!("{:#}", result.unwrap_err()).contains("debug"));
}

#[test]
fn a_missing_event_log_fails_closed() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let mut payload = v2_payload(&v2, &key, &nonce);
    payload.cc_eventlog = None;
    assert!(failure(verify_with_v2(&payload, &nonce, &v2)).contains("cc_eventlog"));
}

#[test]
fn a_tampered_event_log_does_not_replay() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let mut payload = v2_payload(&v2, &key, &nonce);
    let mut log = STANDARD
        .decode(payload.cc_eventlog.as_deref().unwrap())
        .unwrap();
    let first_record = 32 + u32::from_le_bytes(log[28..32].try_into().unwrap()) as usize;
    log[first_record + 12 + 2] ^= 1;
    payload.cc_eventlog = Some(STANDARD.encode(log));
    assert!(failure(verify_with_v2(&payload, &nonce, &v2)).contains("RTMR0"));
}

#[test]
fn an_rtmr3_extended_without_events_does_not_replay() {
    let key = PerBootKey::es256();
    let nonce = hex::encode(fixture_nonce());
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    let payload = v2_payload(&v2, &key, &nonce);
    let mut claims = claims();
    td_mut(&mut claims).rt_mr3[0] ^= 1;
    td_mut(&mut claims).report_data = v2.report_data;
    let result = verify_attestation(&payload, &nonce, &claims, FIXTURE_NOW, &binding_of(&v2));
    assert!(format!("{:#}", result.unwrap_err()).contains("RTMR3"));
}

#[test]
fn the_model_list_is_narrowed_to_the_chat_and_image_models() {
    let list = serde_json::json!({"object": "list", "data": [
        {"id": "z-ai/glm-5.3", "object": "model"},
        {"id": "minimax/h3", "object": "model"},
        {"id": "black-forest-labs/flux.2-klein-4b", "object": "model"},
        {"id": "all-proxy-models", "object": "model"},
        {"id": "xiaomi/mimo-v2.6-pro", "object": "model"},
        {"object": "model"},
    ]});
    let served = served_targets(&list);
    assert_eq!(
        served["data"],
        serde_json::json!([
            {"id": "z-ai/glm-5.3", "object": "model"},
            {"id": "black-forest-labs/flux.2-klein-4b", "object": "model"},
            {"id": "xiaomi/mimo-v2.6-pro", "object": "model"},
        ])
    );
    assert_eq!(
        served_targets(&serde_json::json!({}))["data"],
        serde_json::json!([])
    );
}

#[test]
fn the_upstream_request_carries_no_supplier_or_selector_header() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/chat/completions")
        .header(SELECTOR_HEADER, TARGETS[0])
        .header("x-kubetee-nonce", "buyer-chosen")
        .header("x-kubetee-anything", "buyer")
        .header("x-litellm-tags", "buyer")
        .header("connection", "keep-alive")
        .body(Body::empty())
        .unwrap();
    let upstream = upstream_request(request).unwrap();
    assert!(upstream
        .headers()
        .keys()
        .all(|name| !name.as_str().starts_with("x-kubetee-")
            && !name.as_str().starts_with("x-litellm-")));
    assert!(!upstream.headers().contains_key(SELECTOR_HEADER));
    assert!(!upstream.headers().contains_key("connection"));
    assert_eq!(upstream.headers()[HOST], HOST_NAME);
}

// ---- End to end against a local TLS upstream ----

#[derive(Clone, Copy)]
enum Chat {
    Served,
    Slow,
    Unauthorized,
    Dropped,
    /// The model list sends headers and half its body, then nothing.
    StalledModelList,
    /// The chat sends its first event, then nothing more.
    FirstEventOnly,
    /// The chat sends one event, then supplier and ordinary trailers.
    Trailed,
}

#[derive(Clone, Copy)]
enum Evidence {
    Genuine,
    Unavailable,
    /// A `key_possession` proof under a per-boot key the quote does not bind.
    OtherKey,
    /// The recorded response echoed under a nonce other than the one sent.
    Replayed,
    /// The recorded response without its `keyset` and `bindings`.
    Unbound,
    /// Headers and half the body, then nothing.
    Stalled,
}

struct Upstream {
    evidence: Evidence,
    chat: Chat,
    accepts: AtomicUsize,
    attestations: AtomicUsize,
    chats: AtomicUsize,
    model_lists: AtomicUsize,
    chat_headers: Mutex<Vec<HeaderMap>>,
    /// Every attestation request's query, headers and body length.
    attestation_requests: Mutex<Vec<(String, HeaderMap, usize)>>,
}

/// The per-boot key + v2 binding the local upstream serves for the test leaf
/// and the fixture nonce: one pair for the whole test, since the quote's
/// `report_data` and the possession signature must agree on it.
struct TestBinding {
    key: PerBootKey,
    v2: V2Binding,
    nonce: String,
}

/// The recorded quote's `report_data` is replaced — the one substitution — by
/// the value the served v2 statement derives, exactly as the hardware quote
/// binds whatever `report_data` the guest minted its binding into.
static TEST_BINDING: LazyLock<TestBinding> = LazyLock::new(|| {
    let key = PerBootKey::generate(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let nonce = payload().nonce.clone();
    let v2 = v2_binding_with(&key, &nonce, TEST_LEAF, TEST_KEYSET_NOT_AFTER, None);
    TestBinding { key, v2, nonce }
});

fn test_binding() -> &'static TestBinding {
    &TEST_BINDING
}

struct FixtureChain;

#[async_trait]
impl QuoteChain for FixtureChain {
    async fn verify(&self, quote: &[u8]) -> Result<(QuoteClaims, u64)> {
        let mut claims = tee_evidence::verify_signature_chain(quote, collateral(), FIXTURE_NOW)?;
        td_mut(&mut claims).report_data = test_binding().v2.report_data;
        Ok((claims, FIXTURE_NOW))
    }
}

fn attestation_body(evidence: Evidence) -> Vec<u8> {
    let served = test_binding();
    let nonce = match evidence {
        Evidence::Replayed => hex::encode([5_u8; 32]),
        _ => served.nonce.clone(),
    };
    // The possession proof is over the served binding's report_data (the same
    // one FixtureChain puts in the quote), so `Genuine` verifies end to end.
    let possession = match evidence {
        Evidence::OtherKey => Some(PerBootKey::es256().possession(&served.v2.report_data)),
        _ => Some(served.key.possession(&served.v2.report_data)),
    };
    let mut body: Value =
        serde_json::from_slice(&v2_body(&served.v2, &served.nonce, possession)).unwrap();
    body["nonce"] = Value::from(nonce);
    if matches!(evidence, Evidence::Unbound) {
        let fields = body.as_object_mut().unwrap();
        fields.remove("keyset");
        fields.remove("bindings");
    }
    serde_json::to_vec(&body).unwrap()
}

type Reply = Response<Either<Full<Bytes>, Frames>>;

fn reply(status: u16, body: impl Into<Bytes>) -> Reply {
    Response::builder()
        .status(status)
        .body(Either::Left(Full::new(body.into())))
        .unwrap()
}

/// A body that sends its frames in order, then ends or never sends another.
struct Frames {
    frames: std::collections::VecDeque<hyper::body::Frame<Bytes>>,
    then_stall: bool,
}

impl Frames {
    /// `first`, then nothing ever again.
    fn stalling(first: impl Into<Bytes>) -> Self {
        Self {
            frames: [hyper::body::Frame::data(first.into())].into(),
            then_stall: true,
        }
    }

    /// `data`, then `trailers`, then the end.
    fn trailed(data: &'static [u8], trailers: HeaderMap) -> Self {
        Self {
            frames: [
                hyper::body::Frame::data(Bytes::from_static(data)),
                hyper::body::Frame::trailers(trailers),
            ]
            .into(),
            then_stall: false,
        }
    }
}

impl hyper::body::Body for Frames {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        match self.frames.pop_front() {
            Some(frame) => std::task::Poll::Ready(Some(Ok(frame))),
            None if self.then_stall => std::task::Poll::Pending,
            None => std::task::Poll::Ready(None),
        }
    }
}

/// Headers announcing `body` in full, and only its first half sent.
fn stalled(body: &[u8]) -> Reply {
    Response::builder()
        .status(200)
        .header("content-length", body.len())
        .body(Either::Right(Frames::stalling(Bytes::copy_from_slice(
            &body[..body.len() / 2],
        ))))
        .unwrap()
}

async fn chat_reply(chat: Chat) -> Option<Reply> {
    match chat {
        Chat::Unauthorized => return Some(reply(401, "{\"error\":\"unauthorized\"}")),
        Chat::Dropped => return None,
        Chat::Slow => tokio::time::sleep(Duration::from_millis(300)).await,
        Chat::FirstEventOnly => {
            let response = Response::builder()
                .status(200)
                .header("content-type", "text/event-stream")
                .body(Either::Right(Frames::stalling(Bytes::from_static(
                    FIRST_EVENT,
                ))));
            return Some(response.unwrap());
        }
        Chat::Trailed => {
            let mut trailers = HeaderMap::new();
            trailers.insert("x-kubetee-attestation-quote", HeaderValue::from_static("q"));
            trailers.insert("x-litellm-key-spend", HeaderValue::from_static("0.14"));
            trailers.insert("x-request-cost", HeaderValue::from_static("kept"));
            let response = Response::builder()
                .status(200)
                .header("content-type", "text/event-stream")
                .header(
                    "trailer",
                    "x-kubetee-attestation-quote, x-litellm-key-spend, x-request-cost",
                )
                .body(Either::Right(Frames::trailed(FIRST_EVENT, trailers)));
            return Some(response.unwrap());
        }
        Chat::Served | Chat::StalledModelList => {}
    }
    let response = Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("x-litellm-model-group", "served")
        .header("x-litellm-key-spend", "0.1405700124280008")
        .header("x-kubetee-backend", "served")
        .header("x-request-id", "served");
    Some(
        response
            .body(Either::Left(Full::new(Bytes::from_static(SSE.as_bytes()))))
            .unwrap(),
    )
}

async fn handle(
    upstream: Arc<Upstream>,
    request: Request<Incoming>,
) -> Result<Reply, std::io::Error> {
    let path = request.uri().path().to_owned();
    if path == "/v1/attestation" {
        upstream.attestations.fetch_add(1, Ordering::SeqCst);
        let (parts, body) = request.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        let query = parts.uri.query().unwrap_or_default().to_owned();
        upstream
            .attestation_requests
            .lock()
            .unwrap()
            .push((query, parts.headers, body.len()));
        return Ok(match upstream.evidence {
            Evidence::Unavailable => reply(502, "{\"error\":\"attestation agent unavailable\"}"),
            Evidence::Stalled => stalled(&attestation_body(Evidence::Genuine)),
            evidence => reply(200, attestation_body(evidence)),
        });
    }
    if path == MODELS {
        upstream.model_lists.fetch_add(1, Ordering::SeqCst);
        let authorized = request
            .headers()
            .get(AUTHORIZATION)
            .map(HeaderValue::as_bytes)
            == Some(b"Bearer kt".as_slice());
        let list = serde_json::json!({"object": "list", "data": [
            {"id": "z-ai/glm-5.3", "object": "model"},
            {"id": "minimax/h3", "object": "model"},
            {"id": "black-forest-labs/flux.2-klein-4b", "object": "model"},
        ]});
        return Ok(if matches!(upstream.chat, Chat::StalledModelList) {
            stalled(list.to_string().as_bytes())
        } else if authorized {
            reply(200, list.to_string())
        } else {
            reply(401, "{\"error\":\"no key\"}")
        });
    }
    upstream.chats.fetch_add(1, Ordering::SeqCst);
    let (parts, body) = request.into_parts();
    upstream.chat_headers.lock().unwrap().push(parts.headers);
    body.collect().await.unwrap();
    chat_reply(upstream.chat)
        .await
        .ok_or_else(|| std::io::Error::other("dropped"))
}

fn limits() -> Limits {
    Limits::default()
}

async fn serve(evidence: Evidence, chat: Chat, limits: Limits) -> (KubeteeVerifier, Arc<Upstream>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let upstream = Arc::new(Upstream {
        evidence,
        chat,
        accepts: AtomicUsize::new(0),
        attestations: AtomicUsize::new(0),
        chats: AtomicUsize::new(0),
        model_lists: AtomicUsize::new(0),
        chat_headers: Mutex::new(Vec::new()),
        attestation_requests: Mutex::new(Vec::new()),
    });
    let mut config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(TEST_LEAF.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(TEST_KEY.to_vec())),
            )
            .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = Arc::clone(&upstream);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            state.accepts.fetch_add(1, Ordering::SeqCst);
            let (acceptor, state) = (acceptor.clone(), Arc::clone(&state));
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(move |request| handle(Arc::clone(&state), request));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(TEST_ROOT.to_vec())).unwrap();
    let verifier = KubeteeVerifier::with_parts(
        roots,
        Some(address),
        Arc::new(FixtureChain),
        fixture_nonce,
        limits,
    );
    (verifier, upstream)
}

fn chat(selector: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(CHAT_COMPLETIONS)
        .header(SELECTOR_HEADER, selector)
        .header("content-type", "application/json")
        .header(AUTHORIZATION, "Bearer kt")
        .header("x-buyer-sentinel", "buyer")
        .body(Body::from(
            serde_json::json!({"model": selector, "stream": true}).to_string(),
        ))
        .unwrap()
}

fn chat_with_session(selector: &str, ids: &[&str], supplier_id: Option<&str>) -> Request<Body> {
    let mut request = chat(selector);
    for id in ids {
        request.headers_mut().append(
            "x-gm-session-id",
            HeaderValue::from_bytes(id.as_bytes()).unwrap(),
        );
    }
    if let Some(id) = supplier_id {
        request.headers_mut().insert(
            "x-litellm-session-id",
            HeaderValue::from_bytes(id.as_bytes()).unwrap(),
        );
    }
    request
}

/// Send one chat and read its body to the end, as Envoy does.
async fn round_trip(verifier: &KubeteeVerifier, selector: &str) -> (StatusCode, Bytes) {
    let response = verifier.forward(chat(selector)).await.unwrap();
    let status = response.status();
    (
        status,
        response.into_body().collect().await.unwrap().to_bytes(),
    )
}

fn counts(upstream: &Upstream) -> (usize, usize, usize) {
    (
        upstream.accepts.load(Ordering::SeqCst),
        upstream.attestations.load(Ordering::SeqCst),
        upstream.chats.load(Ordering::SeqCst),
    )
}

#[tokio::test]
async fn a_chat_streams_through_unchanged_without_supplier_headers() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    let response = verifier.forward(chat(TARGETS[2])).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().keys().all(|name| {
        !name.as_str().starts_with("x-kubetee-") && !name.as_str().starts_with("x-litellm-")
    }));
    assert_eq!(response.headers()["x-request-id"], "served");
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, SSE.as_bytes());
    assert_eq!(
        counts(&upstream),
        (1, 1, 1),
        "one connection, one quote, one chat"
    );
    let (query, _, _) = upstream.attestation_requests.lock().unwrap().remove(0);
    assert_eq!(query, format!("nonce={}", payload().nonce));
    let sent = upstream.chat_headers.lock().unwrap().remove(0);
    assert!(sent
        .keys()
        .all(|name| !name.as_str().starts_with("x-kubetee-")));
    assert!(!sent.contains_key(SELECTOR_HEADER));
}

#[tokio::test]
async fn chat_session_ids_are_validated_and_supplier_values_are_untrusted() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    let valid_id = "0123456789abcdef".repeat(4);
    let too_short = "a".repeat(63);
    let too_long = "a".repeat(65);
    let uppercase = "a".repeat(63) + "A";
    let non_hex = "g".repeat(64);
    let cases: Vec<(Vec<&str>, Option<&str>)> = vec![
        (vec![valid_id.as_str()], Some("spoofed-01")),
        (vec![], Some("forged-01")),
        (vec![too_short.as_str()], None),
        (vec![too_long.as_str()], None),
        (vec![uppercase.as_str()], None),
        (vec![non_hex.as_str()], None),
        (vec![valid_id.as_str(), valid_id.as_str()], None),
    ];

    for (ids, supplier_id) in cases {
        let response = verifier
            .forward(chat_with_session(TARGETS[0], &ids, supplier_id))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await.unwrap();
    }

    let sent = upstream.chat_headers.lock().unwrap();
    assert_eq!(sent.len(), 7);
    assert_eq!(sent[0]["x-litellm-session-id"], valid_id.as_str());
    assert!(sent[1..]
        .iter()
        .all(|headers| !headers.contains_key("x-litellm-session-id")));
    assert!(sent
        .iter()
        .all(|headers| !headers.contains_key("x-gm-session-id")));
    assert_eq!(counts(&upstream).2, 7, "invalid IDs still reach upstream");
}

#[tokio::test]
async fn retiring_an_expired_connection_attests_again_before_chat_or_models() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    let mut connection = verifier.checkout().await.unwrap();
    assert_eq!(
        connection.expires_at,
        Some(TEST_KEYSET_NOT_AFTER.parse().unwrap())
    );
    connection.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
    verifier.pool.give_back(connection);
    assert_eq!(verifier.idle_connections(), 0);
    assert_eq!(round_trip(&verifier, TARGETS[0]).await.1, SSE.as_bytes());
    assert_eq!(counts(&upstream), (2, 2, 1));

    let mut connection = verifier.pool.take().unwrap();
    connection.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
    verifier.pool.give_back(connection);
    let request = Request::builder()
        .header(AUTHORIZATION, "Bearer kt")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        verifier.models(request).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(counts(&upstream), (3, 3, 1));
    assert_eq!(upstream.model_lists.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_attested_connection_is_reused_without_attesting_again() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    for selector in [TARGETS[0], TARGETS[1], TARGETS[5]] {
        assert_eq!(round_trip(&verifier, selector).await.1, SSE.as_bytes());
    }
    assert_eq!(counts(&upstream), (1, 1, 3));
    assert_eq!(verifier.idle_connections(), 1);
}

#[tokio::test]
async fn a_connection_returns_once_its_body_reports_its_end() {
    let (verifier, _) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    let response = verifier.forward(chat(TARGETS[0])).await.unwrap();
    let mut body = response.into_body();
    while !hyper::body::Body::is_end_stream(&body) {
        body.frame().await.unwrap().unwrap();
    }
    drop(body);
    assert_eq!(verifier.idle_connections(), 1);
}

#[tokio::test]
async fn a_body_dropped_early_retires_its_connection() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    drop(verifier.forward(chat(TARGETS[0])).await.unwrap());
    assert_eq!(verifier.idle_connections(), 0);
    round_trip(&verifier, TARGETS[0]).await;
    assert_eq!(counts(&upstream), (2, 2, 2));
}

#[tokio::test]
async fn a_connection_that_expires_while_idle_is_not_reused() {
    let short = Limits {
        max_age: Duration::from_millis(300),
        ..Limits::default()
    };
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, short).await;
    round_trip(&verifier, TARGETS[0]).await;
    assert_eq!(verifier.idle_connections(), 1, "pooled while fresh");
    tokio::time::sleep(Duration::from_millis(400)).await;
    round_trip(&verifier, TARGETS[0]).await;
    assert_eq!(counts(&upstream), (2, 2, 2));
}

#[tokio::test]
async fn a_connection_is_renewed_after_its_request_limit() {
    let two = Limits {
        max_requests: 2,
        ..Limits::default()
    };
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, two).await;
    for _ in 0..3 {
        round_trip(&verifier, TARGETS[0]).await;
    }
    assert_eq!(counts(&upstream), (2, 2, 3));
}

#[tokio::test]
async fn the_idle_pool_is_capped() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Slow, limits()).await;
    let verifier = Arc::new(verifier);
    let burst = |verifier: Arc<KubeteeVerifier>| async move {
        let requests = (0..pool::MAX_IDLE + 2).map(|_| {
            let verifier = Arc::clone(&verifier);
            tokio::spawn(async move { round_trip(&verifier, TARGETS[0]).await })
        });
        for request in requests.collect::<Vec<_>>() {
            assert_eq!(request.await.unwrap().0, StatusCode::OK);
        }
    };
    burst(Arc::clone(&verifier)).await;
    assert_eq!(upstream.accepts.load(Ordering::SeqCst), pool::MAX_IDLE + 2);
    assert_eq!(verifier.idle_connections(), pool::MAX_IDLE);
    burst(Arc::clone(&verifier)).await;
    assert_eq!(
        upstream.accepts.load(Ordering::SeqCst),
        pool::MAX_IDLE + 4,
        "the second burst reuses every pooled connection"
    );
    assert_eq!(verifier.idle_connections(), pool::MAX_IDLE);
}

#[tokio::test]
async fn off_list_requests_are_refused_before_any_connection() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    let mut wrong_path = chat(TARGETS[0]);
    *wrong_path.uri_mut() = Uri::from_static("/v1/completions");
    let mut wrong_method = chat(TARGETS[0]);
    *wrong_method.method_mut() = Method::GET;
    let mut no_selector = chat(TARGETS[0]);
    no_selector.headers_mut().remove(SELECTOR_HEADER);
    let mut two_selectors = chat(TARGETS[0]);
    two_selectors
        .headers_mut()
        .append(SELECTOR_HEADER, HeaderValue::from_static("z-ai/glm-5.3"));
    let mut other_body_model = chat(TARGETS[1]);
    *other_body_model.body_mut() = Body::from(r#"{"model":"minimax/h3"}"#);
    let mut no_body_model = chat(TARGETS[1]);
    *no_body_model.body_mut() = Body::from(r#"{"messages":[]}"#);
    let mut not_json = chat(TARGETS[1]);
    *not_json.body_mut() = Body::from("model=z-ai/glm-5.3");
    for request in [
        other_body_model,
        no_body_model,
        not_json,
        chat("minimax/h3"),
        chat("black-forest-labs/flux.2-klein-4b"),
        wrong_path,
        wrong_method,
        no_selector,
        two_selectors,
    ] {
        assert!(verifier.forward(request).await.is_err());
    }
    tokio::task::yield_now().await;
    assert_eq!(counts(&upstream), (0, 0, 0));
}

#[tokio::test]
async fn a_connection_that_fails_attestation_never_carries_a_chat() {
    for (evidence, expected) in [
        (Evidence::Unavailable, "502"),
        (Evidence::OtherKey, "does not verify"),
        (Evidence::Replayed, "echoed a different nonce"),
        (Evidence::Unbound, "no kubetee.attestation.v2 binding"),
    ] {
        let (verifier, upstream) = serve(evidence, Chat::Served, limits()).await;
        let error = verifier.forward(chat(TARGETS[0])).await.unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert_eq!(
            counts(&upstream),
            (3, 3, 0),
            "three attested attempts, no chat"
        );
        assert_eq!(verifier.idle_connections(), 0);
        for (_, headers, body) in upstream.attestation_requests.lock().unwrap().iter() {
            assert_eq!(*body, 0, "an attestation request carries no body");
            assert!(!headers.contains_key("x-buyer-sentinel"));
            assert!(!headers.contains_key(AUTHORIZATION));
        }
    }
}

fn quick_fetch() -> Limits {
    Limits {
        fetch_timeout: Duration::from_millis(300),
        ..Limits::default()
    }
}

#[tokio::test]
async fn an_attestation_body_that_stalls_times_out_and_is_retried() {
    let (verifier, upstream) = serve(Evidence::Stalled, Chat::Served, quick_fetch()).await;
    let result = tokio::time::timeout(Duration::from_secs(10), verifier.forward(chat(TARGETS[0])))
        .await
        .unwrap();
    let error = result.unwrap_err();
    assert!(format!("{error:#}").contains("timed out"), "{error:#}");
    assert_eq!(counts(&upstream), (3, 3, 0), "three attempts, no chat");
    assert_eq!(verifier.idle_connections(), 0);
}

#[tokio::test]
async fn a_model_list_body_that_stalls_times_out_and_retires_its_connection() {
    let (verifier, upstream) =
        serve(Evidence::Genuine, Chat::StalledModelList, quick_fetch()).await;
    let request = Request::builder()
        .uri(MODELS)
        .header(AUTHORIZATION, "Bearer kt")
        .body(Body::empty())
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), verifier.models(request))
        .await
        .unwrap();
    assert!(format!("{:#}", result.unwrap_err()).contains("timed out"));
    assert_eq!(verifier.idle_connections(), 0);
    assert_eq!(upstream.model_lists.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn each_event_reaches_the_caller_as_it_arrives() {
    let (verifier, _) = serve(Evidence::Genuine, Chat::FirstEventOnly, limits()).await;
    let response =
        tokio::time::timeout(Duration::from_secs(10), verifier.forward(chat(TARGETS[0])))
            .await
            .unwrap()
            .unwrap();
    let mut body = response.into_body();
    let first = tokio::time::timeout(Duration::from_secs(10), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.into_data().unwrap(), FIRST_EVENT);
}

#[tokio::test]
async fn supplier_trailers_are_removed_on_the_forwarding_path() {
    let (verifier, _) = serve(Evidence::Genuine, Chat::Trailed, limits()).await;
    let mut request = chat(TARGETS[0]);
    request
        .headers_mut()
        .insert("te", HeaderValue::from_static("trailers"));
    let response = verifier.forward(request).await.unwrap();
    let collected = response.into_body().collect().await.unwrap();
    let trailers = collected.trailers().cloned().unwrap();
    assert_eq!(trailers["x-request-cost"], "kept");
    assert!(!trailers.contains_key("x-kubetee-attestation-quote"));
    assert!(!trailers.contains_key("x-litellm-key-spend"));
    assert_eq!(collected.to_bytes(), FIRST_EVENT);
}

#[tokio::test]
async fn a_chat_body_that_stalls_is_refused_before_any_connection() {
    let slow_caller = Limits {
        request_read_timeout: Duration::from_millis(300),
        ..Limits::default()
    };
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, slow_caller).await;
    let mut request = chat(TARGETS[0]);
    *request.body_mut() = Body::new(Frames::stalling(Bytes::from_static(b"{\"model\":")));
    let result = tokio::time::timeout(Duration::from_secs(10), verifier.forward(request))
        .await
        .unwrap();
    assert!(format!("{:#}", result.unwrap_err()).contains("timed out"));
    assert_eq!(counts(&upstream), (0, 0, 0));
}

#[tokio::test]
async fn a_failed_chat_is_never_retried_and_its_connection_is_retired() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Dropped, limits()).await;
    assert!(verifier.forward(chat(TARGETS[0])).await.is_err());
    assert_eq!(counts(&upstream), (1, 1, 1));
    assert_eq!(verifier.idle_connections(), 0);
}

#[tokio::test]
async fn an_upstream_error_status_passes_through() {
    let (verifier, _) = serve(Evidence::Genuine, Chat::Unauthorized, limits()).await;
    let (status, body) = round_trip(&verifier, TARGETS[1]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, "{\"error\":\"unauthorized\"}".as_bytes());
}

#[tokio::test]
async fn the_model_list_is_fetched_on_an_attested_connection_and_narrowed() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    let request = Request::builder()
        .uri(MODELS)
        .header(AUTHORIZATION, "Bearer kt")
        .body(Body::empty())
        .unwrap();
    let response = verifier.models(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let list: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        list["data"],
        serde_json::json!([
            {"id": "z-ai/glm-5.3", "object": "model"},
            {"id": "black-forest-labs/flux.2-klein-4b", "object": "model"},
        ])
    );
    let keyless = Request::builder().uri(MODELS).body(Body::empty()).unwrap();
    let response = verifier.models(keyless).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    round_trip(&verifier, TARGETS[0]).await;
    assert_eq!(
        counts(&upstream),
        (1, 1, 1),
        "one attested connection serves all three"
    );
}

#[tokio::test]
async fn the_model_list_is_never_fetched_on_a_connection_that_failed_attestation() {
    let (verifier, upstream) = serve(Evidence::OtherKey, Chat::Served, limits()).await;
    let request = Request::builder().uri(MODELS).body(Body::empty()).unwrap();
    assert!(verifier.models(request).await.is_err());
    assert_eq!(counts(&upstream), (3, 3, 0));
    assert_eq!(upstream.model_lists.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn preflight_reports_the_attested_replica() {
    let (verifier, _) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    let attested = verifier.preflight().await.unwrap();
    assert_eq!(attested.pod, "litellm-5dcbc54579-7rm6g");
    assert_eq!(tdx(&attested.measurements).rtmrs[3], [0; 48]);
    assert_eq!(
        verifier.idle_connections(),
        0,
        "a preflight connection is not pooled"
    );
}
