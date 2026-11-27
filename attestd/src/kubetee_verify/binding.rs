//! The `kubetee.attestation.v2` quote-bound key binding and its checks.
//!
//! Construction (`ReportDataForKeyWithContext`, Phase 6 zero-operator trust):
//! `report_data = SHA-384(tag ‖ framed(pkix) ‖ framed(nonce) ‖ framed(context))`
//! `‖ 16 zero bytes`, where `tag` is the raw `KEY_ATTESTATION_TAG` and each
//! input is length-framed (`u64-be length ‖ bytes`) so no two distinct
//! `(pkix, nonce, context)` tuples share a preimage. `pkix` is the DER
//! `SubjectPublicKeyInfo` of a **per-boot in-guest generated** evidence key,
//! `nonce` its raw 32 bytes, and `context` a domain-separation string.
//!
//! The quote commits that `report_data`; the response serves the binding
//! inputs verbatim as a canonical-JCS statement
//! `{"context":..,"keyset_digest":..,"nonce":..,"pkix_pubkey_b64url":..,
//! "purpose":"kubetee.attestation.v2"}` plus `keyset_digest`
//! (`sha256(JCS(keyset))`). Verification re-derives the statement field-by-
//! field (anti-downgrade — nothing is trusted as served) and recomputes the
//! `report_data` from those fields, then the quote must carry it and a
//! `key_possession` signature must verify over it under the bound key.
//!
//! This module is std-only (plus sha2/hex/base64) so its vectors pin the wire
//! format without new dependencies.

use std::collections::BTreeMap;

use anyhow::{ensure, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest as _, Sha256, Sha384};

/// The only binding version this proxy accepts (domain separation).
pub const PURPOSE: &str = "kubetee.attestation.v2";
/// Domain-separation tag for the v2 report-data derivation. Changing this
/// string is a contract change (it is inside the frozen test vector).
pub const KEY_ATTESTATION_TAG: &[u8] = b"kubetee.attestation.v2/ReportDataForKeyWithContext";
/// The key class the per-boot generated key serves (the statement names it).
pub const KEY_PURPOSE: &str = "tls-ephemeral";
/// The `key_possession.input` the proof must name.
pub const POSSESSION_INPUT: &str = "quote_report_data";
/// The `key_possession.alg` the proof must name (ECDSA P-256 / SHA-256, DER).
pub const POSSESSION_ALG: &str = "ecdsa-secp256r1-sha256";

const KEYSET_DIGEST_PREFIX: &str = "sha256:";

/// The JSON tree a keyset and a statement are built from.
#[derive(Clone, Debug)]
enum Json {
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

/// RFC 8785 canonical JSON for the attestation input class.
#[must_use]
fn jcs(value: &Json) -> String {
    match value {
        Json::String(text) => jcs_string(text),
        Json::Array(items) => {
            let elements = items.iter().map(jcs).collect::<Vec<_>>();
            format!("[{}]", elements.join(","))
        }
        Json::Object(fields) => {
            // RFC 8785 orders names by UTF-16 code units. BTreeMap's UTF-8
            // order differs for supplementary characters versus high BMP
            // characters, so sort explicitly at every object level.
            let mut fields = fields.iter().collect::<Vec<_>>();
            fields.sort_unstable_by(|(left, _), (right, _)| {
                left.encode_utf16().cmp(right.encode_utf16())
            });
            let entries = fields
                .into_iter()
                .map(|(key, value)| format!("{}:{}", jcs_string(key), jcs(value)))
                .collect::<Vec<_>>();
            format!("{{{}}}", entries.join(","))
        }
    }
}

fn jcs_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Normalize + validate the caller nonce: 64 lowercase hex chars. ASCII-only
/// (rejects control chars / Unicode whitespace that `trim()` alone would let
/// through — zero-length-input bypass class).
///
/// # Errors
///
/// Returns an error when `nonce` is not 64 ASCII hex characters.
pub fn normalize_nonce(nonce: &str) -> Result<String> {
    ensure!(nonce.is_ascii(), "nonce must be ASCII hex");
    let n = nonce.trim().to_lowercase();
    ensure!(
        n.len() == 64 && n.chars().all(|c| c.is_ascii_hexdigit()),
        "nonce must be 64 hex chars, got {nonce:?}"
    );
    Ok(n)
}

/// `sha256:<hex>` over JCS(keyset) — what the statement's `keyset_digest`
/// must equal when recomputed from the served keyset.
///
/// # Errors
///
/// Returns an error when the keyset carries a value outside the attestation
/// input class (numbers, booleans, null).
pub fn keyset_digest(keyset: &serde_json::Value) -> Result<String> {
    let tree = json_tree(keyset)?;
    Ok(format!(
        "{KEYSET_DIGEST_PREFIX}{}",
        hex::encode(Sha256::digest(jcs(&tree).as_bytes()))
    ))
}

fn json_tree(value: &serde_json::Value) -> Result<Json> {
    match value {
        serde_json::Value::String(text) => Ok(Json::String(text.clone())),
        serde_json::Value::Array(items) => {
            let trees = items.iter().map(json_tree).collect::<Result<Vec<_>>>()?;
            Ok(Json::Array(trees))
        }
        serde_json::Value::Object(fields) => {
            let mut tree = BTreeMap::new();
            for (key, value) in fields {
                tree.insert(key.clone(), json_tree(value)?);
            }
            Ok(Json::Object(tree))
        }
        other => anyhow::bail!("keyset holds {other}, outside the attestation input class"),
    }
}

/// Length-framed concatenation (`u64-be length ‖ bytes`) — the
/// `ReportDataForKeyWithContext` transcript pattern. Framing prevents any two
/// distinct `(pkix, nonce, context)` tuples from sharing a preimage.
fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u64).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// The exact byte string the v2 report-data hash consumes: the raw tag then
/// `framed(pkix) ‖ framed(nonce) ‖ framed(context)`. `pkix` is the DER SPKI
/// of the per-boot key, `nonce` its raw 32 bytes, `context` a non-empty
/// domain-separation string.
///
/// # Errors
///
/// Returns an error when any input is empty (no uncontextualized key binding).
pub fn report_data_preimage_v2(pkix_pubkey: &[u8], nonce: &[u8], context: &str) -> Result<Vec<u8>> {
    ensure!(!pkix_pubkey.is_empty(), "v2 pkix_pubkey must be non-empty");
    ensure!(!nonce.is_empty(), "v2 nonce must be non-empty");
    ensure!(
        !context.is_empty(),
        "v2 context must be non-empty (no uncontextualized key binding)"
    );
    let mut out = Vec::new();
    out.extend_from_slice(KEY_ATTESTATION_TAG);
    out.extend_from_slice(&framed(&[pkix_pubkey, nonce, context.as_bytes()]));
    Ok(out)
}

/// v2 `report_data` = `SHA-384(preimage) ‖ 16 zero bytes` (64 bytes total —
/// the quote report-data field size). The zero suffix keeps the field layout
/// while reserving it against cross-purpose collisions.
///
/// # Errors
///
/// Returns an error when an input is empty.
pub fn report_data_v2(pkix_pubkey: &[u8], nonce: &[u8], context: &str) -> Result<[u8; 64]> {
    let preimage = report_data_preimage_v2(pkix_pubkey, nonce, context)?;
    let digest = Sha384::digest(&preimage);
    let mut out = [0u8; 64];
    out[..48].copy_from_slice(&digest);
    Ok(out)
}

/// The canonical-JCS statement the response serves (and verification re-
/// derives) for v2: `{"context":..,"keyset_digest":..,"nonce":..,
/// "pkix_pubkey_b64url":..,"purpose":"kubetee.attestation.v2"}`.
///
/// # Errors
///
/// Returns an error when `keyset_digest` is malformed, `nonce` is not 64 hex,
/// or `pkix_pubkey_b64url` / `context` are empty.
pub fn report_data_statement_v2(
    keyset_digest: &str,
    nonce: &str,
    pkix_pubkey_b64url: &str,
    context: &str,
) -> Result<String> {
    ensure!(
        keyset_digest.starts_with(KEYSET_DIGEST_PREFIX)
            && keyset_digest.len() == KEYSET_DIGEST_PREFIX.len() + 64
            && keyset_digest[KEYSET_DIGEST_PREFIX.len()..]
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
        "malformed keyset_digest: {keyset_digest:?}"
    );
    let nonce = normalize_nonce(nonce)?;
    ensure!(
        !pkix_pubkey_b64url.is_empty(),
        "v2 pkix_pubkey_b64url must be non-empty"
    );
    ensure!(!context.is_empty(), "v2 context must be non-empty");
    let mut fields = BTreeMap::new();
    fields.insert("context".to_owned(), Json::String(context.to_owned()));
    fields.insert(
        "keyset_digest".to_owned(),
        Json::String(keyset_digest.to_owned()),
    );
    fields.insert("nonce".to_owned(), Json::String(nonce));
    fields.insert(
        "pkix_pubkey_b64url".to_owned(),
        Json::String(pkix_pubkey_b64url.to_owned()),
    );
    fields.insert("purpose".to_owned(), Json::String(PURPOSE.to_owned()));
    Ok(jcs(&Json::Object(fields)))
}

/// Decode the served `pkix_pubkey_b64url` (URL-safe, no pad — standard pad
/// accepted) into the DER `SubjectPublicKeyInfo` the derivation hashes.
///
/// # Errors
///
/// Returns an error when the value is empty or not base64.
pub fn decode_pkix_pubkey(pkix_pubkey_b64url: &str) -> Result<Vec<u8>> {
    ensure!(
        !pkix_pubkey_b64url.is_empty(),
        "v2 pkix_pubkey_b64url is empty"
    );
    let mut s = pkix_pubkey_b64url.trim().to_owned();
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&s))
        .map_err(|error| anyhow::anyhow!("v2 pkix_pubkey_b64url: {error}"))
}

/// Decode the statement's 64-hex nonce into its raw 32 bytes (the derivation
/// hashes the raw bytes, not the hex text).
///
/// # Errors
///
/// Returns an error when `hex_str` is not 64 hex characters.
pub fn bytes_from_hex32(hex_str: &str) -> Result<Vec<u8>> {
    ensure!(
        hex_str.len() == 64 && hex_str.chars().all(|c| c.is_ascii_hexdigit()),
        "nonce hex length"
    );
    (0..32)
        .map(|i| {
            u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
                .map_err(|error| anyhow::anyhow!("nonce hex: {error}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test fixtures intentionally fail hard on malformed local values"
    )]

    use super::*;

    // Frozen derivation vector — shared with the Python builder
    // (kubetee_binding.py) and the Rust reference verifier. The transcript
    // and its report_data are pinned so any change to the tag, framing, or
    // hash breaks this test (contract change).
    const KAT_PKIX_HEX: &str = "302a300506032b6570032100000102030405060708090a0b0c0d0e0f\
                                101112131415161718191a1b1c1d1e1f";
    const KAT_NONCE: [u8; 32] = [0xaa; 32];
    const KAT_CONTEXT: &str = "kubetee-test-context";
    const KAT_REPORT_DATA: &str =
        "7c7f82da79e64d00bb228bf3bd7075ea31b938759d00162f1f1d83021f245e24\
         eff25929ec5761309dbbc014119dc4c000000000000000000000000000000000";

    #[test]
    fn the_v2_report_data_matches_the_cross_language_kat() {
        let pkix = hex::decode(KAT_PKIX_HEX).unwrap();
        let rd = report_data_v2(&pkix, &KAT_NONCE, KAT_CONTEXT).unwrap();
        assert_eq!(
            hex::encode(rd),
            KAT_REPORT_DATA.replace(char::is_whitespace, "")
        );
        assert_eq!(rd.len(), 64);
        assert!(rd[48..].iter().all(|b| *b == 0), "16 zero bytes suffix");
    }

    #[test]
    fn the_transcript_is_tag_then_three_length_framed_parts() {
        let pkix = hex::decode(KAT_PKIX_HEX).unwrap();
        let preimage = report_data_preimage_v2(&pkix, &KAT_NONCE, KAT_CONTEXT).unwrap();
        assert_eq!(
            preimage.len(),
            KEY_ATTESTATION_TAG.len() + (8 + 44) + (8 + 32) + (8 + KAT_CONTEXT.len())
        );
        let mut offset = KEY_ATTESTATION_TAG.len();
        for part in [&pkix[..], &KAT_NONCE[..], KAT_CONTEXT.as_bytes()] {
            let length = usize::try_from(u64::from_be_bytes(
                preimage[offset..offset + 8].try_into().unwrap(),
            ))
            .unwrap();
            assert_eq!(length, part.len());
            offset += 8;
            assert_eq!(&preimage[offset..offset + length], part);
            offset += length;
        }
        assert_eq!(offset, preimage.len());
    }

    #[test]
    fn distinct_contexts_never_share_a_report_data() {
        let pkix = [1u8; 32];
        let nonce = [2u8; 32];
        assert_ne!(
            report_data_v2(&pkix, &nonce, "ctx-a").unwrap(),
            report_data_v2(&pkix, &nonce, "ctx-b").unwrap()
        );
    }

    #[test]
    fn the_v2_statement_is_the_canonical_jcs_of_its_fields() {
        let statement = report_data_statement_v2(
            "sha256:693868b5f94f4dad208e8e37fe93ebf1be212f3451462b079dc9ba828b8d33ea",
            "cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a",
            "AQIDBA",
            "role=nim-terminator",
        )
        .unwrap();
        assert_eq!(
            statement,
            r#"{"context":"role=nim-terminator","keyset_digest":"sha256:693868b5f94f4dad208e8e37fe93ebf1be212f3451462b079dc9ba828b8d33ea","nonce":"cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a","pkix_pubkey_b64url":"AQIDBA","purpose":"kubetee.attestation.v2"}"#
        );
    }

    #[test]
    fn the_statement_nonce_is_normalized_to_lowercase_hex() {
        let upper = report_data_statement_v2(
            "sha256:693868b5f94f4dad208e8e37fe93ebf1be212f3451462b079dc9ba828b8d33ea",
            &format!("CF95{}", "0".repeat(60)),
            "AQIDBA",
            "ctx",
        )
        .unwrap();
        assert!(upper.contains(r#""nonce":"cf95"#));
    }

    #[test]
    fn empty_or_malformed_v2_inputs_fail_closed() {
        let pkix = [1u8; 32];
        assert!(report_data_v2(&[], &[0u8; 32], "ctx").is_err());
        assert!(report_data_v2(&pkix, &[], "ctx").is_err());
        assert!(report_data_v2(&pkix, &[0u8; 32], "").is_err());
        assert!(report_data_statement_v2("sha256:zz", "00", "AQ", "ctx").is_err());
        assert!(report_data_statement_v2(
            "sha256:693868b5f94f4dad208e8e37fe93ebf1be212f3451462b079dc9ba828b8d33ea",
            "short",
            "AQ",
            "ctx"
        )
        .is_err());
        assert!(decode_pkix_pubkey("").is_err());
        assert!(decode_pkix_pubkey("!!!not-base64!!!").is_err());
    }

    #[test]
    fn decode_pkix_accepts_urlsafe_unpadded_and_standard_padded() {
        let raw = [7u8; 16];
        let unpadded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        assert_eq!(decode_pkix_pubkey(&unpadded).unwrap(), raw);
        let padded = base64::engine::general_purpose::STANDARD.encode(raw);
        assert_eq!(decode_pkix_pubkey(&padded).unwrap(), raw);
    }

    #[test]
    fn jcs_orders_object_names_by_utf16_at_every_depth() {
        let value = serde_json::json!({
            "\u{e000}": "bmp",
            "\u{1f600}": {"\u{e000}": "bmp", "\u{1f600}": "supplementary"},
            "array": [{"\u{e000}": "bmp", "\u{1f600}": "supplementary"}]
        });
        assert_eq!(
            jcs(&json_tree(&value).unwrap()),
            "{\"array\":[{\"😀\":\"supplementary\",\"\u{e000}\":\"bmp\"}],\"😀\":{\"😀\":\"supplementary\",\"\u{e000}\":\"bmp\"},\"\u{e000}\":\"bmp\"}"
        );
    }

    #[test]
    fn keyset_digest_reproduces_the_spec_vector() {
        let mut tls_key = BTreeMap::new();
        tls_key.insert(
            "domain".to_owned(),
            Json::String("llm.kubetee.ai".to_owned()),
        );
        tls_key.insert("spki_sha256".to_owned(), Json::String("0".repeat(64)));
        let mut fields = BTreeMap::new();
        fields.insert(
            "not_after".to_owned(),
            Json::String("2030-01-01T00:00:00Z".to_owned()),
        );
        fields.insert(
            "subject".to_owned(),
            Json::String("kubetee.attestation.v1/test-vector".to_owned()),
        );
        fields.insert(
            "tls_public_keys".to_owned(),
            Json::Array(vec![Json::Object(tls_key)]),
        );
        assert_eq!(
            jcs(&Json::Object(fields.clone())),
            "{\"not_after\":\"2030-01-01T00:00:00Z\",\"subject\":\"kubetee.attestation.v1/test-vector\",\"tls_public_keys\":[{\"domain\":\"llm.kubetee.ai\",\"spki_sha256\":\"".to_owned() + &"0".repeat(64) + "\"}]}"
        );
    }

    #[test]
    fn bytes_from_hex32_rejects_short_or_non_hex() {
        assert_eq!(
            bytes_from_hex32(&"ab".repeat(32)).unwrap(),
            [0xab; 32].to_vec()
        );
        assert!(bytes_from_hex32("short").is_err());
        assert!(bytes_from_hex32(&"zz".repeat(32)).is_err());
    }
}
