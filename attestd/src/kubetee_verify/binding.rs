//! The `kubetee.attestation.v1` `report_data` construction and its checks.
//!
//! Construction (the `kubetee.attestation.v1` specification, section 4):
//! `report_data = SHA-256(JCS(statement)) || 32 zero bytes`, where the
//! statement is the fixed template
//! `{"keyset_digest":"sha256:<hex>","nonce":"<64-hex>","purpose":"kubetee.attestation.v1"}`.
//! The statement is served verbatim as `bindings.report_data_statement` and
//! is hashed as served, so nothing is re-canonicalized here. `keyset_digest`
//! is `sha256(JCS(keyset))` over the served keyset (spec section 5), which
//! this module recomputes from the connection's own leaf certificate: the
//! quote, the served keyset, and the TLS session must be one identity.
//!
//! JCS here covers RFC 8785 for the attestation input class: objects,
//! arrays, and strings, keys sorted by UTF-16 code units, ECMA-262 string
//! serialization (assumes well-formed UTF-16 in names). The module is
//! std-only so its vectors pin the wire format without new dependencies.

use std::collections::BTreeMap;

use anyhow::{ensure, Result};
use sha2::{Digest as _, Sha256};

/// The purpose tag every v1 statement carries (domain separation).
pub const PURPOSE: &str = "kubetee.attestation.v1";
const KEYSET_DIGEST_PREFIX: &str = "sha256:";
const STATEMENT_DIGEST_PREFIX: &str = "\"keyset_digest\":\"";
const STATEMENT_NONCE_PREFIX: &str = "\",\"nonce\":\"";
const STATEMENT_SUFFIX: &str = "\",\"purpose\":\"kubetee.attestation.v1\"}";

/// The JSON tree a keyset and a statement are built from.
#[derive(Clone, Debug)]
pub enum Json {
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl From<&str> for Json {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

/// RFC 8785 canonical JSON for the attestation input class.
#[must_use]
pub fn jcs(value: &Json) -> String {
    match value {
        Json::String(text) => jcs_string(text),
        Json::Array(items) => {
            let elements = items.iter().map(jcs).collect::<Vec<_>>();
            format!("[{}]", elements.join(","))
        }
        Json::Object(fields) => {
            // BTreeMap's byte order over UTF-8 equals RFC 8785's UTF-16 code
            // unit order for well-formed strings (UTF-8 preserves code point
            // order and well-formed surrogates never serialize to ASCII).
            let entries = fields
                .iter()
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

/// The served keyset (spec section 5) for a serving certificate's DER SPKI
/// and RFC 3339 `not_after` (`YYYY-MM-DDThh:mm:ssZ`). The SPKI digest is
/// recomputed from the connection's own leaf, never taken from the response.
#[must_use]
pub fn keyset_json(spki_der: &[u8], not_after: &str, domain: &str) -> Json {
    let mut tls_key = BTreeMap::new();
    tls_key.insert("domain".to_owned(), Json::from(domain));
    tls_key.insert(
        "spki_sha256".to_owned(),
        Json::String(hex::encode(Sha256::digest(spki_der))),
    );
    let mut fields = BTreeMap::new();
    fields.insert(
        "subject".to_owned(),
        Json::String(format!("{PURPOSE}/{domain}")),
    );
    fields.insert("not_after".to_owned(), Json::String(not_after.to_owned()));
    fields.insert(
        "tls_public_keys".to_owned(),
        Json::Array(vec![Json::Object(tls_key)]),
    );
    fields.insert("signing_keys".to_owned(), Json::Array(Vec::new()));
    fields.insert("e2ee_keys".to_owned(), Json::Array(Vec::new()));
    Json::Object(fields)
}

/// Check a served v1 statement against the expected keyset digest, the nonce
/// sent, and the quote's `report_data` (spec section 4): derive the binding
/// the statement names and require the quote to carry exactly it.
///
/// # Errors
///
/// Returns an error naming the first check that fails: the statement shape,
/// its keyset digest, its nonce, its purpose tag, or the quoted binding.
pub fn verify_statement(
    statement: &str,
    keyset_digest: &str,
    nonce: &str,
    report_data: &[u8; 64],
) -> Result<()> {
    let expected = report_data_of_statement(statement, keyset_digest, nonce)?;
    ensure!(
        *report_data == expected,
        "TDX report_data is not the v1 binding statement hash"
    );
    Ok(())
}

/// `sha256:<hex>` over JCS(keyset) — what the statement's `keyset_digest`
/// must equal when recomputed from the served keyset (spec section 5).
#[must_use]
pub fn keyset_digest(keyset: &Json) -> String {
    format!(
        "{KEYSET_DIGEST_PREFIX}{}",
        hex::encode(Sha256::digest(jcs(keyset).as_bytes()))
    )
}

/// The 64-byte `report_data` a served v1 statement binds: `SHA-256(statement)`
/// zero-padded. Verifies the statement's `keyset_digest` and `nonce` against
/// the expected values first (the statement is hashed as served).
///
/// # Errors
///
/// Returns an error when the statement is malformed or names another keyset
/// digest or nonce.
pub fn report_data_of_statement(
    statement: &str,
    keyset_digest_value: &str,
    nonce: &str,
) -> Result<[u8; 64]> {
    let Some(rest) = statement
        .strip_prefix('{')
        .and_then(|s| s.strip_prefix(STATEMENT_DIGEST_PREFIX))
        .and_then(|s| s.strip_prefix(KEYSET_DIGEST_PREFIX))
    else {
        anyhow::bail!("kubetee.attestation.v1 statement is not the fixed template");
    };
    let Some(rest) = rest
        .strip_prefix(
            keyset_digest_value
                .strip_prefix(KEYSET_DIGEST_PREFIX)
                .unwrap_or(keyset_digest_value),
        )
        .and_then(|s| s.strip_prefix(STATEMENT_NONCE_PREFIX))
    else {
        anyhow::bail!("kubetee.attestation.v1 statement names a different keyset digest");
    };
    let Some(rest) = rest.strip_prefix(nonce) else {
        anyhow::bail!("kubetee.attestation.v1 statement names a different nonce");
    };
    ensure!(
        rest == STATEMENT_SUFFIX,
        "kubetee.attestation.v1 statement has no kubetee.attestation.v1 purpose"
    );
    let hash = Sha256::digest(statement.as_bytes());
    let mut report_data = [0; 64];
    report_data[..32].copy_from_slice(&hash);
    Ok(report_data)
}

/// `sha256:<hex>` over the JCS of a served keyset (serde `Value`), the spec
/// section 5 recomputation from the response's own keyset.
///
/// # Errors
///
/// Returns an error when the keyset carries a value outside the attestation
/// input class (numbers, booleans, null).
pub fn recompute_keyset_digest(keyset: &serde_json::Value) -> Result<String> {
    let tree = json_tree(keyset)?;
    Ok(keyset_digest(&tree))
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
        other => anyhow::bail!(
            "kubetee.attestation.v1 keyset holds {other}, outside the attestation input class"
        ),
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test fixtures intentionally fail hard on malformed local values"
    )]

    use super::*;

    // Cross-implementation conformance: generated with the shipped Python
    // builder (the supplier's Python implementation of this construction)
    // over tests/fixtures/kubetee/session_leaf.der and the recorded nonce,
    // and independently pinned by the spec section 4 vectors below.
    const SPKI_SHA256: &str = "3f728244ad1bb95542b14cdbf7f637105dc588f8958c862e4beffc450c000cd3";
    const FIXTURE_NONCE: &str = "cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a";
    const FIXTURE_KEYSET_DIGEST: &str =
        "sha256:64f6b8c71a0452909b382f5abcaaa6a76ae5b58bf930ff8f78f5074e4a64873d";
    const FIXTURE_STATEMENT: &str = r#"{"keyset_digest":"sha256:64f6b8c71a0452909b382f5abcaaa6a76ae5b58bf930ff8f78f5074e4a64873d","nonce":"cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a","purpose":"kubetee.attestation.v1"}"#;
    const FIXTURE_REPORT_DATA: &str = "9e4867826f437965258b4bcf964e603e30d31b662a4f3ef0ffc50cba611633710000000000000000000000000000000000000000000000000000000000000000";

    // Spec section 4 published conformance vectors (2026-10-23).
    const SPEC_KEYSET_DIGEST: &str =
        "sha256:693868b5f94f4dad208e8e37fe93ebf1be212f3451462b079dc9ba828b8d33ea";
    const SPEC_STATEMENT: &str = r#"{"keyset_digest":"sha256:693868b5f94f4dad208e8e37fe93ebf1be212f3451462b079dc9ba828b8d33ea","nonce":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","purpose":"kubetee.attestation.v1"}"#;
    const SPEC_STATEMENT_SHA256: &str =
        "755d36ae1b2ea98e9bdb32350b7356b75515e4ecae711a198ade29ec325b14f4";

    fn fixture_report_data() -> [u8; 64] {
        hex::decode(FIXTURE_REPORT_DATA)
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn spec_keyset() -> Json {
        let mut tls_key = BTreeMap::new();
        tls_key.insert("domain".to_owned(), Json::from("llm.kubetee.ai"));
        tls_key.insert("spki_sha256".to_owned(), Json::String("0".repeat(64)));
        let mut fields = BTreeMap::new();
        fields.insert("not_after".to_owned(), Json::from("2030-01-01T00:00:00Z"));
        fields.insert(
            "subject".to_owned(),
            Json::from("kubetee.attestation.v1/test-vector"),
        );
        fields.insert(
            "tls_public_keys".to_owned(),
            Json::Array(vec![Json::Object(tls_key)]),
        );
        Json::Object(fields)
    }

    #[test]
    fn jcs_orders_object_keys_and_escapes_strings() {
        let mut fields = BTreeMap::new();
        fields.insert("b".to_owned(), Json::from("x\"y"));
        fields.insert("a".to_owned(), Json::from("z"));
        assert_eq!(jcs(&Json::Object(fields)), r#"{"a":"z","b":"x\"y"}"#);
        assert_eq!(
            jcs(&Json::Array(vec![Json::from("1"), Json::from("2")])),
            "[\"1\",\"2\"]"
        );
        assert_eq!(jcs(&Json::from("a\nb")), "\"a\\nb\"");
    }

    #[test]
    fn the_spec_keyset_digest_vector_reproduces() {
        assert_eq!(keyset_digest(&spec_keyset()), SPEC_KEYSET_DIGEST);
    }

    #[test]
    fn the_statement_and_its_hash_match_the_spec_vectors() {
        let statement = format!(
            r#"{{"keyset_digest":"{SPEC_KEYSET_DIGEST}","nonce":"{}","purpose":"{PURPOSE}"}}"#,
            "0123456789abcdef".repeat(4)
        );
        assert_eq!(statement, SPEC_STATEMENT);
        assert_eq!(
            hex::encode(Sha256::digest(statement.as_bytes())),
            SPEC_STATEMENT_SHA256
        );
    }

    #[test]
    fn the_fixture_statement_verifies_and_the_serving_keyset_digest_matches() {
        verify_statement(
            FIXTURE_STATEMENT,
            FIXTURE_KEYSET_DIGEST,
            FIXTURE_NONCE,
            &fixture_report_data(),
        )
        .unwrap();
        // A keyset built from the real SPKI digest must reproduce the builder's digest.
        let mut tls_key = BTreeMap::new();
        tls_key.insert("domain".to_owned(), Json::from("llm.kubetee.ai"));
        tls_key.insert(
            "spki_sha256".to_owned(),
            Json::String(SPKI_SHA256.to_owned()),
        );
        let mut fields = BTreeMap::new();
        fields.insert(
            "subject".to_owned(),
            Json::from("kubetee.attestation.v1/llm.kubetee.ai"),
        );
        fields.insert("not_after".to_owned(), Json::from("2026-12-21T10:08:05Z"));
        fields.insert(
            "tls_public_keys".to_owned(),
            Json::Array(vec![Json::Object(tls_key)]),
        );
        fields.insert("signing_keys".to_owned(), Json::Array(Vec::new()));
        fields.insert("e2ee_keys".to_owned(), Json::Array(Vec::new()));
        assert_eq!(keyset_digest(&Json::Object(fields)), FIXTURE_KEYSET_DIGEST);
    }

    #[test]
    fn the_report_data_is_the_statement_hash_zero_padded() {
        let report_data = fixture_report_data();
        assert_eq!(
            hex::encode(&report_data[..32]),
            hex::encode(Sha256::digest(FIXTURE_STATEMENT.as_bytes()))
        );
        assert_eq!(report_data[32..], [0; 32]);
    }

    #[test]
    fn a_different_serving_spki_changes_the_keyset_digest() {
        let keyset = keyset_json(&[0; 32], "2026-12-21T10:08:05Z", "llm.kubetee.ai");
        let other = keyset_json(&[1; 32], "2026-12-21T10:08:05Z", "llm.kubetee.ai");
        assert_ne!(keyset_digest(&keyset), keyset_digest(&other));
    }

    #[test]
    fn a_statement_for_another_keyset_fails_closed() {
        let report_data = fixture_report_data();
        let other = format!("{KEYSET_DIGEST_PREFIX}{}", "0".repeat(64));
        let error =
            verify_statement(FIXTURE_STATEMENT, &other, FIXTURE_NONCE, &report_data).unwrap_err();
        assert!(format!("{error:#}").contains("different keyset digest"));
    }

    #[test]
    fn a_statement_for_another_nonce_fails_closed() {
        let report_data = fixture_report_data();
        let error = verify_statement(
            FIXTURE_STATEMENT,
            FIXTURE_KEYSET_DIGEST,
            &"00".repeat(32),
            &report_data,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("different nonce"));
    }

    #[test]
    fn a_statement_with_another_purpose_fails_closed() {
        let wrong = FIXTURE_STATEMENT.replace(PURPOSE, "kubetee.attestation.v0");
        let error = verify_statement(
            &wrong,
            FIXTURE_KEYSET_DIGEST,
            FIXTURE_NONCE,
            &fixture_report_data(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("purpose"));
    }

    #[test]
    fn a_reused_legacy_report_data_fails_the_v1_binding() {
        // The legacy construction (SHA-512 of the nonce) must not pass as v1.
        let legacy: [u8; 64] = legacy_report_data(FIXTURE_NONCE);
        let error = verify_statement(
            FIXTURE_STATEMENT,
            FIXTURE_KEYSET_DIGEST,
            FIXTURE_NONCE,
            &legacy,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("report_data"));
    }

    fn legacy_report_data(nonce: &str) -> [u8; 64] {
        use sha2::Sha512;
        Sha512::digest(nonce.as_bytes()).into()
    }

    #[test]
    fn a_statement_tampered_after_the_nonce_fails_closed() {
        let tampered = FIXTURE_STATEMENT.replace(PURPOSE, "kubetee.attestation.v1 ");
        let error = verify_statement(
            &tampered,
            FIXTURE_KEYSET_DIGEST,
            FIXTURE_NONCE,
            &fixture_report_data(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("purpose"));
    }
}
