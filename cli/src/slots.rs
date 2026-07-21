//! Upstream provider key slot parsing and id derivation.
//!
//! Multi-key values ride the existing provider key environment variables as
//! semicolon-separated segments. This module is the single implementation used
//! by the CLI's registration body and by the hidden boot helper that fans keys
//! out into per-slot Envoy environment variables.

use std::collections::{BTreeMap, HashSet};

use anyhow::{bail, Context as _, Result};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;

use crate::config::ProviderKeys;

const MAX_PROVIDER_SLOTS: usize = 8;
const SLOT_ID_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySlot {
    pub id: String,
    pub key: String,
}

fn trim_ascii(value: &str) -> &str {
    value.trim_matches(|c: char| c.is_ascii_whitespace())
}

#[must_use]
pub fn has_semicolon(value: Option<&str>) -> bool {
    value.is_some_and(|v| v.contains(';'))
}

/// Derive the opaque 12-character slot id for one provider key.
///
/// `node_secret` is used as UTF-8 bytes exactly as stored; it is not decoded
/// from hex first.
///
/// # Errors
/// Returns an error if the HMAC implementation rejects the key material.
pub fn derive_slot_id(provider: &str, provider_key: &str, node_secret: &str) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(node_secret.as_bytes())
        .context("initialize slot id HMAC")?;
    mac.update(provider.as_bytes());
    mac.update(b":");
    mac.update(provider_key.as_bytes());
    let digest = mac.finalize().into_bytes();
    Ok(BASE32_NOPAD.encode(&digest)[..SLOT_ID_LEN].to_owned())
}

/// Parse a provider key env var and return de-duplicated slots in input order.
///
/// Empty segments are fatal, and the raw segment count is capped before
/// de-duplication so a long repeated list cannot bypass the protocol limit.
///
/// # Errors
/// Returns an error when the list has an empty segment, more than 8 raw
/// segments, or a slot id cannot be derived.
pub fn parse_key_slots(provider: &str, raw: &str, node_secret: &str) -> Result<Vec<KeySlot>> {
    let segments: Vec<&str> = raw.split(';').collect();
    if segments.len() > MAX_PROVIDER_SLOTS {
        bail!(
            "{provider} key configuration has {} semicolon-separated entries; \
             at most {MAX_PROVIDER_SLOTS} upstream key slots are supported",
            segments.len()
        );
    }

    let mut seen = HashSet::new();
    let mut slots = Vec::new();
    for (idx, segment) in segments.iter().enumerate() {
        let key = trim_ascii(segment);
        if key.is_empty() {
            bail!(
                "{provider} key configuration contains an empty slot at position {}; \
                 remove the extra semicolon or fill in the key",
                idx + 1
            );
        }
        let id = derive_slot_id(provider, key, node_secret)?;
        if seen.insert(id.clone()) {
            slots.push(KeySlot {
                id,
                key: key.to_owned(),
            });
        }
    }
    Ok(slots)
}

fn add_provider_slots(
    out: &mut BTreeMap<String, Vec<String>>,
    provider: &str,
    raw: Option<&str>,
    node_secret: &str,
) -> Result<()> {
    let Some(raw) = raw.map(trim_ascii).filter(|v| !v.is_empty()) else {
        return Ok(());
    };
    let slots = parse_key_slots(provider, raw, node_secret)?;
    if !slots.is_empty() {
        out.insert(
            provider.to_owned(),
            slots.into_iter().map(|slot| slot.id).collect(),
        );
    }
    Ok(())
}

/// Compute registry-advertised provider slot ids for direct upstreams only.
///
/// Cloud backend key vars are v1 single-slot and must not contain semicolons.
///
/// # Errors
/// Returns an error when a cloud-backend key contains `;`, or when any direct
/// provider key list is invalid.
pub fn provider_slots_for_keys(
    keys: &ProviderKeys,
    node_secret: &str,
) -> Result<BTreeMap<String, Vec<String>>> {
    validate_cloud_backend_single_keys(keys)?;
    let backends = keys.worker_backends();
    if !backends.is_empty() {
        // v1: a worker with any cloud backend is single-slot for EVERY provider
        // — the registry rejects slot claims from backend workers and its
        // control loop never probes them. Advertising slots for the direct
        // providers (gemini, chutes, zai, moonshot, the non-backend of anthropic/openai)
        // would 422 the registration after the CVM has already launched, and
        // multi-key values there would sit silently unused, so both are refused
        // up front. A mixed worker (Claude on Foundry + GPT on Azure) is two
        // cloud providers, so it too advertises no slots.
        reject_multikey_for_cloud_backend(keys, &backends)?;
        return Ok(BTreeMap::new());
    }

    let mut slots = BTreeMap::new();
    if keys.anthropic_upstream.as_deref().unwrap_or("direct") == "direct" {
        add_provider_slots(
            &mut slots,
            "anthropic",
            keys.anthropic.as_deref(),
            node_secret,
        )?;
    }
    if keys.openai_upstream.as_deref().unwrap_or("direct") == "direct" {
        add_provider_slots(&mut slots, "openai", keys.openai.as_deref(), node_secret)?;
    }
    add_provider_slots(&mut slots, "gemini", keys.google.as_deref(), node_secret)?;
    add_provider_slots(&mut slots, "chutes", keys.chutes.as_deref(), node_secret)?;
    add_provider_slots(&mut slots, "zai", keys.zai.as_deref(), node_secret)?;
    add_provider_slots(
        &mut slots,
        "moonshot",
        keys.moonshot.as_deref(),
        node_secret,
    )?;
    add_provider_slots(
        &mut slots,
        "deepinfra",
        keys.deepinfra.as_deref(),
        node_secret,
    )?;
    Ok(slots)
}

/// Cloud backend key vars are intentionally single-slot in v1.
///
/// # Errors
/// Returns an error when a selected Bedrock or Azure key contains `;`.
pub fn validate_cloud_backend_single_keys(keys: &ProviderKeys) -> Result<()> {
    if keys.anthropic_upstream.as_deref() == Some("bedrock")
        && has_semicolon(keys.bedrock_api_key.as_deref())
    {
        bail!(
            "BEDROCK_API_KEY cannot contain ';' when ANTHROPIC_UPSTREAM=bedrock; \
             cloud backends are single-slot in this release"
        );
    }
    if keys.anthropic_upstream.as_deref() == Some("foundry")
        && has_semicolon(keys.azure_foundry_api_key.as_deref())
    {
        bail!(
            "AZURE_FOUNDRY_API_KEY cannot contain ';' when ANTHROPIC_UPSTREAM=foundry; \
             cloud backends are single-slot in this release"
        );
    }
    if keys.openai_upstream.as_deref() == Some("azure")
        && has_semicolon(keys.azure_openai_api_key.as_deref())
    {
        bail!(
            "AZURE_OPENAI_API_KEY cannot contain ';' when OPENAI_UPSTREAM=azure; \
             cloud backends are single-slot in this release"
        );
    }
    Ok(())
}

/// Reject semicolon-separated direct keys when a cloud backend is
/// selected: backend workers are single-slot in this release, so extra
/// keys would be advertised nowhere and used never.
///
/// # Errors
/// Returns an error naming the offending env var when any ACTIVE
/// direct-provider key holds multiple segments.
pub fn reject_multikey_for_cloud_backend(
    keys: &ProviderKeys,
    backends: &BTreeMap<String, String>,
) -> Result<()> {
    for (var, value) in active_direct_keys(keys) {
        if has_semicolon(value) {
            let adapters = backends
                .values()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join("/");
            bail!(
                "{var} holds multiple keys but the {adapters} cloud backend is selected;                  cloud-backend workers are single-slot in this release — drop the extra                  keys or the cloud backend"
            );
        }
    }
    Ok(())
}

/// Reject semicolon-separated direct keys when the deploy target image
/// cannot fan them out.
///
/// A legacy image's entrypoint passes the raw value as ONE credential —
/// every provider request would fail against a key like `sk-a;sk-b`.
///
/// # Errors
/// Returns an error naming the offending env var when any configured
/// direct-provider key holds multiple segments.
pub fn reject_multikey_for_legacy_image(keys: &ProviderKeys) -> Result<()> {
    for (var, value) in active_direct_keys(keys) {
        if has_semicolon(value) {
            bail!(
                "{var} holds multiple keys but the selected image predates upstream                  key slots; deploy a slot-capable version (newer --version) or drop                  the extra keys"
            );
        }
    }
    Ok(())
}

/// The direct-provider key env vars the deployed image would actually
/// read: keys sidelined by a cloud upstream selector are excluded, so a
/// stale semicolon value there never blocks a deploy.
fn active_direct_keys(keys: &ProviderKeys) -> [(&'static str, Option<&str>); 7] {
    let anthropic_direct = keys.anthropic_upstream.as_deref().unwrap_or("direct") == "direct";
    let openai_direct = keys.openai_upstream.as_deref().unwrap_or("direct") == "direct";
    [
        (
            "ANTHROPIC_API_KEY",
            keys.anthropic.as_deref().filter(|_| anthropic_direct),
        ),
        (
            "OPENAI_API_KEY",
            keys.openai.as_deref().filter(|_| openai_direct),
        ),
        ("GOOGLE_API_KEY", keys.google.as_deref()),
        ("CHUTES_API_KEY", keys.chutes.as_deref()),
        ("ZAI_API_KEY", keys.zai.as_deref()),
        ("MOONSHOT_API_KEY", keys.moonshot.as_deref()),
        ("DEEPINFRA_API_KEY", keys.deepinfra.as_deref()),
    ]
}

#[must_use]
pub fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

/// Render shell exports for `start.sh` to eval without logging.
///
/// # Errors
/// Returns an error when the provider key list is invalid.
pub fn render_slot_env_exports(provider: &str, raw: &str, node_secret: &str) -> Result<String> {
    let slots = parse_key_slots(provider, raw, node_secret)?;
    let prefix = provider.to_ascii_uppercase();
    let export_prefix = format!("GM_{prefix}");

    let mut out = String::new();
    let mut ids = Vec::with_capacity(slots.len());
    for (idx, slot) in slots.iter().enumerate() {
        let slot_num = idx + 1;
        ids.push(slot.id.as_str());
        out.push_str("export ");
        out.push_str(&export_prefix);
        out.push_str("_KEY_SLOT_");
        out.push_str(&slot_num.to_string());
        out.push('=');
        out.push_str(&shell_quote(&slot.key));
        out.push('\n');
    }
    out.push_str("export ");
    out.push_str(&export_prefix);
    out.push_str("_SLOT_IDS=");
    out.push_str(&shell_quote(&ids.join(";")));
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    const SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn cloud_backend_suppresses_all_slot_advertisement() {
        let keys = ProviderKeys {
            anthropic_upstream: Some("bedrock".to_owned()),
            bedrock_api_key: Some("bedrock-key".to_owned()),
            google: Some("g-key".to_owned()),
            ..ProviderKeys::default()
        };
        let slots = provider_slots_for_keys(&keys, SECRET).expect("mixed setup deploys");
        assert!(
            slots.is_empty(),
            "backend workers advertise no slots for any provider",
        );
    }

    #[test]
    fn cloud_backend_rejects_direct_multikey() {
        let keys = ProviderKeys {
            anthropic_upstream: Some("bedrock".to_owned()),
            bedrock_api_key: Some("bedrock-key".to_owned()),
            google: Some("g-a;g-b".to_owned()),
            ..ProviderKeys::default()
        };
        let err = provider_slots_for_keys(&keys, SECRET).expect_err("multi-key must fail");
        assert!(err.to_string().contains("GOOGLE_API_KEY"));
        assert!(err.to_string().contains("bedrock"));
        assert!(
            !err.to_string().contains("g-a"),
            "no key material in errors"
        );
    }

    #[test]
    fn legacy_image_rejects_multikey_but_allows_single() {
        let mut keys = ProviderKeys {
            anthropic: Some("sk-a;sk-b".to_owned()),
            ..ProviderKeys::default()
        };
        let err = reject_multikey_for_legacy_image(&keys).expect_err("multi-key must fail");
        assert!(err.to_string().contains("ANTHROPIC_API_KEY"));
        assert!(
            !err.to_string().contains("sk-a"),
            "no key material in errors"
        );
        keys.anthropic = Some("sk-single".to_owned());
        reject_multikey_for_legacy_image(&keys).expect("single key is legacy-safe");
        // A semicolon value sidelined by a cloud selector is inert: the
        // image reads BEDROCK_API_KEY instead, so the deploy proceeds.
        keys.anthropic = Some("sk-a;sk-b".to_owned());
        keys.anthropic_upstream = Some("bedrock".to_owned());
        reject_multikey_for_legacy_image(&keys)
            .expect("bedrock sidelines the direct anthropic key");
    }

    #[test]
    fn derives_pinned_slot_vector() {
        let id = derive_slot_id("anthropic", "sk-ant-test-key", SECRET).expect("derive slot id");
        assert_eq!(id, "ZITBCTOEBDW4");
    }

    #[test]
    fn trims_ascii_whitespace_before_deriving() {
        let slots =
            parse_key_slots("anthropic", " \t sk-ant-test-key \r\n", SECRET).expect("parse");
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].key, "sk-ant-test-key");
        assert_eq!(slots[0].id, "ZITBCTOEBDW4");
    }

    #[test]
    fn empty_segment_is_fatal() {
        let err = parse_key_slots("openai", "sk-a; ;sk-b", SECRET).expect_err("must fail");
        assert!(err.to_string().contains("empty slot"));
    }

    #[test]
    fn more_than_eight_segments_is_fatal() {
        let raw = "a;b;c;d;e;f;g;h;i";
        let err = parse_key_slots("gemini", raw, SECRET).expect_err("must fail");
        assert!(err.to_string().contains("at most 8"));
    }

    #[test]
    fn duplicate_keys_are_deduped_preserving_first_order() {
        let slots = parse_key_slots("openai", "sk-openai-a;sk-openai-b;sk-openai-a", SECRET)
            .expect("parse");
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].key, "sk-openai-a");
        assert_eq!(slots[1].key, "sk-openai-b");
    }

    #[test]
    fn eight_segments_are_allowed() {
        let slots = parse_key_slots("chutes", "a;b;c;d;e;f;g;h", SECRET).expect("parse");
        assert_eq!(slots.len(), 8);
        let slots = parse_key_slots("zai", "a;b;c;d;e;f;g;h", SECRET).expect("parse");
        assert_eq!(slots.len(), 8);
    }

    #[test]
    fn direct_provider_slots_are_advertised_in_provider_order() {
        let keys = ProviderKeys {
            anthropic: Some("sk-ant-a;sk-ant-b".to_owned()),
            google: Some("AIza".to_owned()),
            zai: Some("zai-key".to_owned()),
            deepinfra: Some("di-a;di-b".to_owned()),
            ..ProviderKeys::default()
        };
        let slots = provider_slots_for_keys(&keys, SECRET).expect("slots");
        assert_eq!(
            slots.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["anthropic", "deepinfra", "gemini", "zai"]
        );
        assert_eq!(slots["anthropic"].len(), 2);
        assert_eq!(slots["gemini"].len(), 1);
        assert_eq!(slots["zai"].len(), 1);
        assert_eq!(slots["deepinfra"].len(), 2);
        assert!(!slots.contains_key("openai"));
    }

    #[test]
    fn deepinfra_direct_multikey_is_advertised() {
        let keys = ProviderKeys {
            deepinfra: Some("di-key-a;di-key-b".to_owned()),
            ..ProviderKeys::default()
        };
        let slots = provider_slots_for_keys(&keys, SECRET).expect("slots");
        assert_eq!(slots["deepinfra"].len(), 2);
    }

    #[test]
    fn cloud_backend_semicolon_is_fatal() {
        let keys = ProviderKeys {
            anthropic_upstream: Some("bedrock".to_owned()),
            bedrock_api_key: Some("bedrock-a;bedrock-b".to_owned()),
            ..ProviderKeys::default()
        };
        let err = provider_slots_for_keys(&keys, SECRET).expect_err("must fail");
        assert!(err
            .to_string()
            .contains("BEDROCK_API_KEY cannot contain ';'"));
    }

    #[test]
    fn slot_env_exports_are_shell_quoted() {
        let exports =
            render_slot_env_exports("openai", "sk-openai-a;sk'openai-b", SECRET).expect("exports");
        assert!(exports.contains("export GM_OPENAI_KEY_SLOT_1='sk-openai-a'\n"));
        assert!(exports.contains("export GM_OPENAI_KEY_SLOT_2='sk'\\''openai-b'\n"));
        assert!(exports.contains("export GM_OPENAI_SLOT_IDS='"));
    }
}
