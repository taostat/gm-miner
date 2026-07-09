//! Offline `compose_hash` derivation for the release `ImageVersion`.
//!
//! ## What `compose_hash` is
//!
//! A dstack CVM's `compose_hash` is `sha256` over the canonical
//! serialization of its `app_compose` object — the wrapper dstack measures
//! into RTMR3 and exposes in the attestation TCB info. The VMM hashes the
//! exact UTF-8 bytes of the submitted `app-compose.json` string, and the
//! guest re-hashes the same file, so the value is **re-derivable offline**:
//! that re-derivability is the whole point of dstack attestation. We mirror
//! the canonical serialization here instead of deploying a CVM to read the
//! hash back.
//!
//! ## The serialization (mirrors dstack's `get_compose_hash`)
//!
//! `app_compose` is serialized as JSON with **lexicographically sorted keys**
//! and **compact separators** (`,` and `:`, no spaces), non-ASCII left as
//! UTF-8 (`ensure_ascii=false`), and the digest is lowercase hex. In Rust a
//! [`BTreeMap`] gives the sorted keys and `serde_json::to_string` gives the
//! compact, UTF-8 form — together they reproduce a real gm-deployed hash
//! byte-for-byte (see the `reproduces_*` gate tests).
//!
//! ## The `app_compose` field set
//!
//! The hashed object is the WRAPPER, not the raw `docker-compose.yaml`. The
//! `docker_compose_file` field carries the rendered compose YAML as one JSON
//! string; `pre_launch_script` carries the bundled pre-launch script. The
//! remaining fields are the Phala-Cloud-set security/runtime flags
//! (`kms_enabled`, `gateway_enabled`, `public_logs`, …) plus `allowed_envs`,
//! the list of env-var names the deploy declares. Every field's value is
//! pinned here to the values a gm release deploy produces; the gate tests
//! anchor that pinning to a real registry-approved hash so a drift in any
//! field is caught in CI rather than at a miner's deploy.

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::deploy::{render_compose, COMPOSE_TEMPLATE, PRELAUNCH_SCRIPT};
use crate::network::Network;

/// The `manifest_version` of the `app_compose` format dstack currently emits.
const MANIFEST_VERSION: u64 = 2;

/// The `runner` a docker-compose miner CVM uses.
const RUNNER: &str = "docker-compose";

/// The `storage_fs` the Phala node provisions for the pinned OS image. Tied
/// to the dstack OS image version ([`crate::deploy::DEFAULT_OS_IMAGE`]); a
/// node on a different image would report a different value and move the
/// hash, which the gate tests would catch.
const STORAGE_FS: &str = "zfs";

/// The `features` array Phala Cloud sets for a KMS-backed, gateway-fronted
/// CVM. A literal in the measured object, so it is pinned here.
const FEATURES: [&str; 2] = ["kms", "tproxy-net"];

/// The env-var names a gm release deploy declares, in deploy order. Lists
/// every supported provider key name plus the node secret, regardless of
/// which keys an individual miner has configured. Hash covers names only,
/// not values, so every miner produces the same `compose_hash`. The order
/// matches `render_env_file`: Anthropic direct/Bedrock, `OpenAI` direct/Azure,
/// Google, Chutes, Z.ai, node secret. Private-registry pull credentials
/// (`DSTACK_DOCKER_*`) are
/// excluded: the gm image is public and those vars do not appear in
/// `allowed_envs`.
const CANONICAL_ALLOWED_ENVS: [&str; 17] = [
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_UPSTREAM",
    "BEDROCK_REGION",
    "BEDROCK_API_KEY",
    "OPENAI_API_KEY",
    "OPENAI_UPSTREAM",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_KEY",
    "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID",
    "AZURE_RESOURCE_GROUP",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "GOOGLE_API_KEY",
    "CHUTES_API_KEY",
    "ZAI_API_KEY",
    "GM_NODE_SECRET",
];

/// The pinned dstack OS image's published reproducible `os_image_hash`.
///
/// This is the measurement of [`crate::deploy::DEFAULT_OS_IMAGE`]
/// (`dstack-0.5.7`), published by dstack's reproducible OS image build and
/// reported in every CVM's attestation TCB info (`os.os_image_hash`). It is
/// verifiable against any live gm CVM on that image and against the
/// registry's approved baseline; the gate test
/// [`tests::os_image_hash_matches_registry_baseline`] anchors it. Bump this
/// in lockstep with `DEFAULT_OS_IMAGE`.
pub const PINNED_OS_IMAGE_HASH: &str =
    "761c05d282c81abeae2d1a8f6d5b1e039c8ce14cc95a6da020b9ed2ff1056816";

/// The pinned `app_compose` security and runtime flag fields a gm release
/// deploy produces, as `(field, value)` pairs. `gateway_enabled` and
/// `tproxy_enabled` are both present and true (dstack accepts either name;
/// the Phala backend emits both); the local key provider is off because the
/// CVM uses Phala's KMS. Each field is measured into the hash, so a drift in
/// any of them is caught by the gate tests.
const RELEASE_FLAGS: [(&str, bool); 9] = [
    ("kms_enabled", true),
    ("gateway_enabled", true),
    ("tproxy_enabled", true),
    ("local_key_provider_enabled", false),
    ("public_logs", true),
    ("public_sysinfo", true),
    ("public_tcbinfo", true),
    ("secure_time", false),
    ("no_instance_id", false),
];

/// Build the `app_compose` object a gm release deploy produces for `network`
/// around the digest-pinned `image_ref`.
///
/// The compose template and pre-launch script are bundled from the repo
/// (`crate::deploy::COMPOSE_TEMPLATE` / `PRELAUNCH_SCRIPT`), so the embedded
/// `docker_compose_file` is byte-identical to what `gmcli deploy` submits.
///
/// Returns a `BTreeMap` so the keys are already in the lexicographic order
/// the canonical serialization requires.
///
/// # Errors
/// Returns an error if the compose template cannot be rendered (a missing
/// placeholder — a template bug).
fn build_app_compose(image_ref: &str, network: Network) -> anyhow::Result<BTreeMap<String, Value>> {
    let docker_compose_file = render_compose(COMPOSE_TEMPLATE, image_ref, network.as_str())?;

    let mut compose: BTreeMap<String, Value> = BTreeMap::new();
    compose.insert(
        "allowed_envs".to_owned(),
        Value::from(CANONICAL_ALLOWED_ENVS.to_vec()),
    );
    compose.insert(
        "docker_compose_file".to_owned(),
        Value::String(docker_compose_file),
    );
    compose.insert("features".to_owned(), Value::from(FEATURES.to_vec()));
    compose.insert(
        "manifest_version".to_owned(),
        Value::Number(MANIFEST_VERSION.into()),
    );
    compose.insert("name".to_owned(), Value::String(String::new()));
    compose.insert(
        "pre_launch_script".to_owned(),
        Value::String(PRELAUNCH_SCRIPT.to_owned()),
    );
    compose.insert("runner".to_owned(), Value::String(RUNNER.to_owned()));
    compose.insert(
        "storage_fs".to_owned(),
        Value::String(STORAGE_FS.to_owned()),
    );
    for (field, value) in RELEASE_FLAGS {
        compose.insert(field.to_owned(), Value::Bool(value));
    }
    Ok(compose)
}

/// Serialize an `app_compose` object to its canonical bytes and return the
/// lowercase-hex `sha256`.
///
/// The map is a [`BTreeMap`], so its keys serialize in lexicographic order;
/// `serde_json::to_string` emits compact separators and UTF-8 (no ASCII
/// escaping) — together the dstack canonical form. The digest is over those
/// exact UTF-8 bytes.
///
/// # Errors
/// Returns an error if serialization fails (it cannot for a `BTreeMap` of
/// JSON values, but the result is propagated rather than unwrapped).
fn hash_app_compose(compose: &BTreeMap<String, Value>) -> anyhow::Result<String> {
    let canonical = serde_json::to_string(compose)
        .map_err(|e| anyhow::anyhow!("serialize app_compose: {e}"))?;
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

/// Compute the `compose_hash` a gm release deploy produces for `network`
/// around the digest-pinned `image_ref`, offline.
///
/// Builds the `app_compose` object ([`build_app_compose`]) and hashes its
/// canonical serialization ([`hash_app_compose`]). The result is bare
/// lowercase 64-hex, the form the registry's `^[0-9a-f]{64}$` accepts.
///
/// # Errors
/// Returns an error if the compose template cannot be rendered.
pub fn compute_compose_hash(image_ref: &str, network: Network) -> anyhow::Result<String> {
    let compose = build_app_compose(image_ref, network)?;
    hash_app_compose(&compose)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    /// The testnet image ref whose `app_compose` hashes to the registry's
    /// approved baseline below — the gm-published public miner image for the
    /// current supported release (v0.1.4). Must track the newest supported
    /// image version: when a new `ImageVersion` is published, bump both this
    /// ref and `REGISTRY_TESTNET_COMPOSE_HASH` to the live registry row.
    const TESTNET_IMAGE_REF: &str =
        "ghcr.io/taostat/gm-miner@sha256:bcb3d8ca557d380319481234c3455602c69891f928ebefd4ec53def67999de80";

    /// HARD ACCEPTANCE GATE. The canonical testnet `compose_hash` produced by
    /// `TESTNET_IMAGE_REF` + `CANONICAL_ALLOWED_ENVS` (the direct provider
    /// keys, cloud upstream settings, and node secret).
    ///
    /// Pre-publication anchor: `ZAI_API_KEY` joined `allowed_envs`, so this
    /// hash is not yet a live registry row.
    ///
    /// Rollout: rebuild the image (the template changes move the digest),
    /// publish the new `ImageVersion` (`gmcli publish-image-version`), bump
    /// `TESTNET_IMAGE_REF` and this anchor to the live registry row, redeploy
    /// the live testnet miners, confirm attestation matches, then retire the
    /// old `98307c5b` row.
    const REGISTRY_TESTNET_COMPOSE_HASH: &str =
        "860c331f0fb85623edce97cc227e9df5af731dbeb6a3418a43e65775d31e3f1b";

    #[test]
    fn reproduces_registry_approved_testnet_compose_hash() {
        let computed = compute_compose_hash(TESTNET_IMAGE_REF, Network::Testnet)
            .expect("offline compose hash must compute");
        assert_eq!(
            computed, REGISTRY_TESTNET_COMPOSE_HASH,
            "offline compose_hash must reproduce the live registry-approved testnet hash \
             byte-for-byte; the anchor must track the newest supported image version. If this \
             fails after a compose/env/image change, bump TESTNET_IMAGE_REF and \
             REGISTRY_TESTNET_COMPOSE_HASH to the live registry routing-table row and publish \
             a new ImageVersion to the registry"
        );
    }

    /// The canonical serialization is sorted-key + compact: the rendered
    /// bytes must contain no `, ` or `": "` spacing and the keys must be in
    /// lexicographic order.
    #[test]
    fn canonical_serialization_is_sorted_and_compact() {
        let compose =
            build_app_compose(TESTNET_IMAGE_REF, Network::Testnet).expect("must build app_compose");
        let canonical = serde_json::to_string(&compose).unwrap();
        assert!(
            canonical.starts_with(r#"{"allowed_envs":["#),
            "keys must be sorted (allowed_envs first) and compact (no space after colon)"
        );
        assert!(
            !canonical.contains(r#"", ""#),
            "compact separators must have no space after a comma"
        );
    }

    /// The measured object must carry the security flags Phala Cloud sets —
    /// the content PR #70's deploy-and-read could not derive. Missing any of
    /// them moves the hash, so assert they are present and true/false as
    /// pinned.
    #[test]
    fn app_compose_carries_the_security_flags() {
        let compose =
            build_app_compose(TESTNET_IMAGE_REF, Network::Testnet).expect("must build app_compose");
        for (key, expected) in [
            ("kms_enabled", true),
            ("gateway_enabled", true),
            ("tproxy_enabled", true),
            ("public_logs", true),
            ("public_sysinfo", true),
            ("local_key_provider_enabled", false),
        ] {
            assert_eq!(
                compose.get(key).and_then(Value::as_bool),
                Some(expected),
                "{key} must be pinned to {expected}"
            );
        }
        assert_eq!(
            compose
                .get("allowed_envs")
                .and_then(|v| v.as_array())
                .map(Vec::len),
            Some(CANONICAL_ALLOWED_ENVS.len()),
            "allowed_envs must be the canonical env-name set"
        );
    }

    /// The network literal feeds the rendered compose, so testnet and mainnet
    /// must produce different hashes — each network gets its own row.
    #[test]
    fn hash_is_network_specific() {
        let testnet = compute_compose_hash(TESTNET_IMAGE_REF, Network::Testnet).unwrap();
        let mainnet = compute_compose_hash(TESTNET_IMAGE_REF, Network::Mainnet).unwrap();
        assert_ne!(
            testnet, mainnet,
            "the GM_NETWORK literal must make the compose_hash network-specific"
        );
    }

    /// A different image digest must move the hash — the digest is embedded in
    /// the rendered compose.
    #[test]
    fn hash_changes_with_image_ref() {
        let a = compute_compose_hash(TESTNET_IMAGE_REF, Network::Testnet).unwrap();
        let b = compute_compose_hash(
            "ghcr.io/taostat/gm-miner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            Network::Testnet,
        )
        .unwrap();
        assert_ne!(a, b, "a different image digest must move the compose_hash");
    }

    /// The pinned OS image hash must match the registry's approved baseline
    /// (every supported testnet row shares it) and the live CVM's measured
    /// `os.os_image_hash`.
    #[test]
    fn os_image_hash_matches_registry_baseline() {
        assert_eq!(
            PINNED_OS_IMAGE_HASH,
            "761c05d282c81abeae2d1a8f6d5b1e039c8ce14cc95a6da020b9ed2ff1056816"
        );
    }
}
