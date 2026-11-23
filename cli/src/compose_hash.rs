//! Offline compose-hash derivation for release image versions.
//!
//! Phala normalizes optional app-compose fields, sorts object keys, and
//! serializes compact UTF-8 JSON before hashing. The v3 builder mirrors that
//! shape and includes the selected KMS root identity in the measured object.

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::deploy::{render_compose, COMPOSE_TEMPLATE, PRELAUNCH_SCRIPT};
use crate::network::Network;

const MANIFEST_VERSION: &str = "3";
const RUNNER: &str = "docker-compose";
const STORAGE_FS: &str = "zfs";
const KEY_PROVIDER: &str = "kms";
const FEATURES: [&str; 2] = ["kms", "tproxy-net"];

/// The env-var names a release declares, in deploy order.
const CANONICAL_ALLOWED_ENVS: [&str; 30] = [
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_UPSTREAM",
    "BEDROCK_REGION",
    "BEDROCK_API_KEY",
    "AZURE_FOUNDRY_ENDPOINT",
    "AZURE_FOUNDRY_API_KEY",
    "AZURE_FOUNDRY_TENANT_ID",
    "AZURE_FOUNDRY_SUBSCRIPTION_ID",
    "AZURE_FOUNDRY_RESOURCE_GROUP",
    "AZURE_FOUNDRY_CLIENT_ID",
    "AZURE_FOUNDRY_CLIENT_SECRET",
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
    "MOONSHOT_API_KEY",
    "DEEPINFRA_API_KEY",
    "KUBETEE_API_KEY",
    "ENGY_API_KEY",
    "MOONMATH_API_KEY",
    "NEAR_API_KEY",
    "GM_NODE_SECRET",
];

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

const NULLABLE_FIELDS: [&str; 8] = [
    "event_log_version",
    "key_provider",
    "port_policy",
    "requirements",
    "snapshotter",
    "storage_discard",
    "swap_size",
    "verity_volumes",
];

const EMPTY_FIELDS: [&str; 4] = [
    "default_gateway_domain",
    "key_provider_id",
    "pre_launch_script",
    "salt",
];

/// The reproducible `os_image_hash` for `DEFAULT_OS_IMAGE`.
pub const PINNED_OS_IMAGE_HASH: &str =
    "4771a29e03e93f0e2d5e37174cd8bb1112942c9689deb36b16c5df9e183d8623";

fn build_app_compose(
    image_ref: &str,
    network: Network,
    key_provider_id: &str,
) -> anyhow::Result<BTreeMap<String, Value>> {
    let docker_compose_file = render_compose(COMPOSE_TEMPLATE, image_ref, network.as_str())?;
    Ok(build_app_compose_from_parts(
        &docker_compose_file,
        PRELAUNCH_SCRIPT,
        key_provider_id,
    ))
}

fn build_app_compose_from_parts(
    docker_compose_file: &str,
    pre_launch_script: &str,
    key_provider_id: &str,
) -> BTreeMap<String, Value> {
    let mut compose = BTreeMap::new();
    compose.insert(
        "allowed_envs".to_owned(),
        Value::from(CANONICAL_ALLOWED_ENVS.to_vec()),
    );
    compose.insert("bash_script".to_owned(), Value::Null);
    compose.insert("default_gateway_domain".to_owned(), Value::Null);
    compose.insert(
        "docker_compose_file".to_owned(),
        Value::String(docker_compose_file.to_owned()),
    );
    compose.insert("event_log_version".to_owned(), Value::Null);
    compose.insert("features".to_owned(), Value::from(FEATURES.to_vec()));
    compose.insert("gateway_enabled".to_owned(), Value::Bool(true));
    compose.insert("init_script".to_owned(), Value::Array(Vec::new()));
    compose.insert(
        "key_provider".to_owned(),
        Value::String(KEY_PROVIDER.to_owned()),
    );
    compose.insert(
        "key_provider_id".to_owned(),
        Value::String(key_provider_id.to_owned()),
    );
    compose.insert(
        "manifest_version".to_owned(),
        Value::String(MANIFEST_VERSION.to_owned()),
    );
    compose.insert("name".to_owned(), Value::String(String::new()));
    compose.insert("port_policy".to_owned(), Value::Null);
    compose.insert(
        "pre_launch_script".to_owned(),
        Value::String(pre_launch_script.to_owned()),
    );
    compose.insert(
        "requirements".to_owned(),
        serde_json::json!({"ephemeral_data_disk": true}),
    );
    compose.insert("runner".to_owned(), Value::String(RUNNER.to_owned()));
    compose.insert("salt".to_owned(), Value::Null);
    compose.insert("snapshotter".to_owned(), Value::Null);
    compose.insert("storage_discard".to_owned(), Value::Null);
    compose.insert(
        "storage_fs".to_owned(),
        Value::String(STORAGE_FS.to_owned()),
    );
    compose.insert("swap_size".to_owned(), Value::Null);
    compose.insert("verity_volumes".to_owned(), Value::Null);
    for (field, value) in RELEASE_FLAGS {
        compose.insert(field.to_owned(), Value::Bool(value));
    }
    compose
}

/// Apply the field normalization used by the Phala compose-hash helper.
fn normalize_app_compose(compose: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    let mut normalized = compose.clone();

    match normalized.get("runner").and_then(Value::as_str) {
        Some("bash") => {
            normalized.remove("docker_compose_file");
        }
        Some("docker-compose") => {
            normalized.remove("bash_script");
        }
        _ => {}
    }

    if !normalized.contains_key("tproxy_enabled") {
        let enabled = normalized
            .get("gateway_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        normalized.insert("tproxy_enabled".to_owned(), Value::Bool(enabled));
    }

    for field in NULLABLE_FIELDS {
        if normalized.get(field).is_some_and(Value::is_null) {
            normalized.remove(field);
        }
    }

    for field in EMPTY_FIELDS {
        if normalized
            .get(field)
            .is_some_and(|value| value.is_null() || value.as_str().is_some_and(str::is_empty))
        {
            normalized.remove(field);
        }
    }

    normalized
}

/// Serialize the normalized compose object and return its lowercase SHA-256.
fn hash_app_compose(compose: &BTreeMap<String, Value>) -> anyhow::Result<String> {
    let canonical = serde_json::to_string(&normalize_app_compose(compose))
        .map_err(|error| anyhow::anyhow!("serialize app_compose: {error}"))?;
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

/// Compute the compose hash for an image, network, and selected KMS root.
///
/// The root identity is the `ca_pubkey` value from GET /kms-roots.
///
/// # Errors
/// Returns an error if the compose template cannot be rendered.
pub fn compute_compose_hash(
    image_ref: &str,
    network: Network,
    key_provider_id: &str,
) -> anyhow::Result<String> {
    hash_app_compose(&build_app_compose(image_ref, network, key_provider_id)?)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    const TESTNET_IMAGE_REF: &str =
        "ghcr.io/taostat/gm-miner@sha256:11f99ebde0d1acb944669be8fd0215086e8857de4324ae3fbeab2fcb42c72299";
    const LIVE_KEY_PROVIDER_ID: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004e8e325a477b0bf22800dc927a46c68638938d283fe73d1f9028eeac7028193f3470122193875f598b7addc503e534712ab437b4120776bbac32ddf8897f844ee";
    const HISTORICAL_REGISTRY_HASH: &str =
        "81e5f2b7544840f5394dd76940a6cf75558a4e822e7992670972af9cca695377";
    const LIVE_DSTACK_065_HASH: &str =
        "0d75dcd1311506ec717f9bac9628e4edfed8023115ea7e78aa0a1086a8b67a79";
    const CANDIDATE_TESTNET_HASH: &str =
        "c87bf90acd02ea5ffff0e19d9207bfd6b48d07d6dbbb25836be49002bd0e7fc7";

    fn decode_fixture(encoded: &str) -> Vec<u8> {
        hex::decode(encoded.trim()).expect("fixture bytes must decode")
    }

    #[test]
    fn historical_v2_bytes_match_the_registry_anchor() {
        let bytes = decode_fixture(include_str!(
            "../tests/fixtures/approved-app-compose-v2.json.hex"
        ));
        let compose: BTreeMap<String, Value> =
            serde_json::from_slice(&bytes).expect("frozen compose fixture must parse");
        let computed = hash_app_compose(&compose).expect("compose hash must compute");
        assert_eq!(computed, HISTORICAL_REGISTRY_HASH);
    }

    #[test]
    fn live_v3_compose_matches_its_fields_and_hash() {
        let bytes = decode_fixture(include_str!(
            "../tests/fixtures/live-dstack-065-app-compose.json.hex"
        ));
        let live: BTreeMap<String, Value> =
            serde_json::from_slice(&bytes).expect("live compose fixture must parse");
        let docker_compose_file = live
            .get("docker_compose_file")
            .and_then(Value::as_str)
            .expect("live compose contains its docker compose bytes");
        let pre_launch_script = live
            .get("pre_launch_script")
            .and_then(Value::as_str)
            .expect("live compose contains its pre-launch bytes");
        let key_provider_id = live
            .get("key_provider_id")
            .and_then(Value::as_str)
            .expect("live compose contains its KMS root identity");
        let built =
            build_app_compose_from_parts(docker_compose_file, pre_launch_script, key_provider_id);

        assert_eq!(built, live, "the v3 fields must match the live compose");
        assert_eq!(
            built.get("manifest_version").and_then(Value::as_str),
            Some("3")
        );
        assert_eq!(
            built
                .get("init_script")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        assert_eq!(
            built.get("key_provider").and_then(Value::as_str),
            Some("kms")
        );
        assert_eq!(
            built
                .get("requirements")
                .and_then(Value::as_object)
                .map(serde_json::Map::len),
            Some(1)
        );
        assert_eq!(
            built
                .get("requirements")
                .and_then(|value| value.get("ephemeral_data_disk"))
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            built.get("secure_time").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(built.get("storage_fs").and_then(Value::as_str), Some("zfs"));
        assert_eq!(
            hash_app_compose(&built).expect("live compose hash must compute"),
            LIVE_DSTACK_065_HASH
        );
    }

    #[test]
    fn candidate_compose_hash_is_deterministic() {
        let first = compute_compose_hash(TESTNET_IMAGE_REF, Network::Testnet, LIVE_KEY_PROVIDER_ID)
            .expect("candidate compose hash must compute");
        let second =
            compute_compose_hash(TESTNET_IMAGE_REF, Network::Testnet, LIVE_KEY_PROVIDER_ID)
                .expect("candidate compose hash must compute");
        assert_eq!(first, second);
        assert_eq!(first, CANDIDATE_TESTNET_HASH);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn candidate_fixture_matches_the_bundled_compose_template() {
        assert_eq!(
            COMPOSE_TEMPLATE,
            include_str!("../tests/fixtures/candidate-compose-v3.yaml")
        );
    }

    #[test]
    fn canonical_serialization_is_sorted_and_compact() {
        let compose = build_app_compose(TESTNET_IMAGE_REF, Network::Testnet, LIVE_KEY_PROVIDER_ID)
            .expect("app compose must build");
        let canonical = serde_json::to_string(&normalize_app_compose(&compose)).unwrap();
        assert!(canonical.starts_with(r#"{"allowed_envs":["#));
        assert!(!canonical.contains(r#"", ""#));
    }

    #[test]
    fn app_compose_carries_the_release_fields() {
        let compose = build_app_compose(TESTNET_IMAGE_REF, Network::Testnet, LIVE_KEY_PROVIDER_ID)
            .expect("app compose must build");
        assert_eq!(
            compose
                .get("allowed_envs")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(CANONICAL_ALLOWED_ENVS.len())
        );
        assert_eq!(
            compose
                .get("requirements")
                .and_then(Value::as_object)
                .map(|value| value.keys().map(String::as_str).collect::<Vec<_>>()),
            Some(vec!["ephemeral_data_disk"])
        );
        for (key, expected) in RELEASE_FLAGS {
            assert_eq!(compose.get(key).and_then(Value::as_bool), Some(expected));
        }
    }

    #[test]
    fn hash_is_network_specific() {
        let testnet =
            compute_compose_hash(TESTNET_IMAGE_REF, Network::Testnet, LIVE_KEY_PROVIDER_ID)
                .unwrap();
        let mainnet =
            compute_compose_hash(TESTNET_IMAGE_REF, Network::Mainnet, LIVE_KEY_PROVIDER_ID)
                .unwrap();
        assert_ne!(testnet, mainnet);
    }

    #[test]
    fn hash_changes_with_image_ref() {
        let first = compute_compose_hash(TESTNET_IMAGE_REF, Network::Testnet, LIVE_KEY_PROVIDER_ID)
            .unwrap();
        let second = compute_compose_hash(
            "ghcr.io/taostat/gm-miner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            Network::Testnet,
            LIVE_KEY_PROVIDER_ID,
        )
        .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn hash_changes_with_the_selected_kms_root_key() {
        let first = compute_compose_hash(TESTNET_IMAGE_REF, Network::Testnet, LIVE_KEY_PROVIDER_ID)
            .unwrap();
        let second =
            compute_compose_hash(TESTNET_IMAGE_REF, Network::Testnet, "another-kms-root-key")
                .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn os_image_hash_matches_the_published_measurement() {
        assert_eq!(
            PINNED_OS_IMAGE_HASH,
            "4771a29e03e93f0e2d5e37174cd8bb1112942c9689deb36b16c5df9e183d8623"
        );
    }
}
