//! Offline compose-hash derivation for release image versions.
//!
//! Phala normalizes optional app-compose fields, sorts object keys, and
//! serializes compact UTF-8 JSON before hashing. The v3 builder mirrors that
//! shape and includes the selected KMS root identity in the measured object.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context as _;
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
    build_app_compose_from_parts(&docker_compose_file, PRELAUNCH_SCRIPT, key_provider_id)
}

fn build_app_compose_from_parts(
    docker_compose_file: &str,
    pre_launch_script: &str,
    key_provider_id: &str,
) -> anyhow::Result<BTreeMap<String, Value>> {
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
    compose.insert(
        "port_policy".to_owned(),
        compose_port_policy(docker_compose_file)?,
    );
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
    Ok(compose)
}

/// Build the policy shape Phala applied to our Compose; reject other published-port forms.
fn compose_port_policy(docker_compose_file: &str) -> anyhow::Result<Value> {
    let docker_compose: Value = serde_saphyr::from_str_with_options(
        docker_compose_file,
        serde_saphyr::options! {
            strict_booleans: true,
            merge_keys: serde_saphyr::options::MergeKeyPolicy::AsOrdinary,
            ignore_binary_tag_for_string: true,
            no_schema: true,
            with_snippet: false,
        },
    )
    .context("parse rendered Docker Compose for Phala port policy")?;
    let services = docker_compose
        .get("services")
        .and_then(Value::as_object)
        .context("rendered Docker Compose must define services")?;
    if services
        .iter()
        .any(|(name, service)| name == "<<" || contains_merge_key(service))
    {
        anyhow::bail!("YAML merge keys are not supported for the expected compose hash");
    }

    let mut ports = BTreeSet::from([8090]);
    for (service_name, service) in services {
        let Some(published_ports) = service.get("ports") else {
            continue;
        };
        let published_ports = published_ports.as_array().with_context(|| {
            format!(
                "port form is not supported for the expected compose hash: services.{service_name}.ports must be an array"
            )
        })?;
        for entry in published_ports {
            let specification = entry.as_str().with_context(|| {
                format!(
                    "port form is not supported for the expected compose hash: services.{service_name}.ports entries must be short-syntax strings"
                )
            })?;
            ports.insert(parse_compose_port(specification)?);
        }
    }

    Ok(serde_json::json!({
        "ports": ports
            .into_iter()
            .map(|port| serde_json::json!({"port": port, "pp": false}))
            .collect::<Vec<_>>(),
        "restrict_mode": true,
    }))
}

fn contains_merge_key(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key("<<") || object.values().any(contains_merge_key)
        }
        Value::Array(values) => values.iter().any(contains_merge_key),
        _ => false,
    }
}

fn parse_compose_port(specification: &str) -> anyhow::Result<u16> {
    let unsupported = || {
        anyhow::anyhow!("port form is not supported for the expected compose hash: {specification}")
    };
    let Some((host, container)) = specification.split_once(':') else {
        return Err(unsupported());
    };
    if container.contains(':') {
        return Err(unsupported());
    }

    let parse_number = |value: &str| {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        value.parse::<u16>().ok().filter(|port| *port != 0)
    };
    let (Some(host_port), Some(container_port)) = (parse_number(host), parse_number(container))
    else {
        return Err(unsupported());
    };
    if host_port != container_port {
        return Err(unsupported());
    }

    Ok(host_port)
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
    const OBSERVED_FROM_PHALA_IMAGE_REF: &str =
        "ghcr.io/taostat/gm-miner@sha256:3d292284becadcfaf4b722cb5f8183f911429d56090079eafed00fac601267a6";
    const LIVE_KEY_PROVIDER_ID: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004e8e325a477b0bf22800dc927a46c68638938d283fe73d1f9028eeac7028193f3470122193875f598b7addc503e534712ab437b4120776bbac32ddf8897f844ee";
    const HISTORICAL_REGISTRY_HASH: &str =
        "81e5f2b7544840f5394dd76940a6cf75558a4e822e7992670972af9cca695377";
    const LIVE_DSTACK_065_HASH: &str =
        "0d75dcd1311506ec717f9bac9628e4edfed8023115ea7e78aa0a1086a8b67a79";
    const CANDIDATE_TESTNET_HASH: &str =
        "d7ed295417f1b1a9bf4dc1e532f68b070464eb83c178069f16ebf86062b56a20";
    const OBSERVED_FROM_PHALA_MAINNET_HASH: &str =
        "700517daccc1d02698a7ab4000b9e3ea882aecad2692ff1e817d74c99d8643dc";
    const OBSERVED_FROM_PHALA_TESTNET_HASH: &str =
        "81960ced2146db48406d9c5870b130d3089a8b7b69215e985e771bb322ef27f6";

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
        let mut built =
            build_app_compose_from_parts(docker_compose_file, pre_launch_script, key_provider_id)
                .expect("live compose fields must build");
        // This captured CVM predates Phala's default; it records null, which
        // Phala's normalization drops for historical compose hashes.
        assert_eq!(live.get("port_policy"), Some(&Value::Null));
        built.insert("port_policy".to_owned(), Value::Null);

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
    fn observed_from_phala_v060_hashes_match_both_networks() {
        let mainnet = compute_compose_hash(
            OBSERVED_FROM_PHALA_IMAGE_REF,
            Network::Mainnet,
            LIVE_KEY_PROVIDER_ID,
        )
        .expect("observed mainnet compose hash must compute");
        let testnet = compute_compose_hash(
            OBSERVED_FROM_PHALA_IMAGE_REF,
            Network::Testnet,
            LIVE_KEY_PROVIDER_ID,
        )
        .expect("observed testnet compose hash must compute");

        assert_eq!(mainnet, OBSERVED_FROM_PHALA_MAINNET_HASH);
        assert_eq!(testnet, OBSERVED_FROM_PHALA_TESTNET_HASH);
    }

    #[test]
    fn observed_port_policy_uses_sorted_equal_port_mappings_and_guest_agent() {
        let compose =
            "services:\n  gm-miner:\n    ports:\n      - \"9902:9902\"\n      - \"8080:8080\"\n";
        let policy = compose_port_policy(compose).expect("port policy must parse");

        assert_eq!(
            serde_json::to_string(&policy).expect("port policy must serialize"),
            r#"{"ports":[{"port":8080,"pp":false},{"port":8090,"pp":false},{"port":9902,"pp":false}],"restrict_mode":true}"#
        );
    }

    #[test]
    fn app_compose_builder_derives_policy_from_rendered_port_changes() {
        let template = render_compose(COMPOSE_TEMPLATE, TESTNET_IMAGE_REF, "testnet")
            .expect("compose template must render");
        assert!(template.contains("\"8080:8080\""));
        let rendered = template.replace("\"8080:8080\"", "\"9000:9000\"");
        let compose =
            build_app_compose_from_parts(&rendered, PRELAUNCH_SCRIPT, LIVE_KEY_PROVIDER_ID)
                .expect("compose builder must derive the changed policy");

        assert_eq!(
            compose.get("port_policy"),
            Some(&serde_json::json!({
                "ports": [
                    {"port": 8090, "pp": false},
                    {"port": 9000, "pp": false},
                    {"port": 9902, "pp": false},
                ],
                "restrict_mode": true,
            }))
        );
    }

    #[test]
    fn app_compose_builder_derives_policy_from_all_services_and_deduplicates_ports() {
        let template = render_compose(COMPOSE_TEMPLATE, TESTNET_IMAGE_REF, "testnet")
            .expect("compose template must render");
        let rendered = template.replacen(
            "      - \"9902:9902\"\n",
            "      - \"9902:9902\"\n      - \"7001:7001\"\n      - \"8090:8090\"\n      - \"7001:7001\"\n",
            1,
        );
        assert_ne!(
            rendered, template,
            "third port must be added to the template"
        );
        let rendered = format!(
            "{rendered}\n  metrics-sidecar:\n    image: metrics-sidecar\n    ports:\n      - \"7002:7002\"\n"
        );

        let compose =
            build_app_compose_from_parts(&rendered, PRELAUNCH_SCRIPT, LIVE_KEY_PROVIDER_ID)
                .expect("compose builder must derive policy from all services");

        assert_eq!(
            compose.get("port_policy"),
            Some(&serde_json::json!({
                "ports": [
                    {"port": 7001, "pp": false},
                    {"port": 7002, "pp": false},
                    {"port": 8080, "pp": false},
                    {"port": 8090, "pp": false},
                    {"port": 9902, "pp": false},
                ],
                "restrict_mode": true,
            }))
        );
    }

    #[test]
    fn unsupported_compose_port_forms_fail_closed() {
        let unsupported_forms = [
            (
                "different host and container ports",
                "ports:\n      - \"9000:8080\"\n",
            ),
            (
                "bind address",
                "ports:\n      - \"127.0.0.1:8080:8080\"\n",
            ),
            (
                "protocol suffix",
                "ports:\n      - \"8080:8080/udp\"\n",
            ),
            (
                "port ranges",
                "ports:\n      - \"8000-8001:8000-8001\"\n",
            ),
            ("bare port", "ports:\n      - \"8080\"\n"),
            (
                "long syntax",
                "ports:\n      - target: 8080\n        published: \"8080\"\n        protocol: tcp\n",
            ),
            ("non-array ports", "ports: \"8080:8080\"\n"),
        ];

        for (description, ports) in unsupported_forms {
            let compose = format!("services:\n  gm-miner:\n    {ports}");
            let error = compose_port_policy(&compose).expect_err(description);
            assert!(
                format!("{error:#}")
                    .contains("port form is not supported for the expected compose hash"),
                "{description}: {error:#}"
            );
        }
    }

    #[test]
    fn app_compose_builder_rejects_merge_keys_under_services() {
        let compose = "services:\n  common: &common\n    ports:\n      - \"8080:8080\"\n  gm-miner:\n    <<: *common\n";
        let error = build_app_compose_from_parts(compose, PRELAUNCH_SCRIPT, LIVE_KEY_PROVIDER_ID)
            .expect_err("compose builder must reject YAML merge keys");

        assert!(format!("{error:#}").contains("YAML merge keys are not supported"));
    }

    #[test]
    fn historical_null_port_policy_is_dropped_during_normalization() {
        let mut compose = BTreeMap::new();
        compose.insert("port_policy".to_owned(), Value::Null);

        assert!(!normalize_app_compose(&compose).contains_key("port_policy"));
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
        let policy = compose.get("port_policy").expect("port policy must be set");
        assert_eq!(
            serde_json::to_string(policy).expect("port policy must serialize"),
            r#"{"ports":[{"port":8080,"pp":false},{"port":8090,"pp":false},{"port":9902,"pp":false}],"restrict_mode":true}"#
        );
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
        assert_eq!(
            compose.get("port_policy"),
            Some(&serde_json::json!({
                "ports": [
                    {"port": 8080, "pp": false},
                    {"port": 8090, "pp": false},
                    {"port": 9902, "pp": false},
                ],
                "restrict_mode": true,
            }))
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
