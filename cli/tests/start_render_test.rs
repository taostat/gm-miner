#![expect(
    clippy::expect_used,
    reason = "integration tests intentionally fail hard on unexpected command output"
)]

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest as _, Sha256};

const DIRECT_TESTNET_SHA256: &str =
    "a2dacd0bc73c7915c57a3d0eb8a1a713c482a9cb4a542e7c0d5ecbbaec52af03";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate must live under repo root")
        .to_owned()
}

fn render_envoy<I, K, V>(vars: I) -> (std::process::ExitStatus, String, String, String)
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    let root = repo_root();
    let out = tempfile::NamedTempFile::new().expect("temp rendered config");
    let output = Command::new("bash")
        .arg(root.join("image/start.sh"))
        .env_clear()
        .env("PATH", "/bin:/usr/bin:/usr/local/bin")
        .env("GM_START_RENDER_ONLY", "1")
        .env("GMCLI_BIN", env!("CARGO_BIN_EXE_gmcli"))
        .env("GM_ENVOY_TEMPLATE_PATH", root.join("image/envoy.yaml"))
        .env("GM_RENDERED_CONFIG", out.path())
        .env("GM_NETWORK", "testnet")
        .env("GM_NODE_SECRET", "node-secret")
        .envs(vars)
        .output()
        .expect("run start.sh render-only");
    let rendered = std::fs::read_to_string(out.path()).unwrap_or_default();
    (
        output.status,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        rendered,
    )
}

#[test]
fn direct_unset_render_matches_pinned_output() {
    let (status, _, stderr, rendered) = render_envoy([("ANTHROPIC_API_KEY", "sk-ant-direct")]);
    assert!(status.success(), "render failed: {stderr}");
    let actual = hex::encode(Sha256::digest(rendered.as_bytes()));
    assert_eq!(actual, DIRECT_TESTNET_SHA256);
    assert!(rendered.contains("exact: api.anthropic.com"));
    assert!(rendered.contains("exact: api.openai.com"));
    assert!(rendered.contains("GM_ANTHROPIC_KEY_SLOT_1"));
    assert!(!rendered.contains("sk-ant-direct"));
    assert!(!rendered.contains("value: \"%ENVIRONMENT(ANTHROPIC_API_KEY)%\""));
}

#[test]
fn engy_route_keeps_v1_path_and_pins_the_wildcard_san() {
    // api.engy.ai serves the OpenAI-compatible surface under /v1 itself and
    // negotiates h2 over ALPN, so it mirrors kubetee rather than deepinfra.
    // Its certificate carries only the wildcard `*.engy.ai`; Envoy's exact DNS
    // SAN matcher resolves that per RFC 6125, as it already does for
    // llm.kubetee.ai, api.z.ai and api.moonshot.ai.
    let (status, _, stderr, rendered) = render_envoy([("ENGY_API_KEY", "sk-engy")]);
    assert!(status.success(), "render failed: {stderr}");
    let cluster = rendered
        .split_once("- name: engy")
        .and_then(|(_, rest)| rest.split_once("\n    - name:"))
        .map_or_else(|| rendered.clone(), |(block, _)| block.to_owned());
    assert!(
        cluster.contains("http2_protocol_options: {}"),
        "engy upstream negotiates h2"
    );
    assert!(
        cluster.contains("exact: api.engy.ai"),
        "engy cluster must pin the SAN to api.engy.ai"
    );
    let route = rendered
        .split_once("exact: \"engy\"")
        .and_then(|(_, rest)| rest.split_once("request_headers_to_remove"))
        .map_or_else(|| rendered.clone(), |(block, _)| block.to_owned());
    assert!(
        !route.contains("regex_rewrite"),
        "engy already serves /v1; a path rewrite would 404 every request"
    );
    assert!(
        !rendered.contains("sk-engy"),
        "the key must never be rendered"
    );
}

#[test]
fn kubetee_route_keeps_v1_path_and_negotiates_h2() {
    // llm.kubetee.ai serves the OpenAI-compatible surface under /v1 itself
    // and negotiates h2 over ALPN, so the route must NOT carry deepinfra's
    // /v1/openai rewrite and the cluster must NOT force http/1.1.
    // TLS 1.3 is mandatory for KubeTEE; Envoy's client default max is 1.2.
    let (status, _, stderr, rendered) = render_envoy([("ANTHROPIC_API_KEY", "sk-ant-direct")]);
    assert!(status.success(), "render failed: {stderr}");
    let cluster = rendered
        .split_once("- name: kubetee")
        .and_then(|(_, rest)| rest.split_once("\n    - name:"))
        .map_or_else(|| rendered.clone(), |(block, _)| block.to_owned());
    assert!(
        cluster.contains("http2_protocol_options: {}"),
        "kubetee upstream negotiates h2"
    );
    assert!(
        cluster.contains("tls_minimum_protocol_version: TLSv1_3"),
        "kubetee requires TLS 1.3"
    );
    assert!(
        cluster.contains("tls_maximum_protocol_version: TLSv1_3"),
        "kubetee requires TLS 1.3"
    );
    assert!(
        cluster.contains("exact: llm.kubetee.ai"),
        "kubetee cluster must pin the SAN to llm.kubetee.ai"
    );
    let route = rendered
        .split_once("exact: \"kubetee\"")
        .and_then(|(_, rest)| rest.split_once("request_headers_to_remove"))
        .map_or_else(|| rendered.clone(), |(block, _)| block.to_owned());
    assert!(
        !route.contains("regex_rewrite"),
        "kubetee already serves /v1; a path rewrite would 404 every request"
    );
}

#[test]
fn ingress_access_log_correlates_stream_termination_without_secrets() {
    let (status, _, stderr, rendered) = render_envoy([("ANTHROPIC_API_KEY", "sk-ant-direct")]);
    assert!(status.success(), "render failed: {stderr}");

    let ingress_hcm = rendered
        .split_once("stat_prefix: ingress_http")
        .and_then(|(_, rest)| rest.split_once("route_config:"))
        .map_or_else(|| rendered.clone(), |(block, _)| block.to_owned());
    assert!(ingress_hcm.contains("name: envoy.access_loggers.stdout"));
    assert!(ingress_hcm.contains("%DYNAMIC_METADATA(gm.access_log:request_id)%"));
    assert!(ingress_hcm.contains("%DYNAMIC_METADATA(gm.access_log:product)%"));
    assert!(ingress_hcm.contains("%DYNAMIC_METADATA(gm.access_log:provider)%"));
    assert!(ingress_hcm.contains("%DYNAMIC_METADATA(gm.access_log:authenticated)%"));
    assert!(rendered.contains(
        "access_metadata:set(\n                              \"gm.access_log\", \"request_id\""
    ));
    for field in [
        "request_id",
        "product",
        "provider",
        "authenticated",
        "protocol",
        "response_code",
        "response_flags",
        "response_code_details",
        "connection_termination_details",
        "downstream_connection_id",
        "downstream_detected_close_type",
        "downstream_local_close_reason",
        "upstream_transport_failure_reason",
        "upstream_cluster",
        "upstream_connection_id",
        "upstream_connection_ids_attempted",
        "upstream_detected_close_type",
        "upstream_local_close_reason",
        "duration_ms",
        "bytes_received",
        "bytes_sent",
        "stream_id",
    ] {
        assert!(
            ingress_hcm.contains(&format!("{field}:")),
            "missing sanitized access-log field {field}",
        );
    }

    for forbidden in ["authorization:", "node_key:", "request_path:", "body:"] {
        assert!(
            !ingress_hcm.contains(forbidden),
            "access log must not include {forbidden}",
        );
    }

    let authentication = rendered
        .find("if presented ~= expected then")
        .expect("node-key authentication guard");
    let metadata_snapshot = rendered
        .find("local access_metadata = handle:streamInfo():dynamicMetadata()")
        .expect("access-log metadata snapshot");
    assert!(
        authentication < metadata_snapshot,
        "caller-supplied correlation metadata must not be trusted before node-key authentication",
    );
    assert!(rendered.contains(
        "access_metadata:set(\n                              \"gm.access_log\", \"authenticated\", true)"
    ));

    for secret_header in [
        "authorization",
        "x-gm-node-key",
        "x-gm-gateway-sig",
        "x-gm-upstream-slot",
        "x-gm-upstream-model",
    ] {
        assert!(
            !ingress_hcm
                .to_ascii_lowercase()
                .contains(&format!("%req({secret_header})%")),
            "access log must not render request header {secret_header}",
        );
    }
}

#[test]
fn moonmath_route_keeps_v1_path_uses_bearer_slots_and_pins_tls() {
    let (status, _, stderr, rendered) = render_envoy([("MOONMATH_API_KEY", "mm-a;mm-b")]);
    assert!(status.success(), "render failed: {stderr}");
    assert!(rendered.contains("exact: zro.moonmath.ai"));
    assert!(rendered.contains("GM_MOONMATH_KEY_SLOT_1"));
    assert!(rendered.contains("GM_MOONMATH_KEY_SLOT_2"));
    assert!(!rendered.contains("mm-a"));
    assert!(!rendered.contains("mm-b"));

    let route = rendered
        .split_once("exact: \"moonmath\"")
        .and_then(|(_, rest)| rest.split_once("request_headers_to_remove"))
        .map_or_else(|| rendered.clone(), |(block, _)| block.to_owned());
    assert!(
        !route.contains("regex_rewrite"),
        "ZRO already serves /v1; a path rewrite would break the request"
    );
    assert!(
        rendered.contains("elseif provider == \"moonmath\" then\n                              headers:add(\"authorization\", \"Bearer \" .. key)"),
        "Moonmath authentication must use the published Bearer scheme"
    );
}

#[test]
fn near_route_has_no_direct_origin_bypass_and_never_renders_the_key() {
    let (status, _, stderr, rendered) = render_envoy([("NEAR_API_KEY", "near-secret")]);
    assert!(status.success(), "render failed: {stderr}");
    let near_route = rendered
        .split_once("## ── NEAR direct confidential inference")
        .and_then(|(_, rest)| rest.split_once("## ── Benchmark"))
        .map_or_else(|| rendered.clone(), |(block, _)| block.to_owned());
    assert!(near_route.contains("exact: \"near\""));
    assert!(near_route.contains("path: \"/v1/models\""));
    assert!(near_route.contains("path: \"/v1/chat/completions\""));
    assert!(!near_route.contains("prefix: \"/\""));
    assert!(near_route.contains("cluster: near_verify_proxy"));
    let anthropic_route = rendered
        .split_once("## ── Anthropic")
        .and_then(|(_, rest)| rest.split_once("## ── OpenAI"))
        .map_or_else(|| rendered.clone(), |(block, _)| block.to_owned());
    assert!(anthropic_route.contains("prefix: \"/\""));
    assert!(rendered.contains("address: 127.0.0.1"));
    assert!(rendered.contains("port_value: 8082"));
    assert!(rendered.contains("zai-org/GLM-5.1-FP8"));
    assert!(rendered.contains("Qwen/Qwen3.6-27B-FP8"));
    assert!(rendered.contains("z-ai/glm-5.2"));
    assert!(rendered.contains("deepseek-ai/DeepSeek-V4-Flash"));
    assert!(rendered.contains("google/gemma-4-31B-it"));
    assert!(rendered.contains("Qwen/Qwen3.8-27B"));
    assert!(!rendered.contains("glm-5-1.completions.near.ai"));
    assert!(!rendered.contains("qwen3-6-27b.completions.near.ai"));
    assert!(!rendered.contains("near-secret"));
    assert!(rendered.contains("if provider ~= \"near\" or bare == \"/v1/models\" then"));
    assert!(rendered.contains("headers:remove(\"x-gm-upstream-model\")"));
}

#[test]
fn deepinfra_cluster_forces_http1_not_h2() {
    // api.deepinfra.com negotiates only http/1.1 (ALPN), so the deepinfra
    // upstream must use http_protocol_options; a copy of zai's h2 config
    // (http2_protocol_options) resets the connection and 503s every route.
    let (status, _, stderr, rendered) = render_envoy([("ANTHROPIC_API_KEY", "sk-ant-direct")]);
    assert!(status.success(), "render failed: {stderr}");
    let block = rendered
        .split_once("- name: deepinfra")
        .and_then(|(_, rest)| rest.split_once("\n    - name:"))
        .map_or_else(|| rendered.clone(), |(block, _)| block.to_owned());
    assert!(
        block.contains("http_protocol_options: {}"),
        "deepinfra cluster must force http/1.1"
    );
    assert!(
        !block.contains("http2_protocol_options"),
        "deepinfra upstream is http/1.1-only; h2 resets the connection"
    );
}

#[test]
fn explicit_direct_render_matches_pinned_output() {
    let (status, _, stderr, rendered) = render_envoy([
        ("ANTHROPIC_API_KEY", "sk-ant-direct"),
        ("ANTHROPIC_UPSTREAM", "direct"),
        ("OPENAI_UPSTREAM", "direct"),
    ]);
    assert!(status.success(), "render failed: {stderr}");
    let actual = hex::encode(Sha256::digest(rendered.as_bytes()));
    assert_eq!(actual, DIRECT_TESTNET_SHA256);
    assert!(rendered.contains("exact: api.anthropic.com"));
    assert!(rendered.contains("exact: api.openai.com"));
    assert!(rendered.contains("GM_ANTHROPIC_KEY_SLOT_1"));
    assert!(!rendered.contains("sk-ant-direct"));
}

#[test]
fn direct_multikey_render_contains_slot_ids_not_key_values() {
    let (status, _, stderr, rendered) =
        render_envoy([("ANTHROPIC_API_KEY", "sk-ant-a; sk-ant-b ")]);
    assert!(status.success(), "render failed: {stderr}");
    assert!(rendered.contains("GM_ANTHROPIC_KEY_SLOT_1"));
    assert!(rendered.contains("GM_ANTHROPIC_KEY_SLOT_2"));
    assert!(rendered.contains("slot_unavailable"));
    assert!(!rendered.contains("sk-ant-a"));
    assert!(!rendered.contains("sk-ant-b"));
}

#[test]
fn no_node_secret_single_key_falls_back_to_direct_env() {
    // Legacy/no-node-secret deployments cannot derive slot ids; a single
    // direct key must keep rendering via the pre-slot direct env fallback.
    let (status, _, stderr, rendered) = render_envoy([
        ("GM_NODE_SECRET", ""),
        ("ANTHROPIC_API_KEY", "sk-ant-legacy"),
    ]);
    assert!(status.success(), "render failed: {stderr}");
    assert!(!rendered.contains("GM_ANTHROPIC_KEY_SLOT_1"));
    assert!(rendered.contains("exact: api.anthropic.com"));
    assert!(!rendered.contains("sk-ant-legacy"));
}

#[test]
fn no_node_secret_multikey_fails_fast() {
    let (status, _, stderr, _) = render_envoy([
        ("GM_NODE_SECRET", ""),
        ("ANTHROPIC_API_KEY", "sk-ant-a;sk-ant-b"),
    ]);
    assert!(
        !status.success(),
        "multi-key without a node secret must fail"
    );
    assert!(
        stderr.contains("GM_NODE_SECRET is unset"),
        "actionable error expected, got: {stderr}"
    );
    assert!(!stderr.contains("sk-ant-a"), "no key material in errors");
}

#[test]
fn bedrock_and_azure_render_cloud_upstreams() {
    let (status, _, stderr, rendered) = render_envoy([
        ("ANTHROPIC_UPSTREAM", "bedrock"),
        ("BEDROCK_REGION", "us-west-2"),
        ("BEDROCK_API_KEY", "bedrock-key"),
        ("OPENAI_UPSTREAM", "azure"),
        (
            "AZURE_OPENAI_ENDPOINT",
            "https://gm-resource.openai.azure.com/",
        ),
        ("AZURE_OPENAI_API_KEY", "azure-key"),
    ]);
    assert!(status.success(), "render failed: {stderr}");

    assert!(rendered.contains("host_rewrite_literal: bedrock-mantle.us-west-2.api.aws"));
    assert!(rendered.contains("address: bedrock-mantle.us-west-2.api.aws"));
    assert!(rendered.contains("sni: bedrock-mantle.us-west-2.api.aws"));
    assert!(rendered.contains("suffix: .api.aws"));
    assert!(!rendered.contains("exact: bedrock-mantle.us-west-2.api.aws"));
    assert!(rendered.contains("substitution: \"/anthropic/v1/messages\""));
    assert!(rendered.contains("value: \"%ENVIRONMENT(BEDROCK_API_KEY)%\""));
    assert!(rendered.contains("append_action: OVERWRITE_IF_EXISTS_OR_ADD"));
    assert!(!rendered.contains("local function json_error"));

    assert!(rendered.contains("host_rewrite_literal: gm-resource.openai.azure.com"));
    assert!(rendered.contains("address: gm-resource.openai.azure.com"));
    assert!(rendered.contains("sni: gm-resource.openai.azure.com"));
    assert!(rendered.contains("filename: /etc/ssl/certs/ca-certificates.crt"));
    assert!(rendered.contains("suffix: .openai.azure.com"));
    assert!(!rendered.contains("exact: gm-resource.openai.azure.com"));
    assert!(rendered.contains("regex: \"^/v1/(chat/completions|responses)$\""));
    assert!(rendered.contains("substitution: \"/openai/v1/\\\\1\""));
    assert!(rendered.contains("key: api-key"));
    assert!(rendered.contains("value: \"%ENVIRONMENT(AZURE_OPENAI_API_KEY)%\""));
}

#[test]
fn azure_openai_rewrites_both_chat_completions_and_responses() {
    // Azure OpenAI serves its OpenAI-compatible surface under /openai/v1,
    // so the path rewrite must map BOTH the chat-completions and the
    // Responses-API inbound paths to their /openai/v1 forms. The gateway
    // forwards POST /v1/responses to the miner verbatim (gm gateway,
    // pipeline/openai_responses.rs), and an Azure miner that only rewrites
    // chat/completions 404s every Responses request upstream.
    let (status, _, stderr, rendered) = render_envoy([
        ("OPENAI_UPSTREAM", "azure"),
        (
            "AZURE_OPENAI_ENDPOINT",
            "https://gm-resource.openai.azure.com/",
        ),
        ("AZURE_OPENAI_API_KEY", "azure-key"),
    ]);
    assert!(status.success(), "render failed: {stderr}");
    let route = rendered
        .split_once("exact: \"openai\"")
        .and_then(|(_, rest)| rest.split_once("request_headers_to_remove"))
        .map_or_else(|| rendered.clone(), |(block, _)| block.to_owned());
    assert!(
        route.contains("regex: \"^/v1/(chat/completions|responses)$\""),
        "rewrite must cover both OpenAI surfaces"
    );
    assert!(
        route.contains("substitution: \"/openai/v1/\\\\1\""),
        "rewrite must prepend /openai/v1 to the captured surface"
    );
}

#[test]
fn direct_openai_keeps_v1_responses_verbatim() {
    // Direct api.openai.com serves the Responses API at /v1/responses
    // itself, so the direct route must NOT carry the /openai/v1 rewrite —
    // a copy of the Azure block would 404 every Responses request.
    let (status, _, stderr, rendered) = render_envoy([("OPENAI_API_KEY", "sk-openai-direct")]);
    assert!(status.success(), "render failed: {stderr}");
    let route = rendered
        .split_once("exact: \"openai\"")
        .and_then(|(_, rest)| rest.split_once("request_headers_to_remove"))
        .map_or_else(|| rendered.clone(), |(block, _)| block.to_owned());
    assert!(
        !route.contains("regex_rewrite"),
        "direct openai must not path-rewrite"
    );
}

#[test]
fn foundry_renders_anthropic_native_passthrough() {
    let (status, _, stderr, rendered) = render_envoy([
        ("ANTHROPIC_UPSTREAM", "foundry"),
        (
            "AZURE_FOUNDRY_ENDPOINT",
            "https://gm-resource.services.ai.azure.com/",
        ),
        ("AZURE_FOUNDRY_API_KEY", "foundry-key"),
    ]);
    assert!(status.success(), "render failed: {stderr}");

    assert!(rendered.contains("host_rewrite_literal: gm-resource.services.ai.azure.com"));
    assert!(rendered.contains("address: gm-resource.services.ai.azure.com"));
    assert!(rendered.contains("sni: gm-resource.services.ai.azure.com"));
    assert!(rendered.contains("suffix: .services.ai.azure.com"));
    assert!(!rendered.contains("exact: gm-resource.services.ai.azure.com"));
    // Foundry's Anthropic passthrough takes the same path rewrite as Bedrock.
    assert!(rendered.contains("substitution: \"/anthropic/v1/messages\""));
    assert!(rendered.contains("key: x-api-key"));
    assert!(rendered.contains("value: \"%ENVIRONMENT(AZURE_FOUNDRY_API_KEY)%\""));
    assert!(rendered.contains("append_action: OVERWRITE_IF_EXISTS_OR_ADD"));
    // Cloud backends are single-slot: no slot fan-out Lua.
    assert!(!rendered.contains("local function json_error"));
    // The key never reaches the rendered config or the logs.
    assert!(!rendered.contains("foundry-key"));
    assert!(!stderr.contains("foundry-key"));
}

#[test]
fn foundry_rejects_endpoint_outside_the_documented_host_suffix() {
    for endpoint in [
        "https://gm-resource.openai.azure.com/",
        "https://gm-resource.cognitiveservices.azure.com/",
        "https://services.ai.azure.com.evil.example/",
        "http://gm-resource.services.ai.azure.com/",
    ] {
        let (status, _, stderr, _) = render_envoy([
            ("ANTHROPIC_UPSTREAM", "foundry"),
            ("AZURE_FOUNDRY_ENDPOINT", endpoint),
            ("AZURE_FOUNDRY_API_KEY", "foundry-key"),
        ]);
        assert!(!status.success(), "{endpoint} should be rejected");
        assert!(
            stderr.contains("Microsoft Foundry") || stderr.contains("AZURE_FOUNDRY_ENDPOINT"),
            "unexpected stderr for {endpoint}: {stderr}"
        );
    }
}

#[test]
fn foundry_requires_endpoint_and_single_slot_key() {
    let (status, _, stderr, _) = render_envoy([
        ("ANTHROPIC_UPSTREAM", "foundry"),
        ("AZURE_FOUNDRY_API_KEY", "foundry-key"),
    ]);
    assert!(!status.success(), "missing endpoint should fail");
    assert!(
        stderr.contains("AZURE_FOUNDRY_ENDPOINT must be set"),
        "unexpected stderr: {stderr}"
    );

    let (status, _, stderr, _) = render_envoy([
        ("ANTHROPIC_UPSTREAM", "foundry"),
        (
            "AZURE_FOUNDRY_ENDPOINT",
            "https://gm-resource.services.ai.azure.com/",
        ),
        ("AZURE_FOUNDRY_API_KEY", "key-one;key-two"),
    ]);
    assert!(!status.success(), "multi-slot Foundry key should fail");
    assert!(
        stderr.contains("cloud backends are single-slot"),
        "unexpected stderr: {stderr}"
    );
    assert!(!stderr.contains("key-one"), "key leaked: {stderr}");
}

#[test]
fn azure_render_uses_suffix_san_for_each_allowed_endpoint_suffix() {
    for (endpoint, host, suffix) in [
        (
            "https://gm-resource.openai.azure.com/",
            "gm-resource.openai.azure.com",
            ".openai.azure.com",
        ),
        (
            "https://gm-resource.services.ai.azure.com/",
            "gm-resource.services.ai.azure.com",
            ".services.ai.azure.com",
        ),
        (
            "https://gm-resource.cognitiveservices.azure.com/openai",
            "gm-resource.cognitiveservices.azure.com",
            ".cognitiveservices.azure.com",
        ),
    ] {
        let (status, _, stderr, rendered) = render_envoy([
            ("OPENAI_UPSTREAM", "azure"),
            ("AZURE_OPENAI_ENDPOINT", endpoint),
            ("AZURE_OPENAI_API_KEY", "azure-key"),
        ]);
        assert!(status.success(), "render failed for {endpoint}: {stderr}");

        assert!(rendered.contains(&format!("address: {host}")));
        assert!(rendered.contains(&format!("sni: {host}")));
        assert!(rendered.contains(&format!("suffix: {suffix}")));
        assert!(!rendered.contains(&format!("exact: {host}")));
    }
}

#[test]
fn direct_empty_slot_fails_fast_without_printing_key_material() {
    let (status, _, stderr, _) = render_envoy([("OPENAI_API_KEY", "sk-a;;sk-b")]);
    assert!(!status.success(), "empty direct slot should fail");
    assert!(stderr.contains("empty slot"), "unexpected stderr: {stderr}");
    assert!(!stderr.contains("sk-a"));
    assert!(!stderr.contains("sk-b"));
}

#[test]
fn cloud_backend_multikey_fails_fast() {
    let (status, _, stderr, _) = render_envoy([
        ("ANTHROPIC_UPSTREAM", "bedrock"),
        ("BEDROCK_REGION", "us-west-2"),
        ("BEDROCK_API_KEY", "bedrock-a;bedrock-b"),
    ]);
    assert!(!status.success(), "cloud backend multikey should fail");
    assert!(stderr.contains("BEDROCK_API_KEY cannot contain ';'"));
    assert!(!stderr.contains("bedrock-a"));
    assert!(!stderr.contains("bedrock-b"));
}

#[test]
fn azure_host_allowlist_rejects_bad_suffix() {
    let (status, _, stderr, _) = render_envoy([
        ("OPENAI_UPSTREAM", "azure"),
        ("AZURE_OPENAI_ENDPOINT", "https://api.evil.example"),
        ("AZURE_OPENAI_API_KEY", "azure-key"),
    ]);
    assert!(!status.success(), "bad Azure host should fail");
    assert!(
        stderr.contains("Azure OpenAI host 'api.evil.example' is not in the allowed suffix set"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn bedrock_region_validation_rejects_bad_host_input() {
    let (status, _, stderr, _) = render_envoy([
        ("ANTHROPIC_UPSTREAM", "bedrock"),
        ("BEDROCK_REGION", "us-west-2.evil.example"),
        ("BEDROCK_API_KEY", "bedrock-key"),
    ]);
    assert!(!status.success(), "bad Bedrock region should fail");
    assert!(
        stderr.contains("BEDROCK_REGION must contain only letters, numbers, and hyphens"),
        "unexpected stderr: {stderr}"
    );
}
