#![expect(
    clippy::expect_used,
    reason = "integration tests intentionally fail hard on unexpected command output"
)]

use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

use mlua::Lua;
use sha2::{Digest as _, Sha256};

const DIRECT_TESTNET_SHA256: &str =
    "1e30536909f2d5db70e7dec8a5e8eb7c9912cd3e7c30a5cb4ed8614883810522";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate must live under repo root")
        .to_owned()
}

fn cloud_hop_binary() -> PathBuf {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY
        .get_or_init(|| {
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
            let output = Command::new(cargo)
                .current_dir(repo_root())
                .args([
                    "build",
                    "-p",
                    "gm-cloud-hop",
                    "--bin",
                    "gm-cloud-hop",
                    "--message-format=json-render-diagnostics",
                ])
                .output()
                .expect("build gm-cloud-hop render fixture");
            assert!(
                output.status.success(),
                "building gm-cloud-hop failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let executable = String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .find_map(|artifact| {
                    let is_hop_binary = artifact.get("reason").and_then(serde_json::Value::as_str)
                        == Some("compiler-artifact")
                        && artifact
                            .get("target")
                            .and_then(|target| target.get("name"))
                            .and_then(serde_json::Value::as_str)
                            == Some("gm-cloud-hop")
                        && artifact
                            .get("target")
                            .and_then(|target| target.get("kind"))
                            .and_then(serde_json::Value::as_array)
                            .is_some_and(|kind| {
                                kind.iter().any(|entry| entry.as_str() == Some("bin"))
                            });
                    is_hop_binary.then(|| {
                        artifact
                            .get("executable")
                            .and_then(serde_json::Value::as_str)
                            .map(PathBuf::from)
                    })
                })
                .flatten()
                .expect("cargo did not report the gm-cloud-hop executable");
            if executable.is_absolute() {
                executable
            } else {
                repo_root().join(executable)
            }
        })
        .clone()
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
        .env("GM_CLOUD_HOP_BIN", cloud_hop_binary())
        .env("GM_ENVOY_TEMPLATE_PATH", root.join("image/envoy.yaml"))
        .env("GM_RENDERED_CONFIG", out.path())
        .env("GM_NETWORK", "testnet")
        .env("GM_NODE_SECRET", "test-node-secret-0001")
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

fn data_plane_lua(rendered: &str) -> Option<String> {
    let (_, rendered) = rendered.split_once("default_source_code:\n")?;
    let (_, source) = rendered.split_once("inline_string: |\n")?;
    let source = &source[..source.find("## ── Graceful load shedding")?];
    let indent = source
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start().len())?;
    Some(
        source
            .lines()
            .map(|line| line.get(indent..).unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

fn execute_lua(source: &str) {
    Lua::new()
        .load(source)
        .exec()
        .expect("embedded Lua behavior fixture must pass");
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
fn node_secret_carrying_lua_breakout_is_rejected_before_render() {
    // A node secret with a quote would close the `local expected = "..."` Lua
    // string literal in the buyer-facing Envoy filter and inject attacker code
    // onto the data path — invisible to attestation, since the CVM env is not
    // covered by compose_hash. The render must fail closed, emitting no config.
    let (status, _, stderr, rendered) = render_envoy([
        ("ANTHROPIC_API_KEY", "sk-ant-direct"),
        (
            "GM_NODE_SECRET",
            "x\"\nfunction envoy_on_response(handle) end\nlocal _y=\"z",
        ),
    ]);
    assert!(
        !status.success(),
        "render must reject a node secret that can break out of the Lua literal"
    );
    assert!(
        stderr.contains("GM_NODE_SECRET must match"),
        "expected the validation error, got: {stderr}"
    );
    assert!(
        !rendered.contains("envoy_on_response"),
        "no injected Lua may reach the rendered config"
    );
    assert!(
        rendered.is_empty(),
        "a rejected render must emit no config at all"
    );
}

#[test]
fn node_secret_valid_first_line_then_quote_is_rejected() {
    // Discriminates whole-string anchoring from a per-line bug: the first line
    // is a full valid match, so a `^`/`$` that anchored per line would accept
    // it. The embedded newline+quote must still be rejected.
    let (status, _, stderr, _) = render_envoy([
        ("ANTHROPIC_API_KEY", "sk-ant-direct"),
        ("GM_NODE_SECRET", "validsecret0123456\n\"payload"),
    ]);
    assert!(
        !status.success(),
        "a value with any non-conforming line must be rejected"
    );
    assert!(
        stderr.contains("GM_NODE_SECRET must match"),
        "got: {stderr}"
    );
}

#[test]
fn token_shaped_node_secret_renders_as_inert_literal() {
    // A secret that itself looks like a `__GM_*__` render token passes the
    // charset check; it must land as a verbatim Lua literal, never be
    // re-expanded by a later substitution into `local expected = ""...""`.
    let (status, _, stderr, rendered) = render_envoy([
        ("ANTHROPIC_API_KEY", "sk-ant-direct"),
        ("GM_NODE_SECRET", "__GM_ANTHROPIC_DEFAULT_SLOT_ENV__"),
    ]);
    assert!(status.success(), "render failed: {stderr}");
    assert!(
        rendered.contains("local expected = \"__GM_ANTHROPIC_DEFAULT_SLOT_ENV__\""),
        "the token-shaped secret must survive verbatim, not be re-expanded"
    );
}

#[test]
fn gemini_route_keeps_native_generate_content_path_verbatim() {
    // The image SKUs use Google's native
    // /v1beta/models/{model}:generateContent endpoint. The route is
    // intentionally path-agnostic so both that endpoint and the existing
    // OpenAI-compatible Gemini surface reach the same upstream unchanged.
    // This render-only test never contacts Google and cannot generate a paid
    // image; it guards the Envoy shape and the absence of a rewrite that would
    // turn a native request into a different API.
    let (status, _, stderr, rendered) = render_envoy([("GOOGLE_API_KEY", "google-key")]);
    assert!(status.success(), "render failed: {stderr}");
    let route = rendered
        .split_once("## ── Gemini")
        .and_then(|(_, rest)| rest.split_once("## ── NEAR direct confidential inference"))
        .map_or_else(|| rendered.clone(), |(block, _)| block.to_owned());
    assert!(
        route.contains("prefix: \"/\""),
        "Gemini must accept native /v1beta/models/...:generateContent paths"
    );
    assert!(route.contains("exact: \"gemini\""));
    assert!(route.contains("cluster: gemini"));
    assert!(
        !route.contains("regex_rewrite") && !route.contains("path:"),
        "native generateContent requests must not be rewritten"
    );
    assert!(rendered.contains("host_rewrite_literal: generativelanguage.googleapis.com"));
    assert!(rendered.contains("sni: generativelanguage.googleapis.com"));
    assert!(
        !rendered.contains("google-key"),
        "the key must never be rendered"
    );
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
        ("AZURE_OPENAI_DEPLOYMENTS", "gpt-5.5=azure-gpt55"),
    ]);
    assert!(status.success(), "render failed: {stderr}");

    assert!(rendered.contains("host_rewrite_literal: bedrock-mantle.us-west-2.api.aws"));
    assert!(rendered.contains("address: bedrock-mantle.us-west-2.api.aws"));
    assert!(rendered.contains("sni: bedrock-mantle.us-west-2.api.aws"));
    assert!(rendered.contains("exact: bedrock-mantle.us-west-2.api.aws"));
    assert!(!rendered.contains("suffix: .api.aws"));
    let ingress = rendered
        .split_once("    - name: cloud_hop_egress")
        .map_or(rendered.as_str(), |(ingress, _)| ingress);
    assert!(
        ingress.contains("status: 400")
            && ingress.contains("AWS Bedrock is unqualified inside this image"),
        "Bedrock inference must be rejected in the ingress route"
    );
    assert!(
        !ingress.contains("host_rewrite_literal: bedrock-mantle.us-west-2.api.aws"),
        "Bedrock must not have a direct ingress route to the Anthropic cluster"
    );
    assert!(!ingress.contains("%ENVIRONMENT(BEDROCK_API_KEY)%"));
    assert!(!rendered.contains("local function json_error"));

    assert!(rendered.contains("host_rewrite_literal: gm-resource.openai.azure.com"));
    assert!(rendered.contains("address: gm-resource.openai.azure.com"));
    assert!(rendered.contains("sni: gm-resource.openai.azure.com"));
    assert!(rendered.contains("filename: /etc/ssl/certs/ca-certificates.crt"));
    assert!(rendered.contains("suffix: .openai.azure.com"));
    assert!(!rendered.contains("exact: gm-resource.openai.azure.com"));
    assert!(rendered.contains("regex: \"^/v1/chat/completions$\""));
    assert!(rendered.contains("substitution: \"/openai/v1/chat/completions\""));
    assert!(!rendered.contains("regex: \"^/v1/(chat/completions|responses)$\""));
    assert!(!rendered.contains("substitution: \"/openai/v1/\\\\1\""));
    assert!(rendered.contains("port_value: 8083"));
    assert!(rendered.contains("key: x-gm-cloud-hop-provider"));
    assert!(rendered.contains("key: api-key"));
    assert!(rendered.contains("value: \"%ENVIRONMENT(GM_OPENAI_KEY_SLOT_1)%\""));
}

#[test]
fn bedrock_inference_render_contract_is_structural() {
    let (status, _, stderr, rendered) = render_envoy([
        ("ANTHROPIC_UPSTREAM", "bedrock"),
        ("BEDROCK_REGION", "us-west-2"),
        ("BEDROCK_API_KEY", "bedrock-key"),
    ]);
    assert!(status.success(), "render failed: {stderr}");
    assert!(rendered.contains("AWS Bedrock is unqualified inside this image"));
    assert!(
        rendered.contains(
            "if cfg.cloud and not cfg.cloud_hop then\n                              if requested ~= nil then\n                                slot_unavailable(handle, requested)"
        ),
        "supplied Bedrock slots must take the 421 unavailable-slot branch"
    );
}

#[test]
fn bedrock_slot_guard_executes_lua() {
    let (status, _, stderr, rendered) = render_envoy([
        ("ANTHROPIC_UPSTREAM", "bedrock"),
        ("BEDROCK_REGION", "us-west-2"),
        ("BEDROCK_API_KEY", "bedrock-key"),
    ]);
    assert!(status.success(), "render failed: {stderr}");
    let source = data_plane_lua(&rendered).expect("data-plane Lua source");
    assert!(
        source.contains("if requested ~= nil then")
            && source.contains("slot_unavailable(handle, requested)"),
        "Bedrock's supplied-slot branch must use the 421 structural contract"
    );
    assert!(
        source.contains("AWS Bedrock is unqualified inside this image"),
        "Bedrock's no-slot branch must remain the unqualified-surface rejection"
    );
    let mut script = source;
    script.push_str(include_str!("fixtures/bedrock_slot_guard.lua"));
    execute_lua(&script);
}

#[test]
fn azure_openai_rewrites_only_qualified_chat_completions() {
    // Azure chat completions is qualified by the dated model echo. Azure
    // Responses is intentionally rejected because its echo is the deployment
    // name, so only the qualified path enters the hop and egress rewrite.
    let (status, _, stderr, rendered) = render_envoy([
        ("OPENAI_UPSTREAM", "azure"),
        (
            "AZURE_OPENAI_ENDPOINT",
            "https://gm-resource.openai.azure.com/",
        ),
        ("AZURE_OPENAI_API_KEY", "azure-key"),
        ("AZURE_OPENAI_DEPLOYMENTS", "gpt-5.5=azure-gpt55"),
    ]);
    assert!(status.success(), "render failed: {stderr}");
    let route = rendered
        .split_once("exact: \"openai\"")
        .and_then(|(_, rest)| rest.split_once("request_headers_to_remove"))
        .map_or_else(|| rendered.clone(), |(block, _)| block.to_owned());
    assert!(
        route.contains("cluster: cloud_hop") && rendered.contains("key: x-gm-cloud-hop-provider"),
        "qualified OpenAI surfaces must enter the measured cloud hop"
    );
    let egress = rendered
        .split_once("stat_prefix: cloud_hop_egress_http")
        .map_or_else(|| rendered.clone(), |(_, block)| block.to_owned());
    assert!(
        egress.contains("regex: \"^/v1/chat/completions$\"")
            && egress.contains("substitution: \"/openai/v1/chat/completions\""),
        "Envoy's egress cluster must rewrite the qualified chat surface"
    );
    assert!(egress.contains("stream_idle_timeout: 1800s"));
    assert!(!egress.contains("^/v1/(chat/completions|responses)$"));
    assert!(rendered.contains("gm_unqualified_surface"));
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
        (
            "AZURE_FOUNDRY_DEPLOYMENTS",
            "claude-sonnet-4-6=gm-echo-test",
        ),
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
    assert!(rendered.contains("value: \"%ENVIRONMENT(GM_ANTHROPIC_KEY_SLOT_1)%\""));
    assert!(rendered.contains("append_action: OVERWRITE_IF_EXISTS_OR_ADD"));
    assert!(rendered.contains("GM_ANTHROPIC_KEY_SLOT_1"));
    assert!(rendered.contains("if env_name == nil or getenv(env_name) == nil then"));
    assert!(rendered.contains("port_value: 8084"));
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
            ("AZURE_OPENAI_DEPLOYMENTS", "gpt-5.5=azure-gpt55"),
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

fn assert_rendered_cloud_slot_contract(rendered: &str) {
    let lua = data_plane_lua(rendered).expect("data-plane Lua source");
    assert!(lua.contains("cloud = true"), "cloud slot config is missing");
    assert!(
        lua.contains("cloud_hop = true"),
        "hop slot config is missing"
    );
    assert!(
        lua.contains("gm_slot_unavailable") && lua.contains("[\":status\"] = \"421\""),
        "qualified slot rejection must remain a 421"
    );
    assert!(
        lua.contains("missing or invalid x-gm-node-key"),
        "the node-secret guard must remain before slot selection"
    );
}

fn execute_cloud_slot_fixture(rendered: &str, provider: &str, request_path: &str, slot_env: &str) {
    let source = data_plane_lua(rendered).expect("data-plane Lua source");
    let mut script = source;
    script.push_str(include_str!("fixtures/cloud_slot_guard.lua"));
    let current_key = if provider == "openai" {
        "azure-key"
    } else {
        "foundry-key"
    };
    let script = script
        .replace(
            "__EXPECTED_SLOT__",
            &gm_miner_cli::slots::derive_slot_id(provider, current_key, "test-node-secret-0001")
                .expect("current HMAC slot"),
        )
        .replace(
            "__OLD_SLOT__",
            &gm_miner_cli::slots::derive_slot_id(
                provider,
                "retired-cloud-key",
                "test-node-secret-0001",
            )
            .expect("old HMAC slot"),
        )
        .replace("__SLOT_ENV__", slot_env)
        .replace("__PROVIDER__", provider)
        .replace("__REQUEST_PATH__", request_path);
    execute_lua(&script);
}

#[test]
fn cloud_slot_guard_executes_lua_and_keeps_structural_coverage() {
    let (status, _, stderr, rendered) = render_envoy([
        ("OPENAI_UPSTREAM", "azure"),
        (
            "AZURE_OPENAI_ENDPOINT",
            "https://gm-resource.openai.azure.com/",
        ),
        ("AZURE_OPENAI_API_KEY", "azure-key"),
        ("AZURE_OPENAI_DEPLOYMENTS", "gpt-5.5=azure-gpt55"),
    ]);
    assert!(status.success(), "render failed: {stderr}");
    assert_rendered_cloud_slot_contract(&rendered);
    execute_cloud_slot_fixture(
        &rendered,
        "openai",
        "/v1/chat/completions",
        "GM_OPENAI_KEY_SLOT_1",
    );
}

#[test]
fn foundry_slot_guard_executes_lua() {
    let (status, _, stderr, rendered) = render_envoy([
        ("ANTHROPIC_UPSTREAM", "foundry"),
        (
            "AZURE_FOUNDRY_ENDPOINT",
            "https://gm-resource.services.ai.azure.com/",
        ),
        ("AZURE_FOUNDRY_API_KEY", "foundry-key"),
        (
            "AZURE_FOUNDRY_DEPLOYMENTS",
            "claude-sonnet-4-6=gm-echo-test",
        ),
    ]);
    assert!(status.success(), "render failed: {stderr}");
    assert_rendered_cloud_slot_contract(&rendered);
    execute_cloud_slot_fixture(
        &rendered,
        "anthropic",
        "/v1/messages",
        "GM_ANTHROPIC_KEY_SLOT_1",
    );
}

#[test]
fn cloud_requires_node_secret_for_slot_derivation() {
    let (status, _, stderr, _) = render_envoy([
        ("GM_NODE_SECRET", ""),
        ("OPENAI_UPSTREAM", "azure"),
        (
            "AZURE_OPENAI_ENDPOINT",
            "https://gm-resource.openai.azure.com/",
        ),
        ("AZURE_OPENAI_API_KEY", "azure-key"),
        ("AZURE_OPENAI_DEPLOYMENTS", "gpt-5.5=azure-gpt55"),
    ]);
    assert!(!status.success(), "cloud slots need a node secret");
    assert!(stderr.contains("GM_NODE_SECRET must be set"), "{stderr}");
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
