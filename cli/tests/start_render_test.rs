#![expect(
    clippy::expect_used,
    reason = "integration tests intentionally fail hard on unexpected command output"
)]

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Command,
};

use mlua::Lua;
use serde_json::{json, Value};

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

fn config(rendered: &str) -> Value {
    serde_yaml_ng::from_str(rendered).expect("rendered Envoy config must be valid YAML")
}

fn ingress(config: &Value) -> &Value {
    &config["static_resources"]["listeners"]
        .as_array()
        .expect("listeners")
        .iter()
        .find(|listener| listener["name"] == "ingress")
        .expect("ingress")["filter_chains"][0]["filters"][0]["typed_config"]
}

fn data_plane_lua(rendered: &str) -> String {
    ingress(&config(rendered))["http_filters"]
        .as_array()
        .expect("filters")
        .iter()
        .find(|filter| filter["name"] == "envoy.filters.http.lua")
        .expect("Lua filter")["typed_config"]["default_source_code"]["inline_string"]
        .as_str()
        .expect("Lua source")
        .to_owned()
}

fn route<'a>(config: &'a Value, provider: &str, path: &str) -> &'a Value {
    let bare = path.split('?').next().expect("path");
    ingress(config)["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .expect("routes")
        .iter()
        .find(|route| {
            let target = &route["match"];
            let path_matches = target["path"].as_str() == Some(bare)
                || target["prefix"]
                    .as_str()
                    .is_some_and(|prefix| bare.starts_with(prefix));
            path_matches
                && target["headers"].as_array().is_none_or(|headers| {
                    headers.iter().all(|header| {
                        header["name"] == "x-gm-provider"
                            && header["string_match"]["exact"] == provider
                    })
                })
        })
        .expect("matching route")
}

fn cluster<'a>(config: &'a Value, name: &str) -> &'a Value {
    config["static_resources"]["clusters"]
        .as_array()
        .expect("clusters")
        .iter()
        .find(|cluster| cluster["name"] == name)
        .expect("cluster")
}

fn assert_tls(config: &Value, name: &str, host: &str) {
    let upstream = cluster(config, name);
    let tls = &upstream["transport_socket"]["typed_config"];
    assert_eq!(tls["sni"], host);
    let expected_matcher = if host.ends_with(".azure.com") {
        json!({"suffix": format!(".{}", host.split_once('.').expect("Azure resource host").1)})
    } else {
        json!({"exact": host})
    };
    assert_eq!(
        tls["common_tls_context"]["validation_context"]["match_typed_subject_alt_names"][0]
            ["matcher"],
        expected_matcher
    );
    assert_eq!(
        upstream["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]
            ["socket_address"]["address"],
        host
    );
}

fn execute_lua(source: &str) {
    Lua::new()
        .load(source)
        .exec()
        .expect("Lua behavior fixture must pass");
}

fn run_request(rendered: &str, headers: &[(&str, &str)], env: &[(&str, &str)]) -> Lua {
    let lua = Lua::new();
    lua.globals()
        .set(
            "input_headers",
            lua.create_table_from(headers.iter().copied())
                .expect("headers"),
        )
        .expect("input headers");
    lua.globals()
        .set(
            "input_env",
            lua.create_table_from(env.iter().copied())
                .expect("environment"),
        )
        .expect("input environment");
    lua.load(data_plane_lua(rendered))
        .exec()
        .expect("load filter");
    lua.load(include_str!("fixtures/request_handle.lua"))
        .exec()
        .expect("execute request");
    lua
}

fn execute_cloud_slot_fixture(rendered: &str, provider: &str, request_path: &str, slot_env: &str) {
    let current_key = if provider == "openai" {
        "azure-key"
    } else {
        "foundry-key"
    };
    let script = format!(
        "{}\n{}",
        data_plane_lua(rendered),
        include_str!("fixtures/cloud_slot_guard.lua")
    )
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

fn cloud_config(provider: &str) -> String {
    let vars = if provider == "openai" {
        [
            ("OPENAI_UPSTREAM", "azure"),
            (
                "AZURE_OPENAI_ENDPOINT",
                "https://gm-resource.openai.azure.com/",
            ),
            ("AZURE_OPENAI_API_KEY", "azure-key"),
        ]
    } else {
        [
            ("ANTHROPIC_UPSTREAM", "foundry"),
            (
                "AZURE_FOUNDRY_ENDPOINT",
                "https://gm-resource.services.ai.azure.com/",
            ),
            ("AZURE_FOUNDRY_API_KEY", "foundry-key"),
        ]
    };
    let (status, _, stderr, rendered) = render_envoy(vars);
    assert!(status.success(), "render failed: {stderr}");
    rendered
}

struct CloudRoute<'a> {
    provider: &'a str,
    path: &'a str,
    egress: &'a str,
    host: &'a str,
    auth: &'a str,
    env: &'a str,
}

fn assert_cloud_route(expected: &CloudRoute<'_>) {
    let CloudRoute {
        provider,
        path,
        egress,
        host,
        auth,
        env,
    } = *expected;
    let rendered = cloud_config(provider);
    let parsed = config(&rendered);
    let selected = route(&parsed, provider, path);
    assert_eq!(selected["route"]["cluster"], provider);
    assert_eq!(selected["route"]["host_rewrite_literal"], host);
    assert_eq!(selected["route"]["regex_rewrite"]["substitution"], egress);
    assert_eq!(selected["route"]["timeout"], "1800s");
    let added = selected["request_headers_to_add"]
        .as_array()
        .expect("route credentials");
    let credential = added
        .iter()
        .find(|header| header["header"]["key"] == auth)
        .expect("auth header");
    assert_eq!(
        credential["header"]["value"],
        format!("%ENVIRONMENT({env})%")
    );
    assert_eq!(credential["append_action"], "OVERWRITE_IF_EXISTS_OR_ADD");
    for header in [
        "authorization",
        "x-api-key",
        "api-key",
        "x-goog-api-key",
        "x-gm-provider",
    ] {
        assert!(
            selected["request_headers_to_remove"]
                .as_array()
                .expect("removed headers")
                .contains(&json!(header)),
            "route must remove caller {header}"
        );
    }
    assert_tls(&parsed, provider, host);
    let filters = ingress(&parsed)["http_filters"]
        .as_array()
        .expect("filters")
        .iter()
        .map(|filter| filter["name"].as_str().expect("filter name"))
        .collect::<Vec<_>>();
    assert_eq!(
        filters,
        [
            "envoy.filters.http.lua",
            "envoy.filters.http.local_ratelimit",
            "envoy.filters.http.router"
        ]
    );
    execute_cloud_slot_fixture(&rendered, provider, path, env);
}

#[test]
fn azure_chat_forwards_to_tls_cluster_after_executing_slot_and_auth_guards() {
    assert_cloud_route(&CloudRoute {
        provider: "openai",
        path: "/v1/chat/completions",
        egress: "/openai/v1/chat/completions",
        host: "gm-resource.openai.azure.com",
        auth: "api-key",
        env: "GM_OPENAI_KEY_SLOT_1",
    });
}

#[test]
fn foundry_messages_forwards_to_tls_cluster_after_executing_slot_and_auth_guards() {
    assert_cloud_route(&CloudRoute {
        provider: "anthropic",
        path: "/v1/messages",
        egress: "/anthropic/v1/messages",
        host: "gm-resource.services.ai.azure.com",
        auth: "x-api-key",
        env: "GM_ANTHROPIC_KEY_SLOT_1",
    });
}

#[test]
fn azure_responses_is_rejected_with_the_typed_400() {
    let parsed = config(&cloud_config("openai"));
    let rejected = route(&parsed, "openai", "/v1/responses?api-version=preview");
    assert_eq!(rejected["direct_response"]["status"], 400);
    let body: Value = serde_json::from_str(
        rejected["direct_response"]["body"]["inline_string"]
            .as_str()
            .expect("body"),
    )
    .expect("typed error");
    assert_eq!(body["error"]["type"], "gm_unqualified_surface");
    assert!(rejected.get("route").is_none());
    assert_eq!(
        route(&parsed, "openai", "/v1/embeddings")["direct_response"]["status"],
        501
    );
}

#[test]
fn bedrock_never_forwards_inference_and_authenticates_before_rejection() {
    let (status, _, stderr, rendered) = render_envoy([
        ("ANTHROPIC_UPSTREAM", "bedrock"),
        ("BEDROCK_REGION", "us-west-2"),
        ("BEDROCK_API_KEY", "bedrock-key"),
    ]);
    assert!(status.success(), "render failed: {stderr}");
    execute_lua(&format!(
        "{}\n{}",
        data_plane_lua(&rendered),
        include_str!("fixtures/bedrock_slot_guard.lua")
    ));
    let parsed = config(&rendered);
    assert_eq!(
        route(&parsed, "anthropic", "/v1/messages")["direct_response"]["status"],
        400
    );
}

#[test]
fn cloud_requests_pass_bodies_unread_and_strip_internal_headers() {
    for (provider, key, slot_env, path) in [
        (
            "openai",
            "azure-key",
            "GM_OPENAI_KEY_SLOT_1",
            "/v1/chat/completions",
        ),
        (
            "anthropic",
            "foundry-key",
            "GM_ANTHROPIC_KEY_SLOT_1",
            "/v1/messages",
        ),
    ] {
        let slot = gm_miner_cli::slots::derive_slot_id(provider, key, "test-node-secret-0001")
            .expect("slot");
        let lua = run_request(
            &cloud_config(provider),
            &[
                (":path", path),
                ("x-gm-provider", provider),
                ("x-gm-node-key", "test-node-secret-0001"),
                ("x-gm-upstream-slot", &slot),
                ("x-gm-request-id", "request-123"),
                ("x-gm-product", "product"),
                ("x-gm-gateway-sig", "signature"),
                ("x-gm-upstream-model", "caller-model"),
                ("x-gm-private", "private"),
                ("authorization", "caller-secret"),
                ("api-key", "caller-key"),
                ("x-api-key", "caller-key"),
                ("x-goog-api-key", "caller-key"),
            ],
            &[(slot_env, key)],
        );
        lua.load(
            r#"
            assert(response_status == nil)
            assert(input_headers["x-gm-provider"] ~= nil)
            for name in pairs(input_headers) do
              assert(name:sub(1, 5) ~= "x-gm-" or name == "x-gm-provider")
            end
            assert(input_headers.authorization == nil)
            assert(input_headers["api-key"] == nil)
            assert(input_headers["x-api-key"] == nil)
            assert(input_headers["x-goog-api-key"] == nil)
            assert(output_metadata.request_id == "request-123")
            assert(output_metadata.authenticated == true)
        "#,
        )
        .exec()
        .expect("sanitized cloud request");
    }
}

#[test]
fn direct_keys_select_hmac_slots_replace_credentials_and_reject_retired_slots() {
    let (status, _, stderr, rendered) = render_envoy([("OPENAI_API_KEY", "key-one;key-two")]);
    assert!(status.success(), "render failed: {stderr}");
    for (key, env) in [
        ("key-one", "GM_OPENAI_KEY_SLOT_1"),
        ("key-two", "GM_OPENAI_KEY_SLOT_2"),
    ] {
        let slot = gm_miner_cli::slots::derive_slot_id("openai", key, "test-node-secret-0001")
            .expect("slot");
        let lua = run_request(
            &rendered,
            &[
                (":path", "/v1/responses"),
                ("x-gm-provider", "openai"),
                ("x-gm-node-key", "test-node-secret-0001"),
                ("x-gm-upstream-slot", &slot),
                ("authorization", "caller-secret"),
                ("api-key", "caller-key"),
            ],
            &[(env, key)],
        );
        assert_eq!(
            lua.globals()
                .get::<Option<String>>("response_status")
                .expect("status"),
            None
        );
        let headers = lua
            .globals()
            .get::<mlua::Table>("input_headers")
            .expect("headers");
        assert_eq!(
            headers.get::<String>("authorization").expect("auth"),
            format!("Bearer {key}")
        );
        assert_eq!(
            headers
                .get::<Option<String>>("api-key")
                .expect("caller key"),
            None
        );
    }
    let lua = run_request(
        &rendered,
        &[
            (":path", "/v1/responses"),
            ("x-gm-provider", "openai"),
            ("x-gm-node-key", "test-node-secret-0001"),
            ("x-gm-upstream-slot", "retired-slot"),
        ],
        &[],
    );
    assert_eq!(
        lua.globals()
            .get::<String>("response_status")
            .expect("status"),
        "421"
    );
}

#[test]
fn token_shaped_node_secret_authenticates_as_an_inert_literal() {
    let secret = "__GM_ANTHROPIC_DEFAULT_SLOT_ENV__";
    let (status, _, stderr, rendered) = render_envoy([
        ("GM_NODE_SECRET", secret),
        ("ANTHROPIC_API_KEY", "direct-key"),
    ]);
    assert!(status.success(), "render failed: {stderr}");
    let lua = run_request(
        &rendered,
        &[(":path", "/v1/messages"), ("x-gm-node-key", secret)],
        &[],
    );
    assert_eq!(
        lua.globals()
            .get::<Option<String>>("response_status")
            .expect("status"),
        None
    );
    let lua = run_request(
        &rendered,
        &[(":path", "/v1/messages"), ("x-gm-node-key", "wrong-secret")],
        &[],
    );
    assert_eq!(
        lua.globals()
            .get::<String>("response_status")
            .expect("status"),
        "401"
    );
    lua.load("assert(next(output_metadata) == nil)")
        .exec()
        .expect("no unauthenticated metadata");
}

#[test]
fn public_attestation_and_legacy_direct_requests_remain_usable() {
    let (status, _, stderr, rendered) =
        render_envoy([("GM_NODE_SECRET", ""), ("OPENAI_API_KEY", "legacy")]);
    assert!(status.success(), "render failed: {stderr}");
    let lua = run_request(
        &rendered,
        &[(":path", "/v1/responses"), ("x-gm-provider", "openai")],
        &[("OPENAI_API_KEY", "legacy")],
    );
    lua.load(
        "assert(response_status == nil); assert(input_headers.authorization == 'Bearer legacy')",
    )
    .exec()
    .expect("legacy direct key");
    let lua = run_request(
        &cloud_config("openai"),
        &[(":path", "/attestation/info?nonce=test")],
        &[],
    );
    lua.load("assert(response_status == nil); assert(next(output_metadata) == nil)")
        .exec()
        .expect("public attestation");
}

#[test]
fn direct_routes_preserve_native_paths_and_tls_pins() {
    let (status, _, stderr, rendered) = render_envoy([("GOOGLE_API_KEY", "google-key")]);
    assert!(status.success(), "render failed: {stderr}");
    let parsed = config(&rendered);
    for (provider, host, path) in [
        ("anthropic", "api.anthropic.com", "/v1/messages"),
        ("openai", "api.openai.com", "/v1/responses"),
        (
            "gemini",
            "generativelanguage.googleapis.com",
            "/v1beta/models/gemini:generateContent",
        ),
        ("kubetee", "llm.kubetee.ai", "/v1/chat/completions"),
        ("engy", "api.engy.ai", "/v1/chat/completions"),
        ("moonmath", "zro.moonmath.ai", "/v1/chat/completions"),
    ] {
        let selected = route(&parsed, provider, path);
        assert_eq!(selected["route"]["cluster"], provider);
        assert_eq!(selected["route"]["host_rewrite_literal"], host);
        assert!(selected["route"].get("regex_rewrite").is_none());
        assert_tls(&parsed, provider, host);
    }
    let kubetee = cluster(&parsed, "kubetee");
    assert_eq!(
        kubetee["transport_socket"]["typed_config"]["common_tls_context"]["tls_params"]
            ["tls_minimum_protocol_version"],
        "TLSv1_3"
    );
    for provider in ["kubetee", "engy"] {
        assert_eq!(
            cluster(&parsed, provider)["typed_extension_protocol_options"]
                ["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"]["explicit_http_config"]
                ["http2_protocol_options"],
            json!({})
        );
    }
}

#[test]
fn near_only_passes_approved_source_models_to_the_local_verifier() {
    let (status, _, stderr, rendered) = render_envoy([("NEAR_API_KEY", "near-key")]);
    assert!(status.success(), "render failed: {stderr}");
    let parsed = config(&rendered);
    assert_eq!(
        route(&parsed, "near", "/v1/chat/completions")["route"]["cluster"],
        "near_verify_proxy"
    );
    for model in ["Qwen/Qwen3.8-27B", "unapproved-source"] {
        let lua = run_request(
            &rendered,
            &[
                (":path", "/v1/chat/completions"),
                ("x-gm-provider", "near"),
                ("x-gm-node-key", "test-node-secret-0001"),
                ("x-gm-upstream-model", model),
            ],
            &[("GM_NEAR_KEY_SLOT_1", "near-key")],
        );
        assert_eq!(
            lua.globals()
                .get::<Option<String>>("response_status")
                .expect("status"),
            (model == "unapproved-source").then(|| "400".to_owned())
        );
    }
}

#[test]
fn internal_headers_are_stripped_without_changing_provider_or_near_routing() {
    let (status, _, stderr, rendered) = render_envoy([
        ("GOOGLE_API_KEY", "google-key"),
        ("NEAR_API_KEY", "near-key"),
    ]);
    assert!(status.success(), "render failed: {stderr}");
    let parsed = config(&rendered);
    for provider in [
        "anthropic",
        "openai",
        "gemini",
        "chutes",
        "zai",
        "moonshot",
        "deepinfra",
        "kubetee",
        "engy",
        "moonmath",
        "near",
        "benchmark",
    ] {
        for path in ["/v1/chat/completions?trace=1", "/v1/models"] {
            let lua = run_request(
                &rendered,
                &[
                    (":path", path),
                    ("x-gm-provider", provider),
                    ("x-gm-node-key", "test-node-secret-0001"),
                    ("x-gm-upstream-model", "Qwen/Qwen3.8-27B"),
                    ("x-gm-private", "private"),
                    ("x-gm-request-id", "request-123"),
                    ("anthropic-beta", "caller-beta"),
                ],
                &[
                    ("GM_GEMINI_KEY_SLOT_1", "google-key"),
                    ("GM_NEAR_KEY_SLOT_1", "near-key"),
                ],
            );
            assert_eq!(
                lua.globals()
                    .get::<Option<String>>("response_status")
                    .expect("status"),
                None
            );
            let headers = lua
                .globals()
                .get::<mlua::Table>("input_headers")
                .expect("headers");
            let routed_provider = headers.get::<String>("x-gm-provider").expect("provider");
            let routed_path = headers.get::<String>(":path").expect("path");
            assert_eq!(routed_provider, provider);
            assert_eq!(routed_path, path);
            let selected = route(&parsed, &routed_provider, &routed_path);
            assert_eq!(
                selected["route"]["cluster"],
                if provider == "near" {
                    "near_verify_proxy"
                } else {
                    provider
                }
            );
            assert!(selected["request_headers_to_remove"]
                .as_array()
                .expect("removed headers")
                .contains(&json!("x-gm-provider")));
            let near_model = provider == "near" && path != "/v1/models";
            assert_eq!(
                headers
                    .get::<Option<String>>("x-gm-upstream-model")
                    .expect("model"),
                near_model.then(|| "Qwen/Qwen3.8-27B".to_owned())
            );
            for pair in headers.pairs::<String, String>() {
                let (name, _) = pair.expect("header");
                assert!(
                    !name.starts_with("x-gm-")
                        || name == "x-gm-provider"
                        || (near_model && name == "x-gm-upstream-model"),
                    "{provider} leaked {name}"
                );
            }
            assert_eq!(
                headers
                    .get::<String>("anthropic-beta")
                    .expect("native header"),
                "caller-beta"
            );
        }
    }
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
fn cloud_requires_node_secret_for_slot_derivation() {
    let (status, _, stderr, _) = render_envoy([
        ("GM_NODE_SECRET", ""),
        ("OPENAI_UPSTREAM", "azure"),
        (
            "AZURE_OPENAI_ENDPOINT",
            "https://gm-resource.openai.azure.com/",
        ),
        ("AZURE_OPENAI_API_KEY", "azure-key"),
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

#[test]
fn azure_endpoint_suffixes_keep_their_original_tls_pins() {
    for endpoint in [
        "https://gm-resource.openai.azure.com/",
        "https://gm-resource.services.ai.azure.com/",
        "https://gm-resource.cognitiveservices.azure.com/openai",
    ] {
        let (status, _, stderr, rendered) = render_envoy([
            ("OPENAI_UPSTREAM", "azure"),
            ("AZURE_OPENAI_ENDPOINT", endpoint),
            ("AZURE_OPENAI_API_KEY", "azure-key"),
        ]);
        assert!(status.success(), "render failed: {stderr}");
        let host = reqwest::Url::parse(endpoint)
            .expect("endpoint")
            .host_str()
            .expect("host")
            .to_owned();
        assert_tls(&config(&rendered), "openai", &host);
    }
}

#[test]
fn deepinfra_keeps_http1_and_its_native_path_rewrite() {
    let (status, _, stderr, rendered) = render_envoy([("DEEPINFRA_API_KEY", "direct-key")]);
    assert!(status.success(), "render failed: {stderr}");
    let parsed = config(&rendered);
    let protocol = &cluster(&parsed, "deepinfra")["typed_extension_protocol_options"]
        ["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"]["explicit_http_config"];
    assert_eq!(protocol, &json!({"http_protocol_options": {}}));
    assert_eq!(
        route(&parsed, "deepinfra", "/v1/chat/completions")["route"]["regex_rewrite"]
            ["substitution"],
        r"/v1/openai/\1"
    );
}

#[test]
fn access_log_uses_only_authenticated_sanitized_correlation_metadata() {
    let rendered = cloud_config("openai");
    let parsed = config(&rendered);
    let fields = ingress(&parsed)["access_log"][0]["typed_config"]["log_format"]["json_format"]
        .as_object()
        .expect("structured access log");
    for name in ["request_id", "product", "provider", "authenticated"] {
        assert_eq!(
            fields[name],
            format!("%DYNAMIC_METADATA(gm.access_log:{name})%")
        );
    }
    for name in [
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
        "timestamp",
    ] {
        assert!(
            fields.contains_key(name),
            "missing termination field {name}"
        );
    }
    assert_eq!(fields.len(), 23);
    let lua = run_request(
        &rendered,
        &[
            (":path", "/v1/chat/completions?private"),
            ("x-gm-provider", "openai"),
            ("x-gm-node-key", "wrong-secret"),
            ("x-gm-request-id", "untrusted-id"),
            ("authorization", "caller-secret"),
        ],
        &[],
    );
    lua.load("assert(response_status == '401'); assert(next(output_metadata) == nil)")
        .exec()
        .expect("unauthenticated values stay out of logs");
}
