//! Assemble the miner's Envoy config from `image/envoy/`.
//!
//! `base.yaml` holds everything shared: the listeners, the attestation route,
//! the catch-all, the loopback clusters and the data-plane Lua filter. Each
//! file in `upstreams/` holds one upstream's routes, clusters and key-slot
//! settings. See `image/envoy/upstreams/README.md` for the file format.
//!
//! Rendering runs inside the TEE at container start (`start.sh` calls the
//! hidden `gmcli render-envoy`), in three steps:
//!
//! 1. Replace every `__GM_<NAME>__` token in each file's text with the
//!    `GM_<NAME>` environment variable, in one left-to-right pass. The pass
//!    never rescans an inserted value, so a node secret shaped like a token
//!    stays an inert literal. An unset variable is an error, not an empty
//!    string: a missing value must stop the render, not ship a blank host.
//! 2. Parse the files as YAML and splice each upstream's routes and clusters into
//!    `base.yaml` at the `gm:upstream-routes` / `gm:upstream-clusters`
//!    markers, adding the gm-internal header strip list to every upstream
//!    route.
//! 3. Build the Lua `slot_config` table from the upstreams' `slots` blocks and
//!    the `GM_<PROVIDER>_SLOT_IDS` variables `gmcli slot-env` exported.
//!
//! The result is written as JSON (see [`render`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{bail, Context as _, Result};
use serde::Deserialize;
use serde_json::Value;

const ROUTES_MARKER: &str = "gm:upstream-routes";
const CLUSTERS_MARKER: &str = "gm:upstream-clusters";
const SLOT_CONFIG_TOKEN: &str = "SLOT_CONFIG";

/// Headers appended to each upstream route's removal list. `KubeTEE` chat keeps
/// its session id for the verifier; the route list alone removes the provider.
const GM_INTERNAL_HEADERS: [&str; 7] = [
    "x-gm-request-id",
    "x-gm-gateway-sig",
    "x-gm-product",
    "x-gm-node-key",
    "x-gm-provider",
    "x-gm-upstream-slot",
    "x-gm-session-id",
];

/// Key-slot settings for one upstream, rendered into the Lua `slot_config`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Slots {
    direct_env: String,
    #[serde(default)]
    cloud: bool,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    no_retry: bool,
    auth_header: Option<String>,
    #[serde(default)]
    auth_prefix: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamFile {
    slots: Option<Slots>,
    #[serde(default)]
    routes: Vec<Value>,
    #[serde(default)]
    clusters: Vec<Value>,
}

struct Upstream {
    provider: String,
    file: UpstreamFile,
}

/// Render the full Envoy config from `template_dir`.
///
/// `selections` picks one variant for each provider that ships variant files
/// (`anthropic.foundry.yaml` is selected by `("anthropic", "foundry")`).
/// `env` resolves `GM_*` variables; production passes `std::env::var`.
///
/// # Errors
/// Returns an error when a file is missing or malformed, a token has no
/// variable, a selection matches no file, or a marker is absent.
pub fn render(
    template_dir: &Path,
    selections: &BTreeMap<String, String>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<String> {
    let upstreams = load_upstreams(&template_dir.join("upstreams"), selections, env)?;
    let slot_config = slot_config_lua(&upstreams, env);
    let base_env = |name: &str| {
        if name == format!("GM_{SLOT_CONFIG_TOKEN}") {
            Some(slot_config.clone())
        } else {
            env(name)
        }
    };
    let base_path = template_dir.join("base.yaml");
    let mut base = parse_rendered(&base_path, &base_env)?;

    let mut routes = Vec::new();
    let mut clusters = Vec::new();
    for upstream in upstreams {
        for mut route in upstream.file.routes {
            add_internal_header_strip(&mut route, &upstream.provider)?;
            routes.push(route);
        }
        clusters.extend(upstream.file.clusters);
    }
    splice(&mut base, ROUTES_MARKER, routes)?;
    splice(&mut base, CLUSTERS_MARKER, clusters)?;
    // JSON, not YAML: every string is quoted, so no scalar can be retyped on
    // the way into Envoy (unquoted YAML turns `2023-06-01` into a date and
    // `on` into a bool). Envoy's YAML loader reads JSON as-is.
    serde_json::to_string_pretty(&base).context("serialize rendered Envoy config")
}

fn load_upstreams(
    dir: &Path,
    selections: &BTreeMap<String, String>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<Upstream>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "yaml") {
            names.push(path);
        }
    }
    names.sort();

    let mut variant_providers = BTreeSet::new();
    let mut selected = BTreeSet::new();
    let mut providers = BTreeSet::new();
    let mut upstreams = Vec::new();
    for path in names {
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .with_context(|| format!("non-UTF-8 upstream file name {}", path.display()))?;
        let provider = match stem.split_once('.') {
            None => stem,
            Some((provider, variant)) => {
                variant_providers.insert(provider.to_owned());
                if selections.get(provider).map(String::as_str) != Some(variant) {
                    continue;
                }
                selected.insert(provider.to_owned());
                provider
            }
        };
        if !providers.insert(provider.to_owned()) {
            bail!("{provider} has more than one upstream file selected");
        }
        // Validate the schema through JSON: serde-saphyr's typed deserializer
        // otherwise accepts null lists and quoted booleans, hiding mistakes.
        let value = parse_rendered(&path, env)?;
        // JSON's struct deserializer also accepts positional arrays. YAML
        // upstream and slots settings must use mappings with named fields.
        if !value.is_object() {
            bail!("{}: upstream must be a mapping", path.display());
        }
        if value
            .get("slots")
            .is_some_and(|slots| !slots.is_null() && !slots.is_object())
        {
            bail!("{}: slots must be a mapping or null", path.display());
        }
        let file: UpstreamFile =
            serde_json::from_value(value).with_context(|| format!("parse {}", path.display()))?;
        if let Some(slots) = &file.slots {
            if !slots.cloud && !slots.disabled && slots.auth_header.is_none() {
                bail!(
                    "{}: a direct upstream's slots need an auth_header",
                    path.display()
                );
            }
        }
        upstreams.push(Upstream {
            provider: provider.to_owned(),
            file,
        });
    }
    check_selections(selections, &variant_providers, &selected)?;
    Ok(upstreams)
}

fn check_selections(
    selections: &BTreeMap<String, String>,
    variant_providers: &BTreeSet<String>,
    selected: &BTreeSet<String>,
) -> Result<()> {
    for (provider, variant) in selections {
        if !selected.contains(provider) {
            bail!("no upstream file {provider}.{variant}.yaml for --select {provider}={variant}");
        }
    }
    for provider in variant_providers {
        if !selections.contains_key(provider) {
            bail!("{provider} ships variant files; pass --select {provider}=<variant>");
        }
    }
    Ok(())
}

fn parse_rendered(path: &Path, env: &dyn Fn(&str) -> Option<String>) -> Result<Value> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let text = substitute(&text, env, path)?;
    let value = serde_saphyr::from_str_with_options(
        &text,
        serde_saphyr::options! {
            // Preserve the old parser's YAML 1.2 booleans and literal merge keys.
            strict_booleans: true,
            merge_keys: serde_saphyr::options::MergeKeyPolicy::AsOrdinary,
            ignore_binary_tag_for_string: true,
            // JSON mapping keys must be strings. Do not coerce boolean/numeric
            // keys: that bypasses YAML duplicate-key and non-finite checks.
            no_schema: true,
            // Substitution has already inserted secrets into this source text.
            with_snippet: false,
        },
    )
    .with_context(|| format!("parse {}", path.display()))?;
    Ok(value)
}

/// Replace each `__GM_<NAME>__` with `GM_<NAME>` in one pass. Inserted values
/// are never rescanned.
fn substitute(text: &str, env: &dyn Fn(&str) -> Option<String>, path: &Path) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("__GM_") {
        let after = &rest[start + 2..];
        let Some(len) = after.find("__") else {
            break;
        };
        let name = &after[..len];
        if !name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            out.push_str(&rest[..start + 2]);
            rest = after;
            continue;
        }
        let Some(value) = env(name) else {
            bail!("{} uses __{name}__ but {name} is not set", path.display());
        };
        out.push_str(&rest[..start]);
        out.push_str(&value);
        rest = &after[len + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn add_internal_header_strip(route: &mut Value, provider: &str) -> Result<()> {
    let Value::Object(map) = route else {
        bail!("a route in upstreams/{provider}*.yaml is not a mapping");
    };
    let mut headers = match map.remove("request_headers_to_remove") {
        None => Vec::new(),
        Some(Value::Array(existing)) => existing,
        Some(_) => bail!("{provider}: request_headers_to_remove must be a list"),
    };
    let keep_kubetee_chat_session = provider == "kubetee"
        && map
            .get("match")
            .and_then(|matched| matched.get("path"))
            .and_then(Value::as_str)
            == Some("/v1/chat/completions");
    for header in GM_INTERNAL_HEADERS {
        if keep_kubetee_chat_session && header == "x-gm-session-id" {
            continue;
        }
        let header = Value::from(header);
        if !headers.contains(&header) {
            headers.push(header);
        }
    }
    map.insert(
        "request_headers_to_remove".to_owned(),
        Value::Array(headers),
    );
    Ok(())
}

/// Replace the one list item equal to `marker` with `items`.
fn splice(root: &mut Value, marker: &str, items: Vec<Value>) -> Result<()> {
    let marker_value = Value::String(marker.to_owned());
    let mut found = 0;
    visit_sequences(root, &mut |seq| {
        found += seq.iter().filter(|item| **item == marker_value).count();
    });
    if found != 1 {
        bail!("base.yaml must contain `- {marker}` exactly once (found {found})");
    }
    let mut items = Some(items);
    visit_sequences(root, &mut |seq| {
        if let Some(pos) = seq.iter().position(|item| *item == marker_value) {
            seq.splice(pos..=pos, items.take().unwrap_or_default());
        }
    });
    Ok(())
}

fn visit_sequences(value: &mut Value, visit: &mut dyn FnMut(&mut Vec<Value>)) {
    match value {
        Value::Array(seq) => {
            visit(seq);
            for item in seq {
                visit_sequences(item, visit);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                visit_sequences(item, visit);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// The Lua `slot_config` table, on one line so it drops into the filter's
/// block scalar without re-indentation.
fn slot_config_lua(upstreams: &[Upstream], env: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::from("{");
    for upstream in upstreams {
        let Some(slots) = &upstream.file.slots else {
            continue;
        };
        let prefix = format!("GM_{}", upstream.provider.to_ascii_uppercase());
        let ids = env(&format!("{prefix}_SLOT_IDS")).unwrap_or_default();
        let ids: Vec<&str> = ids.split(';').filter(|id| !id.is_empty()).collect();
        let default_env = if ids.is_empty() {
            "nil".to_owned()
        } else {
            lua_string(&format!("{prefix}_KEY_SLOT_1"))
        };
        let mut slot_map = String::from("{");
        for (idx, id) in ids.iter().enumerate() {
            let sep = if idx == 0 { "" } else { ", " };
            let env_name = format!("{prefix}_KEY_SLOT_{}", idx + 1);
            let _ = write!(
                slot_map,
                "{sep}[{}] = {}",
                lua_string(id),
                lua_string(&env_name)
            );
        }
        slot_map.push('}');
        let auth_header = slots
            .auth_header
            .as_deref()
            .map_or("nil".to_owned(), lua_string);
        let _ = write!(
            out,
            "[{}] = {{cloud = {}, disabled = {}, no_retry = {}, direct_env = {}, default_env = {default_env}, \
             slots = {slot_map}, auth_header = {auth_header}, auth_prefix = {}}}, ",
            lua_string(&upstream.provider),
            slots.cloud,
            slots.disabled,
            slots.no_retry,
            lua_string(&slots.direct_env),
            lua_string(&slots.auth_prefix),
        );
    }
    out.push('}');
    out
}

fn lua_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_ascii_control() => {
                let _ = write!(out, "\\{:03}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    const BASE: &str = r#"lua: |
  local expected = "__GM_NODE_SECRET__"
  local slot_config = __GM_SLOT_CONFIG__
routes:
  - name: first
  - gm:upstream-routes
  - name: catch-all
clusters:
  - gm:upstream-clusters
"#;

    const DIRECT: &str = r#"slots:
  direct_env: ACME_API_KEY
  auth_header: authorization
  auth_prefix: "Bearer "
routes:
  - name: acme
    request_headers_to_add:
      - value: "2023-06-01"
    request_headers_to_remove:
      - x-api-key
      - x-gm-provider
clusters:
  - name: acme
    host: __GM_ACME_HOST__
"#;

    struct Fixture {
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new(base: &str, upstreams: &[(&str, &str)]) -> Self {
            let dir = tempfile::tempdir().expect("temp dir");
            std::fs::create_dir(dir.path().join("upstreams")).expect("upstreams dir");
            std::fs::write(dir.path().join("base.yaml"), base).expect("base");
            for (name, body) in upstreams {
                std::fs::write(dir.path().join("upstreams").join(name), body).expect("upstream");
            }
            Self { dir }
        }

        fn render(&self, selections: &[(&str, &str)], vars: &[(&str, &str)]) -> Result<String> {
            let selections = selections
                .iter()
                .map(|(provider, variant)| ((*provider).to_owned(), (*variant).to_owned()))
                .collect();
            let vars: BTreeMap<String, String> = vars
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect();
            render(self.dir.path(), &selections, &|name| {
                vars.get(name).cloned()
            })
        }
    }

    const VARS: &[(&str, &str)] = &[
        ("GM_NODE_SECRET", "secret-0001"),
        ("GM_ACME_HOST", "api.acme.test"),
    ];

    fn parsed(rendered: &str) -> serde_json::Value {
        serde_json::from_str(rendered).expect("rendered output is JSON")
    }

    /// The rendered `slot_config`, with the Lua state that owns it.
    fn lua_config(rendered: &str) -> (mlua::Lua, mlua::Table) {
        let lua = mlua::Lua::new();
        let source = parsed(rendered)["lua"].as_str().expect("lua").to_owned();
        let config = lua_slot_config(&lua, &source);
        (lua, config)
    }

    fn lua_slot_config(lua: &mlua::Lua, source: &str) -> mlua::Table {
        lua.load(format!("{source}\nreturn slot_config"))
            .eval()
            .expect("rendered Lua runs")
    }

    #[test]
    fn splices_upstream_routes_between_base_routes_and_adds_internal_strip() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let out = parsed(&fixture.render(&[], VARS).expect("render"));

        let names: Vec<&str> = out["routes"]
            .as_array()
            .expect("routes")
            .iter()
            .map(|route| route["name"].as_str().expect("name"))
            .collect();
        assert_eq!(names, ["first", "acme", "catch-all"]);
        let removed = &out["routes"][1]["request_headers_to_remove"];
        let expected: Vec<&str> = ["x-api-key", "x-gm-provider"]
            .into_iter()
            .chain(
                GM_INTERNAL_HEADERS
                    .into_iter()
                    .filter(|h| *h != "x-gm-provider"),
            )
            .collect();
        assert_eq!(*removed, serde_json::json!(expected));
        assert_eq!(out["clusters"][0]["host"], "api.acme.test");
    }

    #[test]
    fn session_id_survives_only_the_kubetee_chat_route() {
        let fixture = Fixture::new(
            include_str!("../../image/envoy/base.yaml"),
            &[
                (
                    "kubetee.yaml",
                    include_str!("../../image/envoy/upstreams/kubetee.yaml"),
                ),
                (
                    "openai.direct.yaml",
                    include_str!("../../image/envoy/upstreams/openai.direct.yaml"),
                ),
            ],
        );
        let out = parsed(
            &fixture
                .render(
                    &[("openai", "direct")],
                    &[("GM_NODE_SECRET", "secret-0001")],
                )
                .expect("render"),
        );
        let routes = out
            .pointer(concat!(
                "/static_resources/listeners/0/filter_chains/0/filters/0/typed_config/",
                "route_config/virtual_hosts/0/routes",
            ))
            .and_then(serde_json::Value::as_array)
            .expect("rendered routes");
        let route = |provider: &str, path: &str| {
            routes
                .iter()
                .find(|route| {
                    let matched = &route["match"];
                    (matched["path"] == path || matched["prefix"] == path)
                        && matched["headers"].as_array().is_some_and(|headers| {
                            headers.iter().any(|header| {
                                header["name"] == "x-gm-provider"
                                    && header["string_match"]["exact"] == provider
                            })
                        })
                })
                .expect("provider route exists")
        };
        let removes_session = |route: &serde_json::Value| {
            route["request_headers_to_remove"]
                .as_array()
                .expect("removed headers")
                .iter()
                .any(|header| header == "x-gm-session-id")
        };

        assert!(!removes_session(route("kubetee", "/v1/chat/completions")));
        assert!(removes_session(route("kubetee", "/v1/models")));
        assert!(removes_session(route("kubetee", "/v1/images/generations")));
        assert!(removes_session(route("kubetee", "/v1/videos")));
        assert!(removes_session(route("kubetee", "/v1/videos/")));
        assert!(removes_session(route("openai", "/")));
    }

    fn mock_envoy_headers(lua: &mlua::Lua, values: &[(&str, &str)]) -> mlua::Table {
        let headers = lua.create_table().expect("headers");
        for (name, value) in values {
            headers.set(*name, *value).expect("header");
        }
        let methods = lua.create_table().expect("header methods");
        methods
            .set(
                "get",
                lua.create_function(|_, (headers, name): (mlua::Table, String)| {
                    headers.get::<Option<String>>(name)
                })
                .expect("get method"),
            )
            .expect("get method");
        methods
            .set(
                "remove",
                lua.create_function(|_, (headers, name): (mlua::Table, String)| {
                    headers.raw_set(name, mlua::Value::Nil)
                })
                .expect("remove method"),
            )
            .expect("remove method");
        let metatable = lua.create_table().expect("header metatable");
        metatable.set("__index", methods).expect("header index");
        headers
            .set_metatable(Some(metatable))
            .expect("header metatable");
        headers
    }

    fn mock_envoy_handle(lua: &mlua::Lua, headers: mlua::Table) -> mlua::Table {
        let metadata = lua.create_table().expect("metadata");
        metadata
            .set(
                "set",
                lua.create_function(
                    |_,
                     (_metadata, _namespace, _key, _value): (
                        mlua::Table,
                        String,
                        String,
                        mlua::Value,
                    )| Ok(()),
                )
                .expect("metadata set"),
            )
            .expect("metadata set");
        let stream_info = lua.create_table().expect("stream info");
        stream_info
            .set(
                "dynamicMetadata",
                lua.create_function(move |_, _stream_info: mlua::Table| Ok(metadata.clone()))
                    .expect("dynamic metadata"),
            )
            .expect("dynamic metadata");
        let handle = lua.create_table().expect("handle");
        handle
            .set(
                "headers",
                lua.create_function(move |_, _handle: mlua::Table| Ok(headers.clone()))
                    .expect("headers method"),
            )
            .expect("headers method");
        handle
            .set(
                "streamInfo",
                lua.create_function(move |_, _handle: mlua::Table| Ok(stream_info.clone()))
                    .expect("stream info method"),
            )
            .expect("stream info method");
        handle
            .set(
                "respond",
                lua.create_function(
                    |_, (_handle, _headers, body): (mlua::Table, mlua::Table, String)| {
                        Err::<(), _>(mlua::Error::RuntimeError(format!(
                            "unexpected Envoy local reply: {body}"
                        )))
                    },
                )
                .expect("respond method"),
            )
            .expect("respond method");
        handle
    }

    #[test]
    fn lua_keeps_the_session_id_for_kubetee_and_strips_it_for_openai() {
        let fixture = Fixture::new(
            include_str!("../../image/envoy/base.yaml"),
            &[("kubetee.yaml", "routes: []\nclusters: []\n")],
        );
        let out = parsed(
            &fixture
                .render(&[], &[("GM_NODE_SECRET", "secret-0001")])
                .expect("render"),
        );
        let source = out
            .pointer(concat!(
                "/static_resources/listeners/0/filter_chains/0/filters/0/typed_config/",
                "http_filters/0/typed_config/default_source_code/inline_string",
            ))
            .and_then(serde_json::Value::as_str)
            .expect("Lua source");
        let lua = mlua::Lua::new();
        lua.load(source).exec().expect("rendered Lua runs");
        let on_request: mlua::Function =
            lua.globals().get("envoy_on_request").expect("request hook");
        let session_id = "0123456789abcdef".repeat(4);

        for (provider, selector, want_session) in [
            ("kubetee", Some("z-ai/glm-5.2"), true),
            ("openai", None, false),
        ] {
            let mut values = vec![
                (":method", "POST"),
                (":path", "/v1/chat/completions"),
                ("x-gm-provider", provider),
                ("x-gm-node-key", "secret-0001"),
                ("x-gm-session-id", session_id.as_str()),
            ];
            if let Some(selector) = selector {
                values.push(("x-gm-upstream-model", selector));
            }
            let headers = mock_envoy_headers(&lua, &values);
            on_request
                .call::<()>(mock_envoy_handle(&lua, headers.clone()))
                .expect("request hook runs");
            assert_eq!(
                headers
                    .get::<Option<String>>("x-gm-session-id")
                    .expect("session header")
                    .as_deref(),
                want_session.then_some(session_id.as_str()),
                "provider {provider}"
            );
        }
    }

    #[test]
    fn base_routes_do_not_get_the_internal_strip() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let out = parsed(&fixture.render(&[], VARS).expect("render"));
        assert!(out["routes"][0].get("request_headers_to_remove").is_none());
    }

    #[test]
    fn date_shaped_strings_stay_strings() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let rendered = fixture.render(&[], VARS).expect("render");
        assert!(rendered.contains(r#""value": "2023-06-01""#), "{rendered}");
    }

    #[test]
    fn unset_token_names_the_file_and_variable() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let err = fixture
            .render(&[], &[("GM_NODE_SECRET", "s")])
            .expect_err("GM_ACME_HOST is unset");
        let message = format!("{err:#}");
        assert!(message.contains("acme.yaml"), "{message}");
        assert!(message.contains("GM_ACME_HOST is not set"), "{message}");
    }

    #[test]
    fn empty_value_is_allowed() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let out = fixture
            .render(&[], &[("GM_NODE_SECRET", ""), ("GM_ACME_HOST", "h")])
            .expect("render");
        assert!(parsed(&out)["lua"]
            .as_str()
            .expect("lua")
            .contains(r#"local expected = """#));
    }

    #[test]
    fn inserted_values_are_never_rescanned() {
        // Calibration: a rescanning substitute() expands the secret into the
        // Lua table and this fails.
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let out = fixture
            .render(
                &[],
                &[
                    ("GM_NODE_SECRET", "__GM_SLOT_CONFIG__"),
                    ("GM_ACME_HOST", "h"),
                ],
            )
            .expect("render");
        assert!(parsed(&out)["lua"]
            .as_str()
            .expect("lua")
            .contains(r#"local expected = "__GM_SLOT_CONFIG__""#));
    }

    #[test]
    fn lowercase_double_underscore_text_is_left_alone() {
        let fixture = Fixture::new(
            "lua: \"__GM_x__ __GM_\"\nroutes: [gm:upstream-routes]\nclusters: [gm:upstream-clusters]\n",
            &[],
        );
        let out = parsed(&fixture.render(&[], &[]).expect("render"));
        assert_eq!(out["lua"], "__GM_x__ __GM_");
    }

    #[test]
    fn slot_config_maps_each_exported_slot_to_its_env_var() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let mut vars = VARS.to_vec();
        vars.push(("GM_ACME_SLOT_IDS", "AAAA;BBBB"));
        let (_lua, config) = lua_config(&fixture.render(&[], &vars).expect("render"));
        let acme: mlua::Table = config.get("acme").expect("acme entry");
        let slots: mlua::Table = acme.get("slots").expect("slots");
        assert_eq!(
            slots.get::<String>("AAAA").expect("A"),
            "GM_ACME_KEY_SLOT_1"
        );
        assert_eq!(
            slots.get::<String>("BBBB").expect("B"),
            "GM_ACME_KEY_SLOT_2"
        );
        assert_eq!(
            acme.get::<String>("default_env").expect("default"),
            "GM_ACME_KEY_SLOT_1"
        );
        assert_eq!(
            acme.get::<String>("direct_env").expect("direct"),
            "ACME_API_KEY"
        );
        assert_eq!(
            acme.get::<String>("auth_header").expect("header"),
            "authorization"
        );
        assert_eq!(
            acme.get::<String>("auth_prefix").expect("prefix"),
            "Bearer "
        );
        assert!(!acme.get::<bool>("cloud").expect("cloud"));
        assert!(!acme.get::<bool>("no_retry").expect("no_retry"));
    }

    #[test]
    fn slot_config_without_exported_slots_falls_back_to_direct_env() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let (_lua, config) = lua_config(&fixture.render(&[], VARS).expect("render"));
        let acme: mlua::Table = config.get("acme").expect("acme entry");
        assert!(acme
            .get::<Option<String>>("default_env")
            .expect("default")
            .is_none());
        assert_eq!(
            acme.get::<mlua::Table>("slots").expect("slots").raw_len(),
            0
        );
    }

    #[test]
    fn bedrock_mantle_route_is_exact_loopback_and_single_attempt() {
        const BEDROCK_BASE: &str = include_str!("../../image/envoy/base.yaml");
        const BEDROCK: &str = include_str!("../../image/envoy/upstreams/anthropic.bedrock.yaml");
        let fixture = Fixture::new(BEDROCK_BASE, &[("anthropic.bedrock.yaml", BEDROCK)]);
        let out = parsed(
            &fixture
                .render(&[("anthropic", "bedrock")], VARS)
                .expect("render Bedrock route"),
        );

        let route = out
            .pointer(
                "/static_resources/listeners/0/filter_chains/0/filters/0/typed_config/route_config/virtual_hosts/0/routes",
            )
            .and_then(serde_json::Value::as_array)
            .expect("routes")
            .iter()
            .find(|route| route["match"]["path"] == "/v1/messages")
            .expect("Bedrock route");
        assert_eq!(route["match"]["path"], "/v1/messages");
        let has_action_retry_policy = |candidate: &serde_json::Value| {
            candidate
                .pointer("/route/retry_policy")
                .is_some_and(|policy| !policy.is_null())
        };
        assert!(!has_action_retry_policy(route));
        let policy_bearing_fixture = serde_json::json!({
            "retry_policy": null,
            "route": {"retry_policy": {"retry_on": "5xx", "num_retries": 1}}
        });
        assert!(has_action_retry_policy(&policy_bearing_fixture));
        assert!(route["request_headers_to_remove"]
            .as_array()
            .expect("removed headers")
            .iter()
            .any(|header| header == "x-envoy-retry-on"));
        let cluster = out
            .pointer("/static_resources/clusters")
            .and_then(serde_json::Value::as_array)
            .expect("clusters")
            .iter()
            .find(|cluster| cluster["name"] == "bedrock_mantle_adapter")
            .expect("loopback adapter cluster");
        assert_eq!(
            cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]
                ["socket_address"]["address"],
            "127.0.0.1"
        );
        assert_eq!(
            cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]
                ["socket_address"]["port_value"],
            8085
        );

        let source = out
            .pointer(
                "/static_resources/listeners/0/filter_chains/0/filters/0/typed_config/http_filters/0/typed_config/default_source_code/inline_string",
            )
            .and_then(serde_json::Value::as_str)
            .expect("Lua source");
        let lua = mlua::Lua::new();
        let config = lua_slot_config(&lua, source);
        let anthropic: mlua::Table = config.get("anthropic").expect("Anthropic slot config");
        assert!(anthropic.get::<bool>("no_retry").expect("no_retry"));
    }

    #[test]
    fn slot_ids_are_escaped_as_lua_strings() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT)]);
        let mut vars = VARS.to_vec();
        vars.push(("GM_ACME_SLOT_IDS", "a\"b\\c\nd"));
        let (_lua, config) = lua_config(&fixture.render(&[], &vars).expect("render"));
        let acme: mlua::Table = config.get("acme").expect("acme entry");
        let slots: mlua::Table = acme.get("slots").expect("slots");
        assert_eq!(
            slots.get::<String>("a\"b\\c\nd").expect("escaped id"),
            "GM_ACME_KEY_SLOT_1"
        );
    }

    #[test]
    fn upstream_without_slots_has_no_slot_config_entry() {
        let fixture = Fixture::new(BASE, &[("bench.yaml", "routes: [{name: bench}]\n")]);
        let (_lua, config) = lua_config(&fixture.render(&[], VARS).expect("render"));
        assert!(config
            .get::<Option<mlua::Table>>("bench")
            .expect("lookup")
            .is_none());
    }

    const CLOUD: &str = "slots: {direct_env: ACME_API_KEY, cloud: true}\nroutes: [{name: cloud}]\n";

    #[test]
    fn selection_picks_one_variant_file() {
        let fixture = Fixture::new(
            BASE,
            &[("acme.direct.yaml", DIRECT), ("acme.cloud.yaml", CLOUD)],
        );
        let out = parsed(&fixture.render(&[("acme", "cloud")], VARS).expect("render"));
        assert_eq!(out["routes"][1]["name"], "cloud");
        assert_eq!(out["routes"].as_array().expect("routes").len(), 3);
        let (_lua, config) =
            lua_config(&fixture.render(&[("acme", "cloud")], VARS).expect("render"));
        let acme: mlua::Table = config.get("acme").expect("acme entry");
        assert!(acme.get::<bool>("cloud").expect("cloud"));
    }

    #[test]
    fn variant_provider_without_selection_is_an_error() {
        let fixture = Fixture::new(
            BASE,
            &[("acme.direct.yaml", DIRECT), ("acme.cloud.yaml", CLOUD)],
        );
        let err = fixture.render(&[], VARS).expect_err("no selection");
        assert!(
            format!("{err}").contains("--select acme=<variant>"),
            "{err}"
        );
    }

    #[test]
    fn selection_without_a_matching_file_is_an_error() {
        let fixture = Fixture::new(BASE, &[("acme.direct.yaml", DIRECT)]);
        let err = fixture
            .render(&[("acme", "azure")], VARS)
            .expect_err("no file");
        assert!(format!("{err}").contains("acme.azure.yaml"), "{err}");
    }

    #[test]
    fn plain_and_variant_file_for_one_provider_is_an_error() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", DIRECT), ("acme.cloud.yaml", CLOUD)]);
        let err = fixture
            .render(&[("acme", "cloud")], VARS)
            .expect_err("duplicate");
        assert!(
            format!("{err}").contains("more than one upstream file"),
            "{err}"
        );
    }

    #[test]
    fn direct_slots_without_auth_header_are_rejected() {
        let fixture = Fixture::new(
            BASE,
            &[("acme.yaml", "slots: {direct_env: ACME_API_KEY}\n")],
        );
        let err = fixture.render(&[], VARS).expect_err("no auth header");
        assert!(format!("{err}").contains("auth_header"), "{err}");
    }

    #[test]
    fn unknown_upstream_field_is_rejected() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", "route: []\n")]);
        let err = fixture.render(&[], VARS).expect_err("typo");
        assert!(
            format!("{err:#}").contains("unknown field `route`"),
            "{err:#}"
        );
    }

    #[test]
    fn missing_or_repeated_marker_is_an_error() {
        let fixture = Fixture::new("routes: []\nclusters: [gm:upstream-clusters]\n", &[]);
        let err = fixture.render(&[], &[]).expect_err("missing marker");
        assert!(format!("{err}").contains("found 0"), "{err}");

        let fixture = Fixture::new(
            "routes: [gm:upstream-routes, gm:upstream-routes]\nclusters: [gm:upstream-clusters]\n",
            &[],
        );
        let err = fixture.render(&[], &[]).expect_err("repeated marker");
        assert!(format!("{err}").contains("found 2"), "{err}");
    }

    #[test]
    fn malformed_yaml_error_names_the_file_and_location() {
        let fixture = Fixture::new(BASE, &[("acme.yaml", "routes: [\n")]);
        let err = fixture.render(&[], VARS).expect_err("malformed YAML");
        let message = format!("{err:#}");
        assert!(
            message.contains("parse") && message.contains("acme.yaml"),
            "{message}"
        );
        assert!(
            message.contains("line") || message.contains("column"),
            "{message}"
        );
    }

    #[test]
    fn yaml_anchors_and_string_tags_preserve_values_without_expanding_merge_keys() {
        let fixture = Fixture::new(
            BASE,
            &[(
                "acme.yaml",
                "routes: [{name: &name !!str 2023-06-01}, {name: *name}, {<<: {name: merged}}]\n",
            )],
        );
        let value = parsed(&fixture.render(&[], VARS).expect("render"));
        assert_eq!(value["routes"][1]["name"], "2023-06-01");
        assert_eq!(value["routes"][2]["name"], "2023-06-01");
        assert_eq!(value["routes"][3]["<<"]["name"], "merged");
        assert!(value["routes"][3].get("name").is_none());
    }

    #[test]
    fn yaml_multiple_documents_are_rejected_by_single_document_parser() {
        for (base, upstream) in [
            (format!("{BASE}---\nother: document\n"), "routes: []"),
            (BASE.to_owned(), "routes: []\n---\nclusters: []\n"),
        ] {
            let fixture = Fixture::new(&base, &[("acme.yaml", upstream)]);
            fixture.render(&[], VARS).expect_err("multiple documents");
        }
    }

    #[test]
    fn yaml_boolean_like_strings_keep_yaml12_types() {
        let fields =
            "values: [on, off, yes, no, ON, OFF, YES, NO, true, false, True, False, TRUE, FALSE]";
        let fixture = Fixture::new(
            &format!("{BASE}{fields}\n"),
            &[("acme.yaml", &format!("routes: [{{{fields}}}]\n"))],
        );
        let value = parsed(&fixture.render(&[], VARS).expect("render"));
        let expected = serde_json::json!([
            "on", "off", "yes", "no", "ON", "OFF", "YES", "NO", true, false, true, false, true,
            false
        ]);
        assert_eq!(value["values"], expected);
        assert_eq!(value["routes"][1]["values"], expected);
    }

    #[test]
    fn invalid_upstream_schema_is_rejected() {
        // Calibration: serde-saphyr's typed deserializer accepts null lists
        // and quoted booleans, unlike the old renderer's schema checks.
        for yaml in [
            "null\n",
            "routes: null\n",
            "clusters: ~\n",
            "slots: {direct_env: KEY, cloud: on}\n",
            "slots: {direct_env: KEY, cloud: \"true\"}\n",
            "slots: {direct_env: KEY, disabled: \"true\"}\n",
            "slots: {direct_env: KEY, cloud: true, typo: 1}\n",
            "<<: {routes: []}\n",
        ] {
            let fixture = Fixture::new(BASE, &[("acme.yaml", yaml)]);
            let err = fixture.render(&[], VARS).expect_err(yaml);
            assert!(format!("{err:#}").contains("acme.yaml"), "{err:#}");
        }
    }

    #[test]
    fn positional_upstream_fields_are_rejected() {
        // Calibration: serde_json can deserialize this array as UpstreamFile,
        // bypassing the YAML schema's requirement for named fields.
        let fixture = Fixture::new(BASE, &[("acme.yaml", "[null, [], []]\n")]);
        let err = fixture.render(&[], VARS).expect_err("upstream mapping");
        let message = format!("{err:#}");
        assert!(message.contains("acme.yaml"), "{message}");
        assert!(message.contains("mapping"), "{message}");
    }

    #[test]
    fn positional_slot_fields_are_rejected() {
        // These arrays have every Slots field and would otherwise be accepted.
        for yaml in [
            "slots: [KEY, false, false, authorization, \"Bearer \"]\n",
            "slots: [KEY, true, false, null, \"\"]\n",
        ] {
            let fixture = Fixture::new(BASE, &[("acme.yaml", yaml)]);
            let err = fixture.render(&[], VARS).expect_err("slots mapping");
            let message = format!("{err:#}");
            assert!(message.contains("acme.yaml"), "{message}");
            assert!(message.contains("slots"), "{message}");
            assert!(message.contains("mapping"), "{message}");
        }
    }

    #[test]
    fn duplicate_yaml_keys_are_rejected() {
        for (base, upstream) in [
            (format!("{BASE}duplicate: 1\nduplicate: 2\n"), "routes: []"),
            (BASE.to_owned(), "routes: [{name: first, name: second}]\n"),
        ] {
            let fixture = Fixture::new(&base, &[("acme.yaml", upstream)]);
            let err = fixture.render(&[], VARS).expect_err("duplicate key");
            assert!(format!("{err:#}").contains("duplicate"), "{err:#}");
        }
    }

    #[test]
    fn yaml_errors_do_not_include_substituted_source_snippets() {
        // Calibration: default snippet diagnostics print the preceding line's
        // substituted secret even though that line did not cause the error.
        for (base, upstream, filename) in [
            (
                "secret: __GM_NODE_SECRET__\nmalformed: ]\n",
                "routes: []\n",
                "base.yaml",
            ),
            (
                BASE,
                "routes: [{name: __GM_NODE_SECRET__}]\nmalformed: ]\n",
                "acme.yaml",
            ),
        ] {
            let fixture = Fixture::new(base, &[("acme.yaml", upstream)]);
            let err = fixture.render(&[], VARS).expect_err("malformed YAML");
            let message = format!("{err:#}");
            assert!(message.contains(filename), "{message}");
            assert!(message.contains("line 2"), "{message}");
            assert!(!message.contains("secret-0001"), "{message}");
        }
    }

    #[test]
    fn ambiguous_yaml_keys_are_rejected_instead_of_coerced_to_strings() {
        // Calibration: a JSON map requests String keys, so the parser accepts
        // non-finite keys and misses duplicate boolean keys without no_schema.
        for mapping in ["{true: a, True: b}", "{.nan: a}", "{.inf: a}"] {
            for (base, upstream) in [
                (format!("{BASE}extra: {mapping}\n"), "routes: []".to_owned()),
                (BASE.to_owned(), format!("routes: [{mapping}]\n")),
            ] {
                let fixture = Fixture::new(&base, &[("acme.yaml", &upstream)]);
                fixture.render(&[], VARS).expect_err(mapping);
            }
        }
    }
}
