use std::collections::BTreeMap;

use serde_json::Value;

use crate::model_bindings;

pub(super) const PATH: &str = "/model-bindings/kubetee";
const MAX_MODELS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EndpointKind {
    ChatCompletions,
    ImagesGenerations,
}

struct EndpointDefinition {
    name: &'static str,
    path: &'static str,
    kind: EndpointKind,
}

const ENDPOINTS: [EndpointDefinition; 2] = [
    EndpointDefinition {
        name: "chat_completions",
        path: super::CHAT_COMPLETIONS,
        kind: EndpointKind::ChatCompletions,
    },
    EndpointDefinition {
        name: "images_generations",
        path: super::IMAGES_GENERATIONS,
        kind: EndpointKind::ImagesGenerations,
    },
];

impl EndpointKind {
    pub(super) fn for_path(path: &str) -> Option<Self> {
        ENDPOINTS
            .iter()
            .find(|endpoint| endpoint.path == path)
            .map(|endpoint| endpoint.kind)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct KubeteeModelBindings {
    pub(super) models: BTreeMap<String, EndpointKind>,
}

pub(super) fn parse_model_snapshot(
    bytes: &[u8],
    expected_network: &str,
) -> Result<KubeteeModelBindings, &'static str> {
    let envelope = model_bindings::parse_envelope(
        bytes,
        expected_network,
        &["schema_version", "network", "models"],
    )?;
    let rows = envelope
        .get("models")
        .and_then(Value::as_array)
        .filter(|rows| rows.len() <= MAX_MODELS)
        .ok_or("KubeTEE model binding response has an invalid model list")?;
    parse_rows(rows)
}

fn parse_rows(rows: &[Value]) -> Result<KubeteeModelBindings, &'static str> {
    let mut models = BTreeMap::new();
    let mut previous = None;
    for row in rows {
        let (model, endpoint) = parse_row(row)?;
        if previous.is_some_and(|value: &str| value >= model) {
            return Err("KubeTEE model bindings are not sorted or contain a duplicate");
        }
        previous = Some(model);
        models.insert(model.to_owned(), endpoint);
    }
    Ok(KubeteeModelBindings { models })
}

fn parse_row(row: &Value) -> Result<(&str, EndpointKind), &'static str> {
    let row = row
        .as_object()
        .filter(|row| model_bindings::object_has_exact_keys(row, &["upstream_model", "endpoint"]))
        .ok_or("KubeTEE model binding has an invalid shape")?;
    let model = row
        .get("upstream_model")
        .and_then(Value::as_str)
        .filter(|model| model_bindings::valid_model_id(model, b"/"))
        .ok_or("KubeTEE model binding has an invalid upstream model")?;
    let endpoint = row
        .get("endpoint")
        .and_then(Value::as_str)
        .and_then(parse_endpoint)
        .ok_or("KubeTEE model binding has an invalid endpoint")?;
    Ok((model, endpoint))
}

fn parse_endpoint(value: &str) -> Option<EndpointKind> {
    ENDPOINTS
        .iter()
        .find(|endpoint| endpoint.name == value)
        .map(|endpoint| endpoint.kind)
}
