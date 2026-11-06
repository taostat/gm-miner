//! Registry-backed KMS contract allowlist for newly-created Phala CVMs.

use std::collections::HashSet;

use anyhow::{bail, Context, Result};
use reqwest::StatusCode;
use serde::Deserialize;

use crate::client::RegistryClient;

const KMS_ROOTS_PATH: &str = "/kms-roots";

#[derive(Debug, Deserialize)]
struct KmsRootsResponse {
    roots: Vec<KmsRoot>,
}

#[derive(Debug, Deserialize)]
struct KmsRoot {
    kms_contract_id: Option<String>,
    // Only an explicit null authorizes a non-expiring root. An omitted field
    // is an invalid response, not permission to create a CVM with this root.
    #[serde(deserialize_with = "Option::deserialize")]
    allowed_until: Option<String>,
    is_default: bool,
}

/// Resolve the KMS contract for a new CVM from the registry's currently
/// allowed roots. An explicit override must name a non-expiring root.
///
/// # Errors
/// Returns an error if the endpoint is unavailable, its response is invalid,
/// no default exists, or the requested contract is not allowed.
pub async fn resolve_kms_contract_id(
    client: &RegistryClient,
    requested: Option<&str>,
) -> Result<String> {
    let response = client
        .get_public(KMS_ROOTS_PATH)
        .await
        .context("read KMS contract allowlist")?;
    let status = response.status();
    if status == StatusCode::NOT_FOUND {
        bail!(
            "GET {KMS_ROOTS_PATH} returned 404; this registry does not yet publish KMS roots. Ask the registry operator to configure the {KMS_ROOTS_PATH} endpoint before creating a CVM"
        );
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("GET {KMS_ROOTS_PATH} failed ({status}): {body}");
    }

    let roots = response
        .json::<KmsRootsResponse>()
        .await
        .context("parse /kms-roots response")?
        .roots;
    select_kms_contract_id(&roots, requested)
}

fn select_kms_contract_id(roots: &[KmsRoot], requested: Option<&str>) -> Result<String> {
    let allowed_ids = allowed_contract_ids(roots);

    if let Some(requested) = requested {
        if roots.iter().any(|root| {
            root.allowed_until.is_none() && root.kms_contract_id.as_deref() == Some(requested)
        }) {
            return Ok(requested.to_owned());
        }
        bail!(
            "KMS contract ID '{requested}' is not a non-expiring allowed root in GET {KMS_ROOTS_PATH}. Allowed contract IDs: {}",
            list_or_none(&allowed_ids)
        );
    }

    if let Some(default) = roots.iter().find(|root| root.is_default) {
        if default.allowed_until.is_none() {
            if let Some(contract_id) = default
                .kms_contract_id
                .as_deref()
                .filter(|id| !id.is_empty())
            {
                return Ok(contract_id.to_owned());
            }
        }
        bail!(
            "GET {KMS_ROOTS_PATH} marked a default KMS root without a non-expiring contract ID; ask the registry operator to correct the default root"
        );
    }

    if allowed_ids.is_empty() {
        bail!(
            "GET {KMS_ROOTS_PATH} has no default root and lists no non-expiring allowed KMS contract IDs. Pass --kms-contract-id after the registry operator allows a non-expiring contract, or ask them to configure a default root before creating a CVM"
        );
    }
    bail!(
        "GET {KMS_ROOTS_PATH} has no default KMS root; pass --kms-contract-id with one of the listed non-expiring allowed contract IDs: {}",
        allowed_ids.join(", ")
    );
}

fn allowed_contract_ids(roots: &[KmsRoot]) -> Vec<String> {
    let mut seen = HashSet::new();
    roots
        .iter()
        .filter(|root| root.allowed_until.is_none())
        .filter_map(|root| root.kms_contract_id.as_deref())
        .filter(|id| !id.is_empty())
        .filter(|id| seen.insert((*id).to_owned()))
        .map(str::to_owned)
        .collect()
}

fn list_or_none(ids: &[String]) -> String {
    if ids.is_empty() {
        "none".to_owned()
    } else {
        ids.join(", ")
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use std::collections::HashMap;

    use serde_json::{json, Value};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::resolve_kms_contract_id;
    use crate::{
        client::RegistryClient,
        config::{Config, NetworkEntry, TokenEntry},
    };

    fn config(server: &MockServer) -> Config {
        Config {
            active_network: Some("testnet".to_owned()),
            networks: HashMap::from([(
                "testnet".to_owned(),
                NetworkEntry {
                    api_url: Some(server.uri()),
                    tokens: Some(TokenEntry {
                        access_token: Some("test-token".to_owned()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        }
    }

    fn root(contract_id: Option<&str>, is_default: bool, allowed_until: Option<&str>) -> Value {
        json!({
            "ca_pubkey": "abcd",
            "kms_contract_id": contract_id,
            "label": "test root",
            "allowed_until": allowed_until,
            "is_default": is_default,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        })
    }

    async fn mount_roots(server: &MockServer, roots: Vec<Value>) {
        Mock::given(method("GET"))
            .and(path("/kms-roots"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"roots": roots})))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn chooses_the_default_contract_returned_by_the_registry() {
        let server = MockServer::start().await;
        mount_roots(
            &server,
            vec![
                root(Some("registry-default"), true, None),
                root(Some("other-allowed"), false, None),
            ],
        )
        .await;
        let client = RegistryClient::new(config(&server));

        let selected = resolve_kms_contract_id(&client, None)
            .await
            .expect("registry default is selected");

        assert_eq!(selected, "registry-default");
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        assert!(
            !requests[0].headers.contains_key("authorization"),
            "the public KMS roots endpoint must not receive the miner JWT"
        );
    }

    #[tokio::test]
    async fn accepts_an_explicit_non_expiring_allowed_contract() {
        let server = MockServer::start().await;
        mount_roots(
            &server,
            vec![
                root(Some("registry-default"), true, None),
                root(Some("other-allowed"), false, None),
            ],
        )
        .await;
        let client = RegistryClient::new(config(&server));

        let selected = resolve_kms_contract_id(&client, Some("other-allowed"))
            .await
            .expect("a listed non-expiring root is accepted");

        assert_eq!(selected, "other-allowed");
    }

    #[tokio::test]
    async fn missing_expiry_must_not_authorize_a_default_or_override() {
        let server = MockServer::start().await;
        let mut incomplete = root(Some("incomplete-root"), true, None);
        incomplete
            .as_object_mut()
            .expect("root fixture is an object")
            .remove("allowed_until");
        mount_roots(&server, vec![incomplete]).await;
        let client = RegistryClient::new(config(&server));

        for requested in [None, Some("incomplete-root")] {
            let result = resolve_kms_contract_id(&client, requested).await;
            assert!(
                result.is_err(),
                "an omitted expiry must not be treated as explicit null: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_unknown_and_expiring_contract_overrides() {
        let server = MockServer::start().await;
        mount_roots(
            &server,
            vec![
                root(Some("registry-default"), true, None),
                root(Some("expiring-root"), false, Some("2027-01-01T00:00:00Z")),
            ],
        )
        .await;
        let client = RegistryClient::new(config(&server));

        for requested in ["unknown-root", "expiring-root"] {
            let error = resolve_kms_contract_id(&client, Some(requested))
                .await
                .expect_err("unknown and expiring contracts are not accepted");
            let message = error.to_string();
            assert!(message.contains(requested), "{message}");
            assert!(message.contains("registry-default"), "{message}");
        }
    }

    #[tokio::test]
    async fn missing_default_lists_allowed_contracts_and_names_the_override_flag() {
        let server = MockServer::start().await;
        mount_roots(
            &server,
            vec![
                root(Some("allowed-one"), false, None),
                root(Some("expiring-root"), false, Some("2027-01-01T00:00:00Z")),
            ],
        )
        .await;
        let client = RegistryClient::new(config(&server));

        let error = resolve_kms_contract_id(&client, None)
            .await
            .expect_err("a default must be set when no override is supplied");
        let message = error.to_string();
        assert!(message.contains("--kms-contract-id"), "{message}");
        assert!(message.contains("allowed-one"), "{message}");
        assert!(!message.contains("expiring-root"), "{message}");
    }

    #[tokio::test]
    async fn missing_kms_roots_endpoint_has_a_specific_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/kms-roots"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let client = RegistryClient::new(config(&server));

        let error = resolve_kms_contract_id(&client, None)
            .await
            .expect_err("an older registry must not silently use a built-in KMS contract");
        let message = error.to_string();
        assert!(message.contains("404"), "{message}");
        assert!(message.contains("/kms-roots"), "{message}");
        assert!(
            message.contains("does not yet publish KMS roots"),
            "{message}"
        );
        assert!(message.contains("Ask the registry operator"), "{message}");
        assert!(
            !message.contains("update the registry deployment"),
            "the action must be directed to the registry operator: {message}"
        );
    }
}
