//! Registry-backed KMS root selection for newly-created Phala CVMs.

use anyhow::{bail, Context, Result};
use reqwest::StatusCode;
use serde::Deserialize;

use crate::client::RegistryClient;

const KMS_ROOTS_PATH: &str = "/kms-roots";

#[derive(Debug, Deserialize)]
struct KmsRootsResponse {
    roots: Vec<KmsRoot>,
}

/// A non-expiring KMS root published by the registry.
#[derive(Debug, Clone, Deserialize)]
pub struct KmsRoot {
    ca_pubkey: Option<String>,
    kms_contract_id: Option<String>,
    // Only an explicit null authorizes a non-expiring root. An omitted field
    // is an invalid response, not permission to create a CVM with this root.
    #[serde(deserialize_with = "Option::deserialize")]
    allowed_until: Option<String>,
    is_default: bool,
}

impl KmsRoot {
    /// The contract ID Phala uses when creating a CVM with this root.
    ///
    /// # Errors
    /// Returns an error when the registry response has no contract ID.
    pub fn contract_id(&self) -> Result<&str> {
        self.kms_contract_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .context("GET /kms-roots returned a KMS root without a contract ID")
    }

    /// The certificate public key Phala measures as `key_provider_id`.
    ///
    /// # Errors
    /// Returns an error when the registry response has no public key.
    pub fn key_provider_id(&self) -> Result<&str> {
        self.ca_pubkey
            .as_deref()
            .filter(|key| !key.is_empty())
            .context("GET /kms-roots returned a KMS root without a CA public key")
    }
}

/// Fetch the registry's non-expiring KMS roots for this network.
///
/// # Errors
/// Returns an error if the endpoint is unavailable, its response is invalid,
/// or no complete non-expiring roots are listed.
pub async fn fetch_approved_kms_roots(client: &RegistryClient) -> Result<Vec<KmsRoot>> {
    let roots = fetch_kms_roots(client).await?;
    approved_kms_roots(roots)
}

fn approved_kms_roots(roots: Vec<KmsRoot>) -> Result<Vec<KmsRoot>> {
    let mut approved = Vec::new();
    for root in roots
        .into_iter()
        .filter(|root| root.allowed_until.is_none())
    {
        root.contract_id()?;
        root.key_provider_id()?;
        approved.push(root);
    }
    if approved.is_empty() {
        bail!("GET {KMS_ROOTS_PATH} lists no non-expiring KMS roots");
    }
    Ok(approved)
}

/// Resolve a KMS root for a new CVM from the registry's currently allowed
/// roots. An explicit override must name a non-expiring root.
///
/// # Errors
/// Returns an error if the endpoint is unavailable, its response is invalid,
/// no default exists, or the requested contract is not allowed.
pub async fn resolve_kms_root(client: &RegistryClient, requested: Option<&str>) -> Result<KmsRoot> {
    let roots = fetch_kms_roots(client).await?;
    select_kms_root(&roots, requested)
}

/// Resolve only the contract ID for callers that do not need the root key.
///
/// # Errors
/// As [`resolve_kms_root`].
pub async fn resolve_kms_contract_id(
    client: &RegistryClient,
    requested: Option<&str>,
) -> Result<String> {
    Ok(resolve_kms_root(client, requested)
        .await?
        .contract_id()?
        .to_owned())
}

async fn fetch_kms_roots(client: &RegistryClient) -> Result<Vec<KmsRoot>> {
    let response = client
        .get_public(KMS_ROOTS_PATH)
        .await
        .context("read KMS roots")?;
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

    Ok(response
        .json::<KmsRootsResponse>()
        .await
        .context("parse /kms-roots response")?
        .roots)
}

fn select_kms_root(roots: &[KmsRoot], requested: Option<&str>) -> Result<KmsRoot> {
    let allowed_ids = allowed_contract_ids(roots);

    if let Some(requested) = requested {
        if let Some(root) = roots.iter().find(|root| {
            root.allowed_until.is_none()
                && root.kms_contract_id.as_deref() == Some(requested)
                && root.ca_pubkey.as_deref().is_some_and(|key| !key.is_empty())
        }) {
            return Ok(root.clone());
        }
        bail!(
            "KMS contract ID '{requested}' is not a complete, non-expiring allowed root in GET {KMS_ROOTS_PATH}. Allowed contract IDs: {}",
            list_or_none(&allowed_ids)
        );
    }

    if let Some(default) = roots.iter().find(|root| root.is_default) {
        if default.allowed_until.is_none()
            && default
                .kms_contract_id
                .as_deref()
                .is_some_and(|id| !id.is_empty())
            && default
                .ca_pubkey
                .as_deref()
                .is_some_and(|key| !key.is_empty())
        {
            return Ok(default.clone());
        }
        bail!(
            "GET {KMS_ROOTS_PATH} marked a default KMS root without a contract ID, CA public key, or non-expiring authorization; ask the registry operator to correct the default root"
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
    let mut seen = std::collections::HashSet::new();
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

    use super::{
        approved_kms_roots, resolve_kms_contract_id, resolve_kms_root, select_kms_root, KmsRoot,
    };
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

    fn parsed_root(
        contract_id: Option<&str>,
        is_default: bool,
        allowed_until: Option<&str>,
    ) -> KmsRoot {
        serde_json::from_value(root(contract_id, is_default, allowed_until))
            .expect("KMS root fixture parses")
    }

    #[test]
    fn maps_the_default_root_public_key_to_key_provider_id() {
        let selected = select_kms_root(&[parsed_root(Some("selected-root"), true, None)], None)
            .expect("default root is selected");

        assert_eq!(
            selected.contract_id().expect("contract ID"),
            "selected-root"
        );
        assert_eq!(selected.key_provider_id().expect("CA public key"), "abcd");
    }

    async fn mount_roots(server: &MockServer, roots: Vec<Value>) {
        Mock::given(method("GET"))
            .and(path("/kms-roots"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"roots": roots})))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn chooses_the_default_contract_and_key_returned_by_the_registry() {
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

        let selected = resolve_kms_root(&client, None)
            .await
            .expect("registry default is selected");

        assert_eq!(
            selected.contract_id().expect("contract ID"),
            "registry-default"
        );
        assert_eq!(selected.key_provider_id().expect("CA public key"), "abcd");
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        assert!(
            !requests[0].headers.contains_key("authorization"),
            "the public KMS roots endpoint must not receive the miner JWT"
        );
    }

    #[test]
    fn lists_each_complete_non_expiring_root() {
        let roots = approved_kms_roots(vec![
            parsed_root(Some("first"), true, None),
            parsed_root(Some("expiring"), false, Some("2027-01-01T00:00:00Z")),
            parsed_root(Some("second"), false, None),
        ])
        .expect("non-expiring roots are returned");

        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].contract_id().expect("first contract"), "first");
        assert_eq!(roots[1].contract_id().expect("second contract"), "second");
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
            assert!(error.to_string().contains(requested));
        }
    }

    #[tokio::test]
    async fn missing_default_lists_available_contracts() {
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
            .expect_err("an explicit selection is required when no default is listed");
        let message = error.to_string();
        assert!(message.contains("--kms-contract-id"), "{message}");
        assert!(message.contains("allowed-one"), "{message}");
        assert!(!message.contains("expiring-root"), "{message}");
    }

    #[tokio::test]
    async fn missing_kms_roots_endpoint_returns_an_actionable_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/kms-roots"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let client = RegistryClient::new(config(&server));

        let error = resolve_kms_contract_id(&client, None)
            .await
            .expect_err("the missing endpoint returns setup guidance");
        let message = error.to_string();
        assert!(message.contains("404"), "{message}");
        assert!(message.contains("/kms-roots"), "{message}");
        assert!(message.contains("Ask the registry operator"), "{message}");
    }
}
