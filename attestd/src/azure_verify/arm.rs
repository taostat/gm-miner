use anyhow::{bail, Context, Result};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use super::config::AzureVerifyConfig;
use super::endpoint::AzureEndpoint;

const MANAGEMENT_SCOPE: &str = "https://management.azure.com/.default";
/// Newest stable `Microsoft.CognitiveServices` version. Needed at >= 2025-06-01
/// for `accounts/projects`, which the Foundry capture-surface sweep enumerates.
const ARM_API_VERSION: &str = "2026-05-01";
/// `Microsoft.Insights/diagnosticSettings` has only ever shipped as this
/// preview version; there is no stable one.
const DIAGNOSTIC_SETTINGS_API_VERSION: &str = "2021-05-01-preview";

#[derive(Debug, Deserialize)]
pub(crate) struct TokenResponse {
    pub(crate) access_token: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ArmAccount {
    pub(crate) id: String,
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) properties: ArmAccountProperties,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArmAccountProperties {
    pub(crate) custom_sub_domain_name: Option<String>,
    pub(crate) endpoint: Option<String>,
    pub(crate) rai_monitor_config: Option<Value>,
    pub(crate) user_owned_storage: Option<Value>,
}

/// `value` is deliberately NOT `#[serde(default)]`: an ARM list response whose
/// `value` key is missing or renamed must be a hard parse failure, not an empty
/// list that silently passes every capture check. Azure returns `{"value": []}`
/// for an empty collection, so this only fires on a shape we do not model.
#[derive(Debug, Deserialize)]
pub(crate) struct DiagnosticSettingsList {
    pub(crate) value: Vec<DiagnosticSetting>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DiagnosticSetting {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) properties: DiagnosticProperties,
}

/// Only `logs` is modelled: the check is that the settings list is EMPTY, so
/// the destination fields never need reading — which also means a destination
/// field Azure adds later cannot quietly widen what passes.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticProperties {
    #[serde(default)]
    pub(crate) logs: Vec<DiagnosticLog>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticLog {
    pub(crate) category: Option<String>,
    pub(crate) category_group: Option<String>,
    #[serde(default)]
    pub(crate) enabled: bool,
}

/// A `Microsoft.CognitiveServices` child resource the Foundry sweep only needs
/// to *count* and name: projects, connections, capability hosts. Any of them
/// existing on an inference-only account is a capture surface we reject, so the
/// verifier never needs to interpret their bodies.
#[derive(Debug, Deserialize)]
pub(crate) struct ArmChildResource {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) properties: ArmChildProperties,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArmChildProperties {
    /// Present on connections (`AppInsights`, `AzureBlob`, …).
    pub(crate) category: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ArmChildList {
    pub(crate) value: Vec<ArmChildResource>,
    #[serde(rename = "nextLink")]
    pub(crate) next_link: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ArmDeploymentList {
    pub(crate) value: Vec<ArmDeployment>,
    #[serde(rename = "nextLink")]
    pub(crate) next_link: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ArmDeployment {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) properties: ArmDeploymentProperties,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArmDeploymentProperties {
    pub(crate) rai_policy_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ArmRaiPolicy {
    #[serde(default)]
    pub(crate) properties: ArmRaiPolicyProperties,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ArmRaiPolicyProperties {
    pub(crate) mode: Option<String>,
}

#[derive(Debug, Error)]
#[error("{label} request failed ({status}): {body}")]
pub(crate) struct AzureHttpStatusError {
    pub(crate) label: &'static str,
    pub(crate) status: StatusCode,
    pub(crate) body: String,
}

pub(crate) async fn fetch_entra_token(
    client: &Client,
    config: &AzureVerifyConfig,
) -> Result<String> {
    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        encode_path_segment(&config.tenant_id)
    );
    let response = client
        .post(&url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("scope", MANAGEMENT_SCOPE),
        ])
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(AzureHttpStatusError {
            label: "Entra token",
            status,
            body,
        }
        .into());
    }
    let token: TokenResponse = response
        .json()
        .await
        .context("parse Entra token response")?;
    if token.access_token.trim().is_empty() {
        bail!("Entra token response had an empty access_token");
    }
    Ok(token.access_token)
}

pub(crate) async fn fetch_arm_account(
    client: &Client,
    config: &AzureVerifyConfig,
    endpoint: &AzureEndpoint,
    token: &str,
) -> Result<ArmAccount> {
    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.CognitiveServices/accounts/{}?api-version={ARM_API_VERSION}",
        encode_path_segment(&config.subscription_id),
        encode_path_segment(&config.resource_group),
        encode_path_segment(&endpoint.account_name),
    );
    get_json(client, &url, token, "Azure Cognitive Services account").await
}

pub(crate) async fn fetch_diagnostic_settings(
    client: &Client,
    resource_id: &str,
    token: &str,
) -> Result<DiagnosticSettingsList> {
    let resource_path = resource_id
        .strip_prefix('/')
        .with_context(|| format!("ARM resource id must start with '/': {resource_id}"))?;
    let url = format!(
        "https://management.azure.com/{resource_path}/providers/Microsoft.Insights/diagnosticSettings?api-version={DIAGNOSTIC_SETTINGS_API_VERSION}",
    );
    get_json(client, &url, token, "Azure diagnostic settings").await
}

pub(crate) async fn fetch_arm_deployments(
    client: &Client,
    config: &AzureVerifyConfig,
    endpoint: &AzureEndpoint,
    token: &str,
) -> Result<ArmDeploymentList> {
    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.CognitiveServices/accounts/{}/deployments?api-version={ARM_API_VERSION}",
        encode_path_segment(&config.subscription_id),
        encode_path_segment(&config.resource_group),
        encode_path_segment(&endpoint.account_name),
    );
    Ok(ArmDeploymentList {
        value: fetch_paged::<ArmDeploymentList>(client, url, token, "Azure OpenAI deployments")
            .await?,
        next_link: None,
    })
}

/// An ARM list response: a page of items plus an optional `nextLink`.
pub(crate) trait ArmPage: for<'de> Deserialize<'de> {
    type Item;

    fn into_parts(self) -> (Vec<Self::Item>, Option<String>);
}

impl ArmPage for ArmDeploymentList {
    type Item = ArmDeployment;

    fn into_parts(self) -> (Vec<Self::Item>, Option<String>) {
        (self.value, self.next_link)
    }
}

impl ArmPage for ArmChildList {
    type Item = ArmChildResource;

    fn into_parts(self) -> (Vec<Self::Item>, Option<String>) {
        (self.value, self.next_link)
    }
}

/// Drain every page of an ARM list endpoint, following `nextLink`.
/// Upper bound on `nextLink` follows. A server that keeps handing back a link
/// would otherwise wedge the verifier: at boot it never returns, and in the
/// periodic loop it would stall every later target while envoy keeps serving.
/// Far above any real ARM collection on one account.
const MAX_ARM_PAGES: usize = 100;

async fn fetch_paged<P: ArmPage>(
    client: &Client,
    mut url: String,
    token: &str,
    label: &'static str,
) -> Result<Vec<P::Item>> {
    let mut items = Vec::new();
    for _ in 0..MAX_ARM_PAGES {
        let page: P = get_json(client, &url, token, label).await?;
        let (value, next_link) = page.into_parts();
        items.extend(value);
        let Some(next_link) = next_link else {
            return Ok(items);
        };
        if next_link.trim().is_empty() {
            bail!("{label} response had an empty nextLink");
        }
        url = next_link;
    }
    bail!("{label} paginated past {MAX_ARM_PAGES} pages; refusing to follow further")
}

/// Which `Microsoft.CognitiveServices` scope a child collection hangs off:
/// the account itself, or one of its Foundry projects.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ArmScope<'a> {
    Account,
    Project(&'a str),
}

impl ArmScope<'_> {
    /// How the scope is named in a verification failure the operator reads.
    pub(crate) fn label(self) -> String {
        match self {
            Self::Account => "account".to_owned(),
            Self::Project(project) => format!("project '{project}'"),
        }
    }
}

/// Enumerate a `Microsoft.CognitiveServices` child collection (`projects`,
/// `connections`, `capabilityHosts`) under the account or one of its projects,
/// following `nextLink` to the end.
pub(crate) async fn fetch_children(
    client: &Client,
    config: &AzureVerifyConfig,
    endpoint: &AzureEndpoint,
    scope: ArmScope<'_>,
    collection: &str,
    token: &str,
) -> Result<Vec<ArmChildResource>> {
    let project_segment = match scope {
        ArmScope::Account => String::new(),
        ArmScope::Project(project) => format!("/projects/{}", encode_path_segment(project)),
    };
    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.CognitiveServices/accounts/{}{project_segment}/{collection}?api-version={ARM_API_VERSION}",
        encode_path_segment(&config.subscription_id),
        encode_path_segment(&config.resource_group),
        encode_path_segment(&endpoint.account_name),
    );
    fetch_paged::<ArmChildList>(client, url, token, "Azure Foundry child resources").await
}

pub(crate) async fn fetch_arm_rai_policy(
    client: &Client,
    config: &AzureVerifyConfig,
    endpoint: &AzureEndpoint,
    policy_name: &str,
    token: &str,
) -> Result<ArmRaiPolicy> {
    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.CognitiveServices/accounts/{}/raiPolicies/{}?api-version={ARM_API_VERSION}",
        encode_path_segment(&config.subscription_id),
        encode_path_segment(&config.resource_group),
        encode_path_segment(&endpoint.account_name),
        encode_path_segment(policy_name),
    );
    get_json(client, &url, token, "Azure OpenAI RAI policy").await
}

pub(crate) async fn get_json<T: for<'de> Deserialize<'de>>(
    client: &Client,
    url: &str,
    token: &str,
    label: &'static str,
) -> Result<T> {
    let response = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(AzureHttpStatusError {
            label,
            status,
            body,
        }
        .into());
    }
    response
        .json()
        .await
        .with_context(|| format!("parse {label} response"))
}

pub(crate) fn encode_path_segment(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                encoded.push('%');
                encoded.push(char::from(HEX[usize::from(byte >> 4)]));
                encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }
    encoded
}
