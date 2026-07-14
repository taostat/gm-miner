//! The ARM/Entra read surface the verification needs: a token, an account, its
//! diagnostic settings, its child collections, its deployments, its RAI policies.
//!
//! Every request is a read. Nothing in this crate mutates an operator's Azure
//! estate — the fixes are printed as `az` commands for the operator to run.

use anyhow::{anyhow, bail, Context, Result};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use crate::config::AzureVerifyConfig;
use crate::endpoint::AzureEndpoint;

const MANAGEMENT_SCOPE: &str = "https://management.azure.com/.default";
/// Newest stable `Microsoft.CognitiveServices` version. Needed at >= 2025-06-01
/// for `accounts/projects`, which the Foundry capture-surface sweep enumerates.
pub(crate) const ARM_API_VERSION: &str = "2026-05-01";
/// `Microsoft.Insights/diagnosticSettings` has only ever shipped as this
/// preview version; there is no stable one.
const DIAGNOSTIC_SETTINGS_API_VERSION: &str = "2021-05-01-preview";

/// The public ARM control plane. The verifier points here unless a test
/// substitutes a stub.
pub const MANAGEMENT_BASE_URL: &str = "https://management.azure.com";
/// The public Entra token endpoint host.
pub const LOGIN_BASE_URL: &str = "https://login.microsoftonline.com";

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

impl ArmChildResource {
    /// The child's own name, without the parent qualifier ARM prefixes it with.
    ///
    /// ARM returns a nested child's `name` qualified by its parent — a project
    /// of account `acct` comes back as `acct/proj`, not `proj`. Interpolating
    /// that straight into a URL builds `/accounts/acct/projects/acct/proj`,
    /// which addresses nothing; percent-encoding it builds `acct%2Fproj`, which
    /// addresses nothing either. The path segment is the last component.
    pub(crate) fn leaf_name(&self) -> &str {
        self.name.rsplit('/').next().unwrap_or(&self.name)
    }
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
    #[serde(default)]
    pub(crate) model: ArmDeploymentModel,
}

/// `format` is the publisher of the deployed model — `OpenAI`, `Anthropic`, …
/// (`Azure-Samples/claude` deploys Claude with `format: 'Anthropic'`). It is a
/// free-form string in the ARM schema, not an enum, so unknown values must be
/// treated as "might be governed by Azure's RAI filter" and checked.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArmDeploymentModel {
    pub(crate) format: Option<String>,
}

/// Deployments with this model format are served by Anthropic, not by Azure's
/// own inference stack, so Azure's RAI content filter is not in their request
/// path and its mode says nothing about whether they stream.
pub(crate) const ANTHROPIC_MODEL_FORMAT: &str = "Anthropic";

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

/// The ARM reader: one pooled HTTP client plus the control-plane hosts it talks
/// to. Production points at Azure; tests point at a stub (`with_endpoints`).
#[derive(Debug, Clone)]
pub struct AzureVerifier {
    pub(crate) client: Client,
    pub(crate) management_base: String,
    pub(crate) login_base: String,
}

impl AzureVerifier {
    /// A verifier against the real Azure control plane.
    ///
    /// One HTTP client, reused across targets and across every periodic cycle:
    /// rebuilding it per call would throw away the connection pool and re-read
    /// the system trust store on each verification.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be built.
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("build Azure verification HTTP client")?;
        Ok(Self::with_endpoints(
            client,
            MANAGEMENT_BASE_URL,
            LOGIN_BASE_URL,
        ))
    }

    /// The test seam: the same verification, against a stubbed ARM/Entra pair.
    /// Nothing but tests should pass anything other than the real Azure hosts.
    #[must_use]
    pub fn with_endpoints(
        client: Client,
        management_base: impl Into<String>,
        login_base: impl Into<String>,
    ) -> Self {
        Self {
            client,
            management_base: management_base.into(),
            login_base: login_base.into(),
        }
    }

    /// The `/subscriptions/…/accounts/<name>` prefix every account-scoped read
    /// hangs off.
    fn account_url(&self, config: &AzureVerifyConfig, endpoint: &AzureEndpoint) -> String {
        format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.CognitiveServices/accounts/{}",
            self.management_base,
            encode_path_segment(&config.subscription_id),
            encode_path_segment(&config.resource_group),
            encode_path_segment(&endpoint.account_name),
        )
    }

    pub(crate) async fn fetch_entra_token(&self, config: &AzureVerifyConfig) -> Result<String> {
        let url = format!(
            "{}/{}/oauth2/v2.0/token",
            self.login_base,
            encode_path_segment(&config.tenant_id)
        );
        let response = self
            .client
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
        &self,
        config: &AzureVerifyConfig,
        endpoint: &AzureEndpoint,
        token: &str,
    ) -> Result<ArmAccount> {
        let url = format!(
            "{}?api-version={ARM_API_VERSION}",
            self.account_url(config, endpoint)
        );
        self.get_json(&url, token, "Azure Cognitive Services account")
            .await
    }

    pub(crate) async fn fetch_diagnostic_settings(
        &self,
        resource_id: &str,
        token: &str,
    ) -> Result<DiagnosticSettingsList> {
        let resource_path = resource_id
            .strip_prefix('/')
            .with_context(|| format!("ARM resource id must start with '/': {resource_id}"))?;
        let url = format!(
            "{}/{resource_path}/providers/Microsoft.Insights/diagnosticSettings?api-version={DIAGNOSTIC_SETTINGS_API_VERSION}",
            self.management_base,
        );
        self.get_json(&url, token, "Azure diagnostic settings")
            .await
    }

    pub(crate) async fn fetch_arm_deployments(
        &self,
        config: &AzureVerifyConfig,
        endpoint: &AzureEndpoint,
        token: &str,
    ) -> PagedRead<ArmDeployment> {
        let url = format!(
            "{}/deployments?api-version={ARM_API_VERSION}",
            self.account_url(config, endpoint)
        );
        self.fetch_paged::<ArmDeploymentList>(url, token, "Azure OpenAI deployments")
            .await
    }

    /// Enumerate a `Microsoft.CognitiveServices` child collection (`projects`,
    /// `connections`, `capabilityHosts`) under the account or one of its
    /// projects, following `nextLink` to the end.
    pub(crate) async fn fetch_children(
        &self,
        config: &AzureVerifyConfig,
        endpoint: &AzureEndpoint,
        scope: ArmScope<'_>,
        collection: &str,
        token: &str,
    ) -> PagedRead<ArmChildResource> {
        let project_segment = match scope {
            ArmScope::Account => String::new(),
            ArmScope::Project(project) => format!("/projects/{}", encode_path_segment(project)),
        };
        let url = format!(
            "{}{project_segment}/{collection}?api-version={ARM_API_VERSION}",
            self.account_url(config, endpoint)
        );
        self.fetch_paged::<ArmChildList>(url, token, "Azure Foundry child resources")
            .await
    }

    pub(crate) async fn fetch_arm_rai_policy(
        &self,
        config: &AzureVerifyConfig,
        endpoint: &AzureEndpoint,
        policy_name: &str,
        token: &str,
    ) -> Result<ArmRaiPolicy> {
        let url = format!(
            "{}/raiPolicies/{}?api-version={ARM_API_VERSION}",
            self.account_url(config, endpoint),
            encode_path_segment(policy_name),
        );
        self.get_json(&url, token, "Azure OpenAI RAI policy").await
    }

    /// Drain every page, and NEVER throw away what was already read.
    ///
    /// A failure on page 2 does not un-see page 1. If page 1 held an App
    /// Insights connection, that is a violation the caller can already prove —
    /// and if the read returned a bare `Err`, the caller would never run its
    /// assertion, nothing would be recorded, and the transport error would be
    /// all the gate had to weigh. It would then rate a throttle `Transient` and
    /// keep serving prompts into the operator's sink. So the partial page set
    /// comes back alongside the failure: the caller asserts over what it *did*
    /// observe, records any finding, and only then lets the failure through to
    /// `AzureAudit::findings_outrank`, where a finding outranks it.
    async fn fetch_paged<P: ArmPage>(
        &self,
        mut url: String,
        token: &str,
        label: &'static str,
    ) -> PagedRead<P::Item> {
        let mut items = Vec::new();
        for _ in 0..MAX_ARM_PAGES {
            let page: P = match self.get_json(&url, token, label).await {
                Ok(page) => page,
                Err(err) => return PagedRead::truncated(items, err),
            };
            let (value, next_link) = page.into_parts();
            items.extend(value);
            let Some(next_link) = next_link else {
                return PagedRead::complete(items);
            };
            if next_link.trim().is_empty() {
                return PagedRead::truncated(
                    items,
                    anyhow!("{label} response had an empty nextLink"),
                );
            }
            url = next_link;
        }
        PagedRead::truncated(
            items,
            anyhow!("{label} paginated past {MAX_ARM_PAGES} pages; refusing to follow further"),
        )
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        token: &str,
        label: &'static str,
    ) -> Result<T> {
        let response = self
            .client
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
}

/// What a paginated ARM read actually observed, plus the failure that stopped it
/// (if one did). Both, never one or the other: see `fetch_paged`.
pub(crate) struct PagedRead<T> {
    /// Every item read before the failure — a floor on the collection, and
    /// enough to prove a violation that appears in it.
    pub(crate) items: Vec<T>,
    /// The transport (or protocol) failure that cut the read short.
    pub(crate) failure: Option<anyhow::Error>,
}

impl<T> PagedRead<T> {
    /// A collection that was never read because it cannot exist on this account
    /// kind — not a truncation, and not a failure.
    pub(crate) fn none() -> Self {
        Self::complete(Vec::new())
    }

    fn complete(items: Vec<T>) -> Self {
        Self {
            items,
            failure: None,
        }
    }

    fn truncated(items: Vec<T>, failure: anyhow::Error) -> Self {
        Self {
            items,
            failure: Some(failure),
        }
    }
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

/// Upper bound on `nextLink` following. A server that keeps handing back a link
/// would otherwise wedge the verifier: at boot it never returns, and in the
/// periodic loop it would stall every later target while envoy keeps serving.
/// Far above any real ARM collection on one account.
const MAX_ARM_PAGES: usize = 100;

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
#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "unit tests intentionally fail hard on malformed fixtures"
)]
mod tests {
    use super::*;

    #[test]
    fn a_project_name_drops_the_account_arm_qualifies_it_with() {
        // Verbatim from a live account: ARM returns a project's `name` as
        // `<account>/<project>`. Interpolated whole, this addresses nothing.
        let project: ArmChildResource =
            serde_json::from_str(r#"{"name": "hello-0323-resource/hello-0323", "properties": {}}"#)
                .expect("ARM project row must parse");

        assert_eq!(project.leaf_name(), "hello-0323");
    }

    #[test]
    fn an_unqualified_name_is_left_alone() {
        let child: ArmChildResource =
            serde_json::from_str(r#"{"name": "store", "properties": {}}"#)
                .expect("ARM child row must parse");

        assert_eq!(child.leaf_name(), "store");
    }
}
