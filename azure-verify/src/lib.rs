//! Azure owner-capture verification — one implementation, two callers.
//!
//! `attestd` runs it inside the CVM as a fail-closed boot gate (and then
//! periodically); `gmcli doctor` runs the *same* code on the operator's machine
//! as a preflight, so a `doctor` PASS means the boot gate will pass too. The two
//! must never drift: a preflight that green-lights a deploy the enclave then
//! crashloops on is worse than no preflight at all — hence one crate rather than
//! a second, "equivalent" implementation.
//!
//! The crate intentionally uses a narrow `reqwest` + serde surface instead of
//! Azure SDK crates, and issues read-only requests exclusively.

mod arm;
mod checks;
mod config;
mod endpoint;
mod error;
mod periodic;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Result};
use tokio::sync::oneshot;

use crate::arm::{ArmDeploymentList, ArmScope, PagedRead};
use crate::checks::{
    assert_account_binding, assert_no_capture_children, assert_no_diagnostic_capture,
    assess_streaming_configuration, log_streaming_assessment, retain_observable_deployments,
    split_azure_governed_deployments, AI_SERVICES_KIND,
};
use crate::config::{configured_targets_from_env, PeriodicAzureVerifySettings};
use crate::endpoint::{parse_azure_endpoint, AzureEndpoint};
use crate::periodic::run_periodic_azure_verification;

pub use crate::arm::{AzureVerifier, LOGIN_BASE_URL, MANAGEMENT_BASE_URL};
pub use crate::config::{AzureProvider, AzureVerifyConfig};

/// The child collections an operator can attach a prompt-content sink to. Both
/// must be empty on the account and on every project.
const CAPTURE_COLLECTIONS: [&str; 2] = ["connections", "capabilityHosts"];

/// What every read in one target's sweep needs: the ARM coordinates, the parsed
/// data-plane endpoint, and the bearer token they are all made with.
struct Sweep<'a> {
    config: &'a AzureVerifyConfig,
    endpoint: &'a AzureEndpoint,
    token: &'a str,
}

/// One ARM scope inside that sweep: the account, or one of its projects.
struct SweptScope<'a> {
    scope: ArmScope<'a>,
    resource_id: String,
    /// `connections` and `capabilityHosts` exist only under an `AIServices`
    /// account (and its projects); asking a classic `kind: OpenAI` account for
    /// them 404s.
    has_child_collections: bool,
}

/// Every owner-capture violation found on one Azure target, in the order the
/// checks run.
///
/// This is the shared verdict: `attestd` collapses it to pass/fail
/// (`into_result`) at boot, and `gmcli doctor` prints the same findings — each
/// already carrying the `az` command that clears it — as checklist lines.
#[derive(Debug, Clone)]
pub struct AzureAudit {
    /// Which upstream the audited account backs.
    pub provider: AzureProvider,
    /// The data-plane host the target is configured with.
    pub host: String,
    /// The ARM resource id of the account, once it is bound to `host`.
    pub resource_id: Option<String>,
    /// How many Foundry projects were swept alongside the account.
    pub projects_swept: usize,
    /// False when an ARM read failed part-way and the sweep could not finish, so
    /// `findings` is a floor on what is wrong with the account, not the whole of
    /// it. Only ever observed alongside a non-empty `findings` — a truncated
    /// sweep of an otherwise clean account is a transport error, not an audit.
    pub swept_completely: bool,
    /// One message per violation, each ending in the fix.
    pub findings: Vec<String>,
}

impl AzureAudit {
    fn new(provider: AzureProvider, host: String) -> Self {
        Self {
            provider,
            host,
            resource_id: None,
            projects_swept: 0,
            swept_completely: true,
            findings: Vec::new(),
        }
    }

    /// True when the account is bound to its endpoint and every capture surface
    /// is off — i.e. when `attestd` would let the miner bind its listener.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.findings.is_empty()
    }

    fn record(&mut self, outcome: Result<()>) {
        if let Err(err) = outcome {
            self.findings.push(format!("{err:#}"));
        }
    }

    /// Collapse the audit into the boot gate's verdict.
    ///
    /// # Errors
    /// Returns every finding, joined, when any check failed.
    pub fn into_result(self) -> Result<()> {
        if self.findings.is_empty() {
            return Ok(());
        }
        bail!("{}", self.findings.join("\n"));
    }

    /// A finding ALWAYS outranks a transport error — the asymmetry is the whole
    /// safety property, so it lives in one place.
    ///
    /// The sweep keeps reading ARM after it records a violation (doctor wants
    /// every finding, not just the first). That hands an operator a lever if a
    /// later read's failure were allowed to replace what we already found:
    /// attach a capture sink, then induce a 429 on the *next* read, and the
    /// error the gate sees is a throttle — which `classify_verification_error`
    /// rates `Transient` and the periodic loop tolerates, leaving envoy serving
    /// prompts into the sink for the whole tolerance window. So once anything is
    /// in `findings`, the transport error cannot win: the findings are returned
    /// and become a plain (therefore `Definitive`) error at `into_result`.
    ///
    /// The converse must stay true — a genuine Azure blip on a CLEAN account is
    /// still just a transport error, still `Transient`, and does not kill a
    /// miner. Transport errors are never turned into findings.
    fn findings_outrank(mut self, transport: anyhow::Error) -> Result<Self> {
        if self.findings.is_empty() {
            return Err(transport);
        }
        self.swept_completely = false;
        self.findings.push(format!(
            "the sweep stopped early — a later ARM read failed ({transport:#}) — so this account \
             may hold capture surfaces beyond the ones listed above. What is listed above stands \
             regardless, and must be cleared."
        ));
        Ok(self)
    }
}

/// Verify every Azure account this worker's upstream selectors put in the
/// request path (`OPENAI_UPSTREAM=azure`, `ANTHROPIC_UPSTREAM=foundry`).
///
/// # Errors
/// Returns an error when any required env var is missing, an endpoint is not an
/// allowed Azure host, ARM cannot be queried, or any configured account is not
/// bound to its TLS destination with every observable capture surface off.
pub async fn verify_azure_config_from_env() -> Result<()> {
    let targets = configured_targets_from_env()?;
    if targets.is_empty() {
        tracing::info!("no Azure-backed upstream configured; nothing to verify");
        return Ok(());
    }
    let verifier = AzureVerifier::new()?;
    for target in &targets {
        verifier.verify_target(target).await?;
    }
    Ok(())
}

/// Start periodic owner-capture verification for every configured Azure target.
///
/// On definitive verification failure, or too many consecutive transient
/// failures on any one target, the task sends a shutdown reason through
/// `fatal_shutdown`.
///
/// # Errors
/// Returns an error if verifier env is invalid or periodic settings cannot be
/// parsed.
pub fn spawn_periodic_azure_verification_from_env(
    fatal_shutdown: oneshot::Sender<String>,
) -> Result<Option<tokio::task::JoinHandle<()>>> {
    let targets = configured_targets_from_env()?;
    if targets.is_empty() {
        return Ok(None);
    }
    let settings = PeriodicAzureVerifySettings::from_env()?;
    tracing::info!(
        interval_secs = settings.interval.as_secs(),
        transient_failure_limit = settings.transient_failure_limit,
        targets = targets.len(),
        "starting periodic Azure owner-capture verification",
    );
    Ok(Some(tokio::spawn(run_periodic_azure_verification(
        targets,
        settings,
        fatal_shutdown,
    ))))
}

impl AzureVerifier {
    /// The boot gate: audit the target, and fail if anything was found.
    ///
    /// # Errors
    /// Returns an error when ARM cannot be reached or read, or when the account
    /// is not bound to its endpoint with every capture surface off.
    pub async fn verify_target(&self, config: &AzureVerifyConfig) -> Result<()> {
        let audit = self.audit_target(config).await?;
        let provider = audit.provider.label();
        let host = audit.host.clone();
        let resource_id = audit.resource_id.clone().unwrap_or_default();
        audit.into_result()?;
        tracing::info!(
            provider,
            azure_host = %host,
            resource_id = %resource_id,
            "Azure owner-capture verification passed",
        );
        Ok(())
    }

    /// Run every owner-capture check against one configured Azure account and
    /// collect what failed, rather than stopping at the first violation.
    ///
    /// An `Err` here is *not* a policy violation: it means the verification
    /// itself could not be carried out (bad endpoint, expired service-principal
    /// secret, ARM unreachable) AND nothing was found before it gave out. Policy
    /// violations land in `findings` and always outrank a transport error — see
    /// `AzureAudit::findings_outrank`. Every fallible ARM read in the sweep is
    /// funnelled through that one gate, which is why `sweep` is a separate
    /// function: a `?` inside it cannot bypass the rule.
    ///
    /// # Errors
    /// Returns an error when the endpoint is not an allowed Azure host, Entra
    /// refuses the client credentials, or ARM cannot be queried — and no
    /// violation had already been found.
    pub async fn audit_target(&self, config: &AzureVerifyConfig) -> Result<AzureAudit> {
        let endpoint = parse_azure_endpoint(config.provider, &config.endpoint)?;
        let mut audit = AzureAudit::new(config.provider, endpoint.host.clone());
        match self.sweep(config, &endpoint, &mut audit).await {
            Ok(()) => Ok(audit),
            Err(transport) => audit.findings_outrank(transport),
        }
    }

    /// The sweep itself. Every `?` in here is a transport failure that
    /// `audit_target` weighs against what has already been recorded; no caller
    /// may run it without passing the result through `findings_outrank`.
    async fn sweep(
        &self,
        config: &AzureVerifyConfig,
        endpoint: &AzureEndpoint,
        audit: &mut AzureAudit,
    ) -> Result<()> {
        // TODO: add the client-certificate assertion auth variant for
        // deployments that do not want a client secret in the encrypted CVM env.
        let token = self.fetch_entra_token(config).await?;
        let account = self.fetch_arm_account(config, endpoint, &token).await?;
        let resource_id = match assert_account_binding(config.provider, endpoint, &account) {
            Ok(resource_id) => resource_id.to_owned(),
            Err(err) => {
                // Without a bound account there is nothing to sweep: every later
                // check would be reading a resource we have not established is
                // the one serving the configured host.
                audit.record(Err(err));
                return Ok(());
            }
        };
        audit.resource_id = Some(resource_id.clone());
        let sweep = Sweep {
            config,
            endpoint,
            token: &token,
        };

        // The capture sweep is a property of the ACCOUNT, not of the provider: an
        // Azure OpenAI account exporting request logs to an operator-owned
        // workspace is the same surface as a Foundry one doing it. Both are swept.
        //
        // Projects, connections, and capability hosts only exist on `AIServices`
        // accounts. A classic `kind: OpenAI` account has no such child
        // collections, and asking ARM for them would fail the verification on an
        // account that has nothing to hide — so its sweep is the diagnostic
        // settings alone.
        let has_child_collections = account.kind == AI_SERVICES_KIND;
        self.audit_capture_surfaces(&sweep, &resource_id, has_child_collections, audit)
            .await?;

        // Only Azure OpenAI has an ARM-observable streaming control. Azure's RAI
        // content filter is not in Claude's inference path on Foundry, so there is
        // no `raiPolicyName` mode to read there and the verifier never consults one
        // (Microsoft's own Claude templates do set `raiPolicyName`, and it is inert
        // — reading it would prove nothing either way).
        if config.provider == AzureProvider::OpenAi {
            self.audit_async_filter_configuration(&sweep, audit).await?;
        }
        Ok(())
    }

    async fn audit_capture_surfaces(
        &self,
        sweep: &Sweep<'_>,
        resource_id: &str,
        has_child_collections: bool,
        audit: &mut AzureAudit,
    ) -> Result<()> {
        // A truncated project list still names projects we can sweep, and one of
        // them may hold the sink. Sweep what we saw; the failure is released to
        // the gate at the end, by which point any finding outranks it.
        let projects = if has_child_collections {
            self.fetch_children(
                sweep.config,
                sweep.endpoint,
                ArmScope::Account,
                "projects",
                sweep.token,
            )
            .await
        } else {
            PagedRead::none()
        };
        audit.projects_swept = projects.items.len();
        tracing::info!(
            project_count = projects.items.len(),
            "sweeping projects for capture surfaces",
        );

        self.audit_scope(
            sweep,
            &SweptScope {
                scope: ArmScope::Account,
                resource_id: resource_id.to_owned(),
                has_child_collections,
            },
            audit,
        )
        .await?;

        // A project is an ARM resource in its own right and carries its OWN
        // diagnostic settings, so sweeping only the account would miss an export
        // attached to the project the data plane actually routes through.
        //
        // `leaf_name`, not `name`: ARM qualifies a project's name with its
        // account (`acct/proj`), and interpolating that whole addresses nothing.
        for project in &projects.items {
            let project_name = project.leaf_name();
            self.audit_scope(
                sweep,
                &SweptScope {
                    scope: ArmScope::Project(project_name),
                    resource_id: format!("{resource_id}/projects/{project_name}"),
                    has_child_collections: true,
                },
                audit,
            )
            .await?;
        }
        match projects.failure {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }

    /// One scope — the account, or one of its projects — must export nothing and
    /// hold no sink: no diagnostic settings, no connections, no capability hosts.
    async fn audit_scope(
        &self,
        sweep: &Sweep<'_>,
        swept: &SweptScope<'_>,
        audit: &mut AzureAudit,
    ) -> Result<()> {
        let provider = sweep.config.provider;
        let label = swept.scope.label();
        let diagnostics = self
            .fetch_diagnostic_settings(&swept.resource_id, sweep.token)
            .await?;
        audit.record(assert_no_diagnostic_capture(
            provider,
            &label,
            &swept.resource_id,
            &diagnostics,
        ));
        if !swept.has_child_collections {
            return Ok(());
        }
        for collection in CAPTURE_COLLECTIONS {
            // Assert over the children we DID read before letting a truncating
            // failure through: a sink on page 1 is a violation whether or not
            // page 2 answered. Recording it first is what gives the gate
            // something to prefer over the transport error.
            let children = self
                .fetch_children(
                    sweep.config,
                    sweep.endpoint,
                    swept.scope,
                    collection,
                    sweep.token,
                )
                .await;
            audit.record(assert_no_capture_children(
                provider,
                &label,
                &swept.resource_id,
                collection,
                &children.items,
            ));
            if let Some(failure) = children.failure {
                return Err(failure);
            }
        }
        Ok(())
    }

    async fn audit_async_filter_configuration(
        &self,
        sweep: &Sweep<'_>,
        audit: &mut AzureAudit,
    ) -> Result<()> {
        let config = sweep.config;
        let endpoint = sweep.endpoint;
        let token = sweep.token;

        // Whatever page of deployments we got is still evidence: a deployment
        // with no `raiPolicyName` is a violation on sight, and it does not stop
        // being one because a later page throttled.
        let read = self.fetch_arm_deployments(config, endpoint, token).await;
        let mut failure = read.failure;
        let (mut deployments, skipped) = split_azure_governed_deployments(ArmDeploymentList {
            value: read.items,
            next_link: None,
        });
        if skipped > 0 {
            tracing::info!(
                skipped,
                "skipping Anthropic-format deployments in the Azure OpenAI streaming check; \
                 Azure's RAI filter does not govern them",
            );
        }
        tracing::info!(
            deployment_count = deployments.value.len(),
            "checking Azure OpenAI deployment streaming configuration",
        );

        let mut referenced_policy_names = BTreeSet::new();
        for deployment in &deployments.value {
            let rai_policy_name = deployment
                .properties
                .rai_policy_name
                .as_deref()
                .filter(|name| !name.trim().is_empty());
            tracing::debug!(
                deployment = %deployment.name,
                rai_policy_name = rai_policy_name.unwrap_or("<missing>"),
                "Azure OpenAI deployment RAI policy mapping",
            );
            if let Some(rai_policy_name) = rai_policy_name {
                referenced_policy_names.insert(rai_policy_name.to_owned());
            }
        }

        let mut policy_modes = BTreeMap::new();
        for policy_name in referenced_policy_names {
            match self
                .fetch_arm_rai_policy(config, endpoint, &policy_name, token)
                .await
            {
                Ok(policy) => {
                    tracing::debug!(
                        rai_policy_name = %policy_name,
                        mode = policy.properties.mode.as_deref().unwrap_or("<missing>"),
                        "Azure OpenAI RAI policy mode resolved",
                    );
                    policy_modes.insert(policy_name, policy.properties.mode);
                }
                // Stop reading policies, but do NOT discard the ones already
                // resolved: a synchronous mode among them is a violation we can
                // prove, as is any deployment with no policy at all.
                Err(err) => {
                    failure.get_or_insert(err);
                    break;
                }
            }
        }

        // Judge only what is observable. A deployment whose policy we never got
        // to read is dropped rather than assessed — assessing it would turn a
        // transport error into a finding, which is exactly the confusion the
        // definitive/transient split exists to prevent.
        retain_observable_deployments(&mut deployments, &policy_modes);
        let assessment = assess_streaming_configuration(&deployments, &policy_modes);
        audit.record(log_streaming_assessment(&assessment));
        match failure {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "unit tests intentionally fail hard on malformed fixtures"
)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::error::{classify_verification_error, VerificationFailureKind};

    /// The gate's verdict is `into_result`, and every check reaches it the same
    /// way: `record` puts a failure in `findings`, and ANY finding is fatal.
    /// Collecting findings instead of bailing at the first one is the whole
    /// difference between the boot gate and doctor — it must never become the
    /// difference between failing and passing.
    #[test]
    fn any_finding_is_fatal_to_the_boot_gate() {
        let mut audit =
            AzureAudit::new(AzureProvider::Foundry, "acct.services.ai.azure.com".into());
        assert!(audit.passed());
        assert!(audit.clone().into_result().is_ok());

        audit.record(Err(anyhow::anyhow!("a connection is attached")));
        audit.record(Err(anyhow::anyhow!("a diagnostic setting is attached")));
        assert!(!audit.passed());

        // Every finding survives into the failure the operator (or the container
        // log) sees — the gate never reports one and swallows the rest.
        let err = audit
            .into_result()
            .expect_err("a recorded finding must fail the gate")
            .to_string();
        assert!(err.contains("a connection is attached"), "{err}");
        assert!(err.contains("a diagnostic setting is attached"), "{err}");
    }

    /// A check that PASSED must not leave a finding behind — otherwise the gate
    /// fails closed on a clean account and no deploy ever boots.
    #[test]
    fn a_passing_check_records_nothing() {
        let mut audit = AzureAudit::new(AzureProvider::OpenAi, "acct.openai.azure.com".into());
        audit.record(Ok(()));
        assert!(audit.passed());
        assert!(audit.into_result().is_ok());
    }

    const ACCOUNT_PATH: &str =
        "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct";
    const DIAGNOSTICS: &str = "/providers/Microsoft.Insights/diagnosticSettings";

    fn foundry_target() -> AzureVerifyConfig {
        AzureVerifyConfig {
            provider: AzureProvider::Foundry,
            endpoint: "https://acct.services.ai.azure.com".to_owned(),
            tenant_id: "tenant".to_owned(),
            subscription_id: "sub".to_owned(),
            resource_group: "rg".to_owned(),
            client_id: "client".to_owned(),
            client_secret: "secret".to_owned(),
        }
    }

    fn openai_target() -> AzureVerifyConfig {
        AzureVerifyConfig {
            provider: AzureProvider::OpenAi,
            endpoint: "https://acct.openai.azure.com".to_owned(),
            ..foundry_target()
        }
    }

    async fn mount_get(server: &MockServer, at: &str, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(at.to_owned()))
            .respond_with(response)
            .mount(server)
            .await;
    }

    fn ok_json(body: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(body)
    }

    async fn mount_token(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/tenant/oauth2/v2.0/token"))
            .respond_with(ok_json(serde_json::json!({"access_token": "arm-token"})))
            .mount(server)
            .await;
    }

    /// `kind` decides the shape of the sweep: `AIServices` carries projects,
    /// connections and capability hosts; classic `OpenAI` carries deployments.
    async fn mount_account(server: &MockServer, kind: &str) {
        let host = if kind == "AIServices" {
            "https://acct.cognitiveservices.azure.com/"
        } else {
            "https://acct.openai.azure.com/"
        };
        mount_get(
            server,
            ACCOUNT_PATH,
            ok_json(serde_json::json!({
                "id": ACCOUNT_PATH,
                "kind": kind,
                "properties": {
                    "customSubDomainName": "acct",
                    "endpoint": host,
                    "raiMonitorConfig": null,
                    "userOwnedStorage": []
                }
            })),
        )
        .await;
    }

    /// An `AIServices` account with no projects. `capability_hosts` is whatever
    /// the test wants ARM to answer with — including a throttle.
    async fn foundry_arm(
        connections: serde_json::Value,
        capability_hosts: ResponseTemplate,
    ) -> MockServer {
        let server = MockServer::start().await;
        mount_token(&server).await;
        mount_account(&server, "AIServices").await;
        let empty = serde_json::json!({"value": []});
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}/projects"),
            ok_json(empty.clone()),
        )
        .await;
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}{DIAGNOSTICS}"),
            ok_json(empty),
        )
        .await;
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}/connections"),
            ok_json(connections),
        )
        .await;
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}/capabilityHosts"),
            capability_hosts,
        )
        .await;
        server
    }

    fn verifier_for(server: &MockServer) -> AzureVerifier {
        AzureVerifier::with_endpoints(reqwest::Client::new(), server.uri(), server.uri())
    }

    /// THE ATTACK. The operator attaches a capture sink, then induces throttling
    /// on the read that comes *after* the one that catches it. If the 429 were
    /// allowed to replace the finding, the periodic loop would rate the failure
    /// `Transient` and tolerate it — and envoy would keep streaming prompts into
    /// the operator's App Insights for the whole tolerance window.
    ///
    /// The finding must survive the throttle and reach the loop as `Definitive`,
    /// which is what shuts the miner down.
    #[tokio::test]
    async fn a_finding_outranks_a_throttle_on_a_later_read() {
        let server = foundry_arm(
            serde_json::json!({"value": [
                {"name": "telemetry", "properties": {"category": "AppInsights"}}
            ]}),
            ResponseTemplate::new(429).set_body_string("Too Many Requests"),
        )
        .await;

        let err = verifier_for(&server)
            .verify_target(&foundry_target())
            .await
            .expect_err("a capture sink must fail the gate even when a later read is throttled");

        // The violation, not the throttle, is what the operator is told about.
        assert!(err.to_string().contains("AppInsights"), "{err:#}");
        // And this is the bit that decides whether the miner keeps serving.
        assert_eq!(
            classify_verification_error(&err),
            VerificationFailureKind::Definitive,
            "a recorded finding must never be downgraded to a tolerated transient failure: {err:#}"
        );
    }

    /// The converse, and the reason findings are not simply merged with
    /// transport errors: a real Azure blip on a CLEAN account is still
    /// `Transient`, so a throttle does not kill an honest miner.
    #[tokio::test]
    async fn a_throttle_on_a_clean_account_is_still_transient() {
        let server = foundry_arm(
            serde_json::json!({"value": []}),
            ResponseTemplate::new(429).set_body_string("Too Many Requests"),
        )
        .await;

        let err = verifier_for(&server)
            .verify_target(&foundry_target())
            .await
            .expect_err("an unreadable capture surface cannot be declared clean");

        assert_eq!(
            classify_verification_error(&err),
            VerificationFailureKind::Transient,
            "an Azure hiccup on a clean account must not kill the miner: {err:#}"
        );
    }

    fn throttled() -> ResponseTemplate {
        ResponseTemplate::new(429).set_body_string("Too Many Requests")
    }

    /// One page of an ARM collection, pointing at a second page that never
    /// answers. `fetch_paged` must not throw page 1 away when page 2 fails.
    fn page_1_of_2(server: &MockServer, value: &serde_json::Value) -> ResponseTemplate {
        ok_json(serde_json::json!({
            "value": value,
            "nextLink": format!("{}/page-2", server.uri()),
        }))
    }

    /// ATTACK 1 — the violation is on page 1, and page 2 throttles.
    ///
    /// `fetch_paged` used to buffer the whole collection and return `Err`, so
    /// `assert_no_capture_children` never ran, nothing was recorded, and the
    /// gate had only a 429 to weigh — `Transient`, tolerated, prompts still
    /// flowing into the sink. The connection on page 1 was already proof.
    #[tokio::test]
    async fn a_violation_on_page_1_survives_a_throttle_on_page_2() {
        let server = MockServer::start().await;
        mount_token(&server).await;
        mount_account(&server, "AIServices").await;
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}/projects"),
            ok_json(serde_json::json!({"value": []})),
        )
        .await;
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}{DIAGNOSTICS}"),
            ok_json(serde_json::json!({"value": []})),
        )
        .await;
        let page_1 = page_1_of_2(
            &server,
            &serde_json::json!([{"name": "telemetry", "properties": {"category": "AppInsights"}}]),
        );
        mount_get(&server, &format!("{ACCOUNT_PATH}/connections"), page_1).await;
        mount_get(&server, "/page-2", throttled()).await;

        let err = verifier_for(&server)
            .verify_target(&foundry_target())
            .await
            .expect_err("a connection read on page 1 is proof, whatever page 2 does");

        assert!(err.to_string().contains("AppInsights"), "{err:#}");
        assert_eq!(
            classify_verification_error(&err),
            VerificationFailureKind::Definitive,
            "a violation already read must not be downgraded by a later page's throttle: {err:#}"
        );
    }

    /// ATTACK 2 — same shape, deployments pagination. A deployment with no
    /// `raiPolicyName` buffers completions; page 2 throttling does not un-see it.
    #[tokio::test]
    async fn a_deployment_violation_on_page_1_survives_a_throttle_on_page_2() {
        let server = MockServer::start().await;
        mount_token(&server).await;
        mount_account(&server, "OpenAI").await;
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}{DIAGNOSTICS}"),
            ok_json(serde_json::json!({"value": []})),
        )
        .await;
        let page_1 = page_1_of_2(
            &server,
            &serde_json::json!([{"name": "gpt-5", "properties": {"model": {"format": "OpenAI"}}}]),
        );
        mount_get(&server, &format!("{ACCOUNT_PATH}/deployments"), page_1).await;
        mount_get(&server, "/page-2", throttled()).await;

        let err = verifier_for(&server)
            .verify_target(&openai_target())
            .await
            .expect_err("a deployment with no RAI policy is proof, whatever page 2 does");

        assert!(err.to_string().contains("gpt-5"), "{err:#}");
        assert_eq!(
            classify_verification_error(&err),
            VerificationFailureKind::Definitive,
            "{err:#}"
        );
    }

    /// ATTACK 3 — the RAI path. One deployment's violation is observable with no
    /// further reads (no `raiPolicyName` at all); a second deployment's policy
    /// read throttles. The known violation must not be discarded while chasing
    /// the unknown one — and the unresolved policy must NOT be invented as a
    /// violation of its own.
    #[tokio::test]
    async fn a_missing_rai_policy_survives_a_throttle_on_another_policy_read() {
        let server = MockServer::start().await;
        mount_token(&server).await;
        mount_account(&server, "OpenAI").await;
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}{DIAGNOSTICS}"),
            ok_json(serde_json::json!({"value": []})),
        )
        .await;
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}/deployments"),
            ok_json(serde_json::json!({"value": [
                {"name": "unfiltered", "properties": {"model": {"format": "OpenAI"}}},
                {"name": "gpt-5", "properties": {
                    "model": {"format": "OpenAI"},
                    "raiPolicyName": "some-policy"
                }}
            ]})),
        )
        .await;
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}/raiPolicies/some-policy"),
            throttled(),
        )
        .await;

        let err = verifier_for(&server)
            .verify_target(&openai_target())
            .await
            .expect_err(
                "a deployment with no RAI policy fails whatever the other policy read does",
            );

        let message = err.to_string();
        assert!(message.contains("unfiltered"), "{err:#}");
        // The throttled policy is NOT reported as synchronous — we never read it,
        // and inventing a violation out of a transport failure is the mirror of
        // the bug being fixed.
        assert!(!message.contains("some-policy"), "{err:#}");
        assert_eq!(
            classify_verification_error(&err),
            VerificationFailureKind::Definitive,
            "{err:#}"
        );
    }

    /// ATTACK 4, the converse guard — a CLEAN account whose page 2 throttles is
    /// still just an Azure hiccup. `Transient`, tolerated, miner keeps serving.
    /// Without this, the fix above would kill honest miners on Azure's bad days.
    #[tokio::test]
    async fn a_throttled_page_2_on_a_clean_account_is_still_transient() {
        let server = MockServer::start().await;
        mount_token(&server).await;
        mount_account(&server, "AIServices").await;
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}/projects"),
            ok_json(serde_json::json!({"value": []})),
        )
        .await;
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}{DIAGNOSTICS}"),
            ok_json(serde_json::json!({"value": []})),
        )
        .await;
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}/connections"),
            page_1_of_2(&server, &serde_json::json!([])),
        )
        .await;
        mount_get(&server, "/page-2", throttled()).await;

        let err = verifier_for(&server)
            .verify_target(&foundry_target())
            .await
            .expect_err("an unreadable page cannot be declared clean");

        assert_eq!(
            classify_verification_error(&err),
            VerificationFailureKind::Transient,
            "a throttle with nothing found must stay tolerable: {err:#}"
        );
    }

    /// A truncated sweep reports a floor, not a verdict — the audit says so, so
    /// doctor cannot present a partial list as the whole story.
    #[tokio::test]
    async fn a_truncated_sweep_says_it_is_incomplete() {
        let server = foundry_arm(
            serde_json::json!({"value": [
                {"name": "telemetry", "properties": {"category": "AppInsights"}}
            ]}),
            ResponseTemplate::new(429).set_body_string("Too Many Requests"),
        )
        .await;

        let audit = verifier_for(&server)
            .audit_target(&foundry_target())
            .await
            .expect("findings outrank the throttle, so this is an audit and not an error");

        assert!(!audit.passed());
        assert!(!audit.swept_completely);
        assert!(audit.findings.iter().any(|f| f.contains("AppInsights")));
        assert!(audit
            .findings
            .iter()
            .any(|f| f.contains("the sweep stopped early")));
    }
}
