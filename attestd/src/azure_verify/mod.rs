//! In-enclave Azure `OpenAI` owner-capture verification.
//!
//! This module intentionally uses a narrow `reqwest` + serde surface instead
//! of Azure SDK crates. The attested binary runs these checks before binding
//! its listener and then periodically after binding; unsafe verification
//! failures are fatal to keep the miner fail-closed.

mod arm;
mod checks;
mod config;
mod endpoint;
mod error;
mod periodic;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use tokio::sync::oneshot;

use self::arm::{
    fetch_arm_account, fetch_arm_deployments, fetch_arm_rai_policy, fetch_children,
    fetch_diagnostic_settings, fetch_entra_token, ArmScope,
};
use self::checks::{
    assert_account_binding, assert_no_capture_children, assert_no_diagnostic_capture,
    assess_streaming_configuration, log_streaming_assessment, split_azure_governed_deployments,
    AI_SERVICES_KIND,
};
use self::config::{
    configured_targets_from_env, AzureProvider, AzureVerifyConfig, PeriodicAzureVerifySettings,
};
use self::endpoint::{parse_azure_endpoint, AzureEndpoint};
use self::periodic::run_periodic_azure_verification;

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
    let client = arm_client()?;
    for target in &targets {
        verify_azure_target(&client, target).await?;
    }
    Ok(())
}

/// One HTTP client, reused across targets and across every periodic cycle:
/// rebuilding it per call would throw away the connection pool and re-read the
/// system trust store on each verification.
pub(crate) fn arm_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build Azure verification HTTP client")
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

pub(crate) async fn verify_azure_target(client: &Client, config: &AzureVerifyConfig) -> Result<()> {
    let endpoint = parse_azure_endpoint(config.provider, &config.endpoint)?;

    // TODO: add the client-certificate assertion auth variant for deployments
    // that do not want a client secret in the encrypted CVM env.
    let token = fetch_entra_token(client, config).await?;
    let account = fetch_arm_account(client, config, &endpoint, &token).await?;
    let resource_id = assert_account_binding(config.provider, &endpoint, &account)?;

    // The capture sweep is a property of the ACCOUNT, not of the provider: an
    // Azure OpenAI account exporting request logs to an operator-owned
    // workspace is the same surface as a Foundry one doing it. Both are swept.
    //
    // Projects, connections, and capability hosts only exist on `AIServices`
    // accounts. A classic `kind: OpenAI` account has no such child collections,
    // and asking ARM for them would fail the verification on an account that has
    // nothing to hide — so its sweep is the diagnostic settings alone.
    verify_capture_surfaces(
        client,
        config,
        &endpoint,
        resource_id,
        account.kind == AI_SERVICES_KIND,
        &token,
    )
    .await?;

    // Only Azure OpenAI has an ARM-observable streaming control. Azure's RAI
    // content filter is not in Claude's inference path on Foundry, so there is
    // no `raiPolicyName` mode to read there and the verifier never consults one
    // (Microsoft's own Claude templates do set `raiPolicyName`, and it is inert
    // — reading it would prove nothing either way).
    if config.provider == AzureProvider::OpenAi {
        verify_async_filter_configuration(client, config, &endpoint, &token).await?;
    }

    tracing::info!(
        provider = config.provider.label(),
        azure_host = %endpoint.host,
        resource_id = %resource_id,
        "Azure owner-capture verification passed",
    );
    Ok(())
}

/// The child collections an operator can attach a prompt-content sink to. Both
/// must be empty on the account and on every project.
const CAPTURE_COLLECTIONS: [&str; 2] = ["connections", "capabilityHosts"];

async fn verify_capture_surfaces(
    client: &Client,
    config: &AzureVerifyConfig,
    endpoint: &AzureEndpoint,
    resource_id: &str,
    has_child_collections: bool,
    token: &str,
) -> Result<()> {
    if !has_child_collections {
        let diagnostics = fetch_diagnostic_settings(client, resource_id, token).await?;
        return assert_no_diagnostic_capture(
            config.provider,
            &ArmScope::Account.label(),
            resource_id,
            &diagnostics,
        );
    }

    // These reads are independent, and they gate the data plane from starting —
    // run them concurrently rather than paying a round trip each in sequence.
    let ((), projects) = tokio::try_join!(
        assert_scope_is_inference_only(
            client,
            config,
            endpoint,
            ArmScope::Account,
            resource_id,
            token
        ),
        fetch_children(
            client,
            config,
            endpoint,
            ArmScope::Account,
            "projects",
            token
        ),
    )?;

    tracing::info!(
        project_count = projects.len(),
        "sweeping projects for capture surfaces",
    );
    // A project is an ARM resource in its own right and carries its OWN
    // diagnostic settings, so sweeping only the account would miss an export
    // attached to the project the data plane actually routes through.
    for project in &projects {
        let project_resource_id = format!("{resource_id}/projects/{}", project.name);
        assert_scope_is_inference_only(
            client,
            config,
            endpoint,
            ArmScope::Project(&project.name),
            &project_resource_id,
            token,
        )
        .await?;
    }
    Ok(())
}

/// One scope — the account, or one of its projects — must export nothing and
/// hold no sink: no diagnostic settings, no connections, no capability hosts.
async fn assert_scope_is_inference_only(
    client: &Client,
    config: &AzureVerifyConfig,
    endpoint: &AzureEndpoint,
    scope: ArmScope<'_>,
    resource_id: &str,
    token: &str,
) -> Result<()> {
    let diagnostics = fetch_diagnostic_settings(client, resource_id, token).await?;
    assert_no_diagnostic_capture(config.provider, &scope.label(), resource_id, &diagnostics)?;

    for collection in CAPTURE_COLLECTIONS {
        let children = fetch_children(client, config, endpoint, scope, collection, token).await?;
        assert_no_capture_children(config.provider, &scope.label(), collection, &children)?;
    }
    Ok(())
}

async fn verify_async_filter_configuration(
    client: &Client,
    config: &AzureVerifyConfig,
    endpoint: &AzureEndpoint,
    token: &str,
) -> Result<()> {
    let all = fetch_arm_deployments(client, config, endpoint, token).await?;
    let (deployments, skipped) = split_azure_governed_deployments(all);
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
        let policy = fetch_arm_rai_policy(client, config, endpoint, &policy_name, token).await?;
        tracing::debug!(
            rai_policy_name = %policy_name,
            mode = policy.properties.mode.as_deref().unwrap_or("<missing>"),
            "Azure OpenAI RAI policy mode resolved",
        );
        policy_modes.insert(policy_name, policy.properties.mode);
    }

    let assessment = assess_streaming_configuration(&deployments, &policy_modes);
    log_streaming_assessment(&assessment)
}
