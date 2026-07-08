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
    fetch_arm_account, fetch_arm_deployments, fetch_arm_rai_policy, fetch_diagnostic_settings,
    fetch_entra_token,
};
use self::checks::{
    assert_account_binding, assess_streaming_configuration, log_streaming_assessment,
    warn_on_unexpected_diagnostic_logs,
};
use self::config::{AzureVerifyConfig, PeriodicAzureVerifySettings};
use self::endpoint::{parse_azure_openai_endpoint, AzureEndpoint};
use self::periodic::run_periodic_azure_openai_verification;

/// Verify the Azure `OpenAI` upstream configuration from process env.
///
/// # Errors
/// Returns an error when any required env var is missing, the endpoint is not
/// an allowed Azure `OpenAI` host, ARM cannot be queried, or the ARM resource
/// is not bound to the configured TLS destination with content-to-storage
/// persistence disabled.
pub async fn verify_azure_openai_config_from_env() -> Result<()> {
    let config = AzureVerifyConfig::from_env()?;
    verify_azure_openai_config(&config).await
}

/// Start periodic Azure `OpenAI` owner-capture verification from process env.
///
/// On definitive verification failure, or too many consecutive transient
/// failures, the task sends a shutdown reason through `fatal_shutdown`.
///
/// # Errors
/// Returns an error if verifier env is invalid or periodic settings cannot be
/// parsed.
pub fn spawn_periodic_azure_openai_verification_from_env(
    fatal_shutdown: oneshot::Sender<String>,
) -> Result<tokio::task::JoinHandle<()>> {
    let config = AzureVerifyConfig::from_env()?;
    let settings = PeriodicAzureVerifySettings::from_env()?;
    tracing::info!(
        interval_secs = settings.interval.as_secs(),
        transient_failure_limit = settings.transient_failure_limit,
        "starting periodic Azure OpenAI owner-capture verification",
    );
    Ok(tokio::spawn(run_periodic_azure_openai_verification(
        config,
        settings,
        fatal_shutdown,
    )))
}

async fn verify_azure_openai_config(config: &AzureVerifyConfig) -> Result<()> {
    let endpoint = parse_azure_openai_endpoint(&config.endpoint)?;
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build Azure verification HTTP client")?;

    // TODO: add the client-certificate assertion auth variant for deployments
    // that do not want a client secret in the encrypted CVM env.
    let token = fetch_entra_token(&client, config).await?;
    let account = fetch_arm_account(&client, config, &endpoint, &token).await?;
    let resource_id = assert_account_binding(&endpoint, &account)?;
    let diagnostics = fetch_diagnostic_settings(&client, resource_id, &token).await?;
    warn_on_unexpected_diagnostic_logs(&diagnostics);
    verify_async_filter_configuration(&client, config, &endpoint, &token).await?;
    tracing::info!(
        azure_host = %endpoint.host,
        resource_id = %resource_id,
        "Azure OpenAI owner-capture verification passed",
    );
    Ok(())
}

async fn verify_async_filter_configuration(
    client: &Client,
    config: &AzureVerifyConfig,
    endpoint: &AzureEndpoint,
    token: &str,
) -> Result<()> {
    let deployments = fetch_arm_deployments(client, config, endpoint, token).await?;
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
