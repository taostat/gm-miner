use std::env::VarError;
use std::time::Duration;

use anyhow::{bail, Context, Result};

const DEFAULT_VERIFY_INTERVAL_SECS: u64 = 15 * 60;
const MIN_VERIFY_INTERVAL_SECS: u64 = 60;
const DEFAULT_TRANSIENT_FAILURE_LIMIT: u32 = 3;
const MIN_TRANSIENT_FAILURE_LIMIT: u32 = 1;
const VERIFY_INTERVAL_ENV: &str = "GM_AZURE_VERIFY_INTERVAL_SECS";
const TRANSIENT_FAILURE_LIMIT_ENV: &str = "GM_AZURE_VERIFY_TRANSIENT_FAILURE_LIMIT";

/// Which upstream a verified Azure account backs. The owner-capture checks are
/// shared; what differs is the account kind, the endpoint suffix, and whether
/// Azure's RAI content filter is the mechanism that governs streaming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AzureProvider {
    /// `OPENAI_UPSTREAM=azure` — Azure `OpenAI`.
    OpenAi,
    /// `ANTHROPIC_UPSTREAM=foundry` — Claude on Microsoft Foundry.
    Foundry,
}

impl AzureProvider {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::OpenAi => "Azure OpenAI",
            Self::Foundry => "Microsoft Foundry",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AzureVerifyConfig {
    pub(crate) provider: AzureProvider,
    pub(crate) endpoint: String,
    pub(crate) tenant_id: String,
    pub(crate) subscription_id: String,
    pub(crate) resource_group: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PeriodicAzureVerifySettings {
    pub(crate) interval: Duration,
    pub(crate) transient_failure_limit: u32,
}

impl AzureVerifyConfig {
    fn openai_from_env() -> Result<Self> {
        Ok(Self {
            provider: AzureProvider::OpenAi,
            endpoint: required_env("AZURE_OPENAI_ENDPOINT")?,
            tenant_id: required_env("AZURE_TENANT_ID")?,
            subscription_id: required_env("AZURE_SUBSCRIPTION_ID")?,
            resource_group: required_env("AZURE_RESOURCE_GROUP")?,
            client_id: required_env("AZURE_CLIENT_ID")?,
            client_secret: required_env("AZURE_CLIENT_SECRET")?,
        })
    }

    /// Foundry carries its own ARM coordinates rather than reusing the Azure
    /// `OpenAI` ones: a miner may hold the Foundry account in a different tenant,
    /// subscription, resource group, or under a different service principal
    /// than an Azure `OpenAI` account on the same worker.
    fn foundry_from_env() -> Result<Self> {
        Ok(Self {
            provider: AzureProvider::Foundry,
            endpoint: required_env("AZURE_FOUNDRY_ENDPOINT")?,
            tenant_id: required_env("AZURE_FOUNDRY_TENANT_ID")?,
            subscription_id: required_env("AZURE_FOUNDRY_SUBSCRIPTION_ID")?,
            resource_group: required_env("AZURE_FOUNDRY_RESOURCE_GROUP")?,
            client_id: required_env("AZURE_FOUNDRY_CLIENT_ID")?,
            client_secret: required_env("AZURE_FOUNDRY_CLIENT_SECRET")?,
        })
    }
}

/// Every Azure account this worker's upstream selectors put in the request
/// path. A worker may run both (`ANTHROPIC_UPSTREAM=foundry` alongside
/// `OPENAI_UPSTREAM=azure`); each is verified independently and either one
/// failing is fatal.
///
/// # Errors
/// Returns an error when a selected upstream is missing a required env var.
pub(crate) fn configured_targets_from_env() -> Result<Vec<AzureVerifyConfig>> {
    let mut targets = Vec::new();
    if upstream("ANTHROPIC_UPSTREAM") == "foundry" {
        targets.push(AzureVerifyConfig::foundry_from_env()?);
    }
    if upstream("OPENAI_UPSTREAM") == "azure" {
        targets.push(AzureVerifyConfig::openai_from_env()?);
    }
    Ok(targets)
}

fn upstream(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| "direct".to_owned())
}

impl PeriodicAzureVerifySettings {
    pub(crate) fn from_env() -> Result<Self> {
        let interval_secs = env_u64_at_least(
            VERIFY_INTERVAL_ENV,
            DEFAULT_VERIFY_INTERVAL_SECS,
            MIN_VERIFY_INTERVAL_SECS,
        )?;
        let transient_failure_limit = env_u32_at_least(
            TRANSIENT_FAILURE_LIMIT_ENV,
            DEFAULT_TRANSIENT_FAILURE_LIMIT,
            MIN_TRANSIENT_FAILURE_LIMIT,
        )?;
        Ok(Self {
            interval: Duration::from_secs(interval_secs),
            transient_failure_limit,
        })
    }
}

pub(crate) fn required_env(name: &str) -> Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} must be set"))?;
    if value.trim().is_empty() {
        bail!("{name} must not be empty");
    }
    Ok(value)
}

pub(crate) fn env_u64_at_least(name: &str, default: u64, minimum: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(value) => {
            let parsed = value
                .parse::<u64>()
                .with_context(|| format!("{name} must be an integer number of seconds"))?;
            if parsed < minimum {
                tracing::warn!(
                    name,
                    configured = parsed,
                    minimum,
                    "Azure verification interval below minimum; using minimum",
                );
                Ok(minimum)
            } else {
                Ok(parsed)
            }
        }
        Err(VarError::NotPresent) => Ok(default),
        Err(err) => Err(err).with_context(|| format!("read {name}")),
    }
}

pub(crate) fn env_u32_at_least(name: &str, default: u32, minimum: u32) -> Result<u32> {
    match std::env::var(name) {
        Ok(value) => {
            let parsed = value
                .parse::<u32>()
                .with_context(|| format!("{name} must be a positive integer"))?;
            if parsed < minimum {
                tracing::warn!(
                    name,
                    configured = parsed,
                    minimum,
                    "Azure verification transient failure limit below minimum; using minimum",
                );
                Ok(minimum)
            } else {
                Ok(parsed)
            }
        }
        Err(VarError::NotPresent) => Ok(default),
        Err(err) => Err(err).with_context(|| format!("read {name}")),
    }
}
