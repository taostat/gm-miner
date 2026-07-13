//! `gmcli set-api-keys` — persist provider API keys.

use anyhow::{bail, Context as _, Result};

use gm_miner_cli::{
    config::{self, ProviderKeys},
    network::Network,
};

/// Validate a key value passed to `set-api-keys`: reject empty / whitespace-only
/// strings with an actionable error rather than silently storing them.
fn validate_key(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("empty value for --{name}; either omit the flag or pass a non-empty key");
    }
    Ok(())
}

fn validate_selector(name: &str, value: &str, allowed: &[&str]) -> Result<()> {
    validate_key(name, value)?;
    if !allowed.contains(&value) {
        bail!(
            "invalid value for --{name}: {value}; expected one of {}",
            allowed.join(", ")
        );
    }
    Ok(())
}

/// The `ANTHROPIC_UPSTREAM=foundry` flag group: the Claude-on-Azure data-plane
/// endpoint and key, plus the read-only Entra service principal `attestd` uses
/// to verify the Foundry account carries no owner-capture controls. Grouped so
/// the seven flags travel as one argument instead of widening an already-long
/// handler signature.
#[derive(Debug, Default, clap::Args)]
pub(crate) struct FoundryArgs {
    /// Microsoft Foundry endpoint for `ANTHROPIC_UPSTREAM=foundry`
    /// (`https://<resource>.services.ai.azure.com`).
    #[arg(long = "azure-foundry-endpoint")]
    pub(crate) endpoint: Option<String>,

    /// Microsoft Foundry API key for `ANTHROPIC_UPSTREAM=foundry`.
    #[arg(long = "azure-foundry-api-key")]
    pub(crate) api_key: Option<String>,

    /// Azure tenant ID for Foundry ARM verification.
    #[arg(long = "azure-foundry-tenant-id")]
    pub(crate) tenant_id: Option<String>,

    /// Azure subscription ID for Foundry ARM verification.
    #[arg(long = "azure-foundry-subscription-id")]
    pub(crate) subscription_id: Option<String>,

    /// Azure resource group for Foundry ARM verification.
    #[arg(long = "azure-foundry-resource-group")]
    pub(crate) resource_group: Option<String>,

    /// Azure client ID for Foundry ARM verification.
    #[arg(long = "azure-foundry-client-id")]
    pub(crate) client_id: Option<String>,

    /// Azure client secret for Foundry ARM verification.
    #[arg(long = "azure-foundry-client-secret")]
    pub(crate) client_secret: Option<String>,
}

impl FoundryArgs {
    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("azure-foundry-endpoint", self.endpoint.as_deref()),
            ("azure-foundry-api-key", self.api_key.as_deref()),
            ("azure-foundry-tenant-id", self.tenant_id.as_deref()),
            (
                "azure-foundry-subscription-id",
                self.subscription_id.as_deref(),
            ),
            (
                "azure-foundry-resource-group",
                self.resource_group.as_deref(),
            ),
            ("azure-foundry-client-id", self.client_id.as_deref()),
            ("azure-foundry-client-secret", self.client_secret.as_deref()),
        ] {
            if let Some(value) = value {
                validate_key(name, value)?;
            }
        }
        Ok(())
    }

    fn merge_into(self, keys: &mut ProviderKeys) {
        if let Some(v) = self.endpoint {
            keys.azure_foundry_endpoint = Some(v);
        }
        if let Some(v) = self.api_key {
            keys.azure_foundry_api_key = Some(v);
        }
        if let Some(v) = self.tenant_id {
            keys.azure_foundry_tenant_id = Some(v);
        }
        if let Some(v) = self.subscription_id {
            keys.azure_foundry_subscription_id = Some(v);
        }
        if let Some(v) = self.resource_group {
            keys.azure_foundry_resource_group = Some(v);
        }
        if let Some(v) = self.client_id {
            keys.azure_foundry_client_id = Some(v);
        }
        if let Some(v) = self.client_secret {
            keys.azure_foundry_client_secret = Some(v);
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "single CLI command handler validates, persists, and reports all provider settings"
)]
pub(crate) fn cmd_set_api_keys(
    explicit_network: Option<Network>,
    anthropic: Option<String>,
    anthropic_upstream: Option<String>,
    bedrock_region: Option<String>,
    bedrock_api_key: Option<String>,
    foundry: FoundryArgs,
    openai: Option<String>,
    openai_upstream: Option<String>,
    azure_openai_endpoint: Option<String>,
    azure_openai_api_key: Option<String>,
    azure_tenant_id: Option<String>,
    azure_subscription_id: Option<String>,
    azure_resource_group: Option<String>,
    azure_client_id: Option<String>,
    azure_client_secret: Option<String>,
    google: Option<String>,
    chutes: Option<String>,
    zai: Option<String>,
) -> Result<()> {
    // Reject empty values up front so they don't pass the deploy preflight.
    if let Some(ref k) = anthropic {
        validate_key("anthropic", k)?;
    }
    if let Some(ref v) = anthropic_upstream {
        validate_selector("anthropic-upstream", v, &["direct", "bedrock", "foundry"])?;
    }
    foundry.validate()?;
    if let Some(ref v) = bedrock_region {
        validate_key("bedrock-region", v)?;
    }
    if let Some(ref k) = bedrock_api_key {
        validate_key("bedrock-api-key", k)?;
    }
    if let Some(ref k) = openai {
        validate_key("openai", k)?;
    }
    if let Some(ref v) = openai_upstream {
        validate_selector("openai-upstream", v, &["direct", "azure"])?;
    }
    if let Some(ref v) = azure_openai_endpoint {
        validate_key("azure-openai-endpoint", v)?;
    }
    if let Some(ref k) = azure_openai_api_key {
        validate_key("azure-openai-api-key", k)?;
    }
    if let Some(ref v) = azure_tenant_id {
        validate_key("azure-tenant-id", v)?;
    }
    if let Some(ref v) = azure_subscription_id {
        validate_key("azure-subscription-id", v)?;
    }
    if let Some(ref v) = azure_resource_group {
        validate_key("azure-resource-group", v)?;
    }
    if let Some(ref v) = azure_client_id {
        validate_key("azure-client-id", v)?;
    }
    if let Some(ref v) = azure_client_secret {
        validate_key("azure-client-secret", v)?;
    }
    if let Some(ref k) = google {
        validate_key("google", k)?;
    }
    if let Some(ref k) = chutes {
        validate_key("chutes", k)?;
    }
    if let Some(ref k) = zai {
        validate_key("zai", k)?;
    }

    // Load → mutate → save under the lock so a concurrent `deploy` save can't
    // be clobbered, and re-read fresh inside the lock so we merge onto the
    // latest on-disk state rather than a snapshot taken before the lock.
    let (
        has_anthropic,
        has_bedrock,
        has_foundry,
        has_openai,
        has_azure,
        has_google,
        has_chutes,
        has_zai,
    ) = config::with_config_lock(|| {
        let mut cfg = config::load()
            .context("load gmcli config (delete ~/.gmcli/config.json if corrupted)")?;

        // Provider keys are network-independent, but an explicit --network here
        // is still the user's sticky selection — persist it so the promise holds
        // even when set-api-keys is the command that carries the flag.
        if let Some(network) = explicit_network {
            cfg.set_network(network);
        }

        let keys = cfg.provider_keys.get_or_insert_with(ProviderKeys::default);
        if let Some(k) = anthropic {
            keys.anthropic = Some(k);
        }
        if let Some(v) = anthropic_upstream {
            keys.anthropic_upstream = Some(v);
        }
        if let Some(v) = bedrock_region {
            keys.bedrock_region = Some(v);
        }
        if let Some(k) = bedrock_api_key {
            keys.bedrock_api_key = Some(k);
        }
        foundry.merge_into(keys);
        if let Some(k) = openai {
            keys.openai = Some(k);
        }
        if let Some(v) = openai_upstream {
            keys.openai_upstream = Some(v);
        }
        if let Some(v) = azure_openai_endpoint {
            keys.azure_openai_endpoint = Some(v);
        }
        if let Some(k) = azure_openai_api_key {
            keys.azure_openai_api_key = Some(k);
        }
        if let Some(v) = azure_tenant_id {
            keys.azure_tenant_id = Some(v);
        }
        if let Some(v) = azure_subscription_id {
            keys.azure_subscription_id = Some(v);
        }
        if let Some(v) = azure_resource_group {
            keys.azure_resource_group = Some(v);
        }
        if let Some(v) = azure_client_id {
            keys.azure_client_id = Some(v);
        }
        if let Some(v) = azure_client_secret {
            keys.azure_client_secret = Some(v);
        }
        if let Some(k) = google {
            keys.google = Some(k);
        }
        if let Some(k) = chutes {
            keys.chutes = Some(k);
        }
        if let Some(k) = zai {
            keys.zai = Some(k);
        }
        let snapshot = (
            keys.anthropic.is_some(),
            keys.bedrock_api_key.is_some(),
            keys.azure_foundry_api_key.is_some()
                || keys.azure_foundry_endpoint.is_some()
                || keys.azure_foundry_tenant_id.is_some()
                || keys.azure_foundry_subscription_id.is_some()
                || keys.azure_foundry_resource_group.is_some()
                || keys.azure_foundry_client_id.is_some()
                || keys.azure_foundry_client_secret.is_some(),
            keys.openai.is_some(),
            keys.azure_openai_api_key.is_some()
                || keys.azure_openai_endpoint.is_some()
                || keys.azure_tenant_id.is_some()
                || keys.azure_subscription_id.is_some()
                || keys.azure_resource_group.is_some()
                || keys.azure_client_id.is_some()
                || keys.azure_client_secret.is_some(),
            keys.google.is_some(),
            keys.chutes.is_some(),
            keys.zai.is_some(),
        );

        config::save(&cfg).context("save config")?;
        Ok(snapshot)
    })?;

    let mut set_names: Vec<&str> = Vec::new();
    if has_anthropic {
        set_names.push("anthropic");
    }
    if has_bedrock {
        set_names.push("bedrock");
    }
    if has_foundry {
        set_names.push("azure-foundry");
    }
    if has_openai {
        set_names.push("openai");
    }
    if has_azure {
        set_names.push("azure-openai");
    }
    if has_google {
        set_names.push("google");
    }
    if has_chutes {
        set_names.push("chutes");
    }
    if has_zai {
        set_names.push("zai");
    }

    // Report which providers are now configured — never print the values.
    if set_names.is_empty() {
        println!(
            "No keys stored (pass --anthropic, --openai, --google, --chutes, --zai, \
             --bedrock-api-key, or --azure-openai-api-key to set one)."
        );
    } else {
        println!("Provider keys updated.");
        for name in &set_names {
            println!("  {name}: set");
        }
        println!("\nNext: gmcli deploy --image-repo ghcr.io/<owner>/gm-miner");
    }
    Ok(())
}
