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

/// True when any field in a settings group carries a value.
fn any_set(fields: &[Option<&String>]) -> bool {
    fields.iter().any(Option::is_some)
}

/// The `name: state` lines the summary prints, one per settings group that
/// `set-api-keys` persists.
///
/// Every group this command can write appears here, so nothing is saved without
/// being acknowledged. A group counts as configured when *any* of its fields is
/// set — a partial group (`--bedrock-region` with no key yet) is reported, not
/// silently swallowed. Selectors print their value (they are not secrets); keys
/// only ever print `set`.
fn summary_lines(keys: &ProviderKeys) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut group = |name: &str, fields: &[Option<&String>]| {
        if any_set(fields) {
            lines.push(format!("  {name}: set"));
        }
    };

    group("anthropic", &[keys.anthropic.as_ref()]);
    group(
        "bedrock",
        &[keys.bedrock_region.as_ref(), keys.bedrock_api_key.as_ref()],
    );
    group(
        "azure-foundry",
        &[
            keys.azure_foundry_endpoint.as_ref(),
            keys.azure_foundry_api_key.as_ref(),
            keys.azure_foundry_tenant_id.as_ref(),
            keys.azure_foundry_subscription_id.as_ref(),
            keys.azure_foundry_resource_group.as_ref(),
            keys.azure_foundry_client_id.as_ref(),
            keys.azure_foundry_client_secret.as_ref(),
        ],
    );
    group("openai", &[keys.openai.as_ref()]);
    group(
        "azure-openai",
        &[
            keys.azure_openai_endpoint.as_ref(),
            keys.azure_openai_api_key.as_ref(),
            keys.azure_tenant_id.as_ref(),
            keys.azure_subscription_id.as_ref(),
            keys.azure_resource_group.as_ref(),
            keys.azure_client_id.as_ref(),
            keys.azure_client_secret.as_ref(),
        ],
    );
    group("google", &[keys.google.as_ref()]);
    group("chutes", &[keys.chutes.as_ref()]);
    group("zai", &[keys.zai.as_ref()]);
    group("moonshot", &[keys.moonshot.as_ref()]);
    group("deepinfra", &[keys.deepinfra.as_ref()]);

    for (name, selector) in [
        ("anthropic-upstream", keys.anthropic_upstream.as_ref()),
        ("openai-upstream", keys.openai_upstream.as_ref()),
    ] {
        if let Some(value) = selector {
            lines.push(format!("  {name}: {value}"));
        }
    }
    lines
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
    moonshot: Option<String>,
    deepinfra: Option<String>,
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
    if let Some(ref k) = moonshot {
        validate_key("moonshot", k)?;
    }
    if let Some(ref k) = deepinfra {
        validate_key("deepinfra", k)?;
    }

    // Load → mutate → save under the lock so a concurrent `deploy` save can't
    // be clobbered, and re-read fresh inside the lock so we merge onto the
    // latest on-disk state rather than a snapshot taken before the lock.
    let lines = config::with_config_lock(|| {
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
        if let Some(k) = moonshot {
            keys.moonshot = Some(k);
        }
        if let Some(k) = deepinfra {
            keys.deepinfra = Some(k);
        }
        let lines = summary_lines(keys);

        config::save(&cfg).context("save config")?;
        Ok(lines)
    })?;

    // Report what is now configured — never print a key's value.
    if lines.is_empty() {
        println!(
            "No keys stored (pass --anthropic, --openai, --google, --chutes, --zai, --moonshot, \
             --deepinfra, --bedrock-api-key, --azure-foundry-api-key, or --azure-openai-api-key to set one)."
        );
    } else {
        println!("Provider keys updated.");
        for line in &lines {
            println!("{line}");
        }
        println!("\nNext: gmcli deploy --image-repo ghcr.io/<owner>/gm-miner");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::summary_lines;
    use gm_miner_cli::config::ProviderKeys;

    fn foundry_keys() -> ProviderKeys {
        ProviderKeys {
            anthropic_upstream: Some("foundry".to_owned()),
            azure_foundry_endpoint: Some("https://acct.services.ai.azure.com".to_owned()),
            azure_foundry_api_key: Some("foundry-key".to_owned()),
            azure_foundry_tenant_id: Some("tenant".to_owned()),
            azure_foundry_subscription_id: Some("sub".to_owned()),
            azure_foundry_resource_group: Some("rg".to_owned()),
            azure_foundry_client_id: Some("client".to_owned()),
            azure_foundry_client_secret: Some("secret".to_owned()),
            ..ProviderKeys::default()
        }
    }

    #[test]
    fn foundry_group_is_reported_alongside_previously_stored_keys() {
        let keys = ProviderKeys {
            chutes: Some("cpk-1".to_owned()),
            zai: Some("zai-1".to_owned()),
            ..foundry_keys()
        };

        assert_eq!(
            summary_lines(&keys),
            [
                "  azure-foundry: set",
                "  chutes: set",
                "  zai: set",
                "  anthropic-upstream: foundry",
            ]
        );
    }

    #[test]
    fn foundry_group_is_reported_when_only_one_field_is_set() {
        let mut keys = foundry_keys();
        keys.anthropic_upstream = None;
        keys.azure_foundry_endpoint = None;
        keys.azure_foundry_api_key = None;
        keys.azure_foundry_tenant_id = None;
        keys.azure_foundry_subscription_id = None;
        keys.azure_foundry_resource_group = None;
        keys.azure_foundry_client_id = None;

        assert_eq!(summary_lines(&keys), ["  azure-foundry: set"]);
    }

    #[test]
    fn bedrock_region_alone_is_reported() {
        // The region is persisted, so the summary must acknowledge it rather
        // than claim nothing was stored.
        let keys = ProviderKeys {
            bedrock_region: Some("us-west-2".to_owned()),
            ..ProviderKeys::default()
        };

        assert_eq!(summary_lines(&keys), ["  bedrock: set"]);
    }

    #[test]
    fn azure_openai_group_is_reported_from_any_field() {
        let keys = ProviderKeys {
            openai_upstream: Some("azure".to_owned()),
            azure_tenant_id: Some("tenant".to_owned()),
            ..ProviderKeys::default()
        };

        assert_eq!(
            summary_lines(&keys),
            ["  azure-openai: set", "  openai-upstream: azure"]
        );
    }

    #[test]
    fn nothing_set_reports_no_lines() {
        assert!(summary_lines(&ProviderKeys::default()).is_empty());
    }
}
