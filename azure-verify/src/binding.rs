use anyhow::{bail, Result};

use crate::{arm::ArmDeployment, AzureProvider};

/// Model identity observed on the bound account through ARM.
#[derive(Debug, Clone)]
pub struct AzureDeployment {
    pub name: String,
    pub format: Option<String>,
    pub model: Option<String>,
    pub version: Option<String>,
}

impl From<&ArmDeployment> for AzureDeployment {
    fn from(deployment: &ArmDeployment) -> Self {
        Self {
            name: deployment.name.clone(),
            format: deployment.properties.model.format.clone(),
            model: deployment.properties.model.name.clone(),
            version: deployment.properties.model.version.clone(),
        }
    }
}

impl AzureDeployment {
    /// Returns true for an honestly named catalog deployment, false for an
    /// unrelated name. Missing catalog deployments require no ARM finding.
    ///
    /// # Errors
    /// A catalog-named deployment must serve exactly that model in its adapter's
    /// format; any mismatch is a definitive verification failure.
    pub fn verify_binding(&self, provider: AzureProvider) -> Result<bool> {
        if !provider.catalog_ids().contains(&self.name.as_str()) {
            return Ok(false);
        }
        let format = self.format.as_deref().unwrap_or("<missing>");
        let model = self.model.as_deref().unwrap_or("<missing>");
        if format != provider.model_format() || model != self.name {
            bail!(
                "{} deployment '{}' has ARM model.format '{format}' and model.name '{model}'; \
                 expected format '{}' and exact model name '{}'. Delete and recreate the \
                 deployment with that model; this catalog-named mismatch takes the worker offline",
                provider.label(),
                self.name,
                provider.model_format(),
                self.name,
            );
        }
        Ok(true)
    }
}

pub(crate) fn assert_deployment_bindings(
    provider: AzureProvider,
    deployments: &[ArmDeployment],
) -> Result<()> {
    for deployment in deployments {
        AzureDeployment::from(deployment).verify_binding(provider)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::AzureDeployment;
    use crate::AzureProvider;

    fn deployment(name: &str, format: Option<&str>, model: Option<&str>) -> AzureDeployment {
        AzureDeployment {
            name: name.to_owned(),
            format: format.map(str::to_owned),
            model: model.map(str::to_owned),
            version: Some("1".to_owned()),
        }
    }

    #[test]
    fn honest_catalog_deployments_pass_for_both_adapters() {
        for provider in [AzureProvider::OpenAi, AzureProvider::Foundry] {
            for name in provider.catalog_ids() {
                let row = deployment(name, Some(provider.model_format()), Some(name));
                assert!(matches!(row.verify_binding(provider), Ok(true)));
            }
        }
    }

    #[test]
    fn catalog_names_reject_other_models_and_non_ascii_variants() {
        for model in ["gpt-5.4-mini", "GPT-5.4", "gpt-5.4 ", "gpt-5.４"] {
            let row = deployment("gpt-5.4", Some("OpenAI"), Some(model));
            assert!(row.verify_binding(AzureProvider::OpenAi).is_err());
        }
    }

    #[test]
    fn catalog_names_require_the_exact_adapter_format() {
        for format in [None, Some("OpenAI"), Some("anthropic"), Some("Anthropic ")] {
            let row = deployment("claude-opus-4-6", format, Some("claude-opus-4-6"));
            assert!(row.verify_binding(AzureProvider::Foundry).is_err());
        }
        let missing_model = deployment("gpt-5.4", Some("OpenAI"), None);
        assert!(missing_model.verify_binding(AzureProvider::OpenAi).is_err());
    }

    #[test]
    fn unrelated_names_are_ignored_by_the_binding_rule() {
        for name in ["my-deployment", "gpt-5.4-copy", "GPT-5.4", "gpt-5.４"] {
            for provider in [AzureProvider::OpenAi, AzureProvider::Foundry] {
                assert!(matches!(
                    deployment(name, None, None).verify_binding(provider),
                    Ok(false)
                ));
            }
        }
    }

    #[test]
    fn another_adapters_catalog_does_not_define_an_expectation() {
        let row = deployment("claude-opus-4-6", Some("OpenAI"), Some("gpt-5.4"));
        assert!(matches!(
            row.verify_binding(AzureProvider::OpenAi),
            Ok(false)
        ));
        assert!(row.verify_binding(AzureProvider::Foundry).is_err());
    }

    #[test]
    fn an_empty_account_has_no_missing_deployment_failure() {
        for provider in [AzureProvider::OpenAi, AzureProvider::Foundry] {
            assert!(super::assert_deployment_bindings(provider, &[]).is_ok());
        }
    }
}
