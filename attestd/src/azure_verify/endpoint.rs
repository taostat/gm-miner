use anyhow::{bail, Context, Result};
use reqwest::Url;

use super::config::AzureProvider;

pub(crate) const AZURE_OPENAI_ALLOWED_SUFFIXES: [&str; 3] = [
    ".openai.azure.com",
    ".services.ai.azure.com",
    ".cognitiveservices.azure.com",
];

/// Microsoft and Anthropic document Foundry's Anthropic-native passthrough on
/// exactly one host shape: `https://<resource>.services.ai.azure.com`. Nothing
/// else is accepted — a wider allowlist would be an assumption, not a fact.
pub(crate) const AZURE_FOUNDRY_ALLOWED_SUFFIXES: [&str; 1] = [".services.ai.azure.com"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AzureEndpoint {
    pub(crate) host: String,
    pub(crate) account_name: String,
    pub(crate) suffix: &'static str,
}

pub(crate) fn parse_azure_endpoint(
    provider: AzureProvider,
    endpoint: &str,
) -> Result<AzureEndpoint> {
    let (var, allowed): (&str, &[&str]) = match provider {
        AzureProvider::OpenAi => ("AZURE_OPENAI_ENDPOINT", &AZURE_OPENAI_ALLOWED_SUFFIXES),
        AzureProvider::Foundry => ("AZURE_FOUNDRY_ENDPOINT", &AZURE_FOUNDRY_ALLOWED_SUFFIXES),
    };
    let url = Url::parse(endpoint).with_context(|| format!("parse {var} {endpoint:?}"))?;
    if url.scheme() != "https" {
        bail!("{var} must use https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("{var} must not contain userinfo");
    }
    let host = url
        .host_str()
        .with_context(|| format!("{var} must include a DNS host"))?
        .to_ascii_lowercase();
    validate_dns_host(&format!("{var} host"), &host)?;
    let suffix = allowed
        .iter()
        .copied()
        .find(|suffix| host_allowed_by_suffix(&host, suffix));
    let Some(suffix) = suffix else {
        bail!(
            "{var} host '{host}' is not in the allowed suffix set: {}",
            allowed
                .iter()
                .map(|suffix| &suffix[1..])
                .collect::<Vec<_>>()
                .join(", ")
        );
    };
    // The account label is the WHOLE host minus the suffix, and it must be one
    // label. Azure gives an account exactly one name under the service zone —
    // `<customSubDomainName>.services.ai.azure.com` — and the binding rests on
    // that: a globally unique label under a zone only Azure can answer for is
    // proof the endpoint is the account we verified. A host like
    // `acct.extra.services.ai.azure.com` still ends with the suffix and still
    // starts with `acct`, so reading the label as "the first component" would
    // accept a name Azure never issued and the proof would no longer describe
    // what the code accepts. Nobody can provision DNS beneath Microsoft's zone,
    // so this closes no known attack — it makes the check say what it means.
    let account_name = host
        .strip_suffix(suffix)
        .with_context(|| format!("{var} host must end with '{suffix}'"))?
        .to_owned();
    if account_name.is_empty() || account_name.contains('.') {
        bail!(
            "{var} host '{host}' is not '<account>{suffix}' — an Azure account has exactly one \
             name under that zone",
        );
    }
    Ok(AzureEndpoint {
        host,
        account_name,
        suffix,
    })
}

pub(crate) fn validate_dns_host(label: &str, host: &str) -> Result<()> {
    let valid = !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if valid {
        Ok(())
    } else {
        bail!("{label} must be a DNS host (got '{host}')")
    }
}

pub(crate) fn host_allowed_by_suffix(host: &str, suffix: &str) -> bool {
    host.len() > suffix.len() && host.ends_with(suffix)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "unit tests intentionally fail hard on malformed fixtures"
)]
mod tests {
    use super::*;

    #[test]
    fn base_url_allowlist_accepts_azure_openai_suffixes() {
        for endpoint in [
            "https://acct.openai.azure.com/",
            "https://acct.services.ai.azure.com",
            "https://acct.cognitiveservices.azure.com/openai",
        ] {
            assert!(
                parse_azure_endpoint(AzureProvider::OpenAi, endpoint).is_ok(),
                "{endpoint} should be accepted"
            );
        }
    }

    #[test]
    fn base_url_allowlist_rejects_non_https_userinfo_and_bad_suffix() {
        for endpoint in [
            "http://acct.openai.azure.com",
            "acct.openai.azure.com",
            "https://user@acct.openai.azure.com",
            "https://acct.openai.azure.com.evil.example",
            "https://api.evil.example",
        ] {
            assert!(
                parse_azure_endpoint(AzureProvider::OpenAi, endpoint).is_err(),
                "{endpoint} should be rejected"
            );
        }
    }

    #[test]
    fn a_host_with_more_than_the_account_label_is_refused() {
        // Ends with the suffix and starts with a plausible label, so a
        // first-component reading would take `acct` and bind it to an account
        // whose real host is `acct.services.ai.azure.com`. Azure issues exactly
        // one name under the zone; anything else is not that account's host.
        let err = parse_azure_endpoint(
            AzureProvider::Foundry,
            "https://acct.extra.services.ai.azure.com",
        )
        .expect_err("a multi-label account name must be refused")
        .to_string();

        assert!(err.contains("exactly one"), "{err}");
    }

    #[test]
    fn foundry_allowlist_accepts_only_the_documented_services_ai_host() {
        assert!(
            parse_azure_endpoint(AzureProvider::Foundry, "https://acct.services.ai.azure.com")
                .is_ok()
        );
        for endpoint in [
            // Valid for Azure OpenAI, but Foundry's Claude passthrough is not
            // documented on either of these hosts.
            "https://acct.openai.azure.com",
            "https://acct.cognitiveservices.azure.com",
            "https://acct.services.ai.azure.com.evil.example",
        ] {
            assert!(
                parse_azure_endpoint(AzureProvider::Foundry, endpoint).is_err(),
                "{endpoint} should be rejected for Foundry"
            );
        }
    }
}
