mod streaming;

use anyhow::{bail, Context, Result};
use reqwest::Url;
use serde_json::Value;

pub(crate) use self::streaming::{
    assess_streaming_configuration, log_streaming_assessment, split_azure_governed_deployments,
};
use super::arm::{ArmAccount, ArmChildResource, DiagnosticSettingsList};
use super::config::AzureProvider;
use super::endpoint::AzureEndpoint;

/// The account kind that carries Foundry projects, connections, and capability
/// hosts. A classic `kind: OpenAI` account has none of those child collections.
pub(crate) const AI_SERVICES_KIND: &str = "AIServices";

const ALLOWED_OPENAI_ACCOUNT_KINDS: [&str; 2] = ["OpenAI", AI_SERVICES_KIND];
/// Foundry serves Claude only from an `AIServices` account (Microsoft's own
/// Claude reference templates create exactly that kind), so accept nothing else.
const ALLOWED_FOUNDRY_ACCOUNT_KINDS: [&str; 1] = [AI_SERVICES_KIND];

pub(crate) fn assert_account_binding<'account>(
    provider: AzureProvider,
    endpoint: &AzureEndpoint,
    account: &'account ArmAccount,
) -> Result<&'account str> {
    let allowed_kinds: &[&str] = match provider {
        AzureProvider::OpenAi => &ALLOWED_OPENAI_ACCOUNT_KINDS,
        AzureProvider::Foundry => &ALLOWED_FOUNDRY_ACCOUNT_KINDS,
    };
    if !allowed_kinds.contains(&account.kind.as_str()) {
        bail!(
            "{} account kind '{}' is not allowed; expected one of {}",
            provider.label(),
            account.kind,
            allowed_kinds.join(", ")
        );
    }
    let custom_subdomain = account
        .properties
        .custom_sub_domain_name
        .as_deref()
        .context("Azure account properties.customSubDomainName is missing")?;
    if custom_subdomain.trim().is_empty() {
        bail!("Azure account properties.customSubDomainName is empty");
    }
    let custom_subdomain = custom_subdomain.trim().to_ascii_lowercase();
    if custom_subdomain != endpoint.account_name {
        bail!(
            "Azure account properties.customSubDomainName '{custom_subdomain}' does not match configured endpoint account label '{}'",
            endpoint.account_name
        );
    }
    let expected_host = format!("{custom_subdomain}{}", endpoint.suffix);
    let arm_endpoint = account
        .properties
        .endpoint
        .as_deref()
        .context("Azure account properties.endpoint is missing")?;
    let arm_url = Url::parse(arm_endpoint)
        .with_context(|| format!("parse Azure account endpoint {arm_endpoint:?}"))?;
    if arm_url.scheme() != "https" {
        bail!("Azure account properties.endpoint must use https");
    }
    if !arm_url.username().is_empty() || arm_url.password().is_some() {
        bail!("Azure account properties.endpoint must not contain userinfo");
    }
    let arm_host = arm_url
        .host_str()
        .context("Azure account properties.endpoint must include a DNS host")?
        .to_ascii_lowercase();
    if arm_host != expected_host {
        bail!(
            "Azure account properties.endpoint host '{arm_host}' did not match expected '{expected_host}'",
        );
    }
    if arm_host != endpoint.host {
        bail!(
            "{} account endpoint host '{arm_host}' does not match the configured endpoint host '{}'",
            provider.label(),
            endpoint.host
        );
    }
    if account
        .properties
        .rai_monitor_config
        .as_ref()
        .is_some_and(|value| !value.is_null())
    {
        bail!("Azure account properties.raiMonitorConfig must be null or absent");
    }
    if account
        .properties
        .user_owned_storage
        .as_ref()
        .is_some_and(non_empty_json_value)
    {
        bail!("Azure account properties.userOwnedStorage must be null, absent, or empty");
    }
    if account.id.trim().is_empty() {
        bail!("Azure account id is empty");
    }
    Ok(&account.id)
}

pub(crate) fn non_empty_json_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
        Value::String(value) => !value.trim().is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

/// An Azure account backing a gm miner is inference-only: it exports nothing,
/// so the diagnostic-settings list must be EMPTY. Presence is the failure —
/// enabled or not, whatever its categories, whatever its destination.
///
/// Stricter than inspecting the fields, deliberately. Microsoft publishes no
/// field-level schema for the `RequestResponse` category, so whether it can
/// carry request bodies for this resource kind is unsettled; a future sink would
/// arrive as a destination field this verifier does not model; and a *disabled*
/// setting can be enabled between two polls without ever failing a check.
/// Requiring zero settings moots all three.
///
/// This applies to Azure `OpenAI` accounts as well as Foundry ones: an account
/// shipping request logs to an operator-owned workspace is the same capture
/// surface whichever upstream it serves.
pub(crate) fn assert_no_diagnostic_capture(
    provider: AzureProvider,
    scope: &str,
    resource_id: &str,
    settings: &DiagnosticSettingsList,
) -> Result<()> {
    if settings.value.is_empty() {
        return Ok(());
    }
    let named: Vec<String> = settings
        .value
        .iter()
        .map(|setting| {
            let categories: Vec<&str> = setting
                .properties
                .logs
                .iter()
                .filter(|log| log.enabled)
                .map(|log| {
                    log.category
                        .as_deref()
                        .or(log.category_group.as_deref())
                        .unwrap_or("<unnamed>")
                })
                .collect();
            if categories.is_empty() {
                setting.name.clone()
            } else {
                format!("{} ({})", setting.name, categories.join(", "))
            }
        })
        .collect();
    let first = settings
        .value
        .first()
        .map_or("<unnamed>", |s| s.name.as_str());
    bail!(
        "{} {scope} has {} diagnostic setting(s) ({}). A gm miner's Azure account must export \
         nothing: a diagnostic setting is a sink for request data, and a disabled one can be \
         enabled between two verification polls. Remove them, then redeploy:\n  \
         az monitor diagnostic-settings delete --name '{first}' --resource '{resource_id}'\n  \
         az monitor diagnostic-settings list --resource '{resource_id}'   # expect: []",
        provider.label(),
        settings.value.len(),
        named.join(", "),
    )
}

/// Reject every child resource in a capture-capable collection.
///
/// Connections are how an operator attaches a sink to an account or project —
/// and an `AppInsights` connection alone is enough for Foundry to trace prompt
/// content server-side with no code change on the caller's part. Capability
/// hosts redirect Agent-Service storage to operator-owned stores. An
/// inference-only account needs neither, so the safe rule is "none", which also
/// fails closed on connection categories that do not exist yet.
pub(crate) fn assert_no_capture_children(
    provider: AzureProvider,
    scope: &str,
    collection: &str,
    children: &[ArmChildResource],
) -> Result<()> {
    if children.is_empty() {
        return Ok(());
    }
    let named: Vec<String> = children
        .iter()
        .map(|child| match child.properties.category.as_deref() {
            Some(category) => format!("{} ({category})", child.name),
            None => child.name.clone(),
        })
        .collect();
    bail!(
        "{} {scope} has {} {collection} ({}). A gm miner's Azure account must have none — they \
         are the sinks prompt content would be captured to. Remove them, then redeploy.",
        provider.label(),
        children.len(),
        named.join(", "),
    )
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "unit tests intentionally fail hard on malformed fixtures"
)]
mod tests {
    use super::*;
    use crate::azure_verify::arm::ArmAccount;
    use crate::azure_verify::endpoint::parse_azure_endpoint;

    fn valid_endpoint() -> AzureEndpoint {
        parse_azure_endpoint(AzureProvider::OpenAi, "https://acct.openai.azure.com/")
            .expect("valid endpoint must parse")
    }

    fn account_from_json(json: &str) -> ArmAccount {
        serde_json::from_str(json).expect("fixture must parse")
    }

    fn valid_account_json() -> &'static str {
        r#"{
            "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct",
            "kind": "OpenAI",
            "properties": {
                "customSubDomainName": "acct",
                "endpoint": "https://acct.openai.azure.com/",
                "raiMonitorConfig": null,
                "userOwnedStorage": []
            }
        }"#
    }

    #[test]
    fn account_binding_accepts_allowed_kind_matching_endpoint_and_no_storage() {
        let endpoint = valid_endpoint();
        let account = account_from_json(valid_account_json());
        assert!(assert_account_binding(AzureProvider::OpenAi, &endpoint, &account).is_ok());
    }

    #[test]
    fn account_binding_accepts_services_ai_suffix_matching_endpoint() {
        let endpoint =
            parse_azure_endpoint(AzureProvider::OpenAi, "https://acct.services.ai.azure.com/")
                .expect("valid endpoint must parse");
        let account = account_from_json(
            r#"{
                "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct",
                "kind": "AIServices",
                "properties": {
                    "customSubDomainName": "acct",
                    "endpoint": "https://acct.services.ai.azure.com/",
                    "raiMonitorConfig": null,
                    "userOwnedStorage": []
                }
            }"#,
        );
        assert!(assert_account_binding(AzureProvider::OpenAi, &endpoint, &account).is_ok());
    }

    #[test]
    fn account_binding_rejects_custom_subdomain_mismatch() {
        let endpoint = valid_endpoint();
        let account = account_from_json(
            r#"{
                "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct",
                "kind": "OpenAI",
                "properties": {
                    "customSubDomainName": "other",
                    "endpoint": "https://acct.openai.azure.com/"
                }
            }"#,
        );
        let err = assert_account_binding(AzureProvider::OpenAi, &endpoint, &account)
            .expect_err("custom subdomain mismatch must fail")
            .to_string();
        assert!(err.contains("customSubDomainName"), "{err}");
    }

    #[test]
    fn account_binding_rejects_endpoint_host_mismatch() {
        let endpoint =
            parse_azure_endpoint(AzureProvider::OpenAi, "https://other.openai.azure.com/")
                .expect("valid endpoint must parse");
        let account = account_from_json(valid_account_json());
        let err = assert_account_binding(AzureProvider::OpenAi, &endpoint, &account)
            .expect_err("host mismatch must fail")
            .to_string();
        assert!(err.contains("does not match configured"), "{err}");
    }

    #[test]
    fn account_binding_rejects_content_storage_paths() {
        for properties in [
            r#""raiMonitorConfig": {"enabled": true}, "userOwnedStorage": []"#,
            r#""raiMonitorConfig": null, "userOwnedStorage": [{"id": "storage"}]"#,
            r#""raiMonitorConfig": null, "userOwnedStorage": {"id": "storage"}"#,
        ] {
            let json = format!(
                r#"{{
                    "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct",
                    "kind": "OpenAI",
                    "properties": {{
                        "customSubDomainName": "acct",
                        "endpoint": "https://acct.openai.azure.com/",
                        {properties}
                    }}
                }}"#
            );
            let endpoint = valid_endpoint();
            let account = account_from_json(&json);
            assert!(
                assert_account_binding(AzureProvider::OpenAi, &endpoint, &account).is_err(),
                "{properties} must fail"
            );
        }
    }

    #[test]
    fn account_binding_rejects_unallowed_kind() {
        let account = account_from_json(
            r#"{
                "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct",
                "kind": "CognitiveServices",
                "properties": {
                    "customSubDomainName": "acct",
                    "endpoint": "https://acct.openai.azure.com/"
                }
            }"#,
        );
        let err = assert_account_binding(AzureProvider::OpenAi, &valid_endpoint(), &account)
            .expect_err("kind must fail")
            .to_string();
        assert!(
            err.contains("kind 'CognitiveServices' is not allowed"),
            "{err}"
        );
    }

    fn foundry_endpoint() -> AzureEndpoint {
        parse_azure_endpoint(
            AzureProvider::Foundry,
            "https://acct.services.ai.azure.com/",
        )
        .expect("valid Foundry endpoint must parse")
    }

    fn foundry_account_json(kind: &str) -> String {
        format!(
            r#"{{
                "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct",
                "kind": "{kind}",
                "properties": {{
                    "customSubDomainName": "acct",
                    "endpoint": "https://acct.services.ai.azure.com/",
                    "raiMonitorConfig": null,
                    "userOwnedStorage": []
                }}
            }}"#
        )
    }

    #[test]
    fn foundry_account_binding_requires_ai_services_kind() {
        let endpoint = foundry_endpoint();
        let account = account_from_json(&foundry_account_json("AIServices"));
        assert!(assert_account_binding(AzureProvider::Foundry, &endpoint, &account).is_ok());

        // `OpenAI` is a legal kind for the Azure OpenAI upstream but never
        // serves Claude, so Foundry must reject it.
        let account = account_from_json(&foundry_account_json("OpenAI"));
        let err = assert_account_binding(AzureProvider::Foundry, &endpoint, &account)
            .expect_err("OpenAI kind must fail for Foundry")
            .to_string();
        assert!(
            err.contains("Microsoft Foundry account kind 'OpenAI'"),
            "{err}"
        );
    }

    fn diagnostics_from_json(json: &str) -> DiagnosticSettingsList {
        serde_json::from_str(json).expect("fixture must parse")
    }

    #[test]
    fn foundry_accepts_a_scope_with_no_diagnostic_settings_at_all() {
        let settings = diagnostics_from_json(r#"{"value": []}"#);
        assert!(assert_no_diagnostic_capture(AzureProvider::Foundry, "account", "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct", &settings).is_ok());
    }

    /// An ARM list response we cannot parse must fail the verification, not
    /// deserialize into an empty list that passes every capture check. Without
    /// this, a renamed or missing `value` key would silently disable the sweep.
    #[test]
    fn an_unparseable_arm_list_response_is_not_an_empty_list() {
        for body in ["{}", r#"{"settings": []}"#] {
            assert!(
                serde_json::from_str::<DiagnosticSettingsList>(body).is_err(),
                "{body} must not deserialize to an empty diagnostic-settings list"
            );
        }
        for body in ["{}", r#"{"items": []}"#] {
            assert!(
                serde_json::from_str::<super::super::arm::ArmChildList>(body).is_err(),
                "{body} must not deserialize to an empty child list"
            );
        }
    }

    #[test]
    fn foundry_rejects_any_diagnostic_setting_however_it_is_shaped() {
        // A category the Azure OpenAI path allows as "metadata-only" — Foundry
        // rejects it, because Microsoft publishes no field-level schema saying
        // RequestResponse can never carry bodies for this resource kind.
        let logs = diagnostics_from_json(
            r#"{"value": [{"name": "export", "properties": {"logs": [{"category": "RequestResponse", "enabled": true}]}}]}"#,
        );
        let err = assert_no_diagnostic_capture(AzureProvider::Foundry, "account", "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct", &logs)
            .expect_err("enabled log category must fail")
            .to_string();
        assert!(err.contains("RequestResponse"), "{err}");

        // A DISABLED setting must fail too: the operator can flip it on between
        // two verification polls without ever failing a check.
        let disabled = diagnostics_from_json(
            r#"{"value": [{"name": "dormant", "properties": {
                "logs": [{"category": "Audit", "enabled": false}],
                "metrics": [{"category": "AllMetrics", "enabled": false}]
            }}]}"#,
        );
        let err = assert_no_diagnostic_capture(AzureProvider::Foundry, "account", "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct", &disabled)
            .expect_err("a dormant diagnostic setting must fail")
            .to_string();
        assert!(err.contains("dormant"), "{err}");

        // A setting whose sink is a destination field this verifier does not
        // model must still fail — presence is the failure, not the fields.
        let unknown_sink = diagnostics_from_json(
            r#"{"value": [{"name": "future", "properties": {
                "logs": [],
                "dataCollectionRuleId": "/subscriptions/sub/../rules/exfil"
            }}]}"#,
        );
        assert!(assert_no_diagnostic_capture(AzureProvider::Foundry, "account", "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct", &unknown_sink).is_err());

        // And the scope is named, so a project-attached export is diagnosable.
        let err = assert_no_diagnostic_capture(AzureProvider::Foundry, "project 'p1'", "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct", &logs)
            .expect_err("project export must fail")
            .to_string();
        assert!(err.contains("project 'p1'"), "{err}");
    }

    fn children_from_json(json: &str) -> Vec<ArmChildResource> {
        serde_json::from_str(json).expect("fixture must parse")
    }

    #[test]
    fn foundry_rejects_any_connection_including_app_insights() {
        assert!(
            assert_no_capture_children(AzureProvider::Foundry, "account", "connections", &[])
                .is_ok()
        );

        let app_insights = children_from_json(
            r#"[{"name": "telemetry", "properties": {"category": "AppInsights"}}]"#,
        );
        let err = assert_no_capture_children(
            AzureProvider::Foundry,
            "project 'p1'",
            "connections",
            &app_insights,
        )
        .expect_err("an AppInsights connection must fail")
        .to_string();
        assert!(err.contains("AppInsights"), "{err}");
        assert!(err.contains("project 'p1'"), "{err}");

        // Not just AppInsights: any sink category, and any category we have
        // never seen, must fail closed too.
        let blob =
            children_from_json(r#"[{"name": "store", "properties": {"category": "AzureBlob"}}]"#);
        assert!(assert_no_capture_children(
            AzureProvider::Foundry,
            "account",
            "connections",
            &blob
        )
        .is_err());
        let unknown =
            children_from_json(r#"[{"name": "x", "properties": {"category": "FutureSink2027"}}]"#);
        assert!(assert_no_capture_children(
            AzureProvider::Foundry,
            "account",
            "connections",
            &unknown
        )
        .is_err());
    }

    /// The capture rule is a property of the account, not of the upstream: an
    /// Azure `OpenAI` account exporting request logs is the same surface, and the
    /// old warn-only allowlist let it through.
    #[test]
    fn azure_openai_is_held_to_the_same_export_rule_and_the_error_is_actionable() {
        let logs = diagnostics_from_json(
            r#"{"value": [{"name": "to-log-analytics", "properties": {"logs": [{"category": "RequestResponse", "enabled": true}]}}]}"#,
        );
        let err = assert_no_diagnostic_capture(
            AzureProvider::OpenAi,
            "account",
            "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct",
            &logs,
        )
        .expect_err("an Azure OpenAI export must fail, not warn")
        .to_string();
        assert!(err.contains("Azure OpenAI"), "{err}");
        // The operator must be told exactly what to remove — this fires at CVM
        // boot, so a vague message is a crashloop with no way out.
        assert!(err.contains("to-log-analytics"), "{err}");
        assert!(
            err.contains("az monitor diagnostic-settings delete"),
            "{err}"
        );
    }

    #[test]
    fn foundry_rejects_capability_hosts() {
        let hosts = children_from_json(r#"[{"name": "agents", "properties": {}}]"#);
        let err = assert_no_capture_children(
            AzureProvider::Foundry,
            "project 'p1'",
            "capabilityHosts",
            &hosts,
        )
        .expect_err("a capability host must fail")
        .to_string();
        assert!(err.contains("capabilityHosts"), "{err}");
    }
}
