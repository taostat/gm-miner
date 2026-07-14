use std::collections::BTreeMap;

use anyhow::{bail, Result};

use crate::arm::{ArmDeploymentList, ANTHROPIC_MODEL_FORMAT};

/// Split a deployment list into the deployments Azure's RAI content filter
/// actually governs, and the Anthropic-format ones it does not.
///
/// One `AIServices` account can hold GPT *and* Claude deployments — the same
/// account can back `OPENAI_UPSTREAM=azure` and `ANTHROPIC_UPSTREAM=foundry` at
/// once. Azure's RAI filter is not in Claude's request path, and Microsoft's own
/// Claude templates still set `raiPolicyName` to a synchronous default, so
/// judging an Anthropic-format deployment by its RAI mode would fail a
/// perfectly good account.
///
/// `format` is a free-form string in the ARM schema, so only the exactly-known
/// Anthropic value is skipped: a format we do not recognise might be governed by
/// the filter, and is still checked.
pub(crate) fn split_azure_governed_deployments(
    all: ArmDeploymentList,
) -> (ArmDeploymentList, usize) {
    let (skipped, governed): (Vec<_>, Vec<_>) = all.value.into_iter().partition(|deployment| {
        deployment.properties.model.format.as_deref() == Some(ANTHROPIC_MODEL_FORMAT)
    });
    (
        ArmDeploymentList {
            value: governed,
            next_link: None,
        },
        skipped.len(),
    )
}

/// Drop the deployments whose verdict is not yet observable, keeping the ones
/// that already prove something:
///
/// - a deployment with NO `raiPolicyName` is a violation on sight — no read is
///   pending, so it is kept and reported even if the sweep was cut short;
/// - a deployment whose policy we DID resolve is judged on that policy's mode;
/// - a deployment whose policy read never happened (throttled, or never reached
///   because an earlier one throttled) is dropped. Keeping it would assess it
///   against an absent mode and report a violation Azure never told us about —
///   manufacturing a definitive finding out of a transient failure, and killing
///   miners on an Azure hiccup.
///
/// On a complete sweep every referenced policy is resolved, so this drops
/// nothing and the assessment is exactly what it always was.
pub(crate) fn retain_observable_deployments(
    deployments: &mut ArmDeploymentList,
    policy_modes: &BTreeMap<String, Option<String>>,
) {
    deployments.value.retain(|deployment| {
        match deployment
            .properties
            .rai_policy_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            None => true,
            Some(policy) => policy_modes.contains_key(policy),
        }
    });
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamingConfigAssessment {
    pub(crate) deployment_count: usize,
    pub(crate) checked_policy_count: usize,
    pub(crate) violations: Vec<StreamingConfigViolation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StreamingConfigViolation {
    MissingRaiPolicy {
        deployment: String,
    },
    SynchronousMode {
        policy: String,
        mode: Option<String>,
        deployments: Vec<String>,
    },
}

pub(crate) fn assess_streaming_configuration(
    deployments: &ArmDeploymentList,
    policy_modes: &BTreeMap<String, Option<String>>,
) -> StreamingConfigAssessment {
    let mut deployments_by_policy = BTreeMap::<String, Vec<String>>::new();
    let mut violations = Vec::new();

    for deployment in &deployments.value {
        let deployment_name = if deployment.name.trim().is_empty() {
            "<unnamed>".to_owned()
        } else {
            deployment.name.clone()
        };
        match deployment
            .properties
            .rai_policy_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            Some(policy_name) => {
                deployments_by_policy
                    .entry(policy_name.to_owned())
                    .or_default()
                    .push(deployment_name);
            }
            None => {
                violations.push(StreamingConfigViolation::MissingRaiPolicy {
                    deployment: deployment_name,
                });
            }
        }
    }

    for (policy, deployments) in deployments_by_policy {
        let mode = policy_modes.get(&policy).cloned().unwrap_or(None);
        if !rai_policy_mode_allows_streaming(mode.as_deref()) {
            violations.push(StreamingConfigViolation::SynchronousMode {
                policy,
                mode,
                deployments,
            });
        }
    }

    StreamingConfigAssessment {
        deployment_count: deployments.value.len(),
        checked_policy_count: policy_modes.len(),
        violations,
    }
}

pub(crate) fn rai_policy_mode_allows_streaming(mode: Option<&str>) -> bool {
    matches!(mode, Some("Asynchronous_filter" | "Deferred"))
}

pub(crate) fn log_streaming_assessment(assessment: &StreamingConfigAssessment) -> Result<()> {
    if assessment.deployment_count == 0 {
        tracing::info!("no Azure OpenAI deployments to check for streaming configuration");
        return Ok(());
    }

    if assessment.violations.is_empty() {
        tracing::info!(
            deployment_count = assessment.deployment_count,
            rai_policy_count = assessment.checked_policy_count,
            "streaming configuration verified: all referenced Azure OpenAI RAI policies use Asynchronous_filter or Deferred",
        );
        return Ok(());
    }

    let violation_messages = assessment
        .violations
        .iter()
        .map(StreamingConfigViolation::message)
        .collect::<Vec<_>>()
        .join("; ");
    tracing::error!(
        violations = %violation_messages,
        "Azure OpenAI streaming configuration failed",
    );
    bail!("Azure OpenAI streaming configuration failed: {violation_messages}");
}

impl StreamingConfigViolation {
    fn message(&self) -> String {
        match self {
            Self::MissingRaiPolicy { deployment } => {
                format!("deployment '{deployment}' has no properties.raiPolicyName")
            }
            Self::SynchronousMode {
                policy,
                mode,
                deployments,
            } => {
                let mode = mode.as_deref().unwrap_or("<missing>");
                format!(
                    "deployment(s) '{}' reference RAI policy '{policy}' with synchronous mode '{mode}'",
                    deployments.join(", ")
                )
            }
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "unit tests intentionally fail hard on malformed fixtures"
)]
mod tests {
    use super::*;
    use crate::arm::{ArmDeploymentList, ArmRaiPolicy};

    fn deployments_from_json(json: &str) -> ArmDeploymentList {
        serde_json::from_str(json).expect("deployment fixture must parse")
    }

    fn rai_policy_from_json(json: &str) -> ArmRaiPolicy {
        serde_json::from_str(json).expect("RAI policy fixture must parse")
    }

    #[test]
    fn streaming_configuration_accepts_asynchronous_filter_mode() {
        let deployments = deployments_from_json(
            r#"{
                "value": [{
                    "name": "gpt-5",
                    "properties": {"raiPolicyName": "async-policy"}
                }]
            }"#,
        );
        let policy = rai_policy_from_json(
            r#"{
                "properties": {"mode": "Asynchronous_filter"}
            }"#,
        );
        let policy_modes = BTreeMap::from([("async-policy".to_owned(), policy.properties.mode)]);

        let assessment = assess_streaming_configuration(&deployments, &policy_modes);
        assert!(assessment.violations.is_empty(), "{assessment:?}");
    }

    #[test]
    fn streaming_configuration_accepts_legacy_deferred_mode() {
        let deployments = deployments_from_json(
            r#"{
                "value": [{
                    "name": "gpt-5",
                    "properties": {"raiPolicyName": "deferred-policy"}
                }]
            }"#,
        );
        let policy = rai_policy_from_json(
            r#"{
                "properties": {"mode": "Deferred"}
            }"#,
        );
        let policy_modes = BTreeMap::from([("deferred-policy".to_owned(), policy.properties.mode)]);

        let assessment = assess_streaming_configuration(&deployments, &policy_modes);
        assert!(assessment.violations.is_empty(), "{assessment:?}");
    }

    #[test]
    fn streaming_configuration_rejects_blocking_mode() {
        let deployments = deployments_from_json(
            r#"{
                "value": [{
                    "name": "gpt-5",
                    "properties": {"raiPolicyName": "blocking-policy"}
                }]
            }"#,
        );
        let policy = rai_policy_from_json(
            r#"{
                "properties": {"mode": "Blocking"}
            }"#,
        );
        let policy_modes = BTreeMap::from([("blocking-policy".to_owned(), policy.properties.mode)]);

        let assessment = assess_streaming_configuration(&deployments, &policy_modes);
        assert_eq!(
            assessment.violations,
            vec![StreamingConfigViolation::SynchronousMode {
                policy: "blocking-policy".to_owned(),
                mode: Some("Blocking".to_owned()),
                deployments: vec!["gpt-5".to_owned()],
            }]
        );
    }

    #[test]
    fn streaming_configuration_rejects_default_mode() {
        let deployments = deployments_from_json(
            r#"{
                "value": [{
                    "name": "gpt-5",
                    "properties": {"raiPolicyName": "default-policy"}
                }]
            }"#,
        );
        let policy = rai_policy_from_json(
            r#"{
                "properties": {"mode": "Default"}
            }"#,
        );
        let policy_modes = BTreeMap::from([("default-policy".to_owned(), policy.properties.mode)]);

        let assessment = assess_streaming_configuration(&deployments, &policy_modes);
        assert_eq!(
            assessment.violations,
            vec![StreamingConfigViolation::SynchronousMode {
                policy: "default-policy".to_owned(),
                mode: Some("Default".to_owned()),
                deployments: vec!["gpt-5".to_owned()],
            }]
        );
    }

    #[test]
    fn streaming_configuration_rejects_missing_mode() {
        let deployments = deployments_from_json(
            r#"{
                "value": [{
                    "name": "gpt-5",
                    "properties": {"raiPolicyName": "missing-mode-policy"}
                }]
            }"#,
        );
        let policy = rai_policy_from_json(
            r#"{
                "properties": {}
            }"#,
        );
        let policy_modes =
            BTreeMap::from([("missing-mode-policy".to_owned(), policy.properties.mode)]);

        let assessment = assess_streaming_configuration(&deployments, &policy_modes);
        assert_eq!(
            assessment.violations,
            vec![StreamingConfigViolation::SynchronousMode {
                policy: "missing-mode-policy".to_owned(),
                mode: None,
                deployments: vec!["gpt-5".to_owned()],
            }]
        );
    }

    /// One `AIServices` account can serve BOTH upstreams: GPT deployments for
    /// `OPENAI_UPSTREAM=azure` and Claude deployments for
    /// `ANTHROPIC_UPSTREAM=foundry`. Microsoft's own Claude templates set
    /// `raiPolicyName: Microsoft.DefaultV2` — a synchronous mode — so judging a
    /// Claude deployment by Azure's RAI filter would fail the boot gate on an
    /// account that is perfectly fine. Azure's filter is not in Claude's path.
    #[test]
    fn a_mixed_account_does_not_fail_on_its_claude_deployments() {
        let all = deployments_from_json(
            r#"{"value": [
                {"name": "gpt-5", "properties": {
                    "model": {"format": "OpenAI", "name": "gpt-5"},
                    "raiPolicyName": "async-policy"
                }},
                {"name": "claude-opus-4-8", "properties": {
                    "model": {"format": "Anthropic", "name": "claude-opus-4-8"},
                    "raiPolicyName": "Microsoft.DefaultV2"
                }}
            ]}"#,
        );
        let (governed, skipped) = split_azure_governed_deployments(all);
        assert_eq!(skipped, 1, "the Claude deployment must be skipped");
        assert_eq!(governed.value.len(), 1);
        assert_eq!(governed.value[0].name, "gpt-5");

        // The Claude deployment's synchronous RAI policy is never consulted, so
        // the account passes on the strength of its GPT deployment alone.
        let policy_modes = BTreeMap::from([(
            "async-policy".to_owned(),
            Some("Asynchronous_filter".to_owned()),
        )]);
        let assessment = assess_streaming_configuration(&governed, &policy_modes);
        assert!(assessment.violations.is_empty(), "{assessment:?}");
        assert!(log_streaming_assessment(&assessment).is_ok());
    }

    /// A model format we do not recognise might be governed by Azure's filter,
    /// so it must still be checked — only the exactly-known Anthropic value is
    /// skipped.
    #[test]
    fn an_unknown_model_format_is_still_checked() {
        let all = deployments_from_json(
            r#"{"value": [
                {"name": "mystery", "properties": {"model": {"format": "FutureVendor2027"}}},
                {"name": "no-format", "properties": {}}
            ]}"#,
        );
        let (governed, skipped) = split_azure_governed_deployments(all);
        assert_eq!(skipped, 0);
        assert_eq!(governed.value.len(), 2);

        // Neither declares an RAI policy, so both are treated as buffering.
        let assessment = assess_streaming_configuration(&governed, &BTreeMap::new());
        assert_eq!(assessment.violations.len(), 2, "{assessment:?}");
    }

    #[test]
    fn streaming_configuration_accepts_empty_deployments_list() {
        let deployments = deployments_from_json(r#"{"value": []}"#);
        let policy_modes = BTreeMap::new();

        let assessment = assess_streaming_configuration(&deployments, &policy_modes);
        assert_eq!(assessment.deployment_count, 0);
        assert!(assessment.violations.is_empty(), "{assessment:?}");
    }

    #[test]
    fn log_streaming_assessment_always_fails_on_synchronous_deployment() {
        // Async-filter enforcement is gm policy; there is no flag to disable it.
        let deployments = deployments_from_json(
            r#"{
                "value": [{
                    "name": "gpt-5",
                    "properties": {"raiPolicyName": "blocking-policy"}
                }]
            }"#,
        );
        let policy = rai_policy_from_json(r#"{"properties": {"mode": "Blocking"}}"#);
        let policy_modes = BTreeMap::from([("blocking-policy".to_owned(), policy.properties.mode)]);
        let assessment = assess_streaming_configuration(&deployments, &policy_modes);

        let err = log_streaming_assessment(&assessment)
            .expect_err("synchronous deployment must always fail verification");
        assert!(
            err.to_string().contains("streaming configuration failed"),
            "{err}"
        );
    }

    #[test]
    fn log_streaming_assessment_passes_on_async_deployment() {
        let deployments = deployments_from_json(
            r#"{
                "value": [{
                    "name": "gpt-5",
                    "properties": {"raiPolicyName": "async-policy"}
                }]
            }"#,
        );
        let policy = rai_policy_from_json(r#"{"properties": {"mode": "Asynchronous_filter"}}"#);
        let policy_modes = BTreeMap::from([("async-policy".to_owned(), policy.properties.mode)]);
        let assessment = assess_streaming_configuration(&deployments, &policy_modes);

        assert!(
            log_streaming_assessment(&assessment).is_ok(),
            "Asynchronous_filter deployment must pass"
        );
    }

    #[test]
    fn log_streaming_assessment_passes_on_empty_deployments() {
        let deployments = deployments_from_json(r#"{"value": []}"#);
        let assessment = assess_streaming_configuration(&deployments, &BTreeMap::new());

        assert!(
            log_streaming_assessment(&assessment).is_ok(),
            "zero deployments must pass"
        );
    }
}
