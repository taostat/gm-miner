use std::collections::BTreeMap;

use anyhow::{bail, Result};

use crate::azure_verify::arm::ArmDeploymentList;

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
    use crate::azure_verify::arm::{ArmDeploymentList, ArmRaiPolicy};

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
