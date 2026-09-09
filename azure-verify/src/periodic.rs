use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::arm::AzureVerifier;
use crate::config::{AzureVerifyConfig, PeriodicAzureVerifySettings};
use crate::error::{classify_verification_error, VerificationFailureKind};

/// One configured Azure account plus independent consecutive-transient-failure
/// counts for the two periodic operations. The counters are per target and per
/// operation on purpose: a healthy deployment poll must not clear a capture
/// audit's failures, or a worker running both could ride out an indefinite
/// owner-capture outage.
struct TargetState {
    config: AzureVerifyConfig,
    capture_failures: u32,
    deployment_failures: u32,
}

impl TargetState {
    fn new(config: AzureVerifyConfig) -> Self {
        Self {
            config,
            capture_failures: 0,
            deployment_failures: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum VerificationOperation {
    CaptureAudit,
    DeploymentBinding,
}

impl VerificationOperation {
    fn label(self) -> &'static str {
        match self {
            Self::CaptureAudit => "owner-capture verification",
            Self::DeploymentBinding => "deployment binding verification",
        }
    }
}

/// A deployment check may not remain in flight indefinitely: after two poll
/// intervals without a completed verification, the binding is stale and the
/// data plane must stop rather than serving on an unverified deployment.
const DEPLOYMENT_STALE_INTERVALS: u32 = 2;

pub(crate) async fn run_periodic_azure_verification(
    targets: Vec<AzureVerifyConfig>,
    settings: PeriodicAzureVerifySettings,
    fatal_shutdown: oneshot::Sender<String>,
) {
    // Built once and reused for the lifetime of the loop: a fresh client per
    // cycle would discard the connection pool every interval, forever.
    let verifier = match AzureVerifier::new() {
        Ok(verifier) => verifier,
        Err(err) => {
            let _ = fatal_shutdown.send(format!("build Azure verification HTTP client: {err:#}"));
            return;
        }
    };

    run_periodic_azure_verification_with_verifier(verifier, targets, settings, fatal_shutdown)
        .await;
}

async fn run_periodic_azure_verification_with_verifier(
    verifier: AzureVerifier,
    targets: Vec<AzureVerifyConfig>,
    settings: PeriodicAzureVerifySettings,
    fatal_shutdown: oneshot::Sender<String>,
) {
    if targets.is_empty() {
        return;
    }

    let (failure_tx, mut failure_rx) = mpsc::unbounded_channel();
    let mut tasks = Vec::with_capacity(targets.len().saturating_mul(2));
    for config in targets {
        let capture_tx = failure_tx.clone();
        let capture_verifier = verifier.clone();
        let capture_settings = settings;
        let deployment_config = config.clone();
        tasks.push(tokio::spawn(async move {
            run_capture_audit_loop(capture_verifier, config, capture_settings, capture_tx).await;
        }));

        let deployment_tx = failure_tx.clone();
        let deployment_verifier = verifier.clone();
        let deployment_settings = settings;
        tasks.push(tokio::spawn(async move {
            run_deployment_binding_loop(
                deployment_verifier,
                deployment_config,
                deployment_settings,
                deployment_tx,
            )
            .await;
        }));
    }
    drop(failure_tx);

    if let Some(reason) = failure_rx.recv().await {
        for task in tasks {
            task.abort();
        }
        let _ = fatal_shutdown.send(reason);
    }
}

async fn run_capture_audit_loop(
    verifier: AzureVerifier,
    config: AzureVerifyConfig,
    settings: PeriodicAzureVerifySettings,
    failure_tx: mpsc::UnboundedSender<String>,
) {
    let mut state = TargetState::new(config);
    let mut interval = tokio::time::interval(settings.interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Boot already performed the full gate, so the first periodic event should
    // occur at the configured interval rather than immediately.
    interval.tick().await;

    loop {
        interval.tick().await;
        let result = verifier.verify_target(&state.config).await;
        if let Some(reason) = record_result(
            &mut state,
            result,
            VerificationOperation::CaptureAudit,
            settings.transient_failure_limit,
        ) {
            let _ = failure_tx.send(reason);
            return;
        }
    }
}

async fn run_deployment_binding_loop(
    verifier: AzureVerifier,
    config: AzureVerifyConfig,
    settings: PeriodicAzureVerifySettings,
    failure_tx: mpsc::UnboundedSender<String>,
) {
    let mut state = TargetState::new(config);
    let mut interval = tokio::time::interval(settings.deployment_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;
    let cycle_timeout = settings
        .deployment_interval
        .checked_mul(DEPLOYMENT_STALE_INTERVALS)
        .unwrap_or(Duration::MAX);

    loop {
        interval.tick().await;
        let result = match tokio::time::timeout(
            cycle_timeout,
            verifier.verify_deployment_bindings(&state.config),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "deployment binding verification became stale after {DEPLOYMENT_STALE_INTERVALS} deployment intervals"
            )),
        };
        if let Some(reason) = record_result(
            &mut state,
            result,
            VerificationOperation::DeploymentBinding,
            settings.transient_failure_limit,
        ) {
            let _ = failure_tx.send(reason);
            return;
        }
    }
}

fn record_result(
    state: &mut TargetState,
    result: anyhow::Result<()>,
    operation: VerificationOperation,
    transient_failure_limit: u32,
) -> Option<String> {
    let provider = state.config.provider.label();
    let operation_label = operation.label();
    match result {
        Ok(()) => {
            let transient_failures = match operation {
                VerificationOperation::CaptureAudit => &mut state.capture_failures,
                VerificationOperation::DeploymentBinding => &mut state.deployment_failures,
            };
            if *transient_failures > 0 {
                tracing::info!(
                    provider,
                    operation = operation_label,
                    recovered_after = *transient_failures,
                    "periodic Azure verification recovered",
                );
                *transient_failures = 0;
            }
            None
        }
        Err(err) => match classify_verification_error(&err) {
            VerificationFailureKind::Definitive => {
                tracing::error!(
                    provider,
                    operation = operation_label,
                    error = %err,
                    "periodic Azure verification failed definitively",
                );
                Some(format!(
                    "definitive {provider} {operation_label} failure: {err:#}"
                ))
            }
            VerificationFailureKind::Transient => {
                let transient_failures = match operation {
                    VerificationOperation::CaptureAudit => &mut state.capture_failures,
                    VerificationOperation::DeploymentBinding => &mut state.deployment_failures,
                };
                *transient_failures = transient_failures.saturating_add(1);
                if *transient_failures >= transient_failure_limit {
                    tracing::error!(
                        provider,
                        operation = operation_label,
                        error = %err,
                        transient_failures = *transient_failures,
                        transient_failure_limit,
                        "periodic Azure verification exceeded transient failure tolerance",
                    );
                    Some(format!(
                        "{provider} {operation_label} had {} consecutive transient failures \
                         (limit {transient_failure_limit}): {err:#}",
                        *transient_failures,
                    ))
                } else {
                    tracing::warn!(
                        provider,
                        operation = operation_label,
                        error = %err,
                        transient_failures = *transient_failures,
                        transient_failure_limit,
                        "periodic Azure verification hit a transient error",
                    );
                    None
                }
            }
        },
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "unit tests intentionally fail hard on malformed fixtures"
)]
mod tests {
    use super::*;
    use crate::arm::AzureHttpStatusError;
    use crate::config::AzureProvider;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn throttled() -> anyhow::Error {
        anyhow::Error::new(AzureHttpStatusError {
            label: "test",
            status: reqwest::StatusCode::TOO_MANY_REQUESTS,
            body: "throttled".to_owned(),
        })
    }

    fn state() -> TargetState {
        TargetState {
            config: AzureVerifyConfig {
                provider: AzureProvider::Foundry,
                deployment_map: gm_cloud_hop::parse_deployment_map(
                    gm_cloud_hop::CloudProvider::Foundry,
                    "claude-sonnet-4-6=foundry-sonnet",
                )
                .expect("test deployment map"),
                endpoint: "https://acct.services.ai.azure.com".to_owned(),
                tenant_id: "tenant".to_owned(),
                subscription_id: "subscription".to_owned(),
                resource_group: "resource-group".to_owned(),
                client_id: "client".to_owned(),
                client_secret: "secret".to_owned(),
            },
            capture_failures: 0,
            deployment_failures: 0,
        }
    }

    #[tokio::test]
    async fn slow_capture_sweep_does_not_starve_deployment_poll() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tenant/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "arm-token"
            })))
            .mount(&server)
            .await;
        let account_path =
            "/subscriptions/subscription/resourceGroups/resource-group/providers/Microsoft.CognitiveServices/accounts/acct";
        Mock::given(method("GET"))
            .and(path(account_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": account_path,
                "kind": "AIServices",
                "properties": {
                    "customSubDomainName": "acct",
                    "endpoint": "https://acct.services.ai.azure.com/"
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{account_path}/projects")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "{account_path}/providers/Microsoft.Insights/diagnosticSettings"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(500))
                    .set_body_json(serde_json::json!({"value": []})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{account_path}/deployments")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": []
            })))
            .mount(&server)
            .await;

        let verifier =
            AzureVerifier::with_endpoints(reqwest::Client::new(), server.uri(), server.uri());
        let (fatal_tx, fatal_rx) = oneshot::channel();
        let settings = PeriodicAzureVerifySettings {
            interval: Duration::from_millis(10),
            deployment_interval: Duration::from_millis(20),
            transient_failure_limit: 3,
        };
        let task = tokio::spawn(run_periodic_azure_verification_with_verifier(
            verifier,
            vec![state().config],
            settings,
            fatal_tx,
        ));
        let reason = tokio::time::timeout(Duration::from_millis(250), fatal_rx)
            .await
            .expect("deployment poll must run before the slow capture sweep completes")
            .expect("periodic verifier must report the deployment failure");
        assert!(reason.contains("deployment binding"), "{reason}");
        task.abort();
    }

    #[test]
    fn deployment_success_does_not_clear_capture_audit_failures() {
        let mut state = state();
        for _ in 0..2 {
            assert!(record_result(
                &mut state,
                Err(throttled()),
                VerificationOperation::CaptureAudit,
                3,
            )
            .is_none());
            assert!(record_result(
                &mut state,
                Ok(()),
                VerificationOperation::DeploymentBinding,
                3,
            )
            .is_none());
        }

        assert!(record_result(
            &mut state,
            Err(throttled()),
            VerificationOperation::CaptureAudit,
            3,
        )
        .is_some());
    }
}
