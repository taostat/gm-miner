use std::time::Duration;

use crate::AzureVerifiedTarget;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

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

/// A deployment binding must be successfully reverified within two poll
/// intervals of boot or the previous successful verification. The data plane
/// must stop rather than serving on an unverified deployment.
const DEPLOYMENT_STALE_INTERVALS: u32 = 2;

pub(crate) async fn run_periodic_azure_verification(
    targets: Vec<AzureVerifiedTarget>,
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
    targets: Vec<AzureVerifiedTarget>,
    settings: PeriodicAzureVerifySettings,
    fatal_shutdown: oneshot::Sender<String>,
) {
    if targets.is_empty() {
        return;
    }

    let (failure_tx, mut failure_rx) = mpsc::unbounded_channel();
    let mut tasks = Vec::with_capacity(targets.len().saturating_mul(2));
    for target in targets {
        let config = target.config;
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
                target.binding_verified_at,
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
    binding_verified_at: watch::Sender<Instant>,
    settings: PeriodicAzureVerifySettings,
    failure_tx: mpsc::UnboundedSender<String>,
) {
    let mut state = TargetState::new(config);
    let mut interval = tokio::time::interval_at(
        *binding_verified_at.borrow() + settings.deployment_interval,
        settings.deployment_interval,
    );
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let cycle_timeout = settings
        .deployment_interval
        .checked_mul(DEPLOYMENT_STALE_INTERVALS)
        .unwrap_or(Duration::MAX);
    // The boot gate verified this target before this loop was spawned. Keep
    // the target's staleness deadline anchored to that successful verification
    // rather than starting a fresh timeout for every poll attempt.
    let mut stale_deadline = *binding_verified_at.borrow() + cycle_timeout;

    loop {
        if Instant::now() >= stale_deadline
            || tokio::time::timeout_at(stale_deadline, interval.tick())
                .await
                .is_err()
        {
            let _ = failure_tx.send(stale_failure_message());
            return;
        }

        let result = match tokio::time::timeout_at(
            stale_deadline,
            tokio::time::timeout(
                cycle_timeout,
                verifier.verify_deployment_bindings(&state.config),
            ),
        )
        .await
        {
            Err(_) => Err(stale_failure()),
            Ok(Err(_)) if tokio::time::Instant::now() >= stale_deadline => {
                Err(stale_failure())
            }
            Ok(Err(_)) => Err(anyhow::anyhow!(
                "deployment binding verification exceeded its {DEPLOYMENT_STALE_INTERVALS}-interval cycle timeout"
            )),
            Ok(Ok(result)) => result,
        };
        let successful = result.is_ok();
        if let Some(reason) = record_result(
            &mut state,
            result,
            VerificationOperation::DeploymentBinding,
            settings.transient_failure_limit,
        ) {
            let _ = failure_tx.send(reason);
            return;
        }
        if successful {
            let verified_at = Instant::now();
            binding_verified_at.send_replace(verified_at);
            stale_deadline = verified_at + cycle_timeout;
        }
    }
}

fn stale_failure() -> anyhow::Error {
    anyhow::anyhow!(stale_failure_message())
}

fn stale_failure_message() -> String {
    format!(
        "deployment binding verification became stale after {DEPLOYMENT_STALE_INTERVALS} deployment intervals without a successful verification"
    )
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
    async fn round4_staleness_survives_fast_transient_polls() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let verifier =
            AzureVerifier::with_endpoints(reqwest::Client::new(), server.uri(), server.uri());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let settings = PeriodicAzureVerifySettings {
            interval: Duration::from_secs(30),
            deployment_interval: Duration::from_millis(100),
            transient_failure_limit: 3,
        };
        let task = tokio::spawn(run_deployment_binding_loop(
            verifier,
            state().config,
            watch::channel(Instant::now()).0,
            settings,
            tx,
        ));
        let result = tokio::time::timeout(Duration::from_millis(250), rx.recv()).await;
        task.abort();
        assert!(
            result.is_ok(),
            "no definitive stale failure after 2.5 intervals without successful verification"
        );
    }

    #[tokio::test]
    async fn stalled_read_expires_at_last_success_with_controlled_time() {
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
        let reading = std::sync::Arc::new(tokio::sync::Notify::new());
        let notify = reading.clone();
        Mock::given(method("GET"))
            .and(path(format!("{account_path}/deployments")))
            .respond_with(move |_: &wiremock::Request| {
                notify.notify_one();
                ResponseTemplate::new(200).set_delay(Duration::from_secs(5))
            })
            .mount(&server)
            .await;

        let verifier =
            AzureVerifier::with_endpoints(reqwest::Client::new(), server.uri(), server.uri());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let settings = PeriodicAzureVerifySettings {
            interval: Duration::from_secs(30),
            deployment_interval: Duration::from_millis(100),
            transient_failure_limit: 3,
        };
        let last_success = Instant::now();
        let task = tokio::spawn(run_deployment_binding_loop(
            verifier,
            state().config,
            watch::channel(last_success).0,
            settings,
            tx,
        ));
        reading.notified().await;
        tokio::time::pause();
        let remaining = (last_success + Duration::from_millis(200)) - Instant::now();
        tokio::time::advance(
            remaining
                .checked_sub(Duration::from_millis(1))
                .expect("ARM read began before stale deadline"),
        )
        .await;
        tokio::task::yield_now().await;
        assert!(
            rx.try_recv().is_err(),
            "must not expire before last-success deadline"
        );
        tokio::time::advance(Duration::from_millis(2)).await;
        tokio::task::yield_now().await;
        let result = rx
            .try_recv()
            .expect("must expire at last-success deadline, not per-attempt deadline");
        task.abort();
        assert!(result.contains("became stale"), "{result}");
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
                "value": [{"name":"claude-sonnet-4-6","properties":{"model":{"format":"Anthropic","name":"claude-haiku-4-5"}}}]
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
            vec![AzureVerifiedTarget::new(state().config, Instant::now())],
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
    async fn mount_boot_account(server: &MockServer, account: &str, delay: u64) {
        let base = format!("/subscriptions/subscription/resourceGroups/resource-group/providers/Microsoft.CognitiveServices/accounts/{account}");
        Mock::given(method("GET")).and(path(base.clone())).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":base, "kind":"AIServices", "properties":{"customSubDomainName":account,"endpoint":format!("https://{account}.services.ai.azure.com/")}
            }))).mount(server).await;
        for collection in [
            "projects",
            "connections",
            "capabilityHosts",
            "providers/Microsoft.Insights/diagnosticSettings",
        ] {
            let response =
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"value":[]}));
            let response = if collection == "projects" {
                response.set_delay(Duration::from_millis(delay))
            } else {
                response
            };
            Mock::given(method("GET"))
                .and(path(format!("{base}/{collection}")))
                .respond_with(response)
                .mount(server)
                .await;
        }
        Mock::given(method("GET")).and(path(format!("{base}/deployments"))).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"value":[{
                "name":"claude-sonnet-4-6","properties":{"model":{"format":"Anthropic","name":"claude-sonnet-4-6","version":"1"}}
            }]}))).mount(server).await;
    }

    #[tokio::test]
    async fn aged_boot_binding_is_polled_before_its_inherited_deadline() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"access_token": "token"})),
            )
            .mount(&server)
            .await;
        mount_boot_account(&server, "acct", 0).await;
        let verifier =
            AzureVerifier::with_endpoints(reqwest::Client::new(), server.uri(), server.uri());
        let boot = Instant::now()
            .checked_sub(Duration::from_millis(1500))
            .expect("boot timestamp");
        let target = AzureVerifiedTarget::new(state().config, boot);
        let mut updates = target.binding_verified_at.subscribe();
        let settings = PeriodicAzureVerifySettings {
            interval: Duration::from_secs(30),
            deployment_interval: Duration::from_secs(1),
            transient_failure_limit: 3,
        };
        let readiness = crate::AzureBindingReadiness {
            targets: vec![target.clone()],
            window: settings.deployment_interval * 2,
        };
        let (tx, _rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(run_deployment_binding_loop(
            verifier,
            target.config,
            target.binding_verified_at,
            settings,
            tx,
        ));
        tokio::time::timeout(Duration::from_millis(500), updates.changed())
            .await
            .expect("successful poll must publish its timestamp")
            .expect("poll remains alive");
        assert!(*updates.borrow() > boot);
        assert!(readiness.is_fresh());
        task.abort();
        tokio::time::pause();
        tokio::time::advance(settings.deployment_interval * 2).await;
        assert!(!readiness.is_fresh());
    }

    #[tokio::test]
    async fn catalog_named_model_drift_after_boot_stops_the_periodic_verifier() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"access_token":"token"})),
            )
            .mount(&server)
            .await;
        mount_boot_account(&server, "acct", 0).await;
        let verifier =
            AzureVerifier::with_endpoints(reqwest::Client::new(), server.uri(), server.uri());
        let config = state().config;
        let boot = verifier
            .verify_target_with_timestamp(&config)
            .await
            .expect("honest boot");
        Mock::given(method("GET"))
            .and(path("/subscriptions/subscription/resourceGroups/resource-group/providers/Microsoft.CognitiveServices/accounts/acct/deployments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"value":[{
                "name":"claude-sonnet-4-6","properties":{"model":{"format":"Anthropic","name":"claude-haiku-4-5"}}
            }]})))
            .with_priority(1)
            .mount(&server).await;
        let (tx, rx) = oneshot::channel();
        let settings = PeriodicAzureVerifySettings {
            interval: Duration::from_secs(30),
            deployment_interval: Duration::from_millis(100),
            transient_failure_limit: 3,
        };
        let task = tokio::spawn(run_periodic_azure_verification_with_verifier(
            verifier,
            vec![AzureVerifiedTarget::new(config, boot)],
            settings,
            tx,
        ));
        let result = tokio::time::timeout(Duration::from_secs(1), rx).await;
        task.abort();
        let reason = result
            .expect("poll must detect drift")
            .expect("fatal signal");
        assert!(reason.contains("definitive"), "{reason}");
        assert!(reason.contains("claude-sonnet-4-6"), "{reason}");
        assert!(reason.contains("claude-haiku-4-5"), "{reason}");
    }

    #[tokio::test]
    async fn round5_boot_age_survives_a_later_targets_slow_sweep() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"access_token":"token"})),
            )
            .mount(&server)
            .await;
        mount_boot_account(&server, "acct", 0).await;
        mount_boot_account(&server, "acct2", 300).await;
        let verifier =
            AzureVerifier::with_endpoints(reqwest::Client::new(), server.uri(), server.uri());
        let first = state().config;
        let mut second = first.clone();
        second.endpoint = "https://acct2.services.ai.azure.com".to_owned();
        // Same sequential boot-gate control flow as verify_azure_config_from_env.
        let last_success = verifier
            .verify_target_with_timestamp(&first)
            .await
            .expect("first boot binding");
        verifier
            .verify_target(&second)
            .await
            .expect("valid fixture");
        assert!(last_success.elapsed() > Duration::from_millis(200));
        let settings = PeriodicAzureVerifySettings {
            interval: Duration::from_secs(30),
            deployment_interval: Duration::from_millis(100),
            transient_failure_limit: 3,
        };
        let mut targets = vec![AzureVerifiedTarget::new(first.clone(), last_success)];
        crate::refresh_expired_bindings(&verifier, &mut targets, settings)
            .await
            .expect("earlier target must be refreshed after later sweep");
        assert!(*targets[0].binding_verified_at.borrow() > last_success);
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let mut expired = vec![AzureVerifiedTarget::new(first.clone(), last_success)];
        assert!(
            crate::refresh_expired_bindings(&verifier, &mut expired, settings)
                .await
                .is_err(),
            "unverifiable expired boot evidence must prevent startup"
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(run_deployment_binding_loop(
            verifier,
            first,
            watch::channel(last_success).0,
            PeriodicAzureVerifySettings {
                interval: Duration::from_secs(30),
                deployment_interval: Duration::from_millis(100),
                transient_failure_limit: 3,
            },
            tx,
        ));
        let result = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        task.abort();
        assert!(matches!(result, Ok(Some(_))), "boot verification is already older than two intervals, but starting the loop granted another stale window");
    }
}
