use tokio::sync::oneshot;

use crate::arm::AzureVerifier;
use crate::config::{AzureVerifyConfig, PeriodicAzureVerifySettings};
use crate::error::{classify_verification_error, VerificationFailureKind};

/// One configured Azure account plus its own consecutive-transient-failure
/// count. The counters are per target on purpose: a healthy Azure `OpenAI`
/// account must not clear a Foundry account's failures, or a worker running
/// both could ride out an indefinite Foundry outage.
struct TargetState {
    config: AzureVerifyConfig,
    transient_failures: u32,
}

pub(crate) async fn run_periodic_azure_verification(
    targets: Vec<AzureVerifyConfig>,
    settings: PeriodicAzureVerifySettings,
    fatal_shutdown: oneshot::Sender<String>,
) {
    let mut states: Vec<TargetState> = targets
        .into_iter()
        .map(|config| TargetState {
            config,
            transient_failures: 0,
        })
        .collect();

    // Built once and reused for the lifetime of the loop: a fresh client per
    // cycle would discard the connection pool every interval, forever.
    let verifier = match AzureVerifier::new() {
        Ok(verifier) => verifier,
        Err(err) => {
            let _ = fatal_shutdown.send(format!("build Azure verification HTTP client: {err:#}"));
            return;
        }
    };

    let mut full_sweep = tokio::time::interval(settings.interval);
    let mut deployment_poll = tokio::time::interval(settings.deployment_interval);
    // Do not run an extra immediate sweep: boot already performed the full
    // gate, and the first periodic events should occur at their configured
    // intervals.
    full_sweep.tick().await;
    deployment_poll.tick().await;

    loop {
        tokio::select! {
            _ = full_sweep.tick() => {
                for state in &mut states {
                    let result = verifier.verify_target(&state.config).await;
                    if let Some(reason) = record_result(
                        state,
                        result,
                        "owner-capture verification",
                        settings.transient_failure_limit,
                    ) {
                        let _ = fatal_shutdown.send(reason);
                        return;
                    }
                }
            }
            _ = deployment_poll.tick() => {
                for state in &mut states {
                    let result = verifier.verify_deployment_bindings(&state.config).await;
                    if let Some(reason) = record_result(
                        state,
                        result,
                        "deployment binding verification",
                        settings.transient_failure_limit,
                    ) {
                        let _ = fatal_shutdown.send(reason);
                        return;
                    }
                }
            }
        }
    }
}

fn record_result(
    state: &mut TargetState,
    result: anyhow::Result<()>,
    operation: &str,
    transient_failure_limit: u32,
) -> Option<String> {
    let provider = state.config.provider.label();
    match result {
        Ok(()) => {
            if state.transient_failures > 0 {
                tracing::info!(
                    provider,
                    operation,
                    recovered_after = state.transient_failures,
                    "periodic Azure verification recovered",
                );
                state.transient_failures = 0;
            }
            None
        }
        Err(err) => match classify_verification_error(&err) {
            VerificationFailureKind::Definitive => {
                tracing::error!(
                    provider,
                    operation,
                    error = %err,
                    "periodic Azure verification failed definitively",
                );
                Some(format!(
                    "definitive {provider} {operation} failure: {err:#}"
                ))
            }
            VerificationFailureKind::Transient => {
                state.transient_failures = state.transient_failures.saturating_add(1);
                if state.transient_failures >= transient_failure_limit {
                    tracing::error!(
                        provider,
                        operation,
                        error = %err,
                        transient_failures = state.transient_failures,
                        transient_failure_limit,
                        "periodic Azure verification exceeded transient failure tolerance",
                    );
                    Some(format!(
                        "{provider} {operation} had {} consecutive transient failures \
                         (limit {transient_failure_limit}): {err:#}",
                        state.transient_failures,
                    ))
                } else {
                    tracing::warn!(
                        provider,
                        operation,
                        error = %err,
                        transient_failures = state.transient_failures,
                        transient_failure_limit,
                        "periodic Azure verification hit a transient error",
                    );
                    None
                }
            }
        },
    }
}
