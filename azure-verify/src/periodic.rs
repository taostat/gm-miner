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

    loop {
        tokio::time::sleep(settings.interval).await;
        for state in &mut states {
            let provider = state.config.provider.label();
            match verifier.verify_target(&state.config).await {
                Ok(()) => {
                    if state.transient_failures > 0 {
                        tracing::info!(
                            provider,
                            recovered_after = state.transient_failures,
                            "periodic Azure owner-capture verification recovered",
                        );
                        state.transient_failures = 0;
                    }
                }
                Err(err) => match classify_verification_error(&err) {
                    VerificationFailureKind::Definitive => {
                        let reason = format!(
                            "definitive {provider} owner-capture verification failure: {err:#}"
                        );
                        tracing::error!(
                            provider,
                            error = %err,
                            "periodic Azure owner-capture verification failed definitively",
                        );
                        let _ = fatal_shutdown.send(reason);
                        return;
                    }
                    VerificationFailureKind::Transient => {
                        state.transient_failures = state.transient_failures.saturating_add(1);
                        if state.transient_failures >= settings.transient_failure_limit {
                            let reason = format!(
                                "{provider} owner-capture verification had {} consecutive transient failures (limit {}): {err:#}",
                                state.transient_failures, settings.transient_failure_limit
                            );
                            tracing::error!(
                                provider,
                                error = %err,
                                transient_failures = state.transient_failures,
                                transient_failure_limit = settings.transient_failure_limit,
                                "periodic Azure owner-capture verification exceeded transient failure tolerance",
                            );
                            let _ = fatal_shutdown.send(reason);
                            return;
                        }
                        tracing::warn!(
                            provider,
                            error = %err,
                            transient_failures = state.transient_failures,
                            transient_failure_limit = settings.transient_failure_limit,
                            "periodic Azure owner-capture verification hit a transient error",
                        );
                    }
                },
            }
        }
    }
}
