//! Mirror of the gm gateway's error-body classifiers, so adapter-written
//! bodies never read as a provider-account failure or a context-window
//! refusal by accident.

/// Mirrors `is_provider_account_drain` in the gm repo's
/// `gateway/src/pipeline/retry.rs`, which matches these on any status.
pub(crate) const DRAIN_SIGNALS: &[&str] = &[
    "insufficient_quota",
    "exceeded your current quota",
    "add credits to your account",
    "billing_hard_limit_reached",
    "billing hard limit",
    "credit balance is too low",
    "reached your specified api usage limits",
    "account is not active",
    "account has been deactivated",
    "invalid_api_key",
    "incorrect api key",
    "pay with fiat or send tao",
    "exceeded_current_quota_error",
];

pub(crate) fn signals_drain(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    DRAIN_SIGNALS.iter().any(|signal| lower.contains(signal))
}

/// Mirrors `is_context_window_exceeded` in the gm repo's
/// `gateway/src/pipeline/retry.rs`, which reroutes a match to a wider window.
pub(crate) const CONTEXT_WINDOW_SIGNALS: &[&str] = &[
    "context_length_exceeded",
    "maximum context length",
    "prompt is too long",
    "exceed context limit",
    "longer than the maximum model length",
    "exceeds the model's context window",
];

pub(crate) fn signals_context_window(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    CONTEXT_WINDOW_SIGNALS
        .iter()
        .any(|signal| lower.contains(signal))
}
