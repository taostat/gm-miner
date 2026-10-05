//! Self-service channel lifecycle. Destinations and codes live only in memory
//! and request bodies. Output uses the registry's status and error fields.

use std::{fmt::Write as _, io::Read};

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use reqwest::{Response, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{error_detail, escape_controls, registry_response, timestamp};
use crate::{client::RegistryClient, network::Network};

pub const CHANNEL_PATH: &str = "/miners/me/notifications";
pub const CONFIRM_PATH: &str = "/miners/me/notifications/confirm";
const SET_HINT: &str = "Run `gmcli notifications set <apprise-url>` (or `gmcli notifications set -` to read from stdin).";

/// Read a destination argument, or stdin when it is `-`.
///
/// # Errors
/// Rejects empty, multiline, invalid UTF-8 or oversized input without echoing it.
pub fn read_destination(argument: String, mut stdin: impl Read) -> Result<String> {
    let destination = if argument == "-" {
        let mut input = String::new();
        stdin
            .read_to_string(&mut input)
            .map_err(|_| anyhow::anyhow!("could not read the notification URL from stdin"))?;
        input
            .strip_suffix("\r\n")
            .or_else(|| input.strip_suffix('\n'))
            .unwrap_or(&input)
            .to_owned()
    } else {
        argument
    };
    if destination.trim().is_empty()
        || destination.chars().count() > 2048
        || destination.chars().any(char::is_control)
    {
        bail!("provide one notification URL of 1-2048 characters; use `gmcli notifications set --help`");
    }
    Ok(destination)
}

/// Validate before authentication or sending a request; never echo the code.
///
/// # Errors
/// Fails unless the code is exactly six ASCII decimal digits.
pub fn validate_code(code: &str) -> Result<()> {
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("confirmation code must be exactly 6 digits; run `gmcli notifications confirm <code>` with the code sent to your channel");
    }
    Ok(())
}

#[derive(Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors the registry's channel status wire format"
)]
struct ChannelStatus {
    channel: String,
    destination_fingerprint: String,
    digest_enabled: bool,
    verified: bool,
    pending: bool,
    code_expires_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    consecutive_failures: u64,
    auto_disabled: bool,
}

async fn status_body(response: Response) -> Result<ChannelStatus> {
    response.json().await.map_err(|_| {
        anyhow::anyhow!("invalid notification channel status from the registry; retry or contact the registry operator")
    })
}

fn no_subscription(body: &Value) -> bool {
    body.get("error").and_then(Value::as_str) == Some("no_subscription")
}

async fn error_body(response: Response) -> Value {
    // A malformed error can itself contain the URL. Never attach its source.
    response.json().await.unwrap_or(Value::Null)
}

fn channel_error(
    status: StatusCode,
    body: &Value,
    retry_after: Option<u64>,
    network: Network,
) -> anyhow::Error {
    let error = body.get("error").and_then(Value::as_str).unwrap_or("");
    let mut message = match (status, error) {
        (StatusCode::NOT_FOUND, _) if no_subscription(body) => {
            format!("No channel set on {network}. {SET_HINT}")
        }
        (StatusCode::NOT_FOUND, _) => {
            format!("Notifications are switched off on {network} (notification route unavailable).")
        }
        (StatusCode::BAD_GATEWAY, "notifier_unavailable") => {
            "The notification service is temporarily unavailable; retry later. No success was confirmed.".to_owned()
        }
        (StatusCode::SERVICE_UNAVAILABLE, "notifier_not_configured") => {
            format!("The notification service is not configured on {network}; contact the network operator.")
        }
        (StatusCode::TOO_MANY_REQUESTS, _) => retry_after.map_or_else(
            || "A confirmation code was requested too recently. Retry after the cooldown; the registry did not provide a valid Retry-After header.".to_owned(),
            |seconds| format!("A confirmation code was requested too recently. Retry in {seconds} seconds (Retry-After: {seconds})."),
        ),
        (StatusCode::BAD_REQUEST, "code_invalid") => {
            let attempts = body
                .get("attempts_remaining")
                .and_then(Value::as_i64);
            let remaining = attempts.map_or_else(
                || "Check the latest code sent to your channel.".to_owned(),
                |count| format!("{count} attempts remaining."),
            );
            format!("Incorrect confirmation code. {remaining} Run `gmcli notifications confirm <code>` again.")
        }
        (StatusCode::BAD_REQUEST, "code_expired") => {
            format!("The confirmation code has expired. Request a new code. {SET_HINT}")
        }
        (StatusCode::BAD_REQUEST, "code_exhausted") => {
            format!("Confirmation attempts exhausted. Request a new code. {SET_HINT}")
        }
        (StatusCode::CONFLICT, "already_verified") => {
            "This channel is already verified. Run `gmcli notifications status` to check it.".to_owned()
        }
        (StatusCode::CONFLICT, "subscription_changed") => {
            format!("The notification channel changed during this request. Run `gmcli notifications status` to check it, then set the channel again. {SET_HINT}")
        }
        (StatusCode::UNPROCESSABLE_ENTITY, "code_not_delivered") => {
            format!("The confirmation code could not be delivered. The channel is pending. Check the destination, then request another code after the five-minute cooldown. {SET_HINT}")
        }
        _ => format!("Notification channel request on {network} failed ({status})"),
    };
    if !error.is_empty() {
        let _ = write!(message, ": {}", error_detail(body));
    }
    anyhow::anyhow!(message)
}

async fn response_error(response: Response, network: Network) -> anyhow::Error {
    let status = response.status();
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    channel_error(status, &error_body(response).await, retry_after, network)
}

/// Set a pending channel and request a confirmation code.
///
/// # Errors
/// Propagates authentication/transport failures and registry errors.
pub async fn set_channel(
    client: &mut RegistryClient,
    destination: &str,
    digest_enabled: bool,
) -> Result<String> {
    let response = registry_response(
        client
            .put(
                CHANNEL_PATH,
                &json!({"destination": destination, "digest_enabled": digest_enabled}),
            )
            .await,
        client,
    )?;
    let network = client.config.resolved_network();
    if response.status() != StatusCode::OK {
        return Err(response_error(response, network).await);
    }
    Ok(format!("A confirmation code was sent to your channel on {network}.\nNext: gmcli notifications confirm <code>\n"))
}

/// Confirm ownership using a six-digit code, without echoing that code.
///
/// # Errors
/// Reports registry/auth/transport errors; the CLI validates the code before authentication.
pub async fn confirm_channel(client: &mut RegistryClient, code: &str) -> Result<String> {
    let response = registry_response(
        client.post(CONFIRM_PATH, &json!({"code": code})).await,
        client,
    )?;
    let network = client.config.resolved_network();
    if response.status() != StatusCode::OK {
        return Err(response_error(response, network).await);
    }
    Ok(format!("Notification channel verified on {network}.\n"))
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

/// Read and render channel identity, verification state and delivery health.
///
/// # Errors
/// Reports registry/auth/transport errors; an absent channel is normal.
pub async fn channel_status(client: &mut RegistryClient) -> Result<String> {
    let response = registry_response(client.get(CHANNEL_PATH).await, client)?;
    let network = client.config.resolved_network();
    if response.status() == StatusCode::NOT_FOUND {
        let body = error_body(response).await;
        if no_subscription(&body) {
            return Ok(format!("No channel set on {network}. {SET_HINT}\n"));
        }
        return Err(channel_error(StatusCode::NOT_FOUND, &body, None, network));
    }
    if response.status() != StatusCode::OK {
        return Err(response_error(response, network).await);
    }
    let status = status_body(response).await?;
    Ok(format!(
        "Notification channel on {network}:\n  Channel: {}\n  Fingerprint: {}\n  Verified: {}\n  Pending: {}\n  Code expires (UTC): {}\n  Digest enabled: {}\n  Last success (UTC): {}\n  Consecutive failures: {}\n  Auto-disabled: {}\n",
        escape_controls(&status.channel), escape_controls(&status.destination_fingerprint),
        yes_no(status.verified), yes_no(status.pending), timestamp(status.code_expires_at),
        yes_no(status.digest_enabled), timestamp(status.last_success_at),
        status.consecutive_failures, yes_no(status.auto_disabled),
    ))
}

/// Remove the channel. An absent subscription is an idempotent success.
///
/// # Errors
/// Reports registry/auth/transport errors.
pub async fn off_channel(client: &mut RegistryClient) -> Result<String> {
    let response = registry_response(client.delete(CHANNEL_PATH).await, client)?;
    let network = client.config.resolved_network();
    if response.status() == StatusCode::NO_CONTENT {
        return Ok(format!("Notification channel removed on {network}.\n"));
    }
    if response.status() == StatusCode::NOT_FOUND {
        let body = error_body(response).await;
        if no_subscription(&body) {
            return Ok(format!(
                "No channel was set on {network}; nothing to remove.\n"
            ));
        }
        return Err(channel_error(StatusCode::NOT_FOUND, &body, None, network));
    }
    Err(response_error(response, network).await)
}
