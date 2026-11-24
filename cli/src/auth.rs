//! OAuth 2.0 device-code flow against the Taostats auth-gateway.
//!
//! Flow:
//!   1. `POST {device_code_url}` with JSON `{"client_id": ..., "scopes": [...]}`
//!      → `device_code`, `user_code`, `verification_uri`, `interval`, `expires_in`.
//!   2. Display the verification URL + code; optionally open the browser.
//!   3. Poll `POST {token_url}` (form-encoded) with `client_id`, `device_code`,
//!      `grant_type=urn:ietf:params:oauth:grant-type:device_code` until the user
//!      authorizes or the code expires.
//!   4. Return the token bundle to the caller for persistence.
//!
//! The auth-gateway URLs, client ID, and scopes are fetched from the registry
//! at `GET /auth/config` immediately before this function is called — nothing
//! auth-related is baked into the binary.
//!
//! When an access token expires, [`refresh_token`] mints a fresh one from the
//! stored `refresh_token` without a browser round-trip. The full device flow
//! is only re-run when no refresh token is stored or the refresh is rejected;
//! a rate-limited (`429`) refresh is retried, never treated as a rejection.

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::time::{Duration, Instant};
use tracing::debug;

use crate::config::TokenEntry;

/// Token bundle returned by the auth-gateway on a successful device-code flow
/// or refresh-token grant.
///
/// `refresh_token` is `Option` because not every OAuth response carries one:
/// a server that does not rotate refresh tokens omits it from a refresh
/// response, in which case the caller keeps the existing stored value.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: Option<u64>,
    pub token_type: Option<String>,
    pub refresh_token: Option<String>,
}

/// Device authorization endpoint response.
#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default = "default_interval")]
    interval: u64,
    #[serde(default = "default_expires_in")]
    expires_in: u64,
}

fn default_interval() -> u64 {
    5
}
fn default_expires_in() -> u64 {
    900
}

/// Longest `Retry-After` the CLI will honour before re-trying a rate-limited
/// token request. The auth-gateway's per-client limit has been observed sending
/// single-digit values; a far larger one is better surfaced than slept on.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Refresh attempts made against a `429` before giving up — enough to ride out
/// a short per-client burst window without stalling a command for minutes.
const MAX_RATE_LIMITED_REFRESH_ATTEMPTS: u32 = 5;

/// How long to wait before re-trying a `429` from the token endpoint.
///
/// Reads `Retry-After` as delay-seconds (the only form the auth-gateway sends),
/// falls back to the device flow's default poll interval when it is absent or
/// unparseable, and caps the result at [`MAX_RETRY_AFTER`].
fn retry_after(headers: &reqwest::header::HeaderMap) -> Duration {
    let secs = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or_else(default_interval);
    Duration::from_secs(secs).min(MAX_RETRY_AFTER)
}

/// Build an HTTP client with no redirects or idle connection pooling.
///
/// OAuth requests must use the configured endpoint directly: following a
/// 307/308 redirect can forward refresh tokens or device codes in the body.
///
/// `pool_max_idle_per_host(0)` ensures every request opens a fresh TCP
/// connection. Without this the keep-alive connection used for the device-code
/// POST is closed server-side between polls, and the next POST fails with
/// "connection closed before message completed" — reqwest does not retry POSTs
/// automatically.
fn no_pool_client() -> Result<Client> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(0)
        .build()
        .context("build http client")
}

/// Run the device-code flow against the Taostats auth-gateway.
///
/// `device_code_url`, `token_url`, `client_id`, and `scopes` come from
/// `GET {registry}/auth/config` and are passed in by the caller.
///
/// Prints instructions to stdout. Optionally opens the browser when
/// `open_browser` is `true`.
///
/// # Errors
/// Returns an error if any HTTP request fails, the response cannot be parsed,
/// the device code flow times out, or the user denies access.
pub async fn device_login(
    device_code_url: &str,
    token_url: &str,
    client_id: &str,
    scopes: &[String],
    open_browser: bool,
) -> Result<TokenResponse> {
    let client = no_pool_client()?;

    // Step 1: request a device code.
    // The auth-gateway requires the `scopes` array; a singular `scope` string
    // is silently ignored.
    let resp = client
        .post(device_code_url)
        .json(&serde_json::json!({
            "client_id": client_id,
            "scopes": scopes,
        }))
        .send()
        .await
        .with_context(|| format!("POST {device_code_url}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("device code request failed ({status}): {body}");
    }

    let dc: DeviceCodeResponse = resp.json().await.context("parse device code response")?;

    let verify_url = format!("{}?user_code={}", dc.verification_uri, dc.user_code);

    println!();
    println!("To authenticate, visit:");
    println!("  {verify_url}");
    println!();
    println!("Code: {}", dc.user_code);
    println!();

    if open_browser {
        if let Err(e) = open::that(&verify_url) {
            debug!("could not open browser: {e}");
            println!("(Could not open browser automatically — please visit the URL above.)");
        }
    }

    // Step 2: poll until the user authorizes or the code expires.
    poll_for_token(
        token_url,
        client_id,
        &dc.device_code,
        dc.interval,
        dc.expires_in,
    )
    .await
}

/// Whether a failed token poll is worth retrying within the device-code
/// deadline. Connect and timeout failures are transient network blips; a
/// builder error (e.g. a malformed `token_url` from `/auth/config`) can never
/// recover, so it must abort immediately rather than wait out the deadline.
fn is_transient(err: &reqwest::Error) -> bool {
    !err.is_builder() && (err.is_connect() || err.is_timeout() || err.is_request())
}

async fn poll_for_token(
    token_url: &str,
    client_id: &str,
    device_code: &str,
    initial_interval: u64,
    expires_in: u64,
) -> Result<TokenResponse> {
    let deadline = Instant::now() + Duration::from_secs(expires_in);
    let mut interval = Duration::from_secs(initial_interval);

    eprint!("Waiting for browser authorization");

    loop {
        tokio::time::sleep(interval).await;

        if Instant::now() >= deadline {
            eprintln!();
            bail!("login timed out — please try again");
        }

        // Build a fresh client per poll — `pool_max_idle_per_host(0)` on the
        // shared client already prevents keep-alive reuse, but an explicit
        // fresh client makes the intent unmistakable.
        let client = no_pool_client()?;

        // OAuth token endpoints are form-encoded per RFC 8628 §3.4.
        let send = client
            .post(token_url)
            .form(&[
                ("client_id", client_id),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await;
        let resp = match send {
            Ok(resp) => resp,
            // A transient transport failure must not abort the flow: the
            // device code is still valid, so keep polling until the deadline
            // above stops the loop. A non-transient error (bad URL, request
            // build) would never recover, so surface it immediately.
            Err(e) if is_transient(&e) => {
                eprint!(".");
                continue;
            }
            Err(e) => {
                eprintln!();
                return Err(e).with_context(|| format!("POST {token_url}"));
            }
        };

        let status = resp.status();

        if status.is_success() {
            eprintln!();
            let token: TokenResponse = resp.json().await.context("parse token response")?;
            return Ok(token);
        }

        // Redirects are terminal even if their body contains a retryable
        // OAuth error such as authorization_pending or slow_down.
        if status.is_redirection() {
            eprintln!();
            bail!("unexpected status from token endpoint: {status}");
        }

        // A rate-limited poll says nothing about the device code, which is
        // still pending: back off as the gateway asks and keep polling.
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            eprint!(".");
            interval = interval.max(retry_after(resp.headers()));
            continue;
        }

        // Parse the OAuth error code from the 400 body.
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let error = body.get("error").and_then(|v| v.as_str()).unwrap_or("");

        match error {
            "authorization_pending" => {
                eprint!(".");
            }
            "slow_down" => {
                eprint!(".");
                interval += Duration::from_secs(5);
            }
            "expired_token" => {
                eprintln!();
                bail!("login timed out — please try again");
            }
            "access_denied" => {
                eprintln!();
                bail!("login was denied");
            }
            _ => {
                eprintln!();
                bail!("token endpoint error: {error} ({status})");
            }
        }
    }
}

/// Outcome of a refresh-token attempt against the auth-gateway.
///
/// A rejected refresh (the token was revoked, expired, or the client is not
/// permitted the `refresh_token` grant) is [`RefreshOutcome::Rejected`] rather
/// than an `Err`: the caller's correct response is to fall back to the full
/// device flow, not to abort. An `Err` is reserved for transport failures
/// where retrying the device flow would be no more likely to succeed.
#[derive(Debug)]
pub enum RefreshOutcome {
    /// The refresh succeeded; the new token bundle is ready to persist.
    Refreshed(TokenResponse),
    /// The auth-gateway rejected the refresh token — fall back to device login.
    Rejected,
}

/// Exchange a stored `refresh_token` for a fresh access token.
///
/// POSTs the standard OAuth `refresh_token` grant (RFC 6749 §6) to `token_url`
/// — form-encoded `grant_type`, `refresh_token`, `client_id`. On `200` the new
/// [`TokenResponse`] is returned; the auth-gateway rotates the refresh token,
/// so the response's `refresh_token` (when present) supersedes the stored one.
///
/// Any other `4xx` or a `5xx` means the refresh token is no longer usable: the
/// result is [`RefreshOutcome::Rejected`] so the caller can fall back to the
/// device flow. A `429` is the gateway throttling the client, not rejecting the
/// token: the request is retried after `Retry-After`, up to
/// [`MAX_RATE_LIMITED_REFRESH_ATTEMPTS`] times.
///
/// # Errors
/// Returns an error for transport-level failures (the request could not be
/// sent or the success body could not be parsed) and when the gateway is still
/// returning `429` after every attempt — never for an auth-gateway rejection,
/// which is reported as [`RefreshOutcome::Rejected`].
pub async fn refresh_token(
    token_url: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<RefreshOutcome> {
    for attempt in 1..=MAX_RATE_LIMITED_REFRESH_ATTEMPTS {
        let client = no_pool_client()?;

        let resp = client
            .post(token_url)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", client_id),
            ])
            .send()
            .await
            .with_context(|| format!("POST {token_url}"))?;

        let status = resp.status();

        if status.is_success() {
            let token: TokenResponse = resp.json().await.context("parse refresh token response")?;
            return Ok(RefreshOutcome::Refreshed(token));
        }

        // A 429 is the auth-gateway throttling this OAuth client, not a verdict
        // on the refresh token. Falling back to the device flow would only poll
        // the same throttled endpoint, and ask the operator to log in again
        // while their stored login is still valid.
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let wait = retry_after(resp.headers());
            if attempt < MAX_RATE_LIMITED_REFRESH_ATTEMPTS {
                eprintln!(
                    "Auth gateway is rate-limiting token requests — retrying the refresh in {}s.",
                    wait.as_secs()
                );
                tokio::time::sleep(wait).await;
            }
            continue;
        }

        // Any other 4xx is the auth-gateway declining the refresh token
        // (invalid_grant, unsupported_grant_type, …). That is a recoverable
        // state — the caller re-runs the device flow. A 5xx is treated the same
        // way: the device flow is the only remaining path to a valid token.
        if status.is_client_error() || status.is_server_error() {
            let body = resp.text().await.unwrap_or_default();
            debug!("refresh token rejected ({status}): {body}");
            return Ok(RefreshOutcome::Rejected);
        }

        // Any other status (1xx/3xx) is unexpected for an OAuth token endpoint.
        bail!("unexpected status from token endpoint: {status}");
    }

    bail!(
        "the auth gateway at {token_url} is still rate-limiting token requests (429) after \
         {MAX_RATE_LIMITED_REFRESH_ATTEMPTS} attempts — your stored login is still valid; \
         wait a minute and re-run the command"
    )
}

impl TokenResponse {
    /// Convert an auth-gateway token response into a persistable [`TokenEntry`].
    ///
    /// `token_expires_at` is derived from `expires_in` (seconds-from-now) and
    /// stored as an RFC3339 string so the CLI can detect expiry without
    /// re-decoding the JWT. A response with no `refresh_token` yields an entry
    /// with `refresh_token: None` — callers that already hold a refresh token
    /// should use [`TokenResponse::to_entry_keeping`] instead.
    #[must_use]
    pub fn to_entry(&self) -> TokenEntry {
        TokenEntry {
            access_token: Some(self.access_token.clone()),
            token_expires_at: self.expires_in.map(|s| {
                #[expect(
                    clippy::cast_possible_wrap,
                    reason = "expires_in is a small positive number of seconds"
                )]
                let expiry = chrono::Utc::now() + chrono::Duration::seconds(s as i64);
                expiry.to_rfc3339()
            }),
            refresh_token: self.refresh_token.clone(),
        }
    }

    /// Like [`TokenResponse::to_entry`], but falls back to `previous_refresh`
    /// when the response itself carries no `refresh_token`.
    ///
    /// OAuth servers may or may not rotate the refresh token on a refresh
    /// grant. When the response omits one, the previously stored token is
    /// still valid and must be kept — otherwise the next refresh would have
    /// nothing to present.
    #[must_use]
    pub fn to_entry_keeping(&self, previous_refresh: Option<String>) -> TokenEntry {
        let mut entry = self.to_entry();
        if entry.refresh_token.is_none() {
            entry.refresh_token = previous_refresh;
        }
        entry
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::{poll_for_token, retry_after};
    use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
    use std::time::Duration;

    fn headers_with_retry_after(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_str(value).expect("valid header"),
        );
        headers
    }

    #[test]
    fn retry_after_honours_delay_seconds() {
        assert_eq!(
            retry_after(&headers_with_retry_after("7")),
            Duration::from_secs(7)
        );
    }

    /// No header, or the HTTP-date form the gateway does not send, falls back
    /// to the device flow's default interval rather than a zero-wait hot loop.
    #[test]
    fn retry_after_defaults_when_absent_or_unparseable() {
        assert_eq!(retry_after(&HeaderMap::new()), Duration::from_secs(5));
        assert_eq!(
            retry_after(&headers_with_retry_after("Wed, 21 Oct 2026 07:28:00 GMT")),
            Duration::from_secs(5)
        );
    }

    /// A huge `Retry-After` is capped so a command fails in bounded time.
    #[test]
    fn retry_after_is_capped() {
        assert_eq!(
            retry_after(&headers_with_retry_after("3600")),
            Duration::from_secs(30)
        );
    }

    /// A transient transport failure (here: connection refused) must not abort
    /// the device-login poll. The loop swallows the send error, keeps polling,
    /// and only stops when the device code's `expires_in` deadline passes —
    /// surfacing the timeout message, never the raw transport error.
    #[tokio::test]
    async fn poll_tolerates_transient_send_errors() {
        // Port 1 is unbound, so every poll's `send()` fails with connection
        // refused. `initial_interval = 1`, `expires_in = 2` lets exactly one
        // poll fail before the deadline, proving the failure is tolerated.
        let result =
            poll_for_token("http://127.0.0.1:1/token", "client-id", "device-code", 1, 2).await;
        let err = result.expect_err("an unreachable token endpoint must not succeed");
        let msg = err.to_string();
        assert!(
            msg.contains("login timed out"),
            "a transient send error must let polling continue to the deadline, \
             not abort with a transport error: {msg}"
        );
    }

    /// A non-transient error — a malformed `token_url` that reqwest rejects at
    /// build time — must abort immediately with the actionable POST error,
    /// not silently retry until the deadline and report a misleading timeout.
    #[tokio::test]
    async fn poll_aborts_immediately_on_non_transient_error() {
        // `expires_in` is large so a deadline-driven exit would take far too
        // long; a fast return proves the abort path fired.
        let result = poll_for_token("http://[::1", "client-id", "device-code", 0, 3600).await;
        let err = result.expect_err("a malformed token_url must not succeed");
        let msg = err.to_string();
        assert!(
            msg.contains("POST http://[::1"),
            "a non-transient error must surface the actionable POST error, \
             not a deadline timeout: {msg}"
        );
    }
}
