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
//! Token refresh is deferred (issue #65): an expired access token is handled
//! by re-running `gm-miner login`.

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::time::{Duration, Instant};
use tracing::debug;

/// Token bundle returned by the auth-gateway on a successful device-code flow.
///
/// `refresh_token` is not modelled here because token refresh is deferred
/// (issue #65). An expired access token is handled by re-running `gm-miner login`.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: Option<u64>,
    pub token_type: Option<String>,
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

/// Build an HTTP client with no idle connection pooling.
///
/// `pool_max_idle_per_host(0)` ensures every request opens a fresh TCP
/// connection. Without this the keep-alive connection used for the device-code
/// POST is closed server-side between polls, and the next POST fails with
/// "connection closed before message completed" — reqwest does not retry POSTs
/// automatically.
fn no_pool_client() -> Result<Client> {
    Client::builder()
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
        let resp = client
            .post(token_url)
            .form(&[
                ("client_id", client_id),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await
            .with_context(|| format!("POST {token_url}"))?;

        let status = resp.status();

        if status.is_success() {
            eprintln!();
            let token: TokenResponse = resp.json().await.context("parse token response")?;
            return Ok(token);
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
