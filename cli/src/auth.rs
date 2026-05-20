//! Taostats OAuth 2.0 device-code flow.
//!
//! Mirrors blockmachine's CLI auth pattern
//! (`blockmachine_playground/cli/commands/auth.py`).
//!
//! Flow:
//!   1. `POST /v1/device/code` → `device_code` + `user_code` + `verification_uri`
//!   2. Display URL + code; optionally open browser.
//!   3. Poll `POST /v1/oauth/token` until authorized or expired.
//!   4. Store `access_token` in `~/.gm-miner/config.json`.
//!
//! Token refresh is deferred (issue #65): the token endpoint's
//! `refresh_token` is ignored, and an expired access token is handled by
//! re-running `gm-miner login`.

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::time::{Duration, Instant};
use tracing::debug;

/// Token endpoint response.
///
/// The token endpoint also returns a `refresh_token`; it is intentionally
/// not deserialized because token refresh is deferred (issue #65).
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: Option<u64>,
    pub token_type: Option<String>,
}

/// Device code endpoint response.
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

/// Run the device-code flow. Returns the token response on success.
///
/// Prints instructions to stdout. Optionally opens the browser if
/// `open_browser` is true.
///
/// # Errors
/// Returns an error if the HTTP request fails, the response cannot be parsed,
/// the device code flow times out, or the user denies access.
pub async fn device_login(
    auth_url: &str,
    client_id: &str,
    scopes: &[&str],
    open_browser: bool,
) -> Result<TokenResponse> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build http client")?;

    // Step 1: request device code.
    let resp = client
        .post(format!("{auth_url}/v1/device/code"))
        .json(&serde_json::json!({
            "client_id": client_id,
            "scopes": scopes,
        }))
        .send()
        .await
        .context("POST /v1/device/code")?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("device code request failed: {body}");
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

    // Step 2: poll until authorized.
    poll_for_token(
        &client,
        auth_url,
        client_id,
        &dc.device_code,
        dc.interval,
        dc.expires_in,
    )
    .await
}

async fn poll_for_token(
    client: &Client,
    auth_url: &str,
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

        let resp = client
            .post(format!("{auth_url}/v1/oauth/token"))
            .json(&serde_json::json!({
                "client_id": client_id,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            }))
            .send()
            .await
            .context("POST /v1/oauth/token")?;

        let status = resp.status();

        if status.is_success() {
            eprintln!();
            let token: TokenResponse = resp.json().await.context("parse token response")?;
            return Ok(token);
        }

        // Parse OAuth error.
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
