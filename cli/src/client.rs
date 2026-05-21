//! Registry API client with JWT bearer auth.
//!
//! Mirrors the pattern in blockmachine's client.py. The access token is kept
//! fresh before the client is built: `main::ensure_fresh_token` refreshes an
//! expired token via the OAuth `refresh_token` grant (falling back to the
//! device flow), so by the time a `RegistryClient` issues a request the token
//! is valid. A 401 here is a backstop and still surfaces as "authentication
//! expired".

use anyhow::{bail, Context, Result};
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;
use serde_json::Value;

use crate::config::Config;

/// Auth configuration returned by `GET /auth/config`.
///
/// The CLI fetches this before running the device-code flow so all OAuth
/// endpoints and the client identity come from the registry at runtime rather
/// than being baked into the binary.
#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    pub device_code_url: String,
    pub token_url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
}

/// Fetch OAuth configuration from the registry.
///
/// Unauthenticated `GET {api_url}/auth/config`. Called by `gm-miner login`
/// before the device-code flow starts.
///
/// # Errors
/// Returns an error if the request fails or the response cannot be parsed.
pub async fn get_auth_config(api_url: &str) -> Result<AuthConfig> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build http client")?;

    let url = format!("{api_url}/auth/config");
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("GET /auth/config failed ({status}): {body}");
    }

    resp.json::<AuthConfig>()
        .await
        .context("parse /auth/config response")
}

/// Cheapest authenticated endpoint on the registry — used by the deploy
/// command's auth preflight. Returns the caller's current miner block
/// (or 404 if the miner has never registered). Exposed as a constant so
/// the preflight and `gm-miner status` agree on the URL.
pub const ME_PATH: &str = "/miners/me";

pub struct RegistryClient {
    pub config: Config,
    client: Client,
}

impl RegistryClient {
    /// Create a new registry client using the provided config.
    ///
    /// # Panics
    /// Panics if the underlying TLS stack cannot be initialized (extremely rare;
    /// would indicate a system-level misconfiguration).
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "only fails on TLS init — system-level misconfiguration"
    )]
    pub fn new(config: Config) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("gm-miner/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("build reqwest client — system TLS must be available");
        Self { config, client }
    }

    fn access_token(&self) -> Option<&str> {
        self.config
            .active_tokens()
            .and_then(|t| t.access_token.as_deref())
    }

    fn api_url(&self) -> String {
        self.config.api_url()
    }

    /// Issue an authenticated GET request to the registry.
    ///
    /// # Errors
    /// Returns an error if the access token is missing, the request fails
    /// at the network level, or the server returns 401.
    pub async fn get(&mut self, path: &str) -> Result<Response> {
        let url = format!("{}{path}", self.api_url());
        let token = self
            .access_token()
            .ok_or_else(|| anyhow::anyhow!("not logged in — run `gm-miner login` first"))?
            .to_owned();

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            bail!("authentication expired — run `gm-miner login` again");
        }
        Ok(resp)
    }

    /// Issue an authenticated POST request with a JSON body.
    ///
    /// # Errors
    /// Returns an error if the access token is missing, the request fails, or
    /// the server returns 401.
    pub async fn post(&mut self, path: &str, body: &Value) -> Result<Response> {
        let url = format!("{}{path}", self.api_url());
        let token = self
            .access_token()
            .ok_or_else(|| anyhow::anyhow!("not logged in — run `gm-miner login` first"))?
            .to_owned();

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&token)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            bail!("authentication expired — run `gm-miner login` again");
        }
        Ok(resp)
    }

    /// Cheap authenticated probe used by `gm-miner deploy` before any
    /// expensive CVM work. A missing access token surfaces as "not logged
    /// in" and a 401 response surfaces as "authentication expired" — both
    /// from `get` itself. Any non-auth error (e.g. registry 404 because
    /// the miner has never registered, or a 5xx) is *not* a preflight
    /// failure: the eventual `register-image` call would catch those with
    /// more context, so we let them through.
    ///
    /// Before the network probe this also checks the stored
    /// `token_expires_at`: a `deploy` runs many minutes of CVM work before
    /// its trailing `register-image` call, so a token that is valid now but
    /// expires mid-deploy must be caught up front rather than after all the
    /// irreversible CVM work.
    ///
    /// # Errors
    /// Returns an error for a missing token, a stored token that is expired
    /// or about to expire, or a 401 from the registry. The caller does not
    /// need to inspect the response body.
    pub async fn preflight_auth(&mut self) -> Result<()> {
        // Fail fast on a token that is expired or expires within the deploy
        // window — before any registry round-trip or CVM work.
        if self
            .config
            .active_tokens()
            .is_some_and(crate::config::TokenEntry::is_expired_or_near)
        {
            bail!(
                "authentication token has expired (or expires within \
                 {}s) — run `gm-miner login` again before deploying",
                crate::config::TOKEN_EXPIRY_MARGIN_SECS
            );
        }

        let _resp = self
            .get(ME_PATH)
            .await
            .context("authentication preflight (GET /miners/me)")?;
        Ok(())
    }

    /// Issue an authenticated PATCH request with a JSON body.
    ///
    /// # Errors
    /// Returns an error if the access token is missing, the request fails, or
    /// the server returns 401.
    pub async fn patch(&mut self, path: &str, body: &Value) -> Result<Response> {
        let url = format!("{}{path}", self.api_url());
        let token = self
            .access_token()
            .ok_or_else(|| anyhow::anyhow!("not logged in — run `gm-miner login` first"))?
            .to_owned();

        let resp = self
            .client
            .patch(&url)
            .bearer_auth(&token)
            .json(body)
            .send()
            .await
            .with_context(|| format!("PATCH {url}"))?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            bail!("authentication expired — run `gm-miner login` again");
        }
        Ok(resp)
    }
}
