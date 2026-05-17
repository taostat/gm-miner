//! Registry API client with JWT bearer auth and auto-refresh.
//!
//! Mirrors the pattern in blockmachine's client.py.

use anyhow::{bail, Context, Result};
use reqwest::{Client, Response, StatusCode};
use serde_json::Value;

use crate::config::Config;

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
