//! Registry API client with JWT bearer auth.
//!
//! The access token is kept fresh before the client is built:
//! `main::ensure_fresh_token` refreshes an expired token via the OAuth
//! `refresh_token` grant (falling back to the device flow), so by the time a
//! `RegistryClient` issues a request the token is valid. A 401 here is a
//! backstop and still surfaces as "authentication expired".

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

/// Build a one-shot HTTP client with the gmcli user-agent and a 30 s timeout —
/// the shared shape for every gmcli request, so the timeout, user-agent, and
/// redirect policy are set in exactly one place.
///
/// Redirects are never followed. The streaming probe carries the worker's
/// `x-gm-node-key` to a miner-controlled endpoint, and `reqwest` keeps custom
/// headers across a cross-host redirect (it only strips `Authorization` /
/// `Cookie` / `Proxy-Authorization`). A 3xx from a compromised or MITM'd
/// upstream would otherwise resend the node secret to the redirect target. No
/// gmcli request — registry API or probe — has a legitimate reason to redirect.
///
/// # Errors
/// Returns an error if the TLS stack cannot be initialised.
pub fn build_http_client() -> Result<Client> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("gmcli/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build http client")
}

/// Build an HTTP client for probing a miner CVM's own data-plane endpoint —
/// the `-8080s` RA-TLS passthrough route `gmcli check-streaming` (and
/// deploy's post-deploy streaming self-test) sends provider probes to.
///
/// That endpoint terminates TLS with a certificate dstack mints inside the
/// enclave via its `GetTlsKey` RPC (see `attestd::ratls`'s module doc):
/// self-signed and bound to a TDX quote, not CA-issued. A normal
/// certificate-verifying client always fails against it with "self signed
/// certificate in certificate chain", so this client disables certificate
/// verification. That is an accepted trade-off *only* in this narrow context,
/// for two reasons:
///
/// 1. By the time this client is used, `gmcli deploy` has already verified
///    this exact CVM's `compose_hash` and `os_image_hash` against the
///    registry's approved `ImageVersion` list via the trusted Phala Cloud API
///    (see `deploy::hashes::verify_hashes`) — trust in the CVM comes from
///    that prior check, not from this HTTPS connection.
/// 2. Real buyer traffic never goes through this client or trusts it: the
///    production gateway performs the full RA-TLS verification described in
///    `attestd::ratls` (quote validation via `dcap-qvl`, event-log replay)
///    before trusting this same endpoint for buyer traffic. Disabling
///    verification here weakens one operator-run diagnostic, not the path
///    buyers are served on.
///
/// The residual risk is real and deliberately accepted: every request sent
/// with this client carries the per-worker `GM_NODE_SECRET` as
/// `x-gm-node-key`, so an attacker able to intercept the operator's
/// connection to the CVM can present any certificate, have it accepted, and
/// harvest that secret — which is what the CVM's envoy checks before serving
/// traffic on the operator's upstream provider keys. The node secret does
/// *not* protect this connection; it is exposed over it. Closing the gap
/// means verifying the presented certificate against the CVM's TDX quote
/// (what the gateway does), not adding another header.
///
/// Same timeout, user-agent, and no-redirect policy as [`build_http_client`]
/// (see its doc comment for why redirects are disabled — it applies equally
/// here). **Never use this client for the registry API or any other
/// request** — only for hitting a miner CVM's own data-plane endpoint that
/// gmcli has already hash-verified.
///
/// # Errors
/// Returns an error if the TLS stack cannot be initialised.
pub fn build_data_plane_probe_client() -> Result<Client> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("gmcli/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .build()
        .context("build data-plane probe http client")
}

/// Fetch OAuth configuration from the registry.
///
/// Unauthenticated `GET {api_url}/auth/config`. Called by `gmcli login`
/// before the device-code flow starts.
///
/// # Errors
/// Returns an error if the request fails or the response cannot be parsed.
pub async fn get_auth_config(api_url: &str) -> Result<AuthConfig> {
    let client = build_http_client()?;

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
/// the preflight and `gmcli status` agree on the URL.
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
        let client =
            build_http_client().expect("build reqwest client — system TLS must be available");
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
            .ok_or_else(|| anyhow::anyhow!("not logged in — run `gmcli login` first"))?
            .to_owned();

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            bail!("authentication expired — run `gmcli login` again");
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
            .ok_or_else(|| anyhow::anyhow!("not logged in — run `gmcli login` first"))?
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
            bail!("authentication expired — run `gmcli login` again");
        }
        Ok(resp)
    }

    /// Issue an authenticated DELETE request to the registry.
    ///
    /// # Errors
    /// Returns an error if the access token is missing, the request fails,
    /// or the server returns 401.
    pub async fn delete(&mut self, path: &str) -> Result<Response> {
        let url = format!("{}{path}", self.api_url());
        let token = self
            .access_token()
            .ok_or_else(|| anyhow::anyhow!("not logged in — run `gmcli login` first"))?
            .to_owned();

        let resp = self
            .client
            .delete(&url)
            .bearer_auth(&token)
            .send()
            .await
            .with_context(|| format!("DELETE {url}"))?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            bail!("authentication expired — run `gmcli login` again");
        }
        Ok(resp)
    }

    /// Cheap authenticated probe used by `gmcli deploy` before any
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
                 {}s) — run `gmcli login` again before deploying",
                crate::config::TOKEN_EXPIRY_MARGIN_SECS
            );
        }

        let _resp = self
            .get(ME_PATH)
            .await
            .context("authentication preflight (GET /miners/me)")?;
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use rustls::ServerConfig;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{build_data_plane_probe_client, build_http_client};

    /// The gmcli HTTP client must never follow a redirect. The streaming
    /// probe sends the worker's `x-gm-node-key` to a miner-controlled
    /// endpoint, and `reqwest` keeps custom headers across a cross-host
    /// redirect — so a 3xx from a compromised or MITM'd upstream would
    /// otherwise resend the node secret to the redirect target. The 307 is
    /// surfaced verbatim and the origin is dialled exactly once (no chase to
    /// the unroutable target the `Location` points at).
    #[tokio::test]
    async fn http_client_does_not_follow_redirects() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(307).insert_header("location", "http://127.0.0.1:1/never"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let response = build_http_client()
            .expect("build client")
            .get(server.uri())
            .header("x-gm-node-key", "node-secret")
            .send()
            .await
            .expect("the 307 is returned, not followed");

        assert_eq!(
            response.status().as_u16(),
            307,
            "the redirect is surfaced verbatim, not chased"
        );
        // `server` drops here; the `.expect(1)` verifies the origin was hit
        // exactly once — a followed redirect would dial the unroutable
        // target instead and error before this assertion.
    }

    /// Starts a bare HTTPS listener on `127.0.0.1` presenting a freshly
    /// minted, self-signed certificate — standing in for the miner CVM's
    /// dstack-minted RA-TLS cert (self-signed, not CA-issued; see
    /// `attestd::ratls`'s module doc). Serves exactly one request with a
    /// minimal 200 response, then the accept task exits.
    async fn spawn_self_signed_https_server() -> SocketAddr {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(["127.0.0.1".to_owned()])
                .expect("generate self-signed cert");
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivatePkcs8KeyDer::from(signing_key.serialize_der());

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("select tls protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der.into())
            .expect("build tls server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("read bound local addr");

        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut tls) = acceptor.accept(stream).await else {
                return;
            };
            let mut buf = [0_u8; 1024];
            let _ = tls.read(&mut buf).await;
            let body = b"ok";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = tls.write_all(response.as_bytes()).await;
            let _ = tls.write_all(body).await;
            let _ = tls.shutdown().await;
        });

        addr
    }

    /// The regression this whole fix is for: `run_provider_probe` posts to
    /// the miner CVM's `-8080s` RA-TLS passthrough endpoint, whose
    /// certificate is self-signed and dstack-minted, not CA-issued. Proves
    /// two things against the same self-signed server: the dedicated probe
    /// client connects successfully...
    #[tokio::test]
    async fn data_plane_probe_client_accepts_the_cvms_self_signed_cert() {
        let addr = spawn_self_signed_https_server().await;
        let url = format!("https://127.0.0.1:{}/", addr.port());

        let response = build_data_plane_probe_client()
            .expect("build probe client")
            .get(&url)
            .send()
            .await;

        assert!(
            response.is_ok(),
            "the data-plane probe client must accept a self-signed cert: {response:?}"
        );
    }

    /// ...while the plain client — what `check-streaming` used before this
    /// fix — fails with a certificate-verification error against the exact
    /// same server. This is the assertion that proves the bug was real and
    /// that the dedicated probe client is the fix, not an unrelated change.
    #[tokio::test]
    async fn plain_http_client_rejects_the_same_self_signed_cert() {
        let addr = spawn_self_signed_https_server().await;
        let url = format!("https://127.0.0.1:{}/", addr.port());

        let err = build_http_client()
            .expect("build plain client")
            .get(&url)
            .send()
            .await
            .expect_err("the plain client must reject an unverifiable self-signed cert");

        assert!(
            err.is_connect(),
            "expected a connect/TLS-verification error, got: {err}"
        );
    }
}
