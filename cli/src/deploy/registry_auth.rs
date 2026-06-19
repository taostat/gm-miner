//! OCI registry credential probing for the `gmcli deploy` image pull.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// Environment variable carrying the GHCR pull username.
pub const GHCR_PULL_USERNAME_VAR: &str = "GHCR_PULL_USERNAME";
/// Environment variable carrying the GHCR pull token (`read:packages`).
pub const GHCR_PULL_TOKEN_VAR: &str = "GHCR_PULL_TOKEN";

/// Pull credentials for a private container registry, written into the
/// `phala deploy` env file so the CVM's pre-launch script can `docker
/// login` and pull the miner image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryCredentials {
    /// Registry host the credentials authenticate against, e.g. `ghcr.io`.
    pub registry: String,
    /// Registry username.
    pub username: String,
    /// Registry password / token.
    pub password: String,
}

/// Extract the registry host from a container image reference.
///
/// A registry host is the first `/`-separated component, but only when it
/// looks like a host (contains a `.` or `:`, or is the literal
/// `localhost`). A ref with no such component — e.g. `library/alpine` —
/// resolves to Docker Hub (`docker.io`), which is public.
#[must_use]
pub fn registry_host(image_ref: &str) -> String {
    let first = image_ref.split('/').next().unwrap_or(image_ref);
    if first == "localhost" || first.contains('.') || first.contains(':') {
        first.to_owned()
    } else {
        "docker.io".to_owned()
    }
}

/// Resolve private-registry pull credentials for `image_ref`.
///
/// Probes the registry for the resolved `image_ref` with an anonymous OCI
/// Registry v2 manifest request ([`image_is_public`]). Returns `Ok(None)`
/// when the image is genuinely pullable without credentials — so a clean
/// deploy carries no `DSTACK_DOCKER_*` env and no docker auth. When the
/// anonymous probe is denied (the image is private), the operator-set
/// `GHCR_PULL_USERNAME` / `GHCR_PULL_TOKEN` environment variables are
/// required and injected so the CVM's pre-launch script can `docker login`.
///
/// # Errors
/// Returns an error if the registry probe fails for a reason other than an
/// authorization denial (a malformed ref, a 404, or a network/5xx error —
/// the operator should see those rather than have them masked as private),
/// or if the image is private and either credential environment variable is
/// unset or empty.
pub async fn resolve_registry_credentials(image_ref: &str) -> Result<Option<RegistryCredentials>> {
    let registry = registry_host(image_ref);
    if image_is_public(image_ref).await? {
        return Ok(None);
    }

    let username = non_empty_env(GHCR_PULL_USERNAME_VAR);
    let password = non_empty_env(GHCR_PULL_TOKEN_VAR);

    match (username, password) {
        (Some(username), Some(password)) => Ok(Some(RegistryCredentials {
            registry,
            username,
            password,
        })),
        _ => bail!(
            "the miner image is on the private registry `{registry}` but the pull \
             credentials are not set.\n  \
             set {GHCR_PULL_USERNAME_VAR} and {GHCR_PULL_TOKEN_VAR} (a `read:packages` \
             token) so the CVM can authenticate and pull the image"
        ),
    }
}

/// Visibility verdict derived from a single anonymous manifest GET status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// The manifest was served without auth — the image is public.
    Public,
    /// The manifest was denied — the image needs pull credentials.
    Private,
    /// Inconclusive from this status alone: a `401` may carry a Bearer
    /// challenge that an anonymous token exchange can still satisfy, so the
    /// caller must follow the challenge before deciding.
    Probe,
}

/// Map an anonymous manifest-GET HTTP status to a [`Visibility`] verdict.
///
/// `200` is public; `403` is an outright denial (private); `401` is
/// inconclusive — it may carry a Bearer challenge that an anonymous token
/// exchange can satisfy, so it maps to [`Visibility::Probe`]. Any other
/// status is treated as inconclusive here and surfaced as an error by the
/// caller (see [`image_is_public`]).
#[must_use]
pub fn visibility_from_status(status: u16) -> Visibility {
    match status {
        200 => Visibility::Public,
        403 => Visibility::Private,
        // `401` (and any other status) is inconclusive: a `401` may carry a
        // Bearer challenge an anonymous token exchange can satisfy.
        _ => Visibility::Probe,
    }
}

/// A parsed `WWW-Authenticate: Bearer ...` challenge from a registry `401`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerChallenge {
    /// The token-service URL to request an anonymous bearer token from.
    pub realm: String,
    /// The `service` query parameter the token endpoint expects.
    pub service: String,
    /// The `scope` query parameter (e.g. `repository:<repo>:pull`). Some
    /// registries omit it on the manifest challenge.
    pub scope: Option<String>,
}

/// Accept header listing the OCI + Docker manifest media types a registry
/// manifest GET must advertise so the registry returns a manifest rather
/// than a 406.
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.docker.distribution.manifest.v2+json";

/// Split a container image reference into `(repository, reference)`.
///
/// The repository is the ref with the registry host (if any) stripped and
/// without the trailing tag/digest. The reference is the digest (the part
/// after `@`) when present, else the tag (the part after the last `:` in
/// the final path segment), defaulting to `latest`.
///
/// # Examples
/// `ghcr.io/taostat/gm-miner@sha256:abc` → (`taostat/gm-miner`, `sha256:abc`)
/// `ghcr.io/taostat/gm-miner:v1` → (`taostat/gm-miner`, `v1`)
/// `ghcr.io/taostat/gm-miner` → (`taostat/gm-miner`, `latest`)
#[must_use]
pub fn split_repo_reference(image_ref: &str) -> (String, String) {
    let host = registry_host(image_ref);
    // Strip the host component only when `registry_host` actually found one
    // in the ref (it synthesises `docker.io` for host-less refs).
    let path = match image_ref.split_once('/') {
        Some((first, rest)) if first == host => rest,
        _ => image_ref,
    };

    if let Some((repo, digest)) = path.split_once('@') {
        return (repo.to_owned(), digest.to_owned());
    }
    // A tag lives in the final path segment, after the last `:` — never an
    // earlier `:` belonging to a host:port that survived host stripping.
    match path.rsplit_once('/') {
        Some((prefix, last)) => match last.split_once(':') {
            Some((name, tag)) => (format!("{prefix}/{name}"), tag.to_owned()),
            None => (path.to_owned(), "latest".to_owned()),
        },
        None => match path.split_once(':') {
            Some((name, tag)) => (name.to_owned(), tag.to_owned()),
            None => (path.to_owned(), "latest".to_owned()),
        },
    }
}

/// Parse a `WWW-Authenticate: Bearer realm="...",service="...",scope="..."`
/// header value into a [`BearerChallenge`].
///
/// Returns `None` when the scheme is not `Bearer` or the mandatory `realm`
/// and `service` parameters are absent. `scope` is optional. Parameter
/// values are double-quoted per RFC 7235; the quotes are stripped.
#[must_use]
pub fn parse_bearer_challenge(header_value: &str) -> Option<BearerChallenge> {
    let params = header_value.strip_prefix("Bearer ")?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;

    for part in params.split(',') {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_owned();
        match key.trim() {
            "realm" => realm = Some(value),
            "service" => service = Some(value),
            "scope" => scope = Some(value),
            _ => {}
        }
    }

    Some(BearerChallenge {
        realm: realm?,
        service: service?,
        scope,
    })
}

/// Anonymous token response from an OCI registry's token endpoint. Registries
/// return the bearer token under `token` or (Docker Hub) `access_token`.
#[derive(Debug, Deserialize)]
struct RegistryToken {
    token: Option<String>,
    access_token: Option<String>,
}

/// Probe whether `image_ref` is anonymously pullable via an OCI Registry v2
/// manifest request.
///
/// `docker.io` images are treated as public without a probe (matching the
/// existing short-circuit). Otherwise this GETs
/// `https://<host>/v2/<repo>/manifests/<reference>` with no auth: a `200`
/// means public; a `401` carrying a Bearer challenge triggers an anonymous
/// token exchange and a single authenticated retry; a `403` (or a denied
/// retry) means private.
///
/// # Errors
/// Returns an error for any status that is neither a clean public/private
/// verdict nor a usable Bearer challenge — a `404` (likely a malformed ref
/// or wrong registry), a `5xx`, or a network failure — so the operator sees
/// the real problem rather than a silent "treat as public".
pub async fn image_is_public(image_ref: &str) -> Result<bool> {
    let host = registry_host(image_ref);
    if host == "docker.io" {
        return Ok(true);
    }

    let (repo, reference) = split_repo_reference(image_ref);
    let manifest_url = format!("https://{host}/v2/{repo}/manifests/{reference}");
    let client = crate::client::build_http_client()?;

    let resp = client
        .get(&manifest_url)
        .header(reqwest::header::ACCEPT, MANIFEST_ACCEPT)
        .send()
        .await
        .with_context(|| format!("GET {manifest_url}"))?;

    let status = resp.status();
    match visibility_from_status(status.as_u16()) {
        Visibility::Public => Ok(true),
        Visibility::Private => Ok(false),
        Visibility::Probe => probe_with_bearer(&client, &resp, &manifest_url, status).await,
    }
}

/// Follow a registry `401`'s Bearer challenge: exchange for an anonymous
/// token, retry the manifest GET once, and decide public vs private.
///
/// A `401` with no usable Bearer challenge is a denial (private). A
/// non-`200`/`401`/`403` retry status is surfaced as an error.
async fn probe_with_bearer(
    client: &reqwest::Client,
    resp: &reqwest::Response,
    manifest_url: &str,
    status: reqwest::StatusCode,
) -> Result<bool> {
    let Some(challenge) = resp
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_bearer_challenge)
    else {
        // A 401 without a Bearer challenge we can satisfy is a denial.
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Ok(false);
        }
        bail!("registry manifest probe for {manifest_url} returned an unexpected {status}");
    };

    let Some(token) = fetch_anonymous_token(client, &challenge).await? else {
        return Ok(false);
    };

    let retry = client
        .get(manifest_url)
        .header(reqwest::header::ACCEPT, MANIFEST_ACCEPT)
        .bearer_auth(&token)
        .send()
        .await
        .with_context(|| format!("GET {manifest_url} (with anonymous bearer token)"))?;

    let retry_status = retry.status();
    match visibility_from_status(retry_status.as_u16()) {
        Visibility::Public => Ok(true),
        Visibility::Private => Ok(false),
        // A second 401 after an anonymous token means the image is private.
        Visibility::Probe if retry_status == reqwest::StatusCode::UNAUTHORIZED => Ok(false),
        Visibility::Probe => {
            bail!(
                "registry manifest retry for {manifest_url} returned an unexpected {retry_status}"
            )
        }
    }
}

/// Request an anonymous bearer token from a registry token endpoint.
///
/// Returns `Ok(None)` when the token endpoint itself denies the anonymous
/// request (`401`/`403`) — the image is private. Other non-success statuses
/// are surfaced as errors.
///
/// # Errors
/// Returns an error if the token request cannot be sent, the endpoint returns
/// a non-`401`/`403` failure status, or the token response body cannot be
/// parsed.
pub async fn fetch_anonymous_token(
    client: &reqwest::Client,
    challenge: &BearerChallenge,
) -> Result<Option<String>> {
    let mut query: Vec<(&str, &str)> = vec![("service", challenge.service.as_str())];
    if let Some(scope) = &challenge.scope {
        query.push(("scope", scope.as_str()));
    }

    let resp = client
        .get(&challenge.realm)
        .query(&query)
        .send()
        .await
        .with_context(|| format!("GET {} (anonymous token exchange)", challenge.realm))?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(None);
    }
    if !status.is_success() {
        bail!(
            "anonymous token exchange at {} returned an unexpected {status}",
            challenge.realm
        );
    }

    let body: RegistryToken = resp
        .json()
        .await
        .context("parse registry anonymous token response")?;
    Ok(body.token.or(body.access_token).filter(|t| !t.is_empty()))
}

/// Read an environment variable, returning `None` when it is unset or
/// whitespace-only.
#[must_use]
pub fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    // ── registry-host derivation ──────────────────────────────────────────────

    #[test]
    fn registry_host_extracts_ghcr() {
        assert_eq!(
            registry_host("ghcr.io/taostat/gm-miner@sha256:abc"),
            "ghcr.io"
        );
    }

    #[test]
    fn registry_host_extracts_host_with_port() {
        assert_eq!(
            registry_host("localhost:5000/gm-miner@sha256:abc"),
            "localhost:5000"
        );
    }

    /// A ref with no host-looking first component is Docker Hub.
    #[test]
    fn registry_host_defaults_to_docker_hub() {
        assert_eq!(registry_host("library/alpine:3"), "docker.io");
        assert_eq!(registry_host("alpine"), "docker.io");
    }

    // ── anonymous registry visibility probe ───────────────────────────────────

    /// Docker Hub images are public without any network probe.
    #[tokio::test]
    async fn image_is_public_short_circuits_docker_hub() {
        assert!(image_is_public("library/alpine:3")
            .await
            .expect("docker hub is public"));
    }

    /// `200` is public, `403` is private, `401` is inconclusive (a Bearer
    /// challenge may still satisfy it), any other status is inconclusive.
    #[test]
    fn visibility_from_status_maps_each_class() {
        assert_eq!(visibility_from_status(200), Visibility::Public);
        assert_eq!(visibility_from_status(401), Visibility::Probe);
        assert_eq!(visibility_from_status(403), Visibility::Private);
        assert_eq!(visibility_from_status(404), Visibility::Probe);
        assert_eq!(visibility_from_status(500), Visibility::Probe);
    }

    // ── Bearer challenge parsing ──────────────────────────────────────────────

    #[test]
    fn parse_bearer_challenge_well_formed() {
        let challenge = parse_bearer_challenge(
            r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:taostat/gm-miner:pull""#,
        )
        .expect("well-formed challenge parses");
        assert_eq!(challenge.realm, "https://ghcr.io/token");
        assert_eq!(challenge.service, "ghcr.io");
        assert_eq!(
            challenge.scope.as_deref(),
            Some("repository:taostat/gm-miner:pull")
        );
    }

    #[test]
    fn parse_bearer_challenge_missing_scope_is_some() {
        let challenge = parse_bearer_challenge(r#"Bearer realm="https://r/token",service="r""#)
            .expect("realm + service is enough");
        assert_eq!(challenge.scope, None);
    }

    #[test]
    fn parse_bearer_challenge_missing_realm_is_none() {
        assert!(parse_bearer_challenge(r#"Bearer service="r",scope="s""#).is_none());
    }

    #[test]
    fn parse_bearer_challenge_non_bearer_is_none() {
        assert!(parse_bearer_challenge(r#"Basic realm="r""#).is_none());
    }

    #[test]
    fn parse_bearer_challenge_junk_is_none() {
        assert!(parse_bearer_challenge("not a challenge at all").is_none());
    }

    // ── image-ref splitting ───────────────────────────────────────────────────

    #[test]
    fn split_repo_reference_digest() {
        let (repo, reference) = split_repo_reference("ghcr.io/taostat/gm-miner@sha256:abc");
        assert_eq!(repo, "taostat/gm-miner");
        assert_eq!(reference, "sha256:abc");
    }

    #[test]
    fn split_repo_reference_tag() {
        let (repo, reference) = split_repo_reference("ghcr.io/taostat/gm-miner:v1");
        assert_eq!(repo, "taostat/gm-miner");
        assert_eq!(reference, "v1");
    }

    #[test]
    fn split_repo_reference_defaults_to_latest() {
        let (repo, reference) = split_repo_reference("ghcr.io/taostat/gm-miner");
        assert_eq!(repo, "taostat/gm-miner");
        assert_eq!(reference, "latest");
    }

    /// A `host:port` registry must not be mistaken for a tag separator — the
    /// tag is only ever in the final path segment.
    #[test]
    fn split_repo_reference_host_with_port_is_not_a_tag() {
        let (repo, reference) = split_repo_reference("localhost:5000/gm-miner:v2");
        assert_eq!(repo, "gm-miner");
        assert_eq!(reference, "v2");
    }
}
