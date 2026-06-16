//! `gmcli publish-image-version` — publish a release's measured
//! `ImageVersion` to a network's registry.
//!
//! ## Why this exists
//!
//! The registry's attestation enforcement compares a miner CVM's measured
//! `compose_hash` / `os_image_hash` against an allow-list of approved
//! `ImageVersion` rows. That allow-list used to be hand-published. The
//! CLI's rendered compose changes between releases — the digest-pinned
//! image ref and the `GM_NETWORK` literal both feed the compose, and the
//! compose feeds the hash — so a hand-published hash drifts from what the
//! released CLI actually deploys, surfacing as a "HASH MISMATCH" at deploy
//! time. This command closes that gap: the release pipeline runs it so the
//! approved hash is always the one the released CLI produces.
//!
//! ## Why it deploys rather than computing offline
//!
//! dstack's `compose_hash` is `sha256` over the *app-compose.json* manifest
//! that Phala Cloud's backend assembles — not over the `docker-compose.yaml`
//! the CLI renders. The backend owns that manifest's field set, its defaults
//! (`manifest_version`, `runner`, `kms_enabled`, `gateway_enabled`,
//! `key_provider`, the node's `default_gateway_domain`, …) and its exact
//! JSON serialization. None of that is derivable from the CLI's inputs, and
//! an empirical search over the plausible field/serializer space did not
//! reproduce a known-good oracle hash. So the only trustworthy way to learn
//! the hash a release produces is to deploy it once and read back what the
//! platform measured.
//!
//! ## Flow
//!
//! 1. Render the compose for the target network around the digest-pinned
//!    `image_ref` (same render path `gmcli deploy` uses), submit a throwaway
//!    CVM to Phala Cloud, and read back the measured `compose_hash` +
//!    `os_image_hash`.
//! 2. POST the pair to that network's registry admin endpoint
//!    (`POST /admin/image-versions`, `X-API-Key`). The endpoint is an upsert
//!    keyed on `(compose_hash, os_image_hash)`, so re-publishing the same
//!    release is a no-op update — the publish step is idempotent by
//!    construction.
//! 3. Tear the throwaway CVM down (`phala cvms delete`).

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::deploy::{normalize_hash, DeployOutcome, PhalaClient};
use crate::network::Network;

/// The registry admin route the measured version is published to.
pub const ADMIN_IMAGE_VERSIONS_PATH: &str = "/admin/image-versions";

/// The header the registry admin endpoints authenticate with.
pub const REGISTRY_ADMIN_KEY_HEADER: &str = "X-API-Key";

/// Body for `POST /admin/image-versions`.
///
/// Mirrors the registry's `AdminImageVersionRequest`: `compose_hash` and
/// `os_image_hash` are required and must be bare lowercase 64-hex;
/// everything else is optional metadata. `status` defaults to `supported`
/// server-side, so it is omitted here. `image_ref` must be digest-pinned
/// (`<repo>@sha256:<64-hex>`) to satisfy the registry's pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdminImageVersionRequest {
    pub compose_hash: String,
    pub os_image_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_ref: Option<String>,
}

/// The git provenance stamped onto a published version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitProvenance {
    /// The release tag (e.g. `v0.1.2`), recorded in `git_tag` and the notes.
    pub tag: Option<String>,
    /// The release commit SHA (40-hex), recorded in `git_commit` and the notes.
    pub commit: Option<String>,
    /// The `owner/repo` slug, recorded in `git_repo`.
    pub repo: Option<String>,
}

/// Build the admin request body for a measured version.
///
/// `compose_hash` / `os_image_hash` are normalized (lowercased, `sha256:`
/// prefix stripped) so they satisfy the registry's `^[0-9a-f]{64}$` pattern
/// regardless of how Phala Cloud reported them. The `notes` string references
/// the git tag + commit so an operator reading the allow-list can trace a row
/// back to the release that produced it.
#[must_use]
pub fn build_admin_request(
    outcome: &DeployOutcome,
    image_ref: &str,
    network: Network,
    provenance: &GitProvenance,
) -> AdminImageVersionRequest {
    AdminImageVersionRequest {
        compose_hash: normalize_hash(&outcome.hashes.compose_sha256),
        os_image_hash: normalize_hash(&outcome.hashes.os_image_hash),
        notes: Some(release_notes(network, provenance)),
        git_repo: provenance.repo.clone(),
        git_commit: provenance.commit.clone(),
        git_tag: provenance.tag.clone(),
        image_ref: Some(image_ref.to_owned()),
    }
}

/// Compose the human-readable `notes` for a published version.
///
/// References the network plus whichever of tag/commit are known, so the
/// registry row is traceable to the exact release build.
#[must_use]
pub fn release_notes(network: Network, provenance: &GitProvenance) -> String {
    use std::fmt::Write as _;

    let mut notes = format!("gm-miner {network} — auto-published by release CI");
    match (&provenance.tag, &provenance.commit) {
        // `write!` into a String is infallible; the result is discarded.
        (Some(tag), Some(commit)) => {
            let _ = write!(notes, " ({tag}, {commit})");
        }
        (Some(tag), None) => {
            let _ = write!(notes, " ({tag})");
        }
        (None, Some(commit)) => {
            let _ = write!(notes, " ({commit})");
        }
        (None, None) => {}
    }
    notes
}

/// Resolve the registry base URL a network's versions publish to.
///
/// A network's `ImageVersion` row only lives in that network's registry,
/// because the `GM_NETWORK` literal in the rendered compose makes the
/// `compose_hash` network-specific. An explicit override (the workflow's
/// per-network secret URL, or a local test) wins over the built-in default.
#[must_use]
pub fn registry_url_for(network: Network, override_url: Option<&str>) -> String {
    override_url.map_or_else(|| network.default_registry_url().to_owned(), str::to_owned)
}

/// POST a measured version to a network's registry admin endpoint.
///
/// The endpoint is an idempotent upsert keyed on `(compose_hash,
/// os_image_hash)`: a first publish inserts, a re-publish of the same
/// release updates in place. Returns the server's `action` field
/// (`inserted` / `updated`) for logging.
///
/// # Errors
/// Returns an error if the request fails at the network level, the admin key
/// is rejected (401), or the server returns any other non-2xx status.
pub async fn post_admin_image_version(
    registry_url: &str,
    admin_key: &str,
    body: &AdminImageVersionRequest,
) -> Result<String> {
    let client = crate::client::build_http_client()?;
    let url = format!("{registry_url}{ADMIN_IMAGE_VERSIONS_PATH}");

    let resp = client
        .post(&url)
        .header(REGISTRY_ADMIN_KEY_HEADER, admin_key)
        .json(body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        bail!(
            "registry rejected the admin key (401) at {url}; check the \
             REGISTRY_ADMIN_KEY for {registry_url}"
        );
    }
    if !status.is_success() {
        let detail = resp.text().await.unwrap_or_default();
        bail!("POST {ADMIN_IMAGE_VERSIONS_PATH} failed ({status}): {detail}");
    }

    let parsed: serde_json::Value = resp
        .json()
        .await
        .context("parse POST /admin/image-versions response")?;
    Ok(parsed
        .get("action")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("ok")
        .to_owned())
}

/// Deploy a throwaway CVM with `phala`, returning its measured hashes,
/// endpoint, and `app_id`.
///
/// The deploy renders the compose for `network` around `image_ref` exactly
/// as `gmcli deploy` would, so the measured `compose_hash` is the one the
/// released CLI will produce for that network. Provider keys and the node
/// secret are deploy-time env only — they are encrypted client-side into the
/// CVM and never touch the compose, so placeholders are fine here.
///
/// # Errors
/// Returns an error if the compose cannot be rendered or the Phala deploy /
/// hash read-back fails.
pub fn deploy_for_measurement(
    phala: &dyn PhalaClient,
    image_ref: &str,
    network: Network,
    boot_timeout_secs: u64,
) -> Result<DeployOutcome> {
    use crate::config::ProviderKeys;
    use crate::deploy::{render_compose, COMPOSE_TEMPLATE};

    let rendered = render_compose(COMPOSE_TEMPLATE, image_ref, network.as_str())?;
    // No provider keys and a throwaway node secret: neither is part of the
    // compose, so neither affects the measured compose_hash. The CVM only has
    // to boot far enough for Phala to measure and report it.
    let keys = ProviderKeys::default();
    phala.deploy(
        &rendered,
        &keys,
        "publish-image-version-throwaway",
        None,
        boot_timeout_secs,
    )
}

/// Tear down the throwaway CVM created for measurement.
///
/// Best-effort: a failed teardown is logged, not fatal — the version is
/// already published, and an operator can delete a stray CVM from the Phala
/// dashboard. Leaving the publish to fail over a teardown blip would be worse.
pub fn teardown_cvm(app_id: &str, api_key: Option<&str>) {
    let out = crate::deploy::phala_command(api_key)
        .args(["cvms", "delete", app_id, "--yes"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            tracing::info!(app_id, "throwaway CVM torn down");
        }
        Ok(o) => {
            tracing::warn!(
                app_id,
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "could not tear down throwaway CVM — delete it from the Phala dashboard"
            );
        }
        Err(e) => {
            tracing::warn!(
                app_id,
                error = %e,
                "could not run `phala cvms delete` — delete the CVM from the Phala dashboard"
            );
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::*;
    use crate::deploy::DstackDeployResult;

    fn outcome(compose: &str, os: &str) -> DeployOutcome {
        DeployOutcome {
            hashes: DstackDeployResult {
                compose_sha256: compose.to_owned(),
                os_image_hash: os.to_owned(),
            },
            endpoint: "https://app-8080s.node.phala.network".to_owned(),
            app_id: "app_throwaway".to_owned(),
        }
    }

    fn provenance() -> GitProvenance {
        GitProvenance {
            tag: Some("v0.1.2".to_owned()),
            commit: Some("a".repeat(40)),
            repo: Some("taostat/gm-miner".to_owned()),
        }
    }

    #[test]
    fn registry_url_defaults_per_network() {
        assert_eq!(
            registry_url_for(Network::Testnet, None),
            "https://test-registry.saygm.com"
        );
        assert_eq!(
            registry_url_for(Network::Mainnet, None),
            "https://gm-registry.taostats.io"
        );
    }

    #[test]
    fn registry_url_override_wins() {
        assert_eq!(
            registry_url_for(Network::Testnet, Some("https://local.test")),
            "https://local.test"
        );
    }

    /// The published hashes are normalized to bare lowercase hex so they
    /// satisfy the registry's `^[0-9a-f]{64}$` pattern even when Phala
    /// reports them uppercased or `sha256:`-prefixed.
    #[test]
    fn admin_request_normalizes_hashes() {
        let req = build_admin_request(
            &outcome("sha256:ABCDEF", "DEF456"),
            "ghcr.io/taostat/gm-miner@sha256:abc",
            Network::Testnet,
            &provenance(),
        );
        assert_eq!(req.compose_hash, "abcdef");
        assert_eq!(req.os_image_hash, "def456");
    }

    /// Provenance flows into the structured git fields and the `image_ref` is
    /// carried verbatim.
    #[test]
    fn admin_request_carries_provenance() {
        let req = build_admin_request(
            &outcome("abc", "def"),
            "ghcr.io/taostat/gm-miner@sha256:abc",
            Network::Mainnet,
            &provenance(),
        );
        assert_eq!(req.git_tag.as_deref(), Some("v0.1.2"));
        assert_eq!(req.git_commit.as_deref(), Some(&"a".repeat(40)[..]));
        assert_eq!(req.git_repo.as_deref(), Some("taostat/gm-miner"));
        assert_eq!(
            req.image_ref.as_deref(),
            Some("ghcr.io/taostat/gm-miner@sha256:abc")
        );
    }

    /// `status` is never serialized: the registry defaults it to `supported`,
    /// and omitting it keeps the body minimal and matches that default.
    #[test]
    fn admin_request_omits_status_and_empty_options() {
        let req = build_admin_request(
            &outcome("abc", "def"),
            "ghcr.io/taostat/gm-miner@sha256:abc",
            Network::Testnet,
            &GitProvenance::default(),
        );
        let json = serde_json::to_value(&req).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("status"));
        assert!(!obj.contains_key("git_tag"));
        assert!(!obj.contains_key("git_commit"));
        assert!(!obj.contains_key("git_repo"));
        // Required fields and notes always serialize.
        assert!(obj.contains_key("compose_hash"));
        assert!(obj.contains_key("os_image_hash"));
        assert!(obj.contains_key("notes"));
        assert!(obj.contains_key("image_ref"));
    }

    #[test]
    fn notes_reference_tag_and_commit() {
        let notes = release_notes(Network::Testnet, &provenance());
        assert!(notes.contains("testnet"));
        assert!(notes.contains("v0.1.2"));
        assert!(notes.contains(&"a".repeat(40)));
    }

    #[test]
    fn notes_degrade_when_provenance_missing() {
        let notes = release_notes(Network::Mainnet, &GitProvenance::default());
        assert!(notes.contains("mainnet"));
        assert!(!notes.contains('('));
    }

    #[test]
    fn notes_tag_only() {
        let prov = GitProvenance {
            tag: Some("v9.9.9".to_owned()),
            ..GitProvenance::default()
        };
        let notes = release_notes(Network::Testnet, &prov);
        assert!(notes.contains("(v9.9.9)"));
    }
}
