//! Registry image-version fetch, selection, and source resolution.

use anyhow::{bail, Context, Result};
use chrono::DateTime;
use serde::{Deserialize, Serialize};

/// A single approved (`compose_hash`, `os_image_hash`) entry from the registry.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageVersion {
    pub compose_hash: String,
    pub os_image_hash: String,
    pub status: String,
    pub notes: Option<String>,
    pub created_at: String,
    /// Digest-pinned, directly-pullable reference of the gm-published miner
    /// image whose compose renders to `compose_hash`, e.g.
    /// `ghcr.io/taostat/gm-miner@sha256:...`. `gmcli deploy` defaults to this
    /// so a normal miner deploys the gm-supported image rather than building
    /// one. Optional because the field post-dates the earliest rows; an entry
    /// without it cannot be deployed by digest, so the default path fails with
    /// guidance toward `--image-ref` / `--image-repo`.
    #[serde(default)]
    pub image_ref: Option<String>,
    /// Capability stamp from the publish pipeline
    /// (docs/contracts/upstream-key-slots.md in the gm repo, "Slot
    /// capability" section). Rows published before the field exists
    /// default to empty: old images advertise no features.
    #[serde(default)]
    pub features: Vec<String>,
}

impl ImageVersion {
    /// `true` when this image's entrypoint understands upstream key
    /// slots (multi-key fan-out and the `x-gm-upstream-slot` header).
    #[must_use]
    pub fn slot_capable(&self) -> bool {
        self.features.iter().any(|f| f == "upstream-key-slots")
    }
}

/// Response body from `GET /image-versions?status=supported`.
#[derive(Debug, Deserialize)]
pub struct ImageVersionsResponse {
    pub versions: Vec<ImageVersion>,
}

/// Mirror of `ImageVersion` with `Serialize` — only used to build mock
/// registry responses in tests.
#[derive(Serialize)]
pub struct ImageVersionOut {
    pub compose_hash: String,
    pub os_image_hash: String,
    pub status: String,
    pub notes: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_ref: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

/// Fetch supported image versions from the registry.
///
/// Returns the full list sorted newest-first by `created_at`.
///
/// # Errors
/// Returns an error if the registry returns 404 (endpoint not yet deployed),
/// any other non-2xx status, or the response body cannot be parsed.
pub async fn fetch_supported_versions(registry_url: &str) -> Result<Vec<ImageVersion>> {
    // A one-shot client (30 s timeout, gmcli user-agent) — same shape as
    // RegistryClient — rather than bare `reqwest::get()` which has no timeout.
    let client = crate::client::build_http_client()?;

    let url = format!("{registry_url}/image-versions?status=supported");
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    let http_status = resp.status();
    if http_status == reqwest::StatusCode::NOT_FOUND {
        bail!(
            "registry returned 404 for /image-versions — your gmcli build is newer than \
             the registry deployment; wait for the registry to be updated and retry"
        );
    }
    if !http_status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("GET /image-versions failed ({http_status}): {body}");
    }

    let body: ImageVersionsResponse = resp
        .json()
        .await
        .context("parse /image-versions response")?;

    let mut versions = body.versions;

    // Sort newest-first by the parsed `created_at` instant. Raw RFC 3339
    // strings only sort correctly when every offset is `Z`; an entry like
    // `2025-05-01T00:30:00+01:00` would otherwise sort after an older `Z`
    // timestamp. Unparseable timestamps sort last so they are never picked
    // as the default newest version.
    versions.sort_by_key(|v| std::cmp::Reverse(created_at_key(v)));

    Ok(versions)
}

/// Sort key for ordering `ImageVersion`s by `created_at`, newest-first.
///
/// Returns the parsed UTC instant, or `DateTime::<Utc>::MIN_UTC` when the
/// timestamp cannot be parsed so malformed entries sort as oldest.
fn created_at_key(v: &ImageVersion) -> chrono::DateTime<chrono::Utc> {
    DateTime::parse_from_rfc3339(&v.created_at)
        .map_or(chrono::DateTime::<chrono::Utc>::MIN_UTC, |dt| dt.to_utc())
}

/// Select a version from the list, optionally pinned to a specific index
/// (1-based, matching the order returned by the registry newest-first).
///
/// # Errors
/// Returns an error if the list is empty or the requested index is out of range.
pub fn select_version(versions: &[ImageVersion], pin: Option<usize>) -> Result<&ImageVersion> {
    if versions.is_empty() {
        bail!("registry returned no supported image versions — no approved version to deploy");
    }

    match pin {
        None => Ok(&versions[0]),
        Some(n) => {
            if n == 0 || n > versions.len() {
                bail!("--version {n} is out of range (1..={})", versions.len());
            }
            Ok(&versions[n - 1])
        }
    }
}

/// How `gmcli deploy` resolves the miner image to deploy, in priority order.
///
/// A normal miner deploys the gm-published, registry-supported image — they
/// never build. The two non-default arms exist only as explicit opt-ins:
/// `--image-ref` pins a specific pre-built digest, and `--image-repo` requests
/// a local build+push (the legacy path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageSource {
    /// Use this digest-pinned ref verbatim — no build.
    Prebuilt {
        /// The digest-pinned ref to embed in the compose file.
        image_ref: String,
    },
    /// Build the miner image locally and push it to this public repo, then
    /// pin the pushed digest. Requested explicitly via `--image-repo`.
    Build,
}

/// Resolve which image a deploy should use from the operator's flags and the
/// registry-selected supported version.
///
/// Precedence:
///   1. `--image-ref` (explicit pre-built digest) — always wins.
///   2. `--image-repo` (explicit local build opt-in) — build + push.
///   3. The registry-supported version's `image_ref` — the default, so a
///      normal miner deploys the gm-published image without building.
///
/// # Errors
/// Returns an error when neither flag is set and the supported version carries
/// no `image_ref` — there is then no image to deploy, and the message points
/// at `--image-ref` / `--image-repo`.
pub fn resolve_image_source(
    image_ref_flag: Option<&str>,
    image_repo_flag: Option<&str>,
    supported_image_ref: Option<&str>,
) -> Result<ImageSource> {
    if let Some(explicit) = image_ref_flag {
        return Ok(ImageSource::Prebuilt {
            image_ref: explicit.to_owned(),
        });
    }
    if image_repo_flag.is_some() {
        return Ok(ImageSource::Build);
    }
    if let Some(supported) = supported_image_ref {
        return Ok(ImageSource::Prebuilt {
            image_ref: supported.to_owned(),
        });
    }
    bail!(
        "the registry's supported image version has no pullable image_ref, so \
         there is no gm-published image to deploy by default.\n  \
         pass --image-ref <registry/repo@sha256:...> to deploy a specific \
         pre-built image, or --image-repo <registry/owner/gm-miner> to build \
         and push one yourself"
    )
}

/// Format an RFC 3339 `created_at` timestamp for human display.
#[must_use]
pub fn format_created_at(ts: &str) -> String {
    DateTime::parse_from_rfc3339(ts).map_or_else(
        |_| ts.to_owned(),
        |dt| dt.format("%Y-%m-%d %H:%M UTC").to_string(),
    )
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    fn approved(compose: &str, os: &str) -> ImageVersion {
        ImageVersion {
            compose_hash: compose.to_owned(),
            os_image_hash: os.to_owned(),
            status: "supported".to_owned(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_owned(),
            image_ref: None,
            features: vec![],
        }
    }

    // ── default image-ref resolution ──────────────────────────────────────────

    /// With no flags, the registry-supported version's `image_ref` is the
    /// default — a normal miner deploys the gm-published image, never building.
    #[test]
    fn resolve_image_source_defaults_to_supported_ref() {
        let source = resolve_image_source(None, None, Some("ghcr.io/taostat/gm-miner@sha256:abc"))
            .expect("supported ref must resolve");
        assert_eq!(
            source,
            ImageSource::Prebuilt {
                image_ref: "ghcr.io/taostat/gm-miner@sha256:abc".to_owned(),
            },
        );
    }

    /// `--image-ref` wins over both the supported default and `--image-repo`.
    #[test]
    fn resolve_image_source_image_ref_flag_overrides() {
        let source = resolve_image_source(
            Some("ghcr.io/me/gm-miner@sha256:def"),
            Some("ghcr.io/me/gm-miner"),
            Some("ghcr.io/taostat/gm-miner@sha256:abc"),
        )
        .expect("explicit ref must resolve");
        assert_eq!(
            source,
            ImageSource::Prebuilt {
                image_ref: "ghcr.io/me/gm-miner@sha256:def".to_owned(),
            },
        );
    }

    /// `--image-repo` (without `--image-ref`) opts into a local build even when
    /// a supported ref exists.
    #[test]
    fn resolve_image_source_image_repo_opts_into_build() {
        let source = resolve_image_source(
            None,
            Some("ghcr.io/me/gm-miner"),
            Some("ghcr.io/taostat/gm-miner@sha256:abc"),
        )
        .expect("build opt-in must resolve");
        assert_eq!(source, ImageSource::Build);
    }

    /// No flags and no supported `image_ref` is an error — there is nothing to
    /// deploy — and the message points at both escape hatches.
    #[test]
    fn resolve_image_source_errors_when_no_ref_available() {
        let err = resolve_image_source(None, None, None)
            .expect_err("missing image must abort the default path");
        let msg = err.to_string();
        assert!(msg.contains("--image-ref"), "got: {msg}");
        assert!(msg.contains("--image-repo"), "got: {msg}");
    }

    #[test]
    fn select_version_latest_when_no_pin() {
        let versions = vec![
            ImageVersion {
                created_at: "2025-03-01T00:00:00Z".to_string(),
                ..approved("new", "new")
            },
            ImageVersion {
                created_at: "2025-01-01T00:00:00Z".to_string(),
                ..approved("old", "old")
            },
        ];
        let selected = select_version(&versions, None).expect("should select");
        assert_eq!(selected.compose_hash, "new");
    }

    #[test]
    fn select_version_pinned() {
        let versions = vec![
            ImageVersion {
                created_at: "2025-03-01T00:00:00Z".to_string(),
                ..approved("new", "new")
            },
            ImageVersion {
                created_at: "2025-01-01T00:00:00Z".to_string(),
                ..approved("old", "old")
            },
        ];
        let selected = select_version(&versions, Some(2)).expect("should select");
        assert_eq!(selected.compose_hash, "old");
    }

    #[test]
    fn select_version_empty_errors() {
        assert!(select_version(&[], None).is_err());
    }

    #[test]
    fn select_version_out_of_range_errors() {
        let versions = vec![approved("x", "x")];
        assert!(select_version(&versions, Some(2)).is_err());
        assert!(select_version(&versions, Some(0)).is_err());
    }
}
