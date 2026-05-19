//! `gm-miner deploy` — single-shot trust-correct deploy flow.
//!
//! Steps:
//!   1. Read provider API keys from config; error early if none set.
//!   2. Fetch the approved `ImageVersion` list from the registry.
//!   3. Select the newest supported version (or a pinned one if `--version` given).
//!   4. Render the bundled `dstack/docker-compose.yaml` template with the
//!      digest-pinned image ref from the approved version.
//!   5. Submit to dstack-cloud (via the `DstackClient` trait for testability).
//!   6. Read back `compose_sha256` + `os_image_hash` from dstack's response.
//!   7. **Verify** both match the registry's approved version — refuse and exit 1
//!      if they don't.
//!   8. Call `register_image` with the verified hashes.

use anyhow::{bail, Context, Result};
use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::config::ProviderKeys;

// ── Registry image-version types ─────────────────────────────────────────────

/// A single approved (`compose_hash`, `os_image_hash`) entry from the registry.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageVersion {
    pub compose_hash: String,
    pub os_image_hash: String,
    pub status: String,
    pub notes: Option<String>,
    pub created_at: String,
}

/// Response body from `GET /image-versions?status=supported`.
#[derive(Debug, Deserialize)]
pub struct ImageVersionsResponse {
    pub versions: Vec<ImageVersion>,
}

// ── dstack abstraction ────────────────────────────────────────────────────────

/// Result returned after a successful dstack-cloud deploy + status poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DstackDeployResult {
    /// SHA-256 of the rendered `docker-compose.yaml` as computed by dstack-cloud.
    pub compose_sha256: String,
    /// OS image hash reported by dstack-cloud.
    pub os_image_hash: String,
}

/// Abstraction over the dstack-cloud CLI, injectable for tests.
///
/// The real implementation shells out to `dstack-cloud deploy` +
/// `dstack-cloud status --json`. The mock implementation returns
/// pre-canned values without touching the filesystem.
pub trait DstackClient {
    /// Deploy and return the compose + OS image hashes that dstack-cloud
    /// actually used. `compose_yaml` is the rendered compose file content;
    /// `env_vars` are the operator's provider API keys to pass via dstack's
    /// encrypted env upload.
    ///
    /// # Errors
    /// Returns an error if the deploy fails or the hashes cannot be read back.
    fn deploy(&self, compose_yaml: &str, env_vars: &ProviderKeys) -> Result<DstackDeployResult>;
}

// ── Real dstack-cloud implementation ─────────────────────────────────────────

/// Shells out to `dstack-cloud deploy` and parses the resulting
/// `dstack-cloud status --json` to obtain both hashes.
pub struct RealDstackClient {
    /// App name used by dstack-cloud (defaults to `gm-miner-1`).
    pub app_name: String,
    /// Directory for dstack project state (`dist/<app_name>`).
    pub project_dir: std::path::PathBuf,
}

impl RealDstackClient {
    /// Create a client that manages state in `<dist_root>/<app_name>`.
    #[must_use]
    pub fn new(app_name: impl Into<String>, dist_root: &std::path::Path) -> Self {
        let name = app_name.into();
        let project_dir = dist_root.join(&name);
        Self {
            app_name: name,
            project_dir,
        }
    }
}

/// Output of `dstack-cloud status --json`.
#[derive(Debug, Deserialize)]
struct DstackStatus {
    compose_sha256: Option<String>,
    os_image_hash: Option<String>,
}

impl DstackClient for RealDstackClient {
    fn deploy(&self, compose_yaml: &str, env_vars: &ProviderKeys) -> Result<DstackDeployResult> {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        fs::create_dir_all(&self.project_dir)
            .with_context(|| format!("create project dir {}", self.project_dir.display()))?;

        // Write the rendered compose file.
        let compose_path = self.project_dir.join("docker-compose.yaml");
        fs::write(&compose_path, compose_yaml)
            .with_context(|| format!("write {}", compose_path.display()))?;

        // Write .env (mode 0600) with only the keys that are set.
        let env_path = self.project_dir.join(".env");
        {
            let mut lines = String::new();
            if let Some(k) = &env_vars.anthropic {
                lines.push_str("ANTHROPIC_API_KEY=");
                lines.push_str(k);
                lines.push('\n');
            }
            if let Some(k) = &env_vars.openai {
                lines.push_str("OPENAI_API_KEY=");
                lines.push_str(k);
                lines.push('\n');
            }
            if let Some(k) = &env_vars.google {
                lines.push_str("GOOGLE_API_KEY=");
                lines.push_str(k);
                lines.push('\n');
            }
            fs::write(&env_path, &lines)
                .with_context(|| format!("write {}", env_path.display()))?;
            fs::set_permissions(&env_path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 600 {}", env_path.display()))?;
        }

        // Run dstack-cloud deploy.
        let status = std::process::Command::new("dstack-cloud")
            .arg("deploy")
            .current_dir(&self.project_dir)
            .status()
            .context("run dstack-cloud deploy — is dstack-cloud installed?")?;

        if !status.success() {
            bail!(
                "dstack-cloud deploy exited with status {}",
                status.code().unwrap_or(-1)
            );
        }

        // Read back hashes via `dstack-cloud status --json`.
        let out = std::process::Command::new("dstack-cloud")
            .args(["status", "--json"])
            .current_dir(&self.project_dir)
            .output()
            .context("run dstack-cloud status --json")?;

        if !out.status.success() {
            bail!(
                "dstack-cloud status --json failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        let ds: DstackStatus = serde_json::from_slice(&out.stdout)
            .context("parse dstack-cloud status --json output")?;

        let compose_sha256 = ds.compose_sha256.ok_or_else(|| {
            anyhow::anyhow!(
                "dstack-cloud status --json did not include compose_sha256; \
                 try re-running after the instance boots"
            )
        })?;
        let os_image_hash = ds.os_image_hash.ok_or_else(|| {
            anyhow::anyhow!(
                "dstack-cloud status --json did not include os_image_hash; \
                 try re-running after the instance boots"
            )
        })?;

        Ok(DstackDeployResult {
            compose_sha256,
            os_image_hash,
        })
    }
}

// ── Registry image-version fetch ─────────────────────────────────────────────

/// Fetch supported image versions from the registry.
///
/// Returns the full list sorted newest-first by `created_at`.
///
/// # Errors
/// Returns an error if the registry returns 404 (endpoint not yet deployed),
/// any other non-2xx status, or the response body cannot be parsed.
pub async fn fetch_supported_versions(registry_url: &str) -> Result<Vec<ImageVersion>> {
    let url = format!("{registry_url}/image-versions?status=supported");
    let resp = reqwest::get(&url)
        .await
        .with_context(|| format!("GET {url}"))?;

    let http_status = resp.status();
    if http_status == reqwest::StatusCode::NOT_FOUND {
        bail!(
            "registry returned 404 for /image-versions — your gm-miner build is newer than \
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

    // Sort newest-first by created_at (RFC 3339 strings sort lexicographically).
    versions.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    Ok(versions)
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

// ── Compose template rendering ────────────────────────────────────────────────

/// Render the compose template, substituting `${GM_IMAGE_REF...}` with
/// the supplied pinned image reference.
///
/// Mirrors the `sed` invocation in `deploy.sh`:
///
/// ```text
/// sed "s|\${GM_IMAGE_REF[^}]*}|${PINNED_REF}|g" ...
/// ```
///
/// # Errors
/// Returns an error if the substitution did not change the template (i.e.
/// the placeholder was not found).
pub fn render_compose(template: &str, pinned_image_ref: &str) -> Result<String> {
    // Replace the shell-variable placeholder pattern ${GM_IMAGE_REF...}
    // with the digest-pinned ref. We do a simple prefix match: anything
    // that starts with `${GM_IMAGE_REF` and ends at the next `}`.
    let result = replace_image_ref_placeholder(template, pinned_image_ref);
    if result == template {
        bail!(
            "compose template does not contain a GM_IMAGE_REF placeholder; \
             expected something like ${{GM_IMAGE_REF:?...}} in dstack/docker-compose.yaml"
        );
    }
    Ok(result)
}

/// Replace every `${GM_IMAGE_REF...}` shell-variable expression in `text`
/// with `replacement`. Equivalent to the sed expression in `deploy.sh`:
///
/// ```text
/// sed "s|\${GM_IMAGE_REF[^}]*}|${PINNED_REF}|g"
/// ```
fn replace_image_ref_placeholder(text: &str, replacement: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut remaining = text;
    let prefix = "${GM_IMAGE_REF";

    loop {
        match remaining.find(prefix) {
            None => {
                result.push_str(remaining);
                break;
            }
            Some(start) => {
                result.push_str(&remaining[..start]);
                let after_prefix = &remaining[start + prefix.len()..];
                match after_prefix.find('}') {
                    None => {
                        // Unterminated placeholder — leave it as-is.
                        result.push_str(&remaining[start..]);
                        break;
                    }
                    Some(end_offset) => {
                        result.push_str(replacement);
                        remaining = &after_prefix[end_offset + 1..];
                    }
                }
            }
        }
    }

    result
}

// ── Hash verification ─────────────────────────────────────────────────────────

/// Verify that the actual hashes from dstack-cloud match the registry-approved
/// version.
///
/// # Errors
/// Returns a loud, actionable error if either hash does not match.
pub fn verify_hashes(actual: &DstackDeployResult, approved: &ImageVersion) -> Result<()> {
    let compose_match =
        actual.compose_sha256.to_lowercase() == approved.compose_hash.to_lowercase();
    let os_match = actual.os_image_hash.to_lowercase() == approved.os_image_hash.to_lowercase();

    if compose_match && os_match {
        return Ok(());
    }

    let mut msg = String::from("HASH MISMATCH — deployment is suspect; refusing to register.\n\n");

    if !compose_match {
        msg.push_str("  compose_hash\n    expected (registry): ");
        msg.push_str(&approved.compose_hash);
        msg.push_str("\n    actual (dstack):     ");
        msg.push_str(&actual.compose_sha256);
        msg.push_str("\n\n");
    }
    if !os_match {
        msg.push_str("  os_image_hash\n    expected (registry): ");
        msg.push_str(&approved.os_image_hash);
        msg.push_str("\n    actual (dstack):     ");
        msg.push_str(&actual.os_image_hash);
        msg.push_str("\n\n");
    }
    msg.push_str(
        "If you believe this is a legitimate new build, wait for the registry to \
         publish a new approved version and retry.",
    );

    bail!("{msg}");
}

// ── Timestamp helper ──────────────────────────────────────────────────────────

/// Format an RFC 3339 `created_at` timestamp for human display.
#[must_use]
pub fn format_created_at(ts: &str) -> String {
    DateTime::parse_from_rfc3339(ts).map_or_else(
        |_| ts.to_owned(),
        |dt| dt.format("%Y-%m-%d %H:%M UTC").to_string(),
    )
}

// ── Bundled compose template ──────────────────────────────────────────────────

/// The dstack compose template, bundled at compile time from
/// `dstack/docker-compose.yaml` relative to the workspace root.
pub const COMPOSE_TEMPLATE: &str = include_str!("../../dstack/docker-compose.yaml");

// ── Serialisable `ImageVersion` for tests ────────────────────────────────────

/// Mirror of `ImageVersion` with `Serialize` — only used to build mock
/// registry responses in tests.
#[derive(Serialize)]
pub struct ImageVersionOut {
    pub compose_hash: String,
    pub os_image_hash: String,
    pub status: String,
    pub notes: Option<String>,
    pub created_at: String,
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_replaced_once() {
        let template = "image: ${GM_IMAGE_REF:?GM_IMAGE_REF must be set}\n  ports:\n";
        let rendered =
            render_compose(template, "reg.example.com/app@sha256:abc123").expect("should render");
        assert!(rendered.contains("reg.example.com/app@sha256:abc123"));
        assert!(!rendered.contains("GM_IMAGE_REF"));
    }

    #[test]
    fn placeholder_missing_returns_error() {
        let template = "image: my-image\n";
        assert!(render_compose(template, "anything").is_err());
    }

    #[test]
    fn verify_hashes_passes_on_match() {
        let actual = DstackDeployResult {
            compose_sha256: "abc123".to_string(),
            os_image_hash: "def456".to_string(),
        };
        let approved = ImageVersion {
            compose_hash: "abc123".to_string(),
            os_image_hash: "def456".to_string(),
            status: "supported".to_string(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        };
        assert!(verify_hashes(&actual, &approved).is_ok());
    }

    #[test]
    fn verify_hashes_case_insensitive() {
        let actual = DstackDeployResult {
            compose_sha256: "ABC123".to_string(),
            os_image_hash: "DEF456".to_string(),
        };
        let approved = ImageVersion {
            compose_hash: "abc123".to_string(),
            os_image_hash: "def456".to_string(),
            status: "supported".to_string(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        };
        assert!(verify_hashes(&actual, &approved).is_ok());
    }

    #[test]
    fn verify_hashes_fails_on_compose_mismatch() {
        let actual = DstackDeployResult {
            compose_sha256: "WRONG".to_string(),
            os_image_hash: "def456".to_string(),
        };
        let approved = ImageVersion {
            compose_hash: "abc123".to_string(),
            os_image_hash: "def456".to_string(),
            status: "supported".to_string(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let err = verify_hashes(&actual, &approved).unwrap_err();
        assert!(err.to_string().contains("compose_hash"));
        assert!(err.to_string().contains("HASH MISMATCH"));
    }

    #[test]
    fn verify_hashes_fails_on_os_mismatch() {
        let actual = DstackDeployResult {
            compose_sha256: "abc123".to_string(),
            os_image_hash: "WRONG".to_string(),
        };
        let approved = ImageVersion {
            compose_hash: "abc123".to_string(),
            os_image_hash: "def456".to_string(),
            status: "supported".to_string(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let err = verify_hashes(&actual, &approved).unwrap_err();
        assert!(err.to_string().contains("os_image_hash"));
        assert!(err.to_string().contains("HASH MISMATCH"));
    }

    #[test]
    fn verify_hashes_fails_on_both_mismatch() {
        let actual = DstackDeployResult {
            compose_sha256: "W1".to_string(),
            os_image_hash: "W2".to_string(),
        };
        let approved = ImageVersion {
            compose_hash: "abc123".to_string(),
            os_image_hash: "def456".to_string(),
            status: "supported".to_string(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let err = verify_hashes(&actual, &approved).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("compose_hash"));
        assert!(msg.contains("os_image_hash"));
    }

    #[test]
    fn select_version_latest_when_no_pin() {
        let versions = vec![
            ImageVersion {
                compose_hash: "new".to_string(),
                os_image_hash: "new".to_string(),
                status: "supported".to_string(),
                notes: None,
                created_at: "2025-03-01T00:00:00Z".to_string(),
            },
            ImageVersion {
                compose_hash: "old".to_string(),
                os_image_hash: "old".to_string(),
                status: "supported".to_string(),
                notes: None,
                created_at: "2025-01-01T00:00:00Z".to_string(),
            },
        ];
        let selected = select_version(&versions, None).expect("should select");
        assert_eq!(selected.compose_hash, "new");
    }

    #[test]
    fn select_version_pinned() {
        let versions = vec![
            ImageVersion {
                compose_hash: "new".to_string(),
                os_image_hash: "new".to_string(),
                status: "supported".to_string(),
                notes: None,
                created_at: "2025-03-01T00:00:00Z".to_string(),
            },
            ImageVersion {
                compose_hash: "old".to_string(),
                os_image_hash: "old".to_string(),
                status: "supported".to_string(),
                notes: None,
                created_at: "2025-01-01T00:00:00Z".to_string(),
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
        let versions = vec![ImageVersion {
            compose_hash: "x".to_string(),
            os_image_hash: "x".to_string(),
            status: "supported".to_string(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        }];
        assert!(select_version(&versions, Some(2)).is_err());
        assert!(select_version(&versions, Some(0)).is_err());
    }
}
