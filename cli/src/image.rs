//! Miner image build + push for `gm-miner deploy`.
//!
//! Phala Cloud pulls the miner image from a public container registry, so
//! the deploy flow builds the image and pushes it to a registry the
//! operator controls (Docker Hub or GHCR) before submitting the compose
//! stack. The build is `docker buildx build --platform linux/amd64 --push`,
//! followed by a digest read so the compose file pins `image@sha256:...`
//! rather than a mutable tag — the registry's compose-hash allow-list only
//! holds if the image reference is immutable.
//!
//! The argument-construction helpers (`docker_*_args`) are pure functions
//! so the exact CLI wiring can be asserted in tests without spawning a
//! subprocess.

use anyhow::{bail, Context, Result};

// ── Image-build coordinates ────────────────────────────────────────────────────

/// Coordinates for a public-registry image build.
///
/// `repo` is the full registry path the operator pushes to and Phala Cloud
/// pulls from, e.g. `ghcr.io/<owner>/gm-miner` or `docker.io/<user>/gm-miner`.
#[derive(Debug, Clone)]
pub struct ImageCoordinates {
    /// Tagged image ref used for the build/push, e.g. `<repo>:<tag>`.
    pub tagged_ref: String,
    /// Repository path without a tag, e.g. `ghcr.io/<owner>/gm-miner`.
    pub repo: String,
}

impl ImageCoordinates {
    /// Build coordinates from a public-registry repo path and a tag.
    #[must_use]
    pub fn new(repo: impl Into<String>, tag: &str) -> Self {
        let repo = repo.into();
        let tagged_ref = format!("{repo}:{tag}");
        Self { tagged_ref, repo }
    }

    /// Build the digest-pinned ref `<repo>@<digest>` from a resolved image
    /// digest (`sha256:...`).
    #[must_use]
    pub fn pinned_ref(&self, digest: &str) -> String {
        format!("{}@{digest}", self.repo)
    }
}

// ── docker argument builders (pure, testable) ──────────────────────────────────

/// Arguments for the `docker buildx build` that produces the miner image.
///
/// `--platform linux/amd64` because the Phala Cloud TDX host is amd64;
/// `--provenance=false` so the pushed manifest is a plain image manifest
/// (not an OCI image index), which keeps the `@sha256:` digest stable and
/// directly pullable.
#[must_use]
pub fn docker_buildx_args(
    image_version: &str,
    dockerfile: &str,
    tagged_ref: &str,
    context_dir: &str,
) -> Vec<String> {
    vec![
        "buildx".to_owned(),
        "build".to_owned(),
        "--platform".to_owned(),
        "linux/amd64".to_owned(),
        "--provenance=false".to_owned(),
        "--build-arg".to_owned(),
        format!("GM_IMAGE_VERSION={image_version}"),
        "--file".to_owned(),
        dockerfile.to_owned(),
        "--tag".to_owned(),
        tagged_ref.to_owned(),
        "--push".to_owned(),
        context_dir.to_owned(),
    ]
}

/// Arguments for `docker buildx imagetools inspect <ref> --format
/// {{json .Manifest.Digest}}` — reads the digest of the just-pushed image
/// straight from the registry.
#[must_use]
pub fn docker_digest_args(tagged_ref: &str) -> Vec<String> {
    vec![
        "buildx".to_owned(),
        "imagetools".to_owned(),
        "inspect".to_owned(),
        tagged_ref.to_owned(),
        "--format".to_owned(),
        "{{json .Manifest.Digest}}".to_owned(),
    ]
}

// ── Subprocess helpers ─────────────────────────────────────────────────────────

/// Return true if `tool` is on `PATH`.
fn tool_on_path(tool: &str) -> bool {
    std::process::Command::new(tool)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Preflight the host tools the local-build path needs: `docker` (with
/// `buildx`) to build and push the miner image.
///
/// # Errors
/// Returns an error naming every missing tool with an install hint.
pub fn preflight_tools() -> Result<()> {
    if !tool_on_path("docker") {
        bail!(
            "missing required host tool for `gm-miner deploy`:\n  \
             - docker: install: https://docs.docker.com/get-docker/"
        );
    }
    Ok(())
}

/// Build the miner image and push it to the public registry, then resolve
/// the pushed digest into a digest-pinned ref.
///
/// Returns the pinned ref `<repo>@sha256:...`.
///
/// # Errors
/// Returns an error if the build, push, or digest resolution fails.
pub fn build_and_push_image(
    coords: &ImageCoordinates,
    image_version: &str,
    repo_root: &std::path::Path,
) -> Result<String> {
    let dockerfile = repo_root.join("image").join("Dockerfile");
    let dockerfile = dockerfile.to_string_lossy().into_owned();
    let context = repo_root.to_string_lossy().into_owned();

    tracing::info!(
        image = %coords.tagged_ref,
        version = image_version,
        "building and pushing miner image (linux/amd64)"
    );
    let args = docker_buildx_args(image_version, &dockerfile, &coords.tagged_ref, &context);
    let status = std::process::Command::new("docker")
        .args(&args)
        .status()
        .context("run docker buildx build — is Docker installed and running?")?;
    if !status.success() {
        bail!(
            "docker buildx build exited with status {} — \
             check that you are logged in to the target registry \
             (`docker login`)",
            status.code().unwrap_or(-1)
        );
    }

    tracing::info!("resolving pushed image digest");
    let out = std::process::Command::new("docker")
        .args(docker_digest_args(&coords.tagged_ref))
        .output()
        .context("run docker buildx imagetools inspect")?;
    if !out.status.success() {
        bail!(
            "docker buildx imagetools inspect failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let digest = parse_digest(&out.stdout)
        .with_context(|| format!("resolve a sha256 digest for {}", coords.tagged_ref))?;

    let pinned = coords.pinned_ref(&digest);
    tracing::info!(pinned_ref = %pinned, "image pushed");
    Ok(pinned)
}

/// Parse the `sha256:...` digest from `docker buildx imagetools inspect
/// --format {{json .Manifest.Digest}}` output.
///
/// The `{{json ...}}` template emits a JSON string (the digest in quotes);
/// a plain unquoted digest is also accepted so the helper tolerates a
/// format change in a future docker release.
///
/// # Errors
/// Returns an error if the output does not contain a `sha256:` digest.
fn parse_digest(stdout: &[u8]) -> Result<String> {
    let raw = String::from_utf8_lossy(stdout);
    let digest = raw.trim().trim_matches('"').to_owned();
    if !digest.starts_with("sha256:") {
        bail!("expected a sha256: digest, got {digest:?}");
    }
    Ok(digest)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    #[test]
    fn coordinates_tagged_ref_combines_repo_and_tag() {
        let c = ImageCoordinates::new("ghcr.io/taostat/gm-miner", "v0.1.0");
        assert_eq!(c.tagged_ref, "ghcr.io/taostat/gm-miner:v0.1.0");
        assert_eq!(c.repo, "ghcr.io/taostat/gm-miner");
    }

    #[test]
    fn pinned_ref_uses_digest_not_tag() {
        let c = ImageCoordinates::new("ghcr.io/taostat/gm-miner", "v0.1.0");
        let pinned = c.pinned_ref("sha256:deadbeef");
        assert_eq!(pinned, "ghcr.io/taostat/gm-miner@sha256:deadbeef");
        assert!(
            !pinned.contains(":v0.1.0"),
            "pinned ref must not carry the tag"
        );
    }

    #[test]
    fn buildx_args_target_linux_amd64_and_push() {
        let args = docker_buildx_args(
            "abc123",
            "/repo/image/Dockerfile",
            "ghcr.io/o/gm-miner:v1",
            "/repo",
        );
        assert_eq!(&args[0..2], ["buildx", "build"]);
        let plat = args.iter().position(|a| a == "--platform").unwrap();
        assert_eq!(args[plat + 1], "linux/amd64");
        let ba = args.iter().position(|a| a == "--build-arg").unwrap();
        assert_eq!(args[ba + 1], "GM_IMAGE_VERSION=abc123");
        let file = args.iter().position(|a| a == "--file").unwrap();
        assert_eq!(args[file + 1], "/repo/image/Dockerfile");
        assert!(args.iter().any(|a| a == "--push"));
        // --provenance=false keeps the pushed manifest a plain image
        // manifest so the @sha256: digest is stable and pullable.
        assert!(args.iter().any(|a| a == "--provenance=false"));
        assert_eq!(args.last().map(String::as_str), Some("/repo"));
    }

    #[test]
    fn digest_args_request_json_manifest_digest() {
        let args = docker_digest_args("ghcr.io/o/gm-miner:v1");
        assert_eq!(&args[0..3], ["buildx", "imagetools", "inspect"]);
        assert_eq!(args[3], "ghcr.io/o/gm-miner:v1");
        assert!(args.iter().any(|a| a == "{{json .Manifest.Digest}}"));
    }

    #[test]
    fn parse_digest_strips_json_quotes() {
        let digest = parse_digest(b"\"sha256:abc123\"\n").unwrap();
        assert_eq!(digest, "sha256:abc123");
    }

    #[test]
    fn parse_digest_accepts_unquoted_digest() {
        let digest = parse_digest(b"sha256:def456").unwrap();
        assert_eq!(digest, "sha256:def456");
    }

    #[test]
    fn parse_digest_rejects_non_sha256() {
        assert!(parse_digest(b"\"not-a-digest\"").is_err());
        assert!(parse_digest(b"").is_err());
    }
}
