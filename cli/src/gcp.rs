//! GCP + Docker provisioning for `gm-miner deploy`.
//!
//! Ports the infrastructure side of `dstack/deploy.sh` into the CLI: the
//! `gcloud` project/service/bucket/Artifact-Registry setup, the
//! `docker buildx` image build + push, the pushed-digest resolution, and
//! the `dstack-cloud` OS-image pull.  Each external action is a subprocess
//! call with fail-fast error handling and an actionable message.
//!
//! The argument-construction helpers (`gcloud_*_args`) are pure functions
//! so the exact CLI wiring can be asserted in tests without spawning a
//! subprocess — the same testability pattern `deploy.rs` uses for
//! `build_dstack_new_args`.

use anyhow::{bail, Context, Result};

// ── GCP services the deploy requires ──────────────────────────────────────────

/// GCP service APIs enabled before any provisioning, mirroring the
/// `gcloud services enable` call in `dstack/deploy.sh`.
///
/// - `compute` — the TDX C3 CVM runs on Compute Engine.
/// - `artifactregistry` — holds the digest-pinned miner image.
/// - `confidentialcomputing` — required for the TDX confidential VM.
/// - `storage` — dstack-cloud uploads the OS image to a GCS bucket.
pub const REQUIRED_SERVICES: [&str; 4] = [
    "compute.googleapis.com",
    "artifactregistry.googleapis.com",
    "confidentialcomputing.googleapis.com",
    "storage.googleapis.com",
];

/// Default dstack-cloud OS image URL — the referenced (pre-built) UKI
/// image pulled via `dstack-cloud pull`.  An operator can override it
/// with `DSTACK_OS_IMAGE_URL`; mirrors the default in `deploy.sh`.
pub const DEFAULT_DSTACK_OS_IMAGE_URL: &str =
    "https://github.com/Phala-Network/meta-dstack-cloud/releases/download/v0.6.0-test/dstack-cloud-0.6.0-uki.tar.gz";

// ── Image-build coordinates ────────────────────────────────────────────────────

/// Coordinates for the Artifact Registry image build, derived from the
/// GCP project, region, and app name.
#[derive(Debug, Clone)]
pub struct ImageCoordinates {
    /// Artifact Registry Docker host, e.g. `us-central1-docker.pkg.dev`.
    pub ar_host: String,
    /// Full registry path, e.g. `<host>/<project>/<repo>`.
    pub ar_path: String,
    /// Tagged image ref used for the build/push, e.g. `<path>/<app>:<tag>`.
    pub tagged_ref: String,
}

impl ImageCoordinates {
    /// Derive image coordinates the same way `deploy.sh` does:
    /// `AR_HOST=<region>-docker.pkg.dev`,
    /// `AR_PATH=<host>/<project>/<repo>`,
    /// `IMAGE_REF=<path>/<app>:<tag>`.
    #[must_use]
    pub fn derive(region: &str, project: &str, repo: &str, app_name: &str, tag: &str) -> Self {
        let ar_host = format!("{region}-docker.pkg.dev");
        let ar_path = format!("{ar_host}/{project}/{repo}");
        let tagged_ref = format!("{ar_path}/{app_name}:{tag}");
        Self {
            ar_host,
            ar_path,
            tagged_ref,
        }
    }

    /// Build the digest-pinned ref `<ar_path>/<app>@<digest>` from a
    /// resolved image digest (`sha256:...`).
    #[must_use]
    pub fn pinned_ref(&self, app_name: &str, digest: &str) -> String {
        format!("{}/{app_name}@{digest}", self.ar_path)
    }
}

// ── gcloud argument builders (pure, testable) ──────────────────────────────────

/// Arguments for `gcloud config set project <project>`.
#[must_use]
pub fn gcloud_set_project_args(project: &str) -> Vec<String> {
    vec![
        "config".to_owned(),
        "set".to_owned(),
        "project".to_owned(),
        project.to_owned(),
    ]
}

/// Arguments for `gcloud services enable <service...> --quiet`.
#[must_use]
pub fn gcloud_services_enable_args() -> Vec<String> {
    let mut args = vec!["services".to_owned(), "enable".to_owned()];
    for service in REQUIRED_SERVICES {
        args.push(service.to_owned());
    }
    args.push("--quiet".to_owned());
    args
}

/// Arguments for `gcloud storage buckets describe <bucket>`.
#[must_use]
pub fn gcloud_bucket_describe_args(bucket: &str) -> Vec<String> {
    vec![
        "storage".to_owned(),
        "buckets".to_owned(),
        "describe".to_owned(),
        bucket.to_owned(),
    ]
}

/// Arguments for `gcloud storage buckets create <bucket> --location=<region>
/// --uniform-bucket-level-access --quiet`.
#[must_use]
pub fn gcloud_bucket_create_args(bucket: &str, region: &str) -> Vec<String> {
    vec![
        "storage".to_owned(),
        "buckets".to_owned(),
        "create".to_owned(),
        bucket.to_owned(),
        format!("--location={region}"),
        "--uniform-bucket-level-access".to_owned(),
        "--quiet".to_owned(),
    ]
}

/// Arguments for `gcloud artifacts repositories describe <repo>
/// --location=<region>`.
#[must_use]
pub fn gcloud_ar_describe_args(repo: &str, region: &str) -> Vec<String> {
    vec![
        "artifacts".to_owned(),
        "repositories".to_owned(),
        "describe".to_owned(),
        repo.to_owned(),
        format!("--location={region}"),
    ]
}

/// Arguments for `gcloud artifacts repositories create <repo>
/// --repository-format=docker --location=<region> --description=... --quiet`.
#[must_use]
pub fn gcloud_ar_create_args(repo: &str, region: &str) -> Vec<String> {
    vec![
        "artifacts".to_owned(),
        "repositories".to_owned(),
        "create".to_owned(),
        repo.to_owned(),
        "--repository-format=docker".to_owned(),
        format!("--location={region}"),
        "--description=gm miner images".to_owned(),
        "--quiet".to_owned(),
    ]
}

/// Arguments for `gcloud auth configure-docker <ar_host> --quiet`.
#[must_use]
pub fn gcloud_configure_docker_args(ar_host: &str) -> Vec<String> {
    vec![
        "auth".to_owned(),
        "configure-docker".to_owned(),
        ar_host.to_owned(),
        "--quiet".to_owned(),
    ]
}

/// Arguments for `gcloud artifacts docker images describe <ref>
/// --format=value(image_summary.digest)`.
#[must_use]
pub fn gcloud_image_digest_args(tagged_ref: &str) -> Vec<String> {
    vec![
        "artifacts".to_owned(),
        "docker".to_owned(),
        "images".to_owned(),
        "describe".to_owned(),
        tagged_ref.to_owned(),
        "--format=value(image_summary.digest)".to_owned(),
    ]
}

/// Arguments for the `docker buildx build` that produces the miner image.
///
/// Mirrors `deploy.sh`: `--platform linux/amd64` (the TDX C3 host is
/// amd64), `--build-arg GM_IMAGE_VERSION=<version>`, `--file image/Dockerfile`,
/// `--tag <ref>`, `--push`, with the repo root as the build context.
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

/// Preflight the host tools the GCP provisioning path needs.
///
/// `deploy.sh` preflights `gcloud`, `docker`, `python3`, and `mcopy` plus
/// a GNU-tar check.  The CLI does its own JSON/`app.json` handling so it
/// needs neither `python3` nor `mcopy`; the GNU-tar check in `deploy.sh`
/// is vestigial (it guards `gcloud compute images create`, which the
/// script never calls — the OS image is pulled by URL via
/// `dstack-cloud pull`).  Only `gcloud` and `docker` are genuinely
/// required.
///
/// # Errors
/// Returns an error naming every missing tool with an install hint.
pub fn preflight_tools() -> Result<()> {
    let checks = [
        (
            "gcloud",
            "install: https://cloud.google.com/sdk/docs/install",
        ),
        ("docker", "install: https://docs.docker.com/get-docker/"),
    ];
    let mut missing: Vec<String> = Vec::new();
    for (tool, hint) in checks {
        if !tool_on_path(tool) {
            missing.push(format!("  - {tool}: {hint}"));
        }
    }
    if !missing.is_empty() {
        bail!(
            "missing required host tools for `gm-miner deploy`:\n{}",
            missing.join("\n")
        );
    }
    Ok(())
}

/// Run `gcloud <args...>`, failing with an actionable error on non-zero exit.
fn run_gcloud(args: &[String]) -> Result<()> {
    let status = std::process::Command::new("gcloud")
        .args(args)
        .status()
        .context("run gcloud — is the Google Cloud SDK installed?")?;
    if !status.success() {
        bail!(
            "gcloud {} exited with status {}",
            args.first().map_or("", String::as_str),
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

/// Run `gcloud <args...>` for a describe-style probe, returning whether the
/// resource exists.  A non-zero exit means "not found" (the normal path on
/// a fresh project); stdout/stderr are suppressed so the probe is quiet.
fn gcloud_resource_exists(args: &[String]) -> Result<bool> {
    let status = std::process::Command::new("gcloud")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("run gcloud — is the Google Cloud SDK installed?")?;
    Ok(status.success())
}

/// Provision the GCP project: set the active project and enable the
/// required service APIs.  Mirrors the `gcloud config set project` and
/// `gcloud services enable` calls in `deploy.sh`.
///
/// # Errors
/// Returns an error if either `gcloud` call fails.
pub fn configure_project(project: &str) -> Result<()> {
    tracing::info!(project, "setting active GCP project");
    run_gcloud(&gcloud_set_project_args(project))?;

    tracing::info!("enabling required GCP service APIs");
    run_gcloud(&gcloud_services_enable_args())?;
    Ok(())
}

/// Describe-or-create the GCS bucket dstack-cloud uploads the OS image to.
/// Mirrors the bucket block in `deploy.sh`.
///
/// # Errors
/// Returns an error if the create call fails.
pub fn ensure_bucket(bucket: &str, region: &str) -> Result<()> {
    if gcloud_resource_exists(&gcloud_bucket_describe_args(bucket))? {
        tracing::info!(bucket, "GCS bucket already exists");
        return Ok(());
    }
    tracing::info!(bucket, region, "creating GCS bucket");
    run_gcloud(&gcloud_bucket_create_args(bucket, region))
}

/// Describe-or-create the Artifact Registry Docker repository.
/// Mirrors the AR block in `deploy.sh`.
///
/// # Errors
/// Returns an error if the create call fails.
pub fn ensure_artifact_registry(repo: &str, region: &str) -> Result<()> {
    if gcloud_resource_exists(&gcloud_ar_describe_args(repo, region))? {
        tracing::info!(repo, "Artifact Registry repo already exists");
        return Ok(());
    }
    tracing::info!(repo, region, "creating Artifact Registry repo");
    run_gcloud(&gcloud_ar_create_args(repo, region))
}

/// Configure Docker credential helpers for the Artifact Registry host so
/// `docker buildx --push` can authenticate.  Mirrors
/// `gcloud auth configure-docker` in `deploy.sh`.
///
/// # Errors
/// Returns an error if the `gcloud` call fails.
pub fn configure_docker_auth(ar_host: &str) -> Result<()> {
    tracing::info!(ar_host, "configuring Docker auth for Artifact Registry");
    run_gcloud(&gcloud_configure_docker_args(ar_host))
}

/// Build the miner image and push it to Artifact Registry, then resolve
/// the pushed digest into a digest-pinned ref.
///
/// Mirrors the `docker buildx build --push` and digest-resolution steps
/// in `deploy.sh`.  Returns the pinned ref `<ar_path>/<app>@sha256:...`.
///
/// # Errors
/// Returns an error if the build, push, or digest resolution fails.
pub fn build_and_push_image(
    coords: &ImageCoordinates,
    app_name: &str,
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
            "docker buildx build exited with status {}",
            status.code().unwrap_or(-1)
        );
    }

    tracing::info!("resolving pushed image digest");
    let out = std::process::Command::new("gcloud")
        .args(gcloud_image_digest_args(&coords.tagged_ref))
        .output()
        .context("run gcloud artifacts docker images describe")?;
    if !out.status.success() {
        bail!(
            "gcloud artifacts docker images describe failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let digest = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if !digest.starts_with("sha256:") {
        bail!(
            "could not resolve a sha256 digest for {} (got: {digest:?})",
            coords.tagged_ref
        );
    }

    let pinned = coords.pinned_ref(app_name, &digest);
    tracing::info!(pinned_ref = %pinned, "image pushed");
    Ok(pinned)
}

/// Pull the dstack-cloud OS image referenced by `image_url` into the
/// project directory.  Mirrors the `dstack-cloud pull` step in `deploy.sh`.
///
/// The OS image is a referenced (pre-built) artifact, not a per-deploy
/// build — `deploy.sh` pulls it by URL and `dstack-cloud` caches it under
/// `~/.dstack/images`.
///
/// # Errors
/// Returns an error if the `dstack-cloud pull` call fails.
pub fn pull_os_image(image_url: &str, project_dir: &std::path::Path) -> Result<()> {
    tracing::info!(image_url, "pulling dstack-cloud OS image");
    let status = std::process::Command::new("dstack-cloud")
        .arg("pull")
        .arg(image_url)
        .current_dir(project_dir)
        .status()
        .context("run dstack-cloud pull — is dstack-cloud installed?")?;
    if !status.success() {
        bail!(
            "dstack-cloud pull exited with status {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    #[test]
    fn set_project_args_match_deploy_sh() {
        let args = gcloud_set_project_args("my-proj");
        assert_eq!(args, ["config", "set", "project", "my-proj"]);
    }

    #[test]
    fn services_enable_lists_all_four_apis() {
        let args = gcloud_services_enable_args();
        assert_eq!(args[0], "services");
        assert_eq!(args[1], "enable");
        for service in REQUIRED_SERVICES {
            assert!(
                args.iter().any(|a| a == service),
                "missing service {service} in {args:?}"
            );
        }
        assert_eq!(args.last().map(String::as_str), Some("--quiet"));
    }

    #[test]
    fn required_services_cover_compute_ar_cc_storage() {
        assert!(REQUIRED_SERVICES.contains(&"compute.googleapis.com"));
        assert!(REQUIRED_SERVICES.contains(&"artifactregistry.googleapis.com"));
        assert!(REQUIRED_SERVICES.contains(&"confidentialcomputing.googleapis.com"));
        assert!(REQUIRED_SERVICES.contains(&"storage.googleapis.com"));
    }

    #[test]
    fn bucket_create_args_have_location_and_ubla() {
        let args = gcloud_bucket_create_args("gs://proj-dstack", "us-central1");
        assert_eq!(args[0], "storage");
        assert_eq!(args[1], "buckets");
        assert_eq!(args[2], "create");
        assert_eq!(args[3], "gs://proj-dstack");
        assert!(args.iter().any(|a| a == "--location=us-central1"));
        assert!(args.iter().any(|a| a == "--uniform-bucket-level-access"));
        assert!(args.iter().any(|a| a == "--quiet"));
    }

    #[test]
    fn bucket_describe_args_target_the_bucket() {
        let args = gcloud_bucket_describe_args("gs://proj-dstack");
        assert_eq!(args, ["storage", "buckets", "describe", "gs://proj-dstack"]);
    }

    #[test]
    fn ar_create_args_specify_docker_format_and_location() {
        let args = gcloud_ar_create_args("gm-miner", "us-central1");
        assert_eq!(&args[0..3], ["artifacts", "repositories", "create"]);
        assert_eq!(args[3], "gm-miner");
        assert!(args.iter().any(|a| a == "--repository-format=docker"));
        assert!(args.iter().any(|a| a == "--location=us-central1"));
    }

    #[test]
    fn ar_describe_args_include_location() {
        let args = gcloud_ar_describe_args("gm-miner", "us-east1");
        assert_eq!(&args[0..3], ["artifacts", "repositories", "describe"]);
        assert_eq!(args[3], "gm-miner");
        assert!(args.iter().any(|a| a == "--location=us-east1"));
    }

    #[test]
    fn configure_docker_args_target_ar_host() {
        let args = gcloud_configure_docker_args("us-central1-docker.pkg.dev");
        assert_eq!(
            args,
            [
                "auth",
                "configure-docker",
                "us-central1-docker.pkg.dev",
                "--quiet"
            ]
        );
    }

    #[test]
    fn image_digest_args_use_value_format() {
        let args = gcloud_image_digest_args("host/proj/repo/app:v1");
        assert_eq!(&args[0..4], ["artifacts", "docker", "images", "describe"]);
        assert_eq!(args[4], "host/proj/repo/app:v1");
        assert!(args
            .iter()
            .any(|a| a == "--format=value(image_summary.digest)"));
    }

    #[test]
    fn buildx_args_match_deploy_sh() {
        let args = docker_buildx_args(
            "abc123",
            "/repo/image/Dockerfile",
            "host/p/r/app:v1",
            "/repo",
        );
        assert_eq!(&args[0..2], ["buildx", "build"]);
        // --platform linux/amd64 for the TDX C3 host.
        let plat = args.iter().position(|a| a == "--platform").unwrap();
        assert_eq!(args[plat + 1], "linux/amd64");
        // --build-arg carries the image version.
        let ba = args.iter().position(|a| a == "--build-arg").unwrap();
        assert_eq!(args[ba + 1], "GM_IMAGE_VERSION=abc123");
        // --file points at the Dockerfile, build context is the repo root.
        let file = args.iter().position(|a| a == "--file").unwrap();
        assert_eq!(args[file + 1], "/repo/image/Dockerfile");
        assert!(args.iter().any(|a| a == "--push"));
        assert_eq!(args.last().map(String::as_str), Some("/repo"));
    }

    #[test]
    fn image_coordinates_derive_matches_deploy_sh() {
        let c =
            ImageCoordinates::derive("us-central1", "my-proj", "gm-miner", "gm-miner-1", "v0.1.0");
        assert_eq!(c.ar_host, "us-central1-docker.pkg.dev");
        assert_eq!(c.ar_path, "us-central1-docker.pkg.dev/my-proj/gm-miner");
        assert_eq!(
            c.tagged_ref,
            "us-central1-docker.pkg.dev/my-proj/gm-miner/gm-miner-1:v0.1.0"
        );
    }

    #[test]
    fn pinned_ref_uses_digest_not_tag() {
        let c = ImageCoordinates::derive("us-central1", "p", "gm-miner", "gm-miner-1", "v1");
        let pinned = c.pinned_ref("gm-miner-1", "sha256:deadbeef");
        assert_eq!(
            pinned,
            "us-central1-docker.pkg.dev/p/gm-miner/gm-miner-1@sha256:deadbeef"
        );
        assert!(!pinned.contains(":v1"), "pinned ref must not carry the tag");
    }
}
