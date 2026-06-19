//! `gmcli deploy` — single-shot trust-correct deploy flow.
//!
//! This module and `crate::image` together are the whole operator deploy
//! pipeline: the `gmcli deploy` subcommand builds the miner image,
//! submits the compose stack to Phala Cloud, verifies the resulting CVM's
//! measured hashes against the registry allow-list, and registers the
//! image.
//!
//! Phala Cloud owns the confidential VM, the KMS, and `app_id`
//! authorization. The trust check therefore rests entirely on verifying
//! the deployed CVM's compose hash and OS image hash against the
//! registry's approved `ImageVersion` list — there is no client-side KMS
//! trust-pinning to do.
//!
//! Steps (orchestrated from `commands::deploy::cmd_deploy`):
//!   1. Read provider API keys from config; error early if none set.
//!   2. Auth preflight (`GET /miners/me`) — fail fast if the operator
//!      forgot `gmcli login` or has a stale token, before any CVM work.
//!   3. Fetch the approved `ImageVersion` list from the registry.
//!   4. Select the newest supported version (or a pinned one if `--version`
//!      given).
//!   5. Prepare the deploy target ([`prepare_deploy_target`]): build and
//!      push the miner image to a registry (or accept a pre-built
//!      `--image-ref`), then render the bundled `dstack/docker-compose.yaml`
//!      template with the digest-pinned ref. Resolve private-registry pull
//!      credentials from the image ref's host plus the operator-set
//!      `GHCR_PULL_USERNAME` / `GHCR_PULL_TOKEN` env vars.
//!   6. Submit the compose stack to Phala Cloud (via the [`PhalaClient`]
//!      trait for testability) — with a production OS image (`--image` +
//!      `--no-dev-os`), the corrected digest-aware pre-launch script, and
//!      the registry pull credentials in the encrypted env — wait for the
//!      CVM to boot, and read back the measured `compose_hash` +
//!      `os_image_hash` and the CVM's public endpoint.
//!   7. **Verify** both hashes match the registry's approved version —
//!      refuse and exit 1 if they don't.
//!   8. Call `register_image` with the verified hashes and the endpoint.

use anyhow::Result;

mod compose;
mod cvm;
mod hashes;
mod registry_auth;
mod version;

pub use compose::{render_compose, render_env_file, COMPOSE_TEMPLATE, PRELAUNCH_SCRIPT};
pub use cvm::{
    build_phala_deploy_args, parse_phala_cvm_app_id, parse_phala_cvm_detail,
    parse_phala_cvm_endpoint, parse_phala_cvm_name, phala_command, preflight_phala_cli,
    to_ratls_passthrough_endpoint, PhalaClient, PhalaDeployArgs, RealPhalaClient,
    PHALA_APP_ID_FIELD, PHALA_COMPOSE_HASH_FIELD, PHALA_ENDPOINT_FIELD, PHALA_OS_IMAGE_HASH_FIELD,
    POLL_INTERVAL_SECS,
};
pub use hashes::{normalize_hash, verify_hashes, DeployOutcome, DstackDeployResult};
pub use registry_auth::{
    fetch_anonymous_token, image_is_public, non_empty_env, parse_bearer_challenge, registry_host,
    resolve_registry_credentials, split_repo_reference, visibility_from_status, BearerChallenge,
    RegistryCredentials, Visibility, GHCR_PULL_TOKEN_VAR, GHCR_PULL_USERNAME_VAR,
};
pub use version::{
    fetch_supported_versions, format_created_at, resolve_image_source, select_version, ImageSource,
    ImageVersion, ImageVersionOut, ImageVersionsResponse,
};

/// Default maximum time to wait for hashes to appear after deploy (seconds).
pub const DEFAULT_BOOT_TIMEOUT_SECS: u64 = 300;

/// Default OS image passed to `phala deploy --image`.
///
/// The OS image version must match the dstack version of the Phala node
/// the CVM lands on. The current prod nodes (prod5/prod9) run dstack
/// v0.5.7, so `dstack-0.5.7` is the working default; `dstack-0.5.10`
/// returns "no available resources".
pub const DEFAULT_OS_IMAGE: &str = "dstack-0.5.7";

/// Abstraction over the image-build step, injectable so the deploy
/// orchestration can be exercised without a real `docker` toolchain.
///
/// The real implementation (in `crate::image`, wired by `main`) either
/// builds and pushes the miner image to a public registry, or — when the
/// operator supplied `--image-ref` — skips the build and returns the
/// pre-built ref.
pub trait ImageProvisioner {
    /// Build the miner image and return the digest-pinned image ref to
    /// embed in the compose template.
    ///
    /// # Errors
    /// Returns an error if the image build/push fails.
    fn provision(&self) -> Result<String>;
}

/// A prepared deploy target: the digest-pinned miner image ref and the
/// compose file rendered to embed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployTarget {
    /// Digest-pinned miner image reference, e.g.
    /// `ghcr.io/owner/gm-miner@sha256:...`.
    pub image_ref: String,
    /// `docker-compose.yaml` content with `${GM_IMAGE_REF}` substituted.
    pub rendered_compose: String,
}

/// Prepare the deploy target: provision the miner image, then render the
/// compose file with the digest-pinned ref and the active network.
///
/// Returns the digest-pinned image ref (needed to derive the registry
/// pull credentials) and the rendered `docker-compose.yaml` content.
///
/// # Errors
/// Returns an error if image provisioning or compose rendering fails.
pub fn prepare_deploy_target(
    provisioner: &dyn ImageProvisioner,
    network: &str,
) -> Result<DeployTarget> {
    // Build/push the image (or accept a pre-built ref). The
    // build-vs-prebuilt branch lives entirely inside the `ImageProvisioner`.
    let image_ref = provisioner.provision()?;

    // Render the compose template with the digest-pinned ref and the
    // active network — both end up as literals in the rendered compose
    // and contribute to the attestation-measured compose_hash.
    let rendered_compose = render_compose(COMPOSE_TEMPLATE, &image_ref, network)?;

    Ok(DeployTarget {
        image_ref,
        rendered_compose,
    })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use anyhow::bail;

    use super::*;

    /// `prepare_deploy_target` provisions the image and pins the returned
    /// ref into the rendered compose file.
    #[test]
    fn prepare_deploy_target_embeds_provisioner_ref() {
        struct StubProvisioner;
        impl ImageProvisioner for StubProvisioner {
            fn provision(&self) -> Result<String> {
                Ok("ghcr.io/taostat/gm-miner@sha256:deadbeef".to_owned())
            }
        }
        let target =
            prepare_deploy_target(&StubProvisioner, "testnet").expect("orchestration must succeed");
        assert_eq!(target.image_ref, "ghcr.io/taostat/gm-miner@sha256:deadbeef");
        assert!(
            target.rendered_compose.contains("sha256:deadbeef"),
            "the provisioner's ref must be pinned into the compose file"
        );
        assert!(
            !target.rendered_compose.contains("${GM_IMAGE_REF"),
            "the ${{GM_IMAGE_REF}} placeholder must be substituted"
        );
        assert!(
            target.rendered_compose.contains("GM_NETWORK=testnet"),
            "the active network must be substituted into the compose"
        );
    }

    /// An image-build failure must propagate out of `prepare_deploy_target`.
    #[test]
    fn prepare_deploy_target_propagates_build_failure() {
        struct FailingProvisioner;
        impl ImageProvisioner for FailingProvisioner {
            fn provision(&self) -> Result<String> {
                bail!("image build+push failed")
            }
        }
        let err = prepare_deploy_target(&FailingProvisioner, "testnet")
            .expect_err("build failure must abort");
        assert!(err.to_string().contains("image build+push failed"));
    }
}
