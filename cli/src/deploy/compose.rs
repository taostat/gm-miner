//! Env-file and `docker-compose.yaml` rendering for `gmcli deploy`.

use anyhow::{bail, Context, Result};

use crate::config::ProviderKeys;
use crate::deploy::registry_auth::RegistryCredentials;

/// The compose template, bundled at compile time from
/// `dstack/docker-compose.yaml` relative to the workspace root.
pub const COMPOSE_TEMPLATE: &str = include_str!("../../../dstack/docker-compose.yaml");

/// The corrected Phala Cloud pre-launch script, bundled at compile time
/// from `dstack/prelaunch.sh`.
///
/// Phala Cloud auto-injects a pre-launch script (v0.0.14) whose GHCR
/// pull-verification block mis-parses digest-pinned image refs and aborts
/// the boot with a 404. `gmcli deploy` always pins images by digest, so
/// it always passes this corrected, digest-aware script via
/// `phala deploy --pre-launch-script`.
pub const PRELAUNCH_SCRIPT: &str = include_str!("../../../dstack/prelaunch.sh");

/// Placeholder substituted with the active network name (`testnet` /
/// `mainnet`) at compose render time. A literal in the rendered compose,
/// so its value is part of the attestation-measured `compose_hash`.
const GM_NETWORK_PLACEHOLDER: &str = "__GM_NETWORK__";

/// Render the `phala deploy` env file body from the provider keys, node
/// secret, and (optional) private-registry pull credentials.
///
/// Every provider key NAME is written on its own line unconditionally — a
/// configured key gets `NAME=<value>`, an unset key gets a bare `NAME=`
/// (empty value). The `phala` CLI derives the CVM's measured `allowed_envs`
/// from the `.env` line keys, keeping any key whose line is non-blank
/// regardless of its value, so emitting every name fixes `allowed_envs` to
/// the canonical set ([`compose_hash::CANONICAL_ALLOWED_ENVS`]) and makes
/// every miner produce the same `compose_hash` no matter which providers
/// they configured. An empty value is harmless: that upstream just returns
/// 401, the registry capability probe excludes it, and no pool forms. The
/// name order matches `CANONICAL_ALLOWED_ENVS`.
///
/// Extracted as a pure function so the exact env-file contents can be
/// asserted in tests without touching the filesystem.
#[must_use]
pub fn render_env_file(
    env_vars: &ProviderKeys,
    node_secret: &str,
    registry_creds: Option<&RegistryCredentials>,
) -> String {
    let mut lines = String::new();
    for (name, value) in [
        ("ANTHROPIC_API_KEY", env_vars.anthropic.as_deref()),
        ("ANTHROPIC_UPSTREAM", env_vars.anthropic_upstream.as_deref()),
        ("BEDROCK_REGION", env_vars.bedrock_region.as_deref()),
        ("BEDROCK_API_KEY", env_vars.bedrock_api_key.as_deref()),
        (
            "AZURE_FOUNDRY_ENDPOINT",
            env_vars.azure_foundry_endpoint.as_deref(),
        ),
        (
            "AZURE_FOUNDRY_API_KEY",
            env_vars.azure_foundry_api_key.as_deref(),
        ),
        (
            "AZURE_FOUNDRY_TENANT_ID",
            env_vars.azure_foundry_tenant_id.as_deref(),
        ),
        (
            "AZURE_FOUNDRY_SUBSCRIPTION_ID",
            env_vars.azure_foundry_subscription_id.as_deref(),
        ),
        (
            "AZURE_FOUNDRY_RESOURCE_GROUP",
            env_vars.azure_foundry_resource_group.as_deref(),
        ),
        (
            "AZURE_FOUNDRY_CLIENT_ID",
            env_vars.azure_foundry_client_id.as_deref(),
        ),
        (
            "AZURE_FOUNDRY_CLIENT_SECRET",
            env_vars.azure_foundry_client_secret.as_deref(),
        ),
        ("OPENAI_API_KEY", env_vars.openai.as_deref()),
        ("OPENAI_UPSTREAM", env_vars.openai_upstream.as_deref()),
        (
            "AZURE_OPENAI_ENDPOINT",
            env_vars.azure_openai_endpoint.as_deref(),
        ),
        (
            "AZURE_OPENAI_API_KEY",
            env_vars.azure_openai_api_key.as_deref(),
        ),
        ("AZURE_TENANT_ID", env_vars.azure_tenant_id.as_deref()),
        (
            "AZURE_SUBSCRIPTION_ID",
            env_vars.azure_subscription_id.as_deref(),
        ),
        (
            "AZURE_RESOURCE_GROUP",
            env_vars.azure_resource_group.as_deref(),
        ),
        ("AZURE_CLIENT_ID", env_vars.azure_client_id.as_deref()),
        (
            "AZURE_CLIENT_SECRET",
            env_vars.azure_client_secret.as_deref(),
        ),
        ("GOOGLE_API_KEY", env_vars.google.as_deref()),
        ("CHUTES_API_KEY", env_vars.chutes.as_deref()),
        ("ZAI_API_KEY", env_vars.zai.as_deref()),
        ("MOONSHOT_API_KEY", env_vars.moonshot.as_deref()),
    ] {
        lines.push_str(name);
        lines.push('=');
        lines.push_str(value.unwrap_or(""));
        lines.push('\n');
    }
    // The node secret envoy enforces as the x-gm-node-key header. Always
    // written: `cmd_deploy` resolves it before this call.
    lines.push_str("GM_NODE_SECRET=");
    lines.push_str(node_secret);
    lines.push('\n');

    // Private-registry pull credentials, consumed by the CVM's pre-launch
    // script (`docker login` before pulling the private miner image).
    if let Some(creds) = registry_creds {
        lines.push_str("DSTACK_DOCKER_REGISTRY=");
        lines.push_str(&creds.registry);
        lines.push('\n');
        lines.push_str("DSTACK_DOCKER_USERNAME=");
        lines.push_str(&creds.username);
        lines.push('\n');
        lines.push_str("DSTACK_DOCKER_PASSWORD=");
        lines.push_str(&creds.password);
        lines.push('\n');
    }

    lines
}

/// Write the provider keys + node secret + registry credentials to
/// `env_path` at mode 0600.
///
/// Uses a temp-file-then-rename so the target file is always at mode 0600
/// from the moment it exists — no window where a partially-written or
/// broader-permission file is present on disk.
pub(crate) fn write_env_file(
    env_path: &std::path::Path,
    env_vars: &ProviderKeys,
    node_secret: &str,
    registry_creds: Option<&RegistryCredentials>,
) -> Result<()> {
    use std::fs;
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let lines = render_env_file(env_vars, node_secret, registry_creds);

    let parent = env_path
        .parent()
        .context("env file path has no parent directory")?;
    let tmp_path = parent.join(".env.tmp");

    #[cfg(unix)]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .with_context(|| format!("open {}", tmp_path.display()))?;
        file.write_all(lines.as_bytes())
            .with_context(|| format!("write {}", tmp_path.display()))?;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {}", tmp_path.display()))?;
    }

    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .with_context(|| format!("open {}", tmp_path.display()))?;
        file.write_all(lines.as_bytes())
            .with_context(|| format!("write {}", tmp_path.display()))?;
    }

    fs::rename(&tmp_path, env_path)
        .with_context(|| format!("rename {} -> {}", tmp_path.display(), env_path.display()))
}

/// Render the compose template, substituting `${GM_IMAGE_REF...}` with
/// the supplied pinned image reference and `__GM_NETWORK__` with the
/// active network name.
///
/// # Errors
/// Returns an error if either placeholder is missing.
pub fn render_compose(template: &str, pinned_image_ref: &str, network: &str) -> Result<String> {
    // Replace the shell-variable placeholder pattern ${GM_IMAGE_REF...}
    // with the digest-pinned ref. We do a simple prefix match: anything
    // that starts with `${GM_IMAGE_REF` and ends at the next `}`.
    let with_image = replace_image_ref_placeholder(template, pinned_image_ref);
    if with_image == template {
        bail!(
            "compose template does not contain a GM_IMAGE_REF placeholder; \
             expected something like ${{GM_IMAGE_REF:?...}} in dstack/docker-compose.yaml"
        );
    }
    if !with_image.contains(GM_NETWORK_PLACEHOLDER) {
        bail!(
            "compose template does not contain a {GM_NETWORK_PLACEHOLDER} placeholder; \
             expected GM_NETWORK={GM_NETWORK_PLACEHOLDER} in dstack/docker-compose.yaml"
        );
    }
    Ok(with_image.replace(GM_NETWORK_PLACEHOLDER, network))
}

/// Replace every `${GM_IMAGE_REF...}` shell-variable expression in `text`
/// with `replacement`.
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

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_replaced_once() {
        let template = "image: ${GM_IMAGE_REF:?GM_IMAGE_REF must be set}\n  \
                        env: GM_NETWORK=__GM_NETWORK__\n  ports:\n";
        let rendered = render_compose(template, "ghcr.io/o/app@sha256:abc123", "testnet")
            .expect("should render");
        assert!(rendered.contains("ghcr.io/o/app@sha256:abc123"));
        assert!(!rendered.contains("GM_IMAGE_REF"));
    }

    #[test]
    fn placeholder_missing_returns_error() {
        let template = "image: my-image\n";
        assert!(render_compose(template, "anything", "testnet").is_err());
    }

    /// The active network must appear as a rendered literal so it is
    /// part of the attestation-measured `compose_hash`.
    #[test]
    fn network_placeholder_replaced() {
        let template = "image: ${GM_IMAGE_REF:?}\n  env:\n    - GM_NETWORK=__GM_NETWORK__\n";
        let rendered =
            render_compose(template, "anything", "testnet").expect("should render testnet");
        assert!(rendered.contains("GM_NETWORK=testnet"));
        assert!(!rendered.contains("__GM_NETWORK__"));

        let rendered =
            render_compose(template, "anything", "mainnet").expect("should render mainnet");
        assert!(rendered.contains("GM_NETWORK=mainnet"));
    }

    /// A template missing the network placeholder is a compose-file bug —
    /// surface it as a clear error rather than silently rendering an
    /// image without the network selector.
    #[test]
    fn network_placeholder_missing_returns_error() {
        let template = "image: ${GM_IMAGE_REF:?}\n";
        assert!(render_compose(template, "anything", "testnet").is_err());
    }

    /// The bundled compose template must carry both placeholders so a
    /// real deploy renders correctly.
    #[test]
    fn bundled_compose_template_renders() {
        let rendered = render_compose(COMPOSE_TEMPLATE, "ghcr.io/o/m@sha256:deadbeef", "testnet")
            .expect("bundled compose template must render");
        assert!(rendered.contains("ghcr.io/o/m@sha256:deadbeef"));
        assert!(rendered.contains("GM_NETWORK=testnet"));
        assert!(!rendered.contains("__GM_NETWORK__"));
        assert!(
            !rendered.contains("GM_BENCHMARK_UPSTREAM_URL"),
            "GM_BENCHMARK_UPSTREAM_URL must no longer appear in the compose"
        );
    }

    // ── env-file rendering ────────────────────────────────────────────────────

    /// Configured keys carry their value; unset keys are still emitted as
    /// bare `NAME=` lines. The `phala` CLI reads every non-blank line's key
    /// into the CVM's measured `allowed_envs`, so writing every provider
    /// names unconditionally fixes the canonical set regardless of which
    /// keys the miner set — the invariant that makes every miner produce the
    /// same `compose_hash`.
    #[test]
    fn render_env_file_writes_node_secret_and_keys() {
        let keys = ProviderKeys {
            anthropic: Some("sk-ant".to_owned()),
            openai: None,
            google: None,
            chutes: Some("cpk-chutes".to_owned()),
            zai: Some("zai-key".to_owned()),
            ..ProviderKeys::default()
        };
        let body = render_env_file(&keys, "node-secret-xyz", None);
        assert!(body.contains("ANTHROPIC_API_KEY=sk-ant\n"));
        assert!(body.contains("CHUTES_API_KEY=cpk-chutes\n"));
        assert!(body.contains("ZAI_API_KEY=zai-key\n"));
        assert!(body.contains("GM_NODE_SECRET=node-secret-xyz\n"));
        // Unset keys are emitted as empty-value lines so their names still
        // land in the CVM's measured allowed_envs.
        assert!(body.contains("OPENAI_API_KEY=\n"));
        assert!(body.contains("GOOGLE_API_KEY=\n"));
        assert!(
            !body.contains("DSTACK_DOCKER_"),
            "no registry creds must be written when none are supplied"
        );
        assert!(
            !body.contains("GM_BENCHMARK_UPSTREAM_URL"),
            "GM_BENCHMARK_UPSTREAM_URL must no longer be written to the env file"
        );
    }

    #[test]
    fn render_env_file_preserves_semicolon_multikey_values() {
        let keys = ProviderKeys {
            anthropic: Some("sk-ant-a; sk-ant-b ".to_owned()),
            openai: Some("sk-a;sk-b".to_owned()),
            ..ProviderKeys::default()
        };
        let body = render_env_file(&keys, "node-secret", None);
        assert!(body.contains("ANTHROPIC_API_KEY=sk-ant-a; sk-ant-b \n"));
        assert!(body.contains("OPENAI_API_KEY=sk-a;sk-b\n"));
        assert!(!body.contains("GM_ANTHROPIC_KEY_SLOT_"));
    }

    /// Every canonical provider key NAME is present on its own line — in the
    /// `CANONICAL_ALLOWED_ENVS` order — even when the miner configured only
    /// one provider. This is the env-file half of the static-`allowed_envs`
    /// invariant: the `phala` CLI maps these line keys into the measured
    /// `allowed_envs`, so the set is identical for every miner.
    #[test]
    fn render_env_file_always_emits_every_provider_name() {
        let keys = ProviderKeys {
            anthropic: None,
            openai: None,
            google: None,
            chutes: Some("cpk-only".to_owned()),
            ..ProviderKeys::default()
        };
        let body = render_env_file(&keys, "node-secret", None);
        let names: Vec<&str> = body
            .lines()
            .filter_map(|l| l.split('=').next())
            .filter(|n| !n.is_empty())
            .collect();
        assert_eq!(
            names,
            vec![
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_UPSTREAM",
                "BEDROCK_REGION",
                "BEDROCK_API_KEY",
                "AZURE_FOUNDRY_ENDPOINT",
                "AZURE_FOUNDRY_API_KEY",
                "AZURE_FOUNDRY_TENANT_ID",
                "AZURE_FOUNDRY_SUBSCRIPTION_ID",
                "AZURE_FOUNDRY_RESOURCE_GROUP",
                "AZURE_FOUNDRY_CLIENT_ID",
                "AZURE_FOUNDRY_CLIENT_SECRET",
                "OPENAI_API_KEY",
                "OPENAI_UPSTREAM",
                "AZURE_OPENAI_ENDPOINT",
                "AZURE_OPENAI_API_KEY",
                "AZURE_TENANT_ID",
                "AZURE_SUBSCRIPTION_ID",
                "AZURE_RESOURCE_GROUP",
                "AZURE_CLIENT_ID",
                "AZURE_CLIENT_SECRET",
                "GOOGLE_API_KEY",
                "CHUTES_API_KEY",
                "ZAI_API_KEY",
                "MOONSHOT_API_KEY",
                "GM_NODE_SECRET",
            ],
            "the env file must declare every canonical name in CANONICAL_ALLOWED_ENVS order"
        );
    }

    /// When private-registry credentials are supplied, all three
    /// `DSTACK_DOCKER_*` variables the pre-launch script needs must appear.
    #[test]
    fn render_env_file_writes_registry_credentials() {
        let keys = ProviderKeys::default();
        let creds = RegistryCredentials {
            registry: "ghcr.io".to_owned(),
            username: "miner-bot".to_owned(),
            password: "ghp_token".to_owned(),
        };
        let body = render_env_file(&keys, "node-secret", Some(&creds));
        assert!(body.contains("DSTACK_DOCKER_REGISTRY=ghcr.io\n"));
        assert!(body.contains("DSTACK_DOCKER_USERNAME=miner-bot\n"));
        assert!(body.contains("DSTACK_DOCKER_PASSWORD=ghp_token\n"));
    }
}
