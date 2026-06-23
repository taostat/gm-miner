#![expect(
    clippy::expect_used,
    reason = "integration tests intentionally fail hard on unexpected command output"
)]

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest as _, Sha256};

const DIRECT_TESTNET_SHA256: &str =
    "f3abbddee646ad2a6684ae7a160312cc215156f5c34d8ca4c4ca134f896fd6fc";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate must live under repo root")
        .to_owned()
}

fn render_envoy<I, K, V>(vars: I) -> (std::process::ExitStatus, String, String, String)
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    let root = repo_root();
    let out = tempfile::NamedTempFile::new().expect("temp rendered config");
    let output = Command::new("bash")
        .arg(root.join("image/start.sh"))
        .env_clear()
        .env("PATH", "/bin:/usr/bin:/usr/local/bin")
        .env("GM_START_RENDER_ONLY", "1")
        .env("GM_ENVOY_TEMPLATE_PATH", root.join("image/envoy.yaml"))
        .env("GM_RENDERED_CONFIG", out.path())
        .env("GM_NETWORK", "testnet")
        .env("GM_NODE_SECRET", "node-secret")
        .envs(vars)
        .output()
        .expect("run start.sh render-only");
    let rendered = std::fs::read_to_string(out.path()).unwrap_or_default();
    (
        output.status,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        rendered,
    )
}

#[test]
fn direct_unset_render_matches_pre_cloud_output_byte_for_byte() {
    let (status, _, stderr, rendered) = render_envoy([("ANTHROPIC_API_KEY", "sk-ant-direct")]);
    assert!(status.success(), "render failed: {stderr}");
    let actual = hex::encode(Sha256::digest(rendered.as_bytes()));
    assert_eq!(actual, DIRECT_TESTNET_SHA256);
    assert!(rendered.contains("exact: api.anthropic.com"));
    assert!(rendered.contains("exact: api.openai.com"));
}

#[test]
fn explicit_direct_render_matches_pre_cloud_output_byte_for_byte() {
    let (status, _, stderr, rendered) = render_envoy([
        ("ANTHROPIC_API_KEY", "sk-ant-direct"),
        ("ANTHROPIC_UPSTREAM", "direct"),
        ("OPENAI_UPSTREAM", "direct"),
    ]);
    assert!(status.success(), "render failed: {stderr}");
    let actual = hex::encode(Sha256::digest(rendered.as_bytes()));
    assert_eq!(actual, DIRECT_TESTNET_SHA256);
    assert!(rendered.contains("exact: api.anthropic.com"));
    assert!(rendered.contains("exact: api.openai.com"));
}

#[test]
fn bedrock_and_azure_render_cloud_upstreams() {
    let (status, _, stderr, rendered) = render_envoy([
        ("ANTHROPIC_UPSTREAM", "bedrock"),
        ("BEDROCK_REGION", "us-west-2"),
        ("BEDROCK_API_KEY", "bedrock-key"),
        ("OPENAI_UPSTREAM", "azure"),
        (
            "AZURE_OPENAI_ENDPOINT",
            "https://gm-resource.openai.azure.com/",
        ),
        ("AZURE_OPENAI_API_KEY", "azure-key"),
    ]);
    assert!(status.success(), "render failed: {stderr}");

    assert!(rendered.contains("host_rewrite_literal: bedrock-mantle.us-west-2.api.aws"));
    assert!(rendered.contains("address: bedrock-mantle.us-west-2.api.aws"));
    assert!(rendered.contains("sni: bedrock-mantle.us-west-2.api.aws"));
    assert!(rendered.contains("suffix: .api.aws"));
    assert!(!rendered.contains("exact: bedrock-mantle.us-west-2.api.aws"));
    assert!(rendered.contains("substitution: \"/anthropic/v1/messages\""));
    assert!(rendered.contains("value: \"%ENVIRONMENT(BEDROCK_API_KEY)%\""));
    assert!(rendered.contains("append_action: OVERWRITE_IF_EXISTS_OR_ADD"));
    assert!(!rendered.contains("local function json_error"));

    assert!(rendered.contains("host_rewrite_literal: gm-resource.openai.azure.com"));
    assert!(rendered.contains("address: gm-resource.openai.azure.com"));
    assert!(rendered.contains("suffix: .openai.azure.com"));
    assert!(!rendered.contains("exact: gm-resource.openai.azure.com"));
    assert!(rendered.contains("substitution: \"/openai/v1/chat/completions\""));
    assert!(rendered.contains("key: api-key"));
    assert!(rendered.contains("value: \"%ENVIRONMENT(AZURE_OPENAI_API_KEY)%\""));
}

#[test]
fn azure_host_allowlist_rejects_bad_suffix() {
    let (status, _, stderr, _) = render_envoy([
        ("OPENAI_UPSTREAM", "azure"),
        ("AZURE_OPENAI_ENDPOINT", "https://api.evil.example"),
        ("AZURE_OPENAI_API_KEY", "azure-key"),
    ]);
    assert!(!status.success(), "bad Azure host should fail");
    assert!(
        stderr.contains("Azure OpenAI host 'api.evil.example' is not in the allowed suffix set"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn bedrock_region_validation_rejects_bad_host_input() {
    let (status, _, stderr, _) = render_envoy([
        ("ANTHROPIC_UPSTREAM", "bedrock"),
        ("BEDROCK_REGION", "us-west-2.evil.example"),
        ("BEDROCK_API_KEY", "bedrock-key"),
    ]);
    assert!(!status.success(), "bad Bedrock region should fail");
    assert!(
        stderr.contains("BEDROCK_REGION must contain only letters, numbers, and hyphens"),
        "unexpected stderr: {stderr}"
    );
}
