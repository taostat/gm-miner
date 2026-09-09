//! Integration tests for `gmcli set-api-keys`.
//!
//! Verifies:
//!   - Config file is created with mode 0600.
//!   - Missing flags leave existing values intact across runs.
//!   - Key values are never printed back to the operator (by design — the
//!     CLI only prints provider *names*, never values).

#![expect(
    clippy::unwrap_used,
    reason = "test assertions intentionally panic on unexpected values"
)]

use gm_miner_cli::config::{Config, ProviderKeys};

fn run_keys(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_gmcli"))
        .env_clear()
        .env("GMCLI_CONFIG_DIR", dir)
        .args(["--testnet", "set-api-keys"])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn cli_persists_every_key_group_and_preserves_omitted_values() {
    let dir = tempfile::tempdir().unwrap();
    let fields = [
        ("anthropic", "anthropic-key"),
        ("anthropic-upstream", "foundry"),
        ("bedrock-region", "us-east-1"),
        ("bedrock-api-key", "bedrock-key"),
        (
            "azure-foundry-endpoint",
            "https://foundry.services.ai.azure.com",
        ),
        ("azure-foundry-api-key", "foundry-key"),
        ("azure-foundry-tenant-id", "foundry-tenant"),
        ("azure-foundry-subscription-id", "foundry-sub"),
        ("azure-foundry-resource-group", "foundry-rg"),
        ("azure-foundry-client-id", "foundry-client"),
        ("azure-foundry-client-secret", "foundry-secret"),
        ("openai", "openai-key"),
        ("openai-upstream", "azure"),
        ("azure-openai-endpoint", "https://openai.openai.azure.com"),
        ("azure-openai-api-key", "azure-key"),
        ("azure-tenant-id", "azure-tenant"),
        ("azure-subscription-id", "azure-sub"),
        ("azure-resource-group", "azure-rg"),
        ("azure-client-id", "azure-client"),
        ("azure-client-secret", "azure-secret"),
        ("google", "google-key"),
        ("chutes", "chutes-key"),
        ("zai", "zai-key"),
        ("moonshot", "moonshot-key"),
        ("deepinfra", "deepinfra-key"),
        ("kubetee", "kubetee-key"),
        ("engy", "engy-key"),
        ("moonmath", "moonmath-key"),
        ("near", "near-key"),
    ];
    let args = fields
        .iter()
        .flat_map(|(flag, value)| [format!("--{flag}"), (*value).to_owned()])
        .collect::<Vec<_>>();
    let output = run_keys(
        dir.path(),
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config_path = dir.path().join("config.json");
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    for (flag, value) in fields {
        assert_eq!(
            saved["provider_keys"][flag.replace('-', "_")],
            value,
            "{flag}"
        );
        if !flag.ends_with("upstream") {
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains(value),
                "{flag} value was printed"
            );
        }
    }
    let updated = run_keys(dir.path(), &["--openai", "replacement-key"]);
    assert!(updated.status.success());
    let actual: serde_json::Value =
        serde_json::from_slice(&std::fs::read(config_path).unwrap()).unwrap();
    let mut expected = saved;
    expected["provider_keys"]["openai"] = "replacement-key".into();
    assert_eq!(actual, expected);
}

#[test]
fn cli_rejects_invalid_updates_before_writing_any_keys() {
    let dir = tempfile::tempdir().unwrap();
    assert!(run_keys(dir.path(), &["--openai", "first-key"])
        .status
        .success());
    let config_path = dir.path().join("config.json");
    let original = std::fs::read(&config_path).unwrap();
    for args in [
        vec!["--azure-foundry-client-secret", " ", "--openai", ""],
        vec![
            "--openai-upstream",
            "invalid",
            "--openai",
            "replacement-key",
        ],
    ] {
        let output = run_keys(dir.path(), &args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(args[0]));
        assert_eq!(std::fs::read(&config_path).unwrap(), original);
    }
}

fn saved_config(dir: &std::path::Path) -> Config {
    serde_json::from_slice(&std::fs::read(dir.join("config.json")).unwrap()).unwrap()
}

#[cfg(unix)]
#[test]
fn cli_writes_config_at_mode_0600() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    assert!(run_keys(dir.path(), &["--anthropic", "sk-ant-test"])
        .status
        .success());
    let mode = std::fs::metadata(dir.path().join("config.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn cli_no_flags_preserves_keys_and_network_selection() {
    let dir = tempfile::tempdir().unwrap();
    assert!(run_keys(dir.path(), &["--anthropic", "sk-ant-test"])
        .status
        .success());
    let before = std::fs::read(dir.path().join("config.json")).unwrap();
    let output = run_keys(dir.path(), &[]);
    assert!(output.status.success());
    assert_eq!(
        std::fs::read(dir.path().join("config.json")).unwrap(),
        before
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("sk-ant-test"));
}

#[test]
fn cli_stores_secrets_without_printing_them() {
    let dir = tempfile::tempdir().unwrap();
    let secret = "super-secret-key-xyz-9999";
    let output = run_keys(dir.path(), &["--anthropic", secret]);
    assert!(output.status.success());
    assert_eq!(
        saved_config(dir.path())
            .provider_keys
            .unwrap()
            .anthropic
            .as_deref(),
        Some(secret)
    );
    for stream in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(stream).contains(secret));
    }
}

// ── `any_set` helper ─────────────────────────────────────────────────────────

#[test]
fn any_set_false_when_all_none() {
    let keys = ProviderKeys::default();
    assert!(!keys.any_set());
}

#[test]
fn any_set_true_when_anthropic_set() {
    let keys = ProviderKeys {
        anthropic: Some("k".to_owned()),
        openai: None,
        google: None,
        chutes: None,
        ..ProviderKeys::default()
    };
    assert!(keys.any_set());
}

#[test]
fn any_set_true_when_openai_set() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: Some("k".to_owned()),
        google: None,
        chutes: None,
        ..ProviderKeys::default()
    };
    assert!(keys.any_set());
}

#[test]
fn any_set_true_when_google_set() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: None,
        google: Some("k".to_owned()),
        chutes: None,
        ..ProviderKeys::default()
    };
    assert!(keys.any_set());
}

/// `Some("")` must not count as a set key — the deploy preflight must not
/// pass when an operator accidentally stores an empty value (e.g. from an
/// unset shell variable).
#[test]
fn any_set_false_for_empty_string() {
    let keys = ProviderKeys {
        anthropic: Some(String::new()),
        openai: None,
        google: None,
        chutes: None,
        ..ProviderKeys::default()
    };
    assert!(!keys.any_set(), "Some(\"\") must not count as set");
}

/// `Some("  ")` (whitespace-only) must also not count as set.
#[test]
fn any_set_false_for_whitespace_only() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: Some("  ".to_owned()),
        google: None,
        chutes: None,
        ..ProviderKeys::default()
    };
    assert!(!keys.any_set());
}

#[test]
fn any_set_true_when_chutes_set() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: None,
        google: None,
        chutes: Some("k".to_owned()),
        ..ProviderKeys::default()
    };
    assert!(keys.any_set());
}

#[test]
fn any_set_true_when_zai_set() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: None,
        google: None,
        chutes: None,
        zai: Some("k".to_owned()),
        ..ProviderKeys::default()
    };
    assert!(keys.any_set());
}

#[test]
fn any_set_true_when_deepinfra_set() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: None,
        google: None,
        chutes: None,
        deepinfra: Some("k".to_owned()),
        ..ProviderKeys::default()
    };
    assert!(keys.any_set());
}

#[test]
fn any_set_true_when_kubetee_set() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: None,
        google: None,
        chutes: None,
        kubetee: Some("k".to_owned()),
        ..ProviderKeys::default()
    };
    assert!(keys.any_set());
}

#[test]
fn any_set_true_when_engy_set() {
    let keys = ProviderKeys {
        anthropic: None,
        openai: None,
        google: None,
        chutes: None,
        engy: Some("k".to_owned()),
        ..ProviderKeys::default()
    };
    assert!(keys.any_set());
}

#[test]
fn any_set_true_when_moonmath_set() {
    let keys = ProviderKeys {
        moonmath: Some("k".to_owned()),
        ..ProviderKeys::default()
    };
    assert!(keys.any_set());
}

#[test]
fn any_set_true_when_bedrock_selected_and_key_set() {
    let keys = ProviderKeys {
        anthropic_upstream: Some("bedrock".to_owned()),
        bedrock_api_key: Some("k".to_owned()),
        ..ProviderKeys::default()
    };
    assert!(keys.any_set());
}

#[test]
fn any_set_true_when_azure_selected_and_key_set() {
    let keys = ProviderKeys {
        openai_upstream: Some("azure".to_owned()),
        azure_openai_api_key: Some("k".to_owned()),
        ..ProviderKeys::default()
    };
    assert!(keys.any_set());
}

#[test]
fn cloud_key_without_selector_does_not_pass_preflight() {
    let keys = ProviderKeys {
        bedrock_api_key: Some("k".to_owned()),
        azure_openai_api_key: Some("k".to_owned()),
        ..ProviderKeys::default()
    };
    assert!(!keys.any_set());
}

#[test]
fn validate_upstreams_rejects_incomplete_bedrock() {
    let keys = ProviderKeys {
        anthropic_upstream: Some("bedrock".to_owned()),
        bedrock_api_key: Some("k".to_owned()),
        ..ProviderKeys::default()
    };
    let err = keys.validate_upstreams().unwrap_err().to_string();
    assert!(err.contains("--bedrock-region"), "{err}");
}

#[test]
fn validate_upstreams_rejects_malformed_bedrock_region() {
    let keys = ProviderKeys {
        anthropic_upstream: Some("bedrock".to_owned()),
        bedrock_region: Some("us-west-2.evil.example".to_owned()),
        bedrock_api_key: Some("k".to_owned()),
        ..ProviderKeys::default()
    };
    let err = keys.validate_upstreams().unwrap_err().to_string();
    assert!(
        err.contains("--bedrock-region must contain only letters, numbers, and hyphens"),
        "{err}"
    );
}

#[test]
fn validate_upstreams_rejects_incomplete_azure() {
    let keys = ProviderKeys {
        openai_upstream: Some("azure".to_owned()),
        azure_openai_api_key: Some("k".to_owned()),
        ..ProviderKeys::default()
    };
    let err = keys.validate_upstreams().unwrap_err().to_string();
    assert!(err.contains("--azure-openai-endpoint"), "{err}");
}

#[test]
fn validate_upstreams_rejects_non_https_azure_endpoint() {
    for endpoint in ["http://r.openai.azure.com", "r.openai.azure.com"] {
        let keys = ProviderKeys {
            openai_upstream: Some("azure".to_owned()),
            azure_openai_endpoint: Some(endpoint.to_owned()),
            azure_openai_api_key: Some("k".to_owned()),
            azure_tenant_id: Some("tenant".to_owned()),
            azure_subscription_id: Some("sub".to_owned()),
            azure_resource_group: Some("rg".to_owned()),
            azure_client_id: Some("client".to_owned()),
            azure_client_secret: Some("secret".to_owned()),
            ..ProviderKeys::default()
        };
        let err = keys.validate_upstreams().unwrap_err().to_string();
        assert!(
            err.contains("--azure-openai-endpoint must use https"),
            "{err}"
        );
    }
}

#[test]
fn validate_upstreams_rejects_non_allowed_azure_endpoint() {
    let keys = ProviderKeys {
        openai_upstream: Some("azure".to_owned()),
        azure_openai_endpoint: Some("https://api.evil.example".to_owned()),
        azure_openai_api_key: Some("k".to_owned()),
        azure_tenant_id: Some("tenant".to_owned()),
        azure_subscription_id: Some("sub".to_owned()),
        azure_resource_group: Some("rg".to_owned()),
        azure_client_id: Some("client".to_owned()),
        azure_client_secret: Some("secret".to_owned()),
        ..ProviderKeys::default()
    };
    let err = keys.validate_upstreams().unwrap_err().to_string();
    assert!(
        err.contains("host 'api.evil.example' is not in the allowed suffix set"),
        "{err}"
    );
}

#[test]
fn validate_upstreams_accepts_complete_cloud_and_direct() {
    let complete = ProviderKeys {
        anthropic_upstream: Some("bedrock".to_owned()),
        bedrock_region: Some("us-west-2".to_owned()),
        bedrock_api_key: Some("k".to_owned()),
        openai_upstream: Some("azure".to_owned()),
        azure_openai_endpoint: Some("https://r.openai.azure.com".to_owned()),
        azure_openai_api_key: Some("k".to_owned()),
        azure_tenant_id: Some("tenant".to_owned()),
        azure_subscription_id: Some("sub".to_owned()),
        azure_resource_group: Some("rg".to_owned()),
        azure_client_id: Some("client".to_owned()),
        azure_client_secret: Some("secret".to_owned()),
        ..ProviderKeys::default()
    };
    assert!(complete.validate_upstreams().is_ok());
    assert!(ProviderKeys::default().validate_upstreams().is_ok());
}

#[test]
fn cli_rejects_empty_keys_without_creating_config() {
    for value in ["", "   ", "\t\n"] {
        let dir = tempfile::tempdir().unwrap();
        let output = run_keys(dir.path(), &["--openai", value]);
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("empty value for --openai"), "{error}");
        assert!(!dir.path().join("config.json").exists());
    }
}
