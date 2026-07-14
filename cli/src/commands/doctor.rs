//! `gmcli doctor` — a preflight checklist run before deploying.

use anyhow::{bail, Result};

use gm_azure_verify::{AzureProvider, AzureVerifier, AzureVerifyConfig};
use gm_miner_cli::{
    client::RegistryClient,
    config::{Config, ProviderKeys},
    network::Network,
    types::MinerStatus,
};

use crate::commands::persist::try_refresh_token;

/// The state of one `doctor` checklist line.
#[derive(PartialEq, Eq)]
enum Status {
    /// Ready — nothing to do.
    Pass,
    /// A normal pre-deploy state worth surfacing but not a failure (e.g. the
    /// hotkey isn't registered yet — the first `deploy` registers it).
    Info,
    /// Needs the operator's attention before deploying.
    Fail,
}

/// One line of the `doctor` checklist: a status mark, a label, and an
/// optional note (the resolved detail for a pass, the actionable fix for a
/// fail, or context for an info line).
struct Check {
    status: Status,
    label: String,
    note: String,
}

impl Check {
    fn pass(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Pass,
            label: label.into(),
            note: detail.into(),
        }
    }

    fn info(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Info,
            label: label.into(),
            note: detail.into(),
        }
    }

    fn fail(label: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            status: Status::Fail,
            label: label.into(),
            note: fix.into(),
        }
    }

    fn is_failure(&self) -> bool {
        self.status == Status::Fail
    }

    fn render(&self) {
        let (mark, note_prefix) = match self.status {
            Status::Pass => ("[ok]", "      "),
            Status::Info => ("[--]", "      "),
            Status::Fail => ("[!!]", "      → "),
        };
        println!("  {mark} {}", self.label);
        if self.note.is_empty() {
            return;
        }
        // A note can run to several lines (the Azure check lists one finding —
        // and the `az` command that clears it — per capture surface it found).
        // Only the first line carries the mark's prefix; the rest align under it.
        for (i, line) in self.note.lines().enumerate() {
            if i == 0 {
                println!("{note_prefix}{line}");
            } else {
                println!("        {line}");
            }
        }
    }
}

/// `gmcli doctor` — a preflight checklist run before deploying.
///
/// Each check renders green/red with an actionable fix. The hotkey-
/// registration check probes `GET /miners/me`; a 401/403/404 renders as
/// "not registered on subnet N" rather than a raw body, and its remedy names
/// `register-hotkey`.
pub(crate) async fn cmd_doctor(cfg: Config) -> Result<()> {
    let network = cfg.resolved_network();
    println!(
        "gmcli doctor — preflight for {network} (netuid {})\n",
        network.netuid()
    );

    // Non-interactively refresh an expired-but-refreshable token up front so
    // the checklist reflects what a real deploy would see. Unlike the deploy
    // path's `ensure_fresh_token`, this never falls back to an interactive
    // device-code login — a preflight diagnostic must not open a browser or
    // block on auth. A refresh that can't happen leaves the config as-is and
    // `login_check`/`hotkey_check` report the true state.
    let cfg = try_refresh_token(cfg).await;

    let mut checks = vec![
        network_check(network, &cfg),
        login_check(&cfg),
        provider_keys_check(&cfg),
        phala_cli_check(),
        phala_api_key_check(&cfg),
    ];
    checks.extend(azure_checks(cfg.provider_keys.as_ref()).await);
    checks.push(hotkey_check(cfg).await);

    for check in &checks {
        check.render();
    }

    let failures = checks.iter().filter(|c| c.is_failure()).count();
    println!();
    if failures == 0 {
        println!("All checks passed — you're ready to `gmcli deploy`.");
        Ok(())
    } else {
        bail!("{failures} check(s) need attention before deploying (see above).");
    }
}

fn network_check(network: Network, cfg: &Config) -> Check {
    Check::pass(
        format!("Network: {network} (netuid {})", network.netuid()),
        format!("registry {} · chain {}", cfg.api_url(), network.chain_ws()),
    )
}

fn login_check(cfg: &Config) -> Check {
    match cfg.active_tokens() {
        Some(t) if t.access_token.is_some() && !t.is_expired_or_near() => {
            Check::pass("Logged in (token valid)", String::new())
        }
        // An expired access token with a stored refresh token is not a
        // failure: the next registry call refreshes it silently
        // (`ensure_fresh_token`), so the operator does not need to log in
        // again.
        Some(t) if t.access_token.is_some() && t.refresh_token.is_some() => {
            Check::pass("Logged in (token refreshes on next use)", String::new())
        }
        Some(t) if t.access_token.is_some() => {
            Check::fail("Logged in", "your session has expired — run `gmcli login`")
        }
        _ => Check::fail("Logged in", "not logged in — run `gmcli login`"),
    }
}

fn provider_keys_check(cfg: &Config) -> Check {
    let Some(keys) = cfg.provider_keys.as_ref() else {
        return Check::fail(
            "Provider keys usable",
            "no usable provider keys — run `gmcli set-api-keys --anthropic <key>` (and/or --openai / --google / --chutes / --zai, or configure Bedrock/Azure upstreams)",
        );
    };
    if !keys.any_set() {
        return Check::fail(
            "Provider keys usable",
            "no usable provider keys — selected cloud upstreams need their selector and required key, or configure a direct provider key",
        );
    }
    if let Err(err) = keys.validate_upstreams() {
        return Check::fail("Provider upstream config", err.to_string());
    }
    Check::pass("Provider keys usable", "upstream config valid")
}

/// Every Azure account the configured upstream selectors put in the request
/// path, with the ARM coordinates to read its control plane.
///
/// A target is only built when the selector is Azure-backed *and* every ARM
/// field is present: an incomplete one is `provider_keys_check`'s failure to
/// report (it names the missing flag), and there is nothing to verify until it
/// is fixed.
fn azure_targets(keys: &ProviderKeys) -> Vec<AzureVerifyConfig> {
    let mut targets = Vec::new();
    if keys.anthropic_upstream.as_deref() == Some("foundry") {
        targets.extend(azure_target(
            AzureProvider::Foundry,
            keys.azure_foundry_endpoint.as_deref(),
            [
                keys.azure_foundry_tenant_id.as_deref(),
                keys.azure_foundry_subscription_id.as_deref(),
                keys.azure_foundry_resource_group.as_deref(),
                keys.azure_foundry_client_id.as_deref(),
                keys.azure_foundry_client_secret.as_deref(),
            ],
        ));
    }
    if keys.openai_upstream.as_deref() == Some("azure") {
        targets.extend(azure_target(
            AzureProvider::OpenAi,
            keys.azure_openai_endpoint.as_deref(),
            [
                keys.azure_tenant_id.as_deref(),
                keys.azure_subscription_id.as_deref(),
                keys.azure_resource_group.as_deref(),
                keys.azure_client_id.as_deref(),
                keys.azure_client_secret.as_deref(),
            ],
        ));
    }
    targets
}

/// The ARM service-principal coordinates, in the order `AzureVerifyConfig`
/// names them: tenant, subscription, resource group, client id, client secret.
///
/// Every value is passed to the verifier **verbatim** — exactly the bytes
/// `render_env_file` will write into the CVM's env (`value.unwrap_or("")`, no
/// normalization). Trimming them here would be its own drift: a secret stored
/// with a stray space would pass doctor and then be rejected by Entra inside the
/// enclave, which is the precise failure this check exists to prevent.
fn azure_target(
    provider: AzureProvider,
    endpoint: Option<&str>,
    arm: [Option<&str>; 5],
) -> Option<AzureVerifyConfig> {
    let [tenant_id, subscription_id, resource_group, client_id, client_secret] = arm;
    Some(AzureVerifyConfig {
        provider,
        endpoint: configured(endpoint)?,
        tenant_id: configured(tenant_id)?,
        subscription_id: configured(subscription_id)?,
        resource_group: configured(resource_group)?,
        client_id: configured(client_id)?,
        client_secret: configured(client_secret)?,
    })
}

/// A field counts as configured when it holds something other than whitespace —
/// the same test `ProviderKeys::validate_upstreams` applies, so a half-set
/// target is reported there and not audited here. The value itself is returned
/// unchanged.
fn configured(value: Option<&str>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty()).map(str::to_owned)
}

/// Run the owner-capture sweep `attestd` runs at boot, here, before the
/// operator pays for a CVM that would crashloop on it.
///
/// This is the same code the enclave's fail-closed boot gate runs
/// (`gm-azure-verify`), not a re-implementation of it — a `[ok]` here is a
/// promise the boot gate keeps. With no Azure-backed upstream selected there is
/// nothing to check and no line is printed.
async fn azure_checks(keys: Option<&ProviderKeys>) -> Vec<Check> {
    let targets = keys.map(azure_targets).unwrap_or_default();
    if targets.is_empty() {
        return Vec::new();
    }
    let verifier = match AzureVerifier::new() {
        Ok(verifier) => verifier,
        Err(err) => {
            return vec![Check::fail(
                "Azure owner-capture preflight",
                format!("couldn't build an HTTPS client to reach Azure: {err:#}"),
            )]
        }
    };
    let mut checks = Vec::with_capacity(targets.len());
    for target in &targets {
        checks.push(azure_check(&verifier, target).await);
    }
    checks
}

/// Blank every GUID out of a message before printing it.
///
/// A failed ARM/Entra call carries the URL it was made to and the body Azure
/// answered with — which between them name the tenant, the subscription, the
/// client id, and Azure's own correlation ids. Doctor output is the first thing
/// an operator pastes into an issue or a support channel, so the ids come out.
/// Nothing actionable is lost: the status code, the `AADSTS…` code, and the
/// resource names all survive.
///
/// The `az` commands in a *finding* are left alone on purpose — they carry the
/// operator's own subscription id because they have to run.
fn redact_ids(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(found) = next_guid(rest) {
        out.push_str(&rest[..found]);
        out.push_str("<redacted>");
        rest = &rest[found + GUID_LEN..];
    }
    out.push_str(rest);
    out
}

/// `8-4-4-4-12` hex, the shape of every Azure tenant/subscription/client id.
const GUID_LEN: usize = 36;
const GUID_GROUPS: [usize; 5] = [8, 4, 4, 4, 12];

/// The byte offset of the first GUID in `text`, if any.
fn next_guid(text: &str) -> Option<usize> {
    (0..text.len())
        .filter(|start| text.is_char_boundary(*start))
        .find(|start| text.get(*start..start + GUID_LEN).is_some_and(is_guid))
}

fn is_guid(candidate: &str) -> bool {
    let mut rest = candidate;
    for (i, group) in GUID_GROUPS.iter().enumerate() {
        let Some(chunk) = rest.get(..*group) else {
            return false;
        };
        if !chunk.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        rest = &rest[*group..];
        if i < GUID_GROUPS.len() - 1 {
            if rest.as_bytes().first() != Some(&b'-') {
                return false;
            }
            rest = &rest[1..];
        }
    }
    rest.is_empty()
}

async fn azure_check(verifier: &AzureVerifier, target: &AzureVerifyConfig) -> Check {
    let label = format!("Azure owner-capture controls ({})", target.provider.label());
    let audit = match verifier.audit_target(target).await {
        Ok(audit) => audit,
        // The sweep could not be carried out at all: a bad endpoint, an expired
        // service-principal secret, ARM unreachable. attestd would fail its boot
        // gate on exactly this, so it is a doctor failure, not a skip.
        Err(err) => {
            return Check::fail(
                label,
                format!(
                    "couldn't verify {} with Azure: {}\ncheck the ARM service principal from \
                     `gmcli set-api-keys` (tenant/subscription/resource-group/client-id/secret) — \
                     a secret that has expired, or a principal without Reader on the account, \
                     fails the same way inside the CVM",
                    target.endpoint,
                    redact_ids(&format!("{err:#}")),
                ),
            )
        }
    };

    if audit.passed() {
        return Check::pass(
            label,
            format!(
                "{} · account and {} project(s) clean: no diagnostic settings, no connections, \
                 no capability hosts",
                audit.host, audit.projects_swept,
            ),
        );
    }
    let findings = audit.findings.join("\n");
    Check::fail(
        label,
        format!(
            "{} would fail `attestd`'s boot gate — the CVM will crashloop until this is \
             cleared:\n{findings}",
            audit.host,
        ),
    )
}

fn phala_cli_check() -> Check {
    let on_path = std::process::Command::new("phala")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if on_path {
        Check::pass("`phala` CLI on PATH", String::new())
    } else {
        Check::fail(
            "`phala` CLI on PATH",
            "not found — install with `npm i -g phala`",
        )
    }
}

fn phala_api_key_check(cfg: &Config) -> Check {
    // Accept exactly the sources `deploy` resolves a Phala credential from
    // (env var, saved gmcli config key, or an existing `phala` CLI session),
    // so doctor never reports a deploy that can authenticate as not ready.
    match gm_miner_cli::phala::credential_source(cfg.phala_api_key.as_deref()) {
        Some(source) => Check::pass(format!("Phala Cloud credential ({source})"), String::new()),
        None => Check::fail(
            "Phala Cloud API key",
            "no Phala credential — set PHALA_API_KEY, run `phala auth login`, \
             or paste a key when `gmcli deploy` prompts (it is then saved)",
        ),
    }
}

/// Probe `GET /miners/me` and classify the result for the doctor checklist.
///
/// A 401/403/404 means the hotkey isn't registered on the subnet — rendered
/// as an actionable line, never the raw body. The 404 remedy names
/// `register-hotkey` (and its `--hotkey-ss58` bring-your-own escape hatch).
async fn hotkey_check(cfg: Config) -> Check {
    let network = cfg.resolved_network();
    let netuid = network.netuid();
    if cfg
        .active_tokens()
        .and_then(|t| t.access_token.as_deref())
        .is_none()
    {
        return Check::fail(
            format!("Registered with gm on subnet {netuid}"),
            "can't check until you're logged in — run `gmcli login`",
        );
    }

    let mut client = RegistryClient::new(cfg.clone());
    let resp = match client.get(gm_miner_cli::client::ME_PATH).await {
        Ok(resp) => resp,
        Err(err) => {
            return Check::fail(
                format!("Registered with gm on subnet {netuid}"),
                format!("couldn't reach the registry: {err}"),
            );
        }
    };

    let label = format!("Registered with gm on subnet {netuid}");
    let status = resp.status();
    if status.is_success() {
        let hotkey = resp
            .json::<MinerStatus>()
            .await
            .map_or_else(|_| "<registered>".to_owned(), |m| m.hotkey);
        return Check::pass(label, hotkey);
    }
    // A 404 is the expected state before the first deploy: the registry has no
    // miner record for this hotkey yet. This branch is only reached once logged
    // in, so the hotkey identity is already known — the only step left is
    // `deploy`, which posts `/miners/register` and creates the record this probe
    // reads. Surface it as informational, not a failure — doctor *precedes* it.
    if status.as_u16() == 404 {
        let who = cfg
            .token_hotkey()
            .map_or_else(|| "your hotkey".to_owned(), |hk| format!("hotkey {hk}"));
        return Check::info(
            label,
            format!(
                "no registry record for {who} on `{network}` yet — your first \
                 `gmcli deploy` creates it. On the wrong network? Pass \
                 `--network mainnet`/`--network testnet`."
            ),
        );
    }
    // A 401/403 with a valid-looking token usually means the wrong network.
    if matches!(status.as_u16(), 401 | 403) {
        return Check::fail(
            label,
            format!(
                "registry rejected the request ({status}). On the wrong network? \
                 You're on `{network}` — pass `--network mainnet`/`--network testnet`."
            ),
        );
    }
    Check::fail(label, format!("registry returned {status}"))
}

#[cfg(test)]
mod tests {
    use super::{azure_check, azure_checks, provider_keys_check, Status};
    use gm_azure_verify::{AzureProvider, AzureVerifier, AzureVerifyConfig};
    use gm_miner_cli::config::{Config, ProviderKeys};
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg(keys: ProviderKeys) -> Config {
        Config {
            provider_keys: Some(keys),
            ..Default::default()
        }
    }

    #[test]
    fn cloud_key_without_selector_is_not_usable() {
        let check = provider_keys_check(&cfg(ProviderKeys {
            bedrock_api_key: Some("bedrock-key".to_owned()),
            ..ProviderKeys::default()
        }));

        assert!(check.status == Status::Fail);
        assert!(check.label.contains("Provider keys usable"));
        assert!(
            check.note.contains("no usable provider keys"),
            "got: {}",
            check.note
        );
    }

    #[test]
    fn selected_bedrock_without_region_fails_upstream_validation() {
        let check = provider_keys_check(&cfg(ProviderKeys {
            anthropic_upstream: Some("bedrock".to_owned()),
            bedrock_api_key: Some("bedrock-key".to_owned()),
            ..ProviderKeys::default()
        }));

        assert!(check.status == Status::Fail);
        assert!(check.label.contains("Provider upstream config"));
        assert!(
            check.note.contains("--bedrock-region"),
            "got: {}",
            check.note
        );
    }

    #[test]
    fn complete_bedrock_config_passes() {
        let check = provider_keys_check(&cfg(ProviderKeys {
            anthropic_upstream: Some("bedrock".to_owned()),
            bedrock_region: Some("us-east-1".to_owned()),
            bedrock_api_key: Some("bedrock-key".to_owned()),
            ..ProviderKeys::default()
        }));

        assert!(check.status == Status::Pass);
        assert!(check.note.contains("upstream config valid"));
    }

    #[test]
    fn complete_azure_config_passes() {
        let check = provider_keys_check(&cfg(ProviderKeys {
            openai_upstream: Some("azure".to_owned()),
            azure_openai_endpoint: Some("https://acct.openai.azure.com".to_owned()),
            azure_openai_api_key: Some("azure-key".to_owned()),
            azure_tenant_id: Some("tenant".to_owned()),
            azure_subscription_id: Some("sub".to_owned()),
            azure_resource_group: Some("rg".to_owned()),
            azure_client_id: Some("client".to_owned()),
            azure_client_secret: Some("secret".to_owned()),
            ..ProviderKeys::default()
        }));

        assert!(check.status == Status::Pass);
        assert!(check.note.contains("upstream config valid"));
    }

    fn complete_foundry_keys() -> ProviderKeys {
        ProviderKeys {
            anthropic_upstream: Some("foundry".to_owned()),
            azure_foundry_endpoint: Some("https://acct.services.ai.azure.com".to_owned()),
            azure_foundry_api_key: Some("foundry-key".to_owned()),
            azure_foundry_tenant_id: Some("tenant".to_owned()),
            azure_foundry_subscription_id: Some("sub".to_owned()),
            azure_foundry_resource_group: Some("rg".to_owned()),
            azure_foundry_client_id: Some("client".to_owned()),
            azure_foundry_client_secret: Some("secret".to_owned()),
            ..ProviderKeys::default()
        }
    }

    #[test]
    fn complete_foundry_config_passes() {
        let check = provider_keys_check(&cfg(complete_foundry_keys()));
        assert!(check.status == Status::Pass);
        assert!(check.note.contains("upstream config valid"));
    }

    #[test]
    fn foundry_without_arm_credentials_fails_upstream_validation() {
        let mut keys = complete_foundry_keys();
        keys.azure_foundry_client_secret = None;
        let check = provider_keys_check(&cfg(keys));

        assert!(check.status == Status::Fail);
        assert!(
            check.note.contains("--azure-foundry-client-secret"),
            "{}",
            check.note
        );
    }

    #[test]
    fn foundry_endpoint_outside_services_ai_fails_upstream_validation() {
        let mut keys = complete_foundry_keys();
        keys.azure_foundry_endpoint = Some("https://acct.openai.azure.com".to_owned());
        let check = provider_keys_check(&cfg(keys));

        assert!(check.status == Status::Fail);
        assert!(
            check.note.contains("services.ai.azure.com"),
            "{}",
            check.note
        );
    }

    /// The ARM resource id of the account the fixtures describe. ARM returns it
    /// on the account body, and every scoped read hangs off it.
    const ACCOUNT_PATH: &str =
        "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct";
    const DIAGNOSTICS: &str = "/providers/Microsoft.Insights/diagnosticSettings";

    fn foundry_target() -> AzureVerifyConfig {
        AzureVerifyConfig {
            provider: AzureProvider::Foundry,
            endpoint: "https://acct.services.ai.azure.com".to_owned(),
            tenant_id: "tenant".to_owned(),
            subscription_id: "sub".to_owned(),
            resource_group: "rg".to_owned(),
            client_id: "client".to_owned(),
            client_secret: "secret".to_owned(),
        }
    }

    async fn mount_get(server: &MockServer, at: &str, body: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(at.to_owned()))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    /// An `AIServices` account with one project `p1`, whose account-scoped and
    /// project-scoped connection lists are whatever the test says they are.
    ///
    /// Note the account body reports `properties.endpoint` on
    /// `cognitiveservices.azure.com` while the miner talks to
    /// `services.ai.azure.com` — that is what a live Foundry account returns,
    /// and it must still bind.
    async fn foundry_arm(
        connections: serde_json::Value,
        project_connections: serde_json::Value,
    ) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tenant/oauth2/v2.0/token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"access_token": "arm-token"})),
            )
            .mount(&server)
            .await;
        mount_get(
            &server,
            ACCOUNT_PATH,
            json!({
                "id": ACCOUNT_PATH,
                "kind": "AIServices",
                "properties": {
                    "customSubDomainName": "acct",
                    "endpoint": "https://acct.cognitiveservices.azure.com/",
                    "raiMonitorConfig": null,
                    "userOwnedStorage": []
                }
            }),
        )
        .await;
        // Verbatim from a live account: ARM qualifies a project's `name` with
        // its account. The sweep must address it as `/projects/p1` all the same
        // — the mounts below are the only paths that exist on this stub, so a
        // regression to `/projects/acct/p1` shows up as a 404, not a silent pass.
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}/projects"),
            json!({"value": [{"name": "acct/p1", "properties": {}}]}),
        )
        .await;
        let empty = json!({"value": []});
        for at in [
            format!("{ACCOUNT_PATH}{DIAGNOSTICS}"),
            format!("{ACCOUNT_PATH}/capabilityHosts"),
            format!("{ACCOUNT_PATH}/projects/p1{DIAGNOSTICS}"),
            format!("{ACCOUNT_PATH}/projects/p1/capabilityHosts"),
        ] {
            mount_get(&server, &at, empty.clone()).await;
        }
        mount_get(&server, &format!("{ACCOUNT_PATH}/connections"), connections).await;
        mount_get(
            &server,
            &format!("{ACCOUNT_PATH}/projects/p1/connections"),
            project_connections,
        )
        .await;
        server
    }

    fn verifier_for(server: &MockServer) -> AzureVerifier {
        AzureVerifier::with_endpoints(reqwest::Client::new(), server.uri(), server.uri())
    }

    /// A connection's `name` comes back unqualified — unlike a project's, which
    /// ARM prefixes with its account (see `ArmChildResource::leaf_name`). The
    /// live example in `docs/foundry-setup.md` is a bare
    /// `hello0323resourceappiafzvcx`, so the delete URL interpolates it as-is.
    fn app_insights_connection() -> serde_json::Value {
        json!({"value": [{"name": "telemetry", "properties": {"category": "AppInsights"}}]})
    }

    /// Doctor must audit exactly the bytes `render_env_file` ships. A secret
    /// stored with a stray space is shipped with it and rejected by Entra in the
    /// CVM, so doctor must carry it through and fail the same way — normalizing
    /// it here would manufacture the "doctor PASS, attestd fail" drift the
    /// shared crate exists to prevent.
    #[test]
    fn azure_targets_pass_credentials_through_verbatim() {
        let mut keys = complete_foundry_keys();
        keys.azure_foundry_client_secret = Some("  secret-with-space  ".to_owned());
        keys.azure_foundry_endpoint = Some(" https://acct.services.ai.azure.com ".to_owned());

        let targets = super::azure_targets(&keys);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].client_secret, "  secret-with-space  ");
        assert_eq!(targets[0].endpoint, " https://acct.services.ai.azure.com ");
    }

    #[test]
    fn guids_are_redacted_from_azure_error_output() {
        let redacted = super::redact_ids(
            "POST https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token: \
             AADSTS7000222: client secret expired",
        );

        assert!(!redacted.contains("72f988bf"), "{redacted}");
        assert!(redacted.contains("<redacted>"), "{redacted}");
        // Still actionable: the code that tells the operator what to fix stays.
        assert!(redacted.contains("AADSTS7000222"), "{redacted}");
        assert_eq!(super::redact_ids("no ids here"), "no ids here");
    }

    #[tokio::test]
    async fn a_clean_foundry_account_passes_the_owner_capture_preflight() {
        let empty = json!({"value": []});
        let server = foundry_arm(empty.clone(), empty).await;
        let check = azure_check(&verifier_for(&server), &foundry_target()).await;

        assert!(check.status == Status::Pass, "{}", check.note);
        assert!(check.label.contains("Microsoft Foundry"), "{}", check.label);
        assert!(
            check.note.contains("acct.services.ai.azure.com") && check.note.contains("1 project"),
            "{}",
            check.note
        );
    }

    /// The default state of a portal-created Foundry resource: Azure attaches an
    /// Application Insights connection on its own. attestd refuses to boot on it,
    /// so doctor must catch it — and hand over the delete.
    #[tokio::test]
    async fn an_app_insights_connection_on_the_account_fails_with_its_delete_command() {
        let server = foundry_arm(app_insights_connection(), json!({"value": []})).await;
        let check = azure_check(&verifier_for(&server), &foundry_target()).await;

        assert!(check.status == Status::Fail);
        assert!(check.note.contains("AppInsights"), "{}", check.note);
        assert!(check.note.contains("crashloop"), "{}", check.note);
        assert!(
            check.note.contains(&format!(
                "az rest --method delete --url \"https://management.azure.com{ACCOUNT_PATH}/connections/telemetry?api-version="
            )),
            "{}",
            check.note
        );
    }

    /// A connection hung off the *project* is the one an account-only sweep
    /// would miss — and it is the project the data plane routes through.
    #[tokio::test]
    async fn a_project_scoped_connection_is_caught() {
        let server = foundry_arm(json!({"value": []}), app_insights_connection()).await;
        let check = azure_check(&verifier_for(&server), &foundry_target()).await;

        assert!(check.status == Status::Fail);
        assert!(check.note.contains("project 'p1'"), "{}", check.note);
        assert!(
            check.note.contains(&format!(
                "https://management.azure.com{ACCOUNT_PATH}/projects/p1/connections/telemetry"
            )),
            "{}",
            check.note
        );
    }

    /// Expired service-principal credentials are an actionable doctor failure,
    /// not a panic and not a silent pass.
    #[tokio::test]
    async fn rejected_service_principal_credentials_fail_actionably() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tenant/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(
                json!({"error": "invalid_client", "error_description": "AADSTS7000222"}),
            ))
            .mount(&server)
            .await;

        let check = azure_check(&verifier_for(&server), &foundry_target()).await;
        assert!(check.status == Status::Fail);
        assert!(check.note.contains("couldn't verify"), "{}", check.note);
        assert!(check.note.contains("service principal"), "{}", check.note);
    }

    /// No Azure-backed upstream: nothing to verify, and nothing to report.
    /// The check is skipped, never failed — and never dials out.
    #[tokio::test]
    async fn a_non_azure_config_skips_the_azure_preflight() {
        let direct = ProviderKeys {
            anthropic: Some("sk-ant-key".to_owned()),
            anthropic_upstream: Some("direct".to_owned()),
            ..ProviderKeys::default()
        };
        assert!(azure_checks(Some(&direct)).await.is_empty());
        assert!(azure_checks(None).await.is_empty());

        // Nor does a stray Azure key without the selector make a target: only
        // the selector puts an account in the request path.
        let unselected = ProviderKeys {
            azure_foundry_endpoint: Some("https://acct.services.ai.azure.com".to_owned()),
            azure_foundry_api_key: Some("foundry-key".to_owned()),
            ..ProviderKeys::default()
        };
        assert!(azure_checks(Some(&unselected)).await.is_empty());
    }

    /// A selected upstream whose ARM credentials are half-configured has nothing
    /// to verify *with*; `provider_keys_check` is what names the missing flag.
    #[tokio::test]
    async fn an_incomplete_azure_target_is_left_to_the_provider_keys_check() {
        let mut keys = complete_foundry_keys();
        keys.azure_foundry_client_secret = None;
        assert!(azure_checks(Some(&keys)).await.is_empty());
        assert!(provider_keys_check(&cfg(keys)).status == Status::Fail);
    }
}
