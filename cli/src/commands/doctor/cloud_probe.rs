use anyhow::{Context as _, Result};
use gm_azure_verify::AzureProvider;
use serde::Deserialize;

use super::Check;

#[derive(Deserialize)]
struct ModelEcho {
    model: String,
}

pub(super) async fn cloud_identity_check(
    client: &reqwest::Client,
    provider: AzureProvider,
    endpoint: &str,
    api_key: &str,
    deployment: &str,
) -> Check {
    let label = format!("Cloud model echo ({}/{deployment})", provider.label());
    let (path, body) = cloud_probe_body(provider, deployment);
    let url = match cloud_probe_url(endpoint, path) {
        Ok(url) => url,
        Err(error) => return Check::fail(label, format!("invalid cloud endpoint: {error:#}")),
    };
    let mut request = client.post(url).json(&body);
    request = match provider {
        AzureProvider::OpenAi => request.header("api-key", api_key),
        AzureProvider::Foundry => request
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01"),
    };
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => return Check::fail(label, format!("request failed: {error}")),
    };
    if !response.status().is_success() {
        return Check::fail(
            label,
            format!("cloud endpoint returned {}", response.status()),
        );
    }
    let body = match response.bytes().await {
        Ok(body) => body,
        Err(error) => return Check::fail(label, format!("could not read response body: {error}")),
    };
    let echo = match parse_echo(&body) {
        Ok(echo) => echo,
        Err(error) => return Check::fail(label, format!("invalid model echo: {error:#}")),
    };
    if !echo_matches(deployment, &echo) {
        return Check::fail(
            label,
            format!("model substitution: deployment={deployment} echo={echo}"),
        );
    }
    Check::pass(label, format!("deployment={deployment} echo={echo}"))
}

fn parse_echo(body: &[u8]) -> Result<String> {
    anyhow::ensure!(
        body.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'{'),
        "response must be a JSON object"
    );
    let echo: ModelEcho = serde_json::from_slice(body).context("read response model")?;
    Ok(echo.model)
}

fn echo_matches(deployment: &str, echo: &str) -> bool {
    if echo == deployment {
        return true;
    }
    let Some(date) = echo
        .strip_prefix(deployment)
        .and_then(|suffix| suffix.strip_prefix('-'))
    else {
        return false;
    };
    (date.len() == 8 && date.bytes().all(|byte| byte.is_ascii_digit()))
        || (date.len() == 10
            && date.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 4 | 7) {
                    byte == b'-'
                } else {
                    byte.is_ascii_digit()
                }
            }))
}

pub(super) fn cloud_probe_url(endpoint: &str, path: &str) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(endpoint).context("parse endpoint URL")?;
    // start.sh selects the endpoint's host but always connects over HTTPS on 443.
    // Preserve explicit HTTP ports for local diagnostic fixtures.
    if url.scheme() == "https" {
        url.set_port(None)
            .map_err(|()| anyhow::anyhow!("cloud endpoint cannot use an HTTPS port"))?;
    }
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

pub(super) fn cloud_probe_body(
    provider: AzureProvider,
    deployment: &str,
) -> (&'static str, serde_json::Value) {
    match provider {
        AzureProvider::OpenAi => (
            "/openai/v1/chat/completions",
            serde_json::json!({
                "model": deployment,
                "messages": [{"role": "user", "content": "Reply with one token."}],
                "max_completion_tokens": 1,
                "stream": false,
            }),
        ),
        AzureProvider::Foundry => (
            "/anthropic/v1/messages",
            serde_json::json!({
                "model": deployment,
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "Reply with one token."}],
            }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{echo_matches, parse_echo};

    #[test]
    fn rejects_missing_non_string_duplicate_and_non_object_echoes() {
        for body in [
            "{}",
            r#"{"model":1}"#,
            r#"{"model":"gpt-5.4","mo\u0064el":"gpt-5.4"}"#,
            r#"["gpt-5.4"]"#,
            r#"{"model":"gpt-5.4"} trailing"#,
        ] {
            assert!(parse_echo(body.as_bytes()).is_err(), "{body}");
        }
    }

    #[test]
    fn accepts_only_exact_and_dated_echoes() {
        for echo in ["gpt-5.4", "gpt-5.4-20260305", "gpt-5.4-2026-03-05"] {
            assert!(echo_matches("gpt-5.4", echo));
        }
        for echo in ["gpt-5.4-mini", "gpt-5.4-2026030x", "gpt-5.４", "GPT-5.4"] {
            assert!(!echo_matches("gpt-5.4", echo));
        }
    }
}
