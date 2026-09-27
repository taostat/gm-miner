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
    let status = response.status();
    if !status.is_success() {
        if provider == AzureProvider::OpenAi && status == reqwest::StatusCode::BAD_REQUEST {
            if let Ok(body) = response.bytes().await {
                if is_reasoning_budget_exhausted(&body) {
                    return Check::info(
                        label,
                        "Azure reported an output limit (HTTP 400) — probe inconclusive; \
                         model identity remains unverified. Retry the probe; if this persists, \
                         investigate the deployment or probe token budget.",
                    );
                }
            }
        }
        return Check::fail(label, format!("cloud endpoint returned {status}"));
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

/// Recognize the known Azure output-limit error, which can occur when reasoning
/// consumes the probe budget. It does not establish the cause or model identity.
fn is_reasoning_budget_exhausted(body: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct ErrorResponse {
        error: ProbeError,
    }

    // Typed deserialization rejects ambiguous duplicate fields. An internally
    // tagged error also requires an object and the expected error type.
    #[derive(Deserialize)]
    #[serde(tag = "type")]
    enum ProbeError {
        #[serde(rename = "invalid_request_error")]
        InvalidRequest {
            message: String,
            code: Option<String>,
            param: Option<String>,
        },
    }

    if body.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return false;
    }
    let Ok(ErrorResponse {
        error:
            ProbeError::InvalidRequest {
                message,
                code,
                param,
            },
    }) = serde_json::from_slice(body)
    else {
        return false;
    };
    // A specific code/parameter can identify a different request error. Do not
    // downgrade it just because its text mentions an output limit.
    if code.is_some() || param.is_some() {
        return false;
    }
    let message = message.split_whitespace().collect::<Vec<_>>().join(" ");
    let Some(suffix) = message.strip_prefix(
        "Could not finish the message because max_tokens or model output limit was reached.",
    ) else {
        return false;
    };
    matches!(
        suffix,
        "" | " Please try again with higher max_tokens."
            | " Please try again with a higher max_tokens."
    )
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
                // Reasoning models burn part of this budget on hidden reasoning
                // tokens before any visible output; 1 starves them into a 400
                // ("max_tokens or model output limit was reached") even though
                // the deployment is healthy. Keep the probe bounded; exhaustion
                // at this budget is still inconclusive, not an identity pass.
                "max_completion_tokens": 256,
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
    use super::{echo_matches, is_reasoning_budget_exhausted, parse_echo};
    use serde_json::json;

    const OUTPUT_LIMIT_MESSAGE: &str = "Could not finish the message because max_tokens or \
        model output limit was reached.";

    fn output_limit_error(message: &str) -> serde_json::Value {
        json!({"error": {
            "message": message,
            "type": "invalid_request_error",
            "param": null,
            "code": null,
        }})
    }

    #[test]
    fn accepts_known_output_limit_errors() {
        for suffix in [
            "",
            " Please try again with higher max_tokens.",
            " Please try again with a higher max_tokens.",
        ] {
            let body = output_limit_error(&format!("{OUTPUT_LIMIT_MESSAGE}{suffix}"));
            let body = body
                .to_string()
                .replace("max_tokens", "max_\\u0074okens")
                .replace("model output", "model\\noutput");
            assert!(is_reasoning_budget_exhausted(body.as_bytes()), "{body}");
        }
        let body = json!({"error": {
            "message": OUTPUT_LIMIT_MESSAGE,
            "type": "invalid_request_error"
        }});
        assert!(is_reasoning_budget_exhausted(body.to_string().as_bytes()));
    }

    #[test]
    fn rejects_unrelated_and_ambiguous_output_limit_errors() {
        let known = output_limit_error(OUTPUT_LIMIT_MESSAGE);
        let mut cases = vec![
            output_limit_error("Unrecognized request argument supplied: temperature").to_string(),
            output_limit_error(&format!("Invalid deployment: {OUTPUT_LIMIT_MESSAGE}")).to_string(),
            output_limit_error(&format!("{OUTPUT_LIMIT_MESSAGE} Deployment is disabled."))
                .to_string(),
            "not JSON".to_owned(),
            "{}".to_owned(),
            format!("{known} trailing"),
            format!("[{known}]"),
            format!(r#"{{"error":{{}},"error":{}}}"#, known["error"]),
            known.to_string().replace(
                r#""message":"#,
                r#""message":"deployment missing","message":"#,
            ),
            known
                .to_string()
                .replace(r#""type":"#, r#""type":"authentication_error","type":"#),
            known.to_string().replace(
                r#""code":null"#,
                r#""code":"DeploymentNotFound","code":null"#,
            ),
            known
                .to_string()
                .replace(r#""param":null"#, r#""param":"model","param":null"#),
            json!({"error": [OUTPUT_LIMIT_MESSAGE, "invalid_request_error", null, null]})
                .to_string(),
        ];
        for (field, value) in [
            ("message", json!(null)),
            ("message", json!(42)),
            ("type", json!("authentication_error")),
            ("type", json!(null)),
            ("code", json!("DeploymentNotFound")),
            ("param", json!("model")),
        ] {
            let mut body = known.clone();
            body["error"][field] = value;
            cases.push(body.to_string());
        }
        for body in cases {
            assert!(!is_reasoning_budget_exhausted(body.as_bytes()), "{body}");
        }
    }

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
