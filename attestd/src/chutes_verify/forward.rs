//! The loopback HTTP surface: validates a chat request, encrypts it to an
//! admitted instance, and returns only what the instance authenticated.

use std::sync::Arc;

use axum::body::{to_bytes, Body, Bytes};
use axum::http::{header, HeaderValue, Method, Request, Response, StatusCode};
use futures_util::StreamExt as _;
use serde_json::{Map, Value};
use tracing::warn;

use crate::chutes_verify::admission::{Admissions, ChutesApi, Invocation};
use crate::chutes_verify::crypto::{self, ResponseKey, MAX_PLAINTEXT_BYTES};
use crate::chutes_verify::error::ChutesError;
use crate::chutes_verify::stream::StreamDecryptor;
use crate::chutes_verify::{target_for_model, ChutesTarget, CHAT_COMPLETIONS, SELECTOR_HEADER};

const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

pub struct ChutesVerifier<A> {
    api: Arc<A>,
    admissions: Admissions<A>,
}

struct Prepared {
    target: ChutesTarget,
    api_key: String,
    payload: Map<String, Value>,
    stream: bool,
}

impl<A: ChutesApi> ChutesVerifier<A> {
    pub fn new(api: A) -> Self {
        let api = Arc::new(api);
        Self {
            admissions: Admissions::new(Arc::clone(&api)),
            api,
        }
    }

    /// Serve one request; every failure becomes a response naming its cause.
    pub async fn forward(&self, request: Request<Body>) -> Response<Body> {
        self.try_forward(request)
            .await
            .unwrap_or_else(ChutesError::into_response)
    }

    async fn try_forward(&self, request: Request<Body>) -> Result<Response<Body>, ChutesError> {
        let prepared = prepare(request).await?;
        let ticket = self
            .admissions
            .ticket(&prepared.api_key, prepared.target.chute_id)
            .await?;
        let encrypted = crypto::encrypt_request(&ticket.e2e_pubkey, prepared.payload)
            .map_err(ChutesError::Rejected)?;
        let invocation = Invocation {
            chute_id: prepared.target.chute_id,
            ticket,
            stream: prepared.stream,
            blob: encrypted.blob,
        };
        let response = self.api.invoke(&prepared.api_key, invocation).await?;
        let status = response.status();
        if !status.is_success() {
            return Err(ChutesError::Upstream {
                stage: "invoke",
                status,
            });
        }
        if prepared.stream {
            return Ok(stream_response(
                response,
                encrypted.response_key,
                prepared.target.model,
            ));
        }
        complete_response(response, &encrypted.response_key, prepared.target.model).await
    }
}

async fn prepare(request: Request<Body>) -> Result<Prepared, ChutesError> {
    let bad = |message: String| ChutesError::BadRequest(message);
    let selector = request
        .headers()
        .get(SELECTOR_HEADER)
        .ok_or_else(|| bad(format!("missing {SELECTOR_HEADER}")))?
        .to_str()
        .map_err(|_| bad(format!("{SELECTOR_HEADER} is not ASCII")))?;
    let target = target_for_model(selector)
        .ok_or_else(|| bad(format!("{selector} is not a verified Chutes model")))?;
    if request.method() != Method::POST || request.uri().path() != CHAT_COMPLETIONS {
        return Err(bad(format!(
            "{} is served only at POST {CHAT_COMPLETIONS}, not {} {}",
            target.model,
            request.method(),
            request.uri().path()
        )));
    }
    let api_key = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|key| !key.is_empty())
        .ok_or(ChutesError::MissingCredential)?
        .to_owned();
    let body = to_bytes(request.into_body(), MAX_REQUEST_BYTES)
        .await
        .map_err(|_| bad(format!("request body exceeds {MAX_REQUEST_BYTES} bytes")))?;
    let Ok(Value::Object(mut payload)) = serde_json::from_slice(&body) else {
        return Err(bad("request body is not a JSON object".to_owned()));
    };
    if payload.keys().any(|key| key.starts_with("e2e_")) {
        return Err(bad("e2e_ fields are reserved for the transport".to_owned()));
    }
    if payload.get("model").and_then(Value::as_str) != Some(target.model) {
        return Err(bad(format!(
            "body model must equal the selector {}",
            target.model
        )));
    }
    let stream = match payload.get("stream") {
        None | Some(Value::Bool(false) | Value::Null) => false,
        Some(Value::Bool(true)) => true,
        Some(_) => return Err(bad("stream must be a boolean".to_owned())),
    };
    if stream {
        let options = payload
            .entry("stream_options")
            .or_insert_with(|| Value::Object(Map::new()));
        let Value::Object(options) = options else {
            return Err(bad("stream_options must be an object".to_owned()));
        };
        options.insert("include_usage".to_owned(), Value::Bool(true));
    }
    Ok(Prepared {
        target,
        api_key,
        payload,
        stream,
    })
}

async fn complete_response(
    mut response: reqwest::Response,
    key: &ResponseKey,
    model: &str,
) -> Result<Response<Body>, ChutesError> {
    let mut blob = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        ChutesError::BadResponse(anyhow::Error::new(error).context("read Chutes response"))
    })? {
        if blob.len() + chunk.len() > MAX_PLAINTEXT_BYTES {
            return Err(ChutesError::BadResponse(anyhow::anyhow!(
                "encrypted response exceeds {MAX_PLAINTEXT_BYTES} bytes"
            )));
        }
        blob.extend_from_slice(&chunk);
    }
    let json = key
        .decrypt_response(&blob)
        .map_err(ChutesError::BadResponse)?;
    let Ok(Value::Object(completion)) = serde_json::from_slice(&json) else {
        return Err(ChutesError::BadResponse(anyhow::anyhow!(
            "decrypted response is not a JSON object"
        )));
    };
    if completion.get("model").and_then(Value::as_str) != Some(model) {
        return Err(ChutesError::BadResponse(anyhow::anyhow!(
            "decrypted response names model {:?}, expected {model}",
            completion.get("model")
        )));
    }
    Ok(with_content_type(
        Response::new(Body::from(json)),
        "application/json",
    ))
}

fn stream_response(
    response: reqwest::Response,
    key: ResponseKey,
    model: &'static str,
) -> Response<Body> {
    let state = Some((response.bytes_stream(), StreamDecryptor::new(key, model)));
    let events = futures_util::stream::unfold(state, |state| async move {
        let (mut upstream, mut decryptor) = state?;
        loop {
            let outcome = match upstream.next().await {
                Some(Ok(bytes)) => decryptor.feed(&bytes).map(Some),
                Some(Err(error)) => Err(anyhow::Error::new(error).context("read Chutes stream")),
                None => decryptor.finish().map(|()| None),
            };
            match outcome {
                Ok(Some(output)) if output.is_empty() => {}
                Ok(Some(output)) => {
                    return Some((Ok(Bytes::from(output)), Some((upstream, decryptor))))
                }
                Ok(None) => return None,
                Err(error) => {
                    warn!(cause = %format!("{error:#}"), "Chutes stream aborted");
                    return Some((Err(std::io::Error::other(format!("{error:#}"))), None));
                }
            }
        }
    });
    with_content_type(
        Response::new(Body::from_stream(events)),
        "text/event-stream",
    )
}

fn with_content_type(mut response: Response<Body>, content_type: &'static str) -> Response<Body> {
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test fixtures fail the test")]
mod tests {
    use super::*;
    use crate::chutes_verify::admission::tests::FakeApi;
    use crate::chutes_verify::crypto::tests::{Instance, Responder};
    use crate::chutes_verify::stream::tests::{content, usage_frame};
    use http_body_util::BodyExt as _;

    const MODEL: &str = "zai-org/GLM-5.2-TEE";

    fn request(body: &Value) -> Request<Body> {
        Request::post(CHAT_COMPLETIONS)
            .header(SELECTOR_HEADER, MODEL)
            .header(header::AUTHORIZATION, "Bearer cpk_test")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn chat(stream: bool) -> Value {
        serde_json::json!({"model": MODEL, "messages": [{"role": "user", "content": "hi"}], "stream": stream})
    }

    /// A verifier whose one discovered instance is played by the test: each
    /// invoke is opened with the instance key and answered by `reply`.
    fn verifier(
        reply: impl Fn(&Responder) -> (StatusCode, Vec<u8>) + Send + Sync + 'static,
    ) -> (ChutesVerifier<FakeApi>, Arc<Instance>) {
        let api = FakeApi::new(1);
        let instance = Arc::new(Instance::new());
        api.instances.lock().unwrap()[0]
            .1
            .clone_from(&instance.public_b64);
        let player = Arc::clone(&instance);
        *api.answer.lock().unwrap() = Some(Box::new(move |blob| {
            let (status, body) = reply(&Responder::new(&player.open_request(blob)));
            axum::http::Response::builder()
                .status(status)
                .body(reqwest::Body::from(body))
                .unwrap()
        }));
        (ChutesVerifier::new(api), instance)
    }

    fn sent(verifier: &ChutesVerifier<FakeApi>, instance: &Instance) -> Map<String, Value> {
        instance.open_request(&verifier.api.invoked.lock().unwrap().last().unwrap().blob)
    }

    async fn body_text(response: Response<Body>) -> Result<String, String> {
        response
            .into_body()
            .collect()
            .await
            .map(|body| String::from_utf8(body.to_bytes().to_vec()).unwrap())
            .map_err(|error| error.to_string())
    }

    fn stream_event(responder: &Responder, data: &str) -> String {
        let chunk = responder.stream_chunk(&format!("data: {data}\n\n"));
        format!("data: {}\n\n", serde_json::json!({"e2e": chunk}))
    }

    fn stream_init(responder: &Responder) -> String {
        format!(
            "data: {}\n\n",
            serde_json::json!({"e2e_init": responder.stream_init()})
        )
    }

    #[tokio::test]
    async fn requests_off_the_contract_are_refused_before_any_upstream_call() {
        let (verifier, _) = verifier(|_| (StatusCode::OK, Vec::new()));
        let mut absent = request(&chat(false));
        absent.headers_mut().remove(SELECTOR_HEADER);
        let mut off_list = request(&chat(false));
        off_list
            .headers_mut()
            .insert(SELECTOR_HEADER, HeaderValue::from_static("zai-org/GLM-5.2"));
        let mut mismatched = chat(false);
        mismatched["model"] = Value::from("moonshotai/Kimi-K3-TEE");
        let mut reserved = chat(false);
        reserved["e2e_response_pk"] = Value::from("attacker");
        let mut wrong_path = request(&chat(false));
        *wrong_path.uri_mut() = "/v1/completions".parse().unwrap();
        for request in [
            absent,
            off_list,
            request(&mismatched),
            request(&reserved),
            wrong_path,
        ] {
            assert_eq!(
                verifier.forward(request).await.status(),
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            verifier
                .api
                .discoveries
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn missing_credential_is_unauthorized() {
        let (verifier, _) = verifier(|_| (StatusCode::OK, Vec::new()));
        let mut unauthenticated = request(&chat(false));
        unauthenticated.headers_mut().remove(header::AUTHORIZATION);
        assert_eq!(
            verifier.forward(unauthenticated).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn upstream_status_passes_through_without_its_body() {
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_REQUEST,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let (verifier, _) = verifier(move |_| (status, b"relay detail".to_vec()));
            let response = verifier.forward(request(&chat(false))).await;
            assert_eq!(response.status(), status);
            assert!(!body_text(response).await.unwrap().contains("relay detail"));
        }
    }

    #[tokio::test]
    async fn completion_travels_encrypted_and_is_model_checked() {
        let completion =
            serde_json::json!({"model": MODEL, "choices": [], "usage": {"total_tokens": 3}});
        let reply = completion.to_string();
        let (proxy, instance) =
            verifier(move |responder| (StatusCode::OK, responder.response_blob(reply.as_bytes())));
        let response = proxy.forward(request(&chat(false))).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await.unwrap(), completion.to_string());
        assert_eq!(sent(&proxy, &instance)["messages"], chat(false)["messages"]);
        let blob = proxy.api.invoked.lock().unwrap()[0].blob.clone();
        assert!(
            !String::from_utf8_lossy(&blob).contains("messages"),
            "request left in plaintext"
        );

        let (proxy, _) = verifier(|responder: &Responder| {
            (
                StatusCode::OK,
                responder.response_blob(br#"{"model":"x/y"}"#),
            )
        });
        assert_eq!(
            proxy.forward(request(&chat(false))).await.status(),
            StatusCode::BAD_GATEWAY
        );
        let (proxy, _) = verifier(|_: &Responder| (StatusCode::OK, b"not encrypted".to_vec()));
        assert_eq!(
            proxy.forward(request(&chat(false))).await.status(),
            StatusCode::BAD_GATEWAY
        );
    }

    #[tokio::test]
    async fn stream_asks_for_usage_and_releases_done_only_when_verified() {
        let (verifier, instance) = verifier(|responder| {
            let body = [
                stream_init(responder),
                stream_event(responder, &content("hi", 11)),
                stream_event(responder, &usage_frame(11)),
                stream_event(responder, "[DONE]"),
            ]
            .concat();
            (StatusCode::OK, body.into_bytes())
        });
        let response = verifier.forward(request(&chat(true))).await;
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/event-stream"
        );
        assert!(body_text(response)
            .await
            .unwrap()
            .ends_with("data: [DONE]\n\n"));
        assert_eq!(
            sent(&verifier, &instance)["stream_options"]["include_usage"],
            true
        );
        assert!(verifier.api.invoked.lock().unwrap()[0].stream);
    }

    #[tokio::test]
    async fn stream_without_the_encrypted_done_aborts_the_connection() {
        let (verifier, _) = verifier(|responder| {
            let body = [
                stream_init(responder),
                stream_event(responder, &content("hi", 11)),
                "data: [DONE]\n\n".to_owned(),
            ]
            .concat();
            (StatusCode::OK, body.into_bytes())
        });
        let response = verifier.forward(request(&chat(true))).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.is_err());
    }
}
