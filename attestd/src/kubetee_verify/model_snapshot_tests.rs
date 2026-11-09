use super::*;
use tokio::sync::RwLock;

#[derive(Clone, Copy, Debug)]
enum BindingChange {
    Remove,
    Endpoint,
    Expire,
}

async fn change_bindings(
    cache: &Arc<RwLock<SnapshotCache<KubeteeModelBindings>>>,
    change: BindingChange,
) {
    let mut cache = cache.write().await;
    match change {
        BindingChange::Remove => cache.edit_snapshot(|snapshot| snapshot.models.clear()),
        BindingChange::Endpoint => cache.edit_snapshot(|snapshot| {
            for endpoint in snapshot.models.values_mut() {
                *endpoint = match endpoint {
                    EndpointKind::ChatCompletions => EndpointKind::ImagesGenerations,
                    EndpointKind::ImagesGenerations => EndpointKind::ChatCompletions,
                };
            }
        }),
        BindingChange::Expire => cache.age(
            std::time::Instant::now(),
            model_bindings::FRESHNESS_TTL + Duration::from_secs(1),
        ),
    }
}

fn inference(path: &'static str, model: &str) -> Request<Body> {
    let mut request = chat(model);
    *request.uri_mut() = Uri::from_static(path);
    request
}

#[tokio::test]
async fn inference_rejects_a_json_array_without_a_model_field() {
    for (path, model) in [
        (CHAT_COMPLETIONS, TEST_CHAT_MODELS[0]),
        (IMAGES_GENERATIONS, TEST_IMAGE_MODEL),
    ] {
        let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
        let request =
            inference(path, model).map(|_| Body::from(serde_json::json!([model]).to_string()));
        assert!(
            verifier.forward(request).await.is_err(),
            "{path} requires an object with a model field, not a positional array"
        );
        assert_eq!(counts(&upstream), (0, 0, 0));
    }
}

fn assert_binding_rejected(result: Result<Response<Body>>, change: BindingChange) {
    match change {
        BindingChange::Expire => {
            assert_eq!(result.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        BindingChange::Remove | BindingChange::Endpoint => {
            let error = result.unwrap_err();
            let message = error.to_string();
            assert!(
                message.contains("unsupported KubeTEE model selector")
                    || message.contains("not admitted for this endpoint"),
                "{message}"
            );
        }
    }
}

#[tokio::test]
async fn binding_changes_during_body_collection_reject_before_inference() {
    for (path, model) in [
        (CHAT_COMPLETIONS, TEST_CHAT_MODELS[0]),
        (IMAGES_GENERATIONS, TEST_IMAGE_MODEL),
    ] {
        for change in [
            BindingChange::Remove,
            BindingChange::Endpoint,
            BindingChange::Expire,
        ] {
            let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
            let cache = verifier.model_snapshot.cache_for_test();
            let body = Body::from_stream(futures_util::stream::once(async move {
                change_bindings(&cache, change).await;
                Ok::<_, std::io::Error>(serde_json::json!({"model": model}).to_string())
            }));
            let request = inference(path, model).map(|_| body);
            assert_binding_rejected(verifier.forward(request).await, change);
            assert_eq!(counts(&upstream), (0, 0, 0), "{path}: {change:?}");
        }
    }
}

struct ChangingChain {
    cache: Arc<RwLock<SnapshotCache<KubeteeModelBindings>>>,
    change: BindingChange,
}

#[async_trait]
impl QuoteChain for ChangingChain {
    async fn verify(&self, quote: &[u8]) -> Result<(QuoteClaims, u64)> {
        let claims = FixtureChain.verify(quote).await?;
        change_bindings(&self.cache, self.change).await;
        Ok(claims)
    }
}

#[tokio::test]
async fn binding_changes_during_attestation_reject_before_inference() {
    for (path, model) in [
        (CHAT_COMPLETIONS, TEST_CHAT_MODELS[0]),
        (IMAGES_GENERATIONS, TEST_IMAGE_MODEL),
    ] {
        for change in [
            BindingChange::Remove,
            BindingChange::Endpoint,
            BindingChange::Expire,
        ] {
            let (mut verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
            verifier.quote_chain = Arc::new(ChangingChain {
                cache: verifier.model_snapshot.cache_for_test(),
                change,
            });
            assert_binding_rejected(verifier.forward(inference(path, model)).await, change);
            assert_eq!(counts(&upstream), (1, 1, 0), "{path}: {change:?}");
        }
    }
}

#[tokio::test]
async fn model_list_uses_bindings_current_after_upstream_io() {
    for change in [BindingChange::Remove, BindingChange::Expire] {
        let (mut verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
        verifier.quote_chain = Arc::new(ChangingChain {
            cache: verifier.model_snapshot.cache_for_test(),
            change,
        });
        let request = Request::builder()
            .uri(MODELS)
            .header(AUTHORIZATION, "Bearer kt")
            .body(Body::empty())
            .unwrap();
        let response = verifier.models(request).await.unwrap();
        if matches!(change, BindingChange::Expire) {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        } else {
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let list: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(list["data"], serde_json::json!([]));
        }
        assert_eq!(upstream.chats.load(Ordering::SeqCst), 0);
    }
}

fn models_request() -> Request<Body> {
    Request::builder()
        .uri(MODELS)
        .header(AUTHORIZATION, "Bearer kt")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn registry_updates_admit_new_models_and_empty_snapshots_revoke_them() {
    let (mut verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    let payload = Arc::new(RwLock::new(
        serde_json::json!({
            "schema_version": 1, "network": "mainnet", "models": [
                {"upstream_model": "minimax/h3", "endpoint": "chat_completions"},
                {"upstream_model": "registry/new-image", "endpoint": "images_generations"},
            ],
        })
        .to_string()
        .into_bytes(),
    ));
    verifier.model_snapshot = verifier
        .model_snapshot
        .clone()
        .with_url(&registry_server(payload.clone()).await);
    verifier.refresh_bindings().await.unwrap();
    for (path, model) in [
        (CHAT_COMPLETIONS, "minimax/h3"),
        (IMAGES_GENERATIONS, "registry/new-image"),
    ] {
        let mut request = inference(path, model);
        request.headers_mut().insert(
            SESSION_ID_HEADER,
            HeaderValue::from_str(&"a".repeat(64)).unwrap(),
        );
        let response = verifier.forward(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            SSE
        );
    }
    assert_eq!(counts(&upstream), (1, 1, 2));
    {
        let headers = upstream.chat_headers.lock().unwrap();
        assert!(headers[0].contains_key(LITELLM_SESSION_ID_HEADER));
        assert!(!headers[1].contains_key(LITELLM_SESSION_ID_HEADER));
        assert!(!headers[1].contains_key(SESSION_ID_HEADER));
        assert!(!headers[1].contains_key(SELECTOR_HEADER));
    }
    let response = verifier.models(models_request()).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let list: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        list["data"],
        serde_json::json!([{"id": "minimax/h3", "object": "model"}])
    );

    *payload.write().await = br#"{"schema_version":1,"network":"mainnet","models":[]}"#.to_vec();
    verifier.refresh_bindings().await.unwrap();
    for (path, model) in [
        (CHAT_COMPLETIONS, "minimax/h3"),
        (IMAGES_GENERATIONS, "registry/new-image"),
    ] {
        assert!(verifier.forward(inference(path, model)).await.is_err());
    }
    assert_eq!(counts(&upstream), (1, 1, 2));
    let response = verifier.models(models_request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let list: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(list["data"], serde_json::json!([]));
}

#[tokio::test]
async fn missing_and_stale_bindings_fail_closed_for_chat_images_and_models() {
    for stale in [false, true] {
        let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
        if stale {
            change_bindings(
                &verifier.model_snapshot.cache_for_test(),
                BindingChange::Expire,
            )
            .await;
        } else {
            verifier
                .model_snapshot
                .cache_for_test()
                .write()
                .await
                .clear();
        }
        for (path, model) in [
            (CHAT_COMPLETIONS, TEST_CHAT_MODELS[0]),
            (IMAGES_GENERATIONS, TEST_IMAGE_MODEL),
        ] {
            let response = verifier.forward(inference(path, model)).await.unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        let response = verifier.models(models_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(counts(&upstream), (0, 0, 0));
        assert_eq!(upstream.model_lists.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn image_requests_require_attestation_and_are_never_retried() {
    for (evidence, behaviour, expected_counts) in [
        (Evidence::Unbound, Chat::Served, (3, 3, 0)),
        (Evidence::Genuine, Chat::Dropped, (1, 1, 1)),
    ] {
        let (verifier, upstream) = serve(evidence, behaviour, limits()).await;
        let result = verifier
            .forward(inference(IMAGES_GENERATIONS, TEST_IMAGE_MODEL))
            .await;
        assert!(result.is_err());
        assert_eq!(counts(&upstream), expected_counts);
        assert_eq!(verifier.idle_connections(), 0);
    }
}
