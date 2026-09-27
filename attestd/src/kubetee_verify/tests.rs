#![expect(
    clippy::unwrap_used,
    reason = "test fixtures intentionally fail hard on malformed local values"
)]

//! The evidence is one live `GET /v1/attestation` response from
//! `llm.kubetee.ai` (2026-09-27, pod `litellm-5959f596d-l4qkl`), the leaf
//! certificate of the TLS session it arrived on, and the Intel collateral
//! for its quote, verified offline at [`FIXTURE_NOW`].
//!
//! The end-to-end tests serve that quote from a local TLS server whose
//! certificate chains to a test root, and which signs the TLS-possession
//! proof with its own test key.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use dcap_qvl::policy::QuoteClaims;
use dcap_qvl::quote::{EnclaveReport, Report, TDReport10};
use dcap_qvl::tcb_info::TcbStatus;
use http_body_util::{Either, Full};
use hyper::service::service_fn;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest as _, Sha256};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::evidence::verify_attestation;
use super::*;

const FIXTURE_NOW: u64 = 1_790_532_956;
const ATTESTATION: &[u8] = include_bytes!("../../tests/fixtures/kubetee/attestation.json");
const SESSION_LEAF: &[u8] = include_bytes!("../../tests/fixtures/kubetee/session_leaf.der");
const COLLATERAL: &[u8] = include_bytes!("../../tests/fixtures/kubetee/collateral.json");
const TEST_ROOT: &[u8] = include_bytes!("../../tests/fixtures/kubetee/test_ca.der");
const TEST_LEAF: &[u8] = include_bytes!("../../tests/fixtures/kubetee/test_leaf.der");
const TEST_KEY: &[u8] = include_bytes!("../../tests/fixtures/kubetee/test_leaf_key.pk8");
const FIRST_EVENT: &[u8] = b"data: {\"choices\":[]}\n\n";
const SSE: &str = "data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\ndata: [DONE]\n\n";

fn payload() -> AttestationPayload {
    serde_json::from_slice(ATTESTATION).unwrap()
}

fn fixture_nonce() -> [u8; 32] {
    hex::decode(payload().nonce).unwrap().try_into().unwrap()
}

fn collateral() -> QuoteCollateralV3 {
    serde_json::from_slice(COLLATERAL).unwrap()
}

fn quote() -> Vec<u8> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payload().quote).unwrap()
}

fn claims() -> QuoteClaims {
    tee_evidence::verify_signature_chain(&quote(), collateral(), FIXTURE_NOW).unwrap()
}

fn td_mut(claims: &mut QuoteClaims) -> &mut TDReport10 {
    match &mut claims.report {
        Report::TD10(td) => td,
        Report::TD15(td) => &mut td.base,
        Report::SgxEnclave(_) => unreachable!("fixture is a TDX quote"),
    }
}

fn standalone(payload: &AttestationPayload, nonce: &str, claims: &QuoteClaims) -> Result<()> {
    verify_attestation(payload, nonce, SESSION_LEAF, claims, FIXTURE_NOW).map(|_| ())
}

fn failure(result: Result<()>) -> String {
    format!("{:#}", result.unwrap_err())
}

#[test]
fn the_live_attestation_verifies_offline() {
    let payload = payload();
    let measurements = verify_attestation(
        &payload,
        &payload.nonce,
        SESSION_LEAF,
        &claims(),
        FIXTURE_NOW,
    )
    .unwrap();
    assert_eq!(measurements.rtmrs[3], [0; 48], "RTMR3 carries no events");
    assert_ne!(measurements.rtmrs[2], [0; 48]);
}

#[test]
fn a_different_echoed_nonce_fails_closed() {
    let mut payload = payload();
    let nonce = payload.nonce.clone();
    payload.nonce = hex::encode([7_u8; 32]);
    assert!(failure(standalone(&payload, &nonce, &claims())).contains("echoed a different nonce"));
}

#[test]
fn an_uppercased_echo_is_not_the_nonce_sent() {
    let mut payload = payload();
    let nonce = payload.nonce.clone();
    payload.nonce = nonce.to_uppercase();
    assert!(failure(standalone(&payload, &nonce, &claims())).contains("echoed a different nonce"));
}

#[test]
fn a_replayed_quote_under_a_new_nonce_fails_the_binding() {
    let mut payload = payload();
    let fresh = hex::encode([9_u8; 32]);
    payload.nonce.clone_from(&fresh);
    assert!(failure(standalone(&payload, &fresh, &claims())).contains("report_data"));
}

#[test]
fn an_sgx_report_fails_closed() {
    let mut claims = claims();
    claims.report = Report::SgxEnclave(EnclaveReport {
        cpu_svn: [0; 16],
        misc_select: 0,
        reserved1: [0; 28],
        attributes: [0; 16],
        mr_enclave: [0; 32],
        reserved2: [0; 32],
        mr_signer: [0; 32],
        reserved3: [0; 96],
        isv_prod_id: 0,
        isv_svn: 0,
        reserved4: [0; 60],
        report_data: [0; 64],
    });
    let payload = payload();
    assert!(failure(standalone(&payload, &payload.nonce, &claims)).contains("SGX"));
}

#[test]
fn a_tcb_below_up_to_date_fails_closed() {
    let mut claims = claims();
    claims.platform.tcb_level.tcb_status = TcbStatus::SWHardeningNeeded;
    let payload = payload();
    assert!(failure(standalone(&payload, &payload.nonce, &claims)).contains("TCB"));
}

#[test]
fn a_debug_td_fails_closed() {
    let mut claims = claims();
    td_mut(&mut claims).td_attributes[0] |= 1;
    let payload = payload();
    assert!(failure(standalone(&payload, &payload.nonce, &claims)).contains("debug"));
}

#[test]
fn a_missing_event_log_fails_closed() {
    let mut payload = payload();
    payload.cc_eventlog = None;
    assert!(failure(standalone(&payload, &payload.nonce, &claims())).contains("cc_eventlog"));
}

#[test]
fn a_tampered_event_log_does_not_replay() {
    let mut payload = payload();
    let engine = base64::engine::general_purpose::STANDARD;
    let mut log = base64::Engine::decode(&engine, payload.cc_eventlog.as_deref().unwrap()).unwrap();
    let first_record = 32 + u32::from_le_bytes(log[28..32].try_into().unwrap()) as usize;
    log[first_record + 12 + 2] ^= 1;
    payload.cc_eventlog = Some(base64::Engine::encode(&engine, log));
    assert!(failure(standalone(&payload, &payload.nonce, &claims())).contains("RTMR0"));
}

#[test]
fn an_rtmr3_extended_without_events_does_not_replay() {
    let mut claims = claims();
    td_mut(&mut claims).rt_mr3[0] ^= 1;
    let payload = payload();
    assert!(failure(standalone(&payload, &payload.nonce, &claims)).contains("RTMR3"));
}

#[test]
fn a_proof_for_another_certificate_fails_closed() {
    let payload = payload();
    let result = verify_attestation(&payload, &payload.nonce, TEST_LEAF, &claims(), FIXTURE_NOW);
    assert!(format!("{:#}", result.unwrap_err()).contains("other than this connection's"));
}

#[test]
fn a_bad_tls_signature_fails_closed() {
    let mut payload = payload();
    let possession = payload.tls_possession.as_mut().unwrap();
    let engine = base64::engine::general_purpose::STANDARD;
    let mut signature = base64::Engine::decode(&engine, &possession.tls_signature).unwrap();
    signature[10] ^= 1;
    possession.tls_signature = base64::Engine::encode(&engine, signature);
    assert!(failure(standalone(&payload, &payload.nonce, &claims())).contains("does not verify"));
}

#[test]
fn a_non_rs256_proof_fails_closed() {
    let mut payload = payload();
    payload.tls_possession.as_mut().unwrap().tls_signature_alg = "ES256".to_owned();
    assert!(failure(standalone(&payload, &payload.nonce, &claims())).contains("RS256"));
}

#[test]
fn the_model_list_is_narrowed_to_the_chat_and_image_models() {
    let list = serde_json::json!({"object": "list", "data": [
        {"id": "z-ai/glm-5.3", "object": "model"},
        {"id": "minimax/h3", "object": "model"},
        {"id": "black-forest-labs/flux.2-klein-4b", "object": "model"},
        {"id": "all-proxy-models", "object": "model"},
        {"id": "xiaomi/mimo-v2.6-pro", "object": "model"},
        {"object": "model"},
    ]});
    let served = served_targets(&list);
    assert_eq!(
        served["data"],
        serde_json::json!([
            {"id": "z-ai/glm-5.3", "object": "model"},
            {"id": "black-forest-labs/flux.2-klein-4b", "object": "model"},
            {"id": "xiaomi/mimo-v2.6-pro", "object": "model"},
        ])
    );
    assert_eq!(
        served_targets(&serde_json::json!({}))["data"],
        serde_json::json!([])
    );
}

#[test]
fn the_upstream_request_carries_no_supplier_or_selector_header() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/chat/completions")
        .header(SELECTOR_HEADER, TARGETS[0])
        .header("x-kubetee-nonce", "buyer-chosen")
        .header("x-kubetee-anything", "buyer")
        .header("x-litellm-tags", "buyer")
        .header("connection", "keep-alive")
        .body(Body::empty())
        .unwrap();
    let upstream = upstream_request(request).unwrap();
    assert!(upstream
        .headers()
        .keys()
        .all(|name| !name.as_str().starts_with("x-kubetee-")
            && !name.as_str().starts_with("x-litellm-")));
    assert!(!upstream.headers().contains_key(SELECTOR_HEADER));
    assert!(!upstream.headers().contains_key("connection"));
    assert_eq!(upstream.headers()[HOST], HOST_NAME);
}

// ---- End to end against a local TLS upstream ----

#[derive(Clone, Copy)]
enum Chat {
    Served,
    Slow,
    Unauthorized,
    Dropped,
    /// The model list sends headers and half its body, then nothing.
    StalledModelList,
    /// The chat sends its first event, then nothing more.
    FirstEventOnly,
    /// The chat sends one event, then supplier and ordinary trailers.
    Trailed,
}

#[derive(Clone, Copy)]
enum Evidence {
    Genuine,
    Unavailable,
    /// The proof the recorded session carried, naming that session's certificate.
    OtherCertificate,
    /// The recorded quote, echoed under a nonce other than the one sent.
    Replayed,
    /// Headers and half the body, then nothing.
    Stalled,
}

struct Upstream {
    evidence: Evidence,
    chat: Chat,
    accepts: AtomicUsize,
    attestations: AtomicUsize,
    chats: AtomicUsize,
    model_lists: AtomicUsize,
    chat_headers: Mutex<Vec<HeaderMap>>,
    /// Every attestation request's query, headers and body length.
    attestation_requests: Mutex<Vec<(String, HeaderMap, usize)>>,
}

struct FixtureCollateral;

#[async_trait]
impl Collateral for FixtureCollateral {
    async fn fetch(&self, _quote: &[u8]) -> Result<QuoteCollateralV3> {
        Ok(collateral())
    }

    fn now(&self) -> Result<u64> {
        Ok(FIXTURE_NOW)
    }
}

fn sign(nonce: &str) -> String {
    let key = RsaKeyPair::from_pkcs8(TEST_KEY).unwrap();
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        nonce.as_bytes(),
        &mut signature,
    )
    .unwrap();
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signature)
}

fn attestation_body(evidence: Evidence) -> Vec<u8> {
    let mut payload: Value = serde_json::from_slice(ATTESTATION).unwrap();
    let nonce = payload["nonce"].as_str().unwrap().to_owned();
    if !matches!(evidence, Evidence::OtherCertificate) {
        payload["tls_possession"] = serde_json::json!({
            "tls_signature": sign(&nonce),
            "tls_signature_alg": "RS256",
            "tls_signature_input": "sha256(nonce)",
            "tls_cert_sha256": hex::encode(Sha256::digest(TEST_LEAF)),
        });
    }
    if matches!(evidence, Evidence::Replayed) {
        payload["nonce"] = Value::from(hex::encode([5_u8; 32]));
    }
    serde_json::to_vec(&payload).unwrap()
}

type Reply = Response<Either<Full<Bytes>, Frames>>;

fn reply(status: u16, body: impl Into<Bytes>) -> Reply {
    Response::builder()
        .status(status)
        .body(Either::Left(Full::new(body.into())))
        .unwrap()
}

/// A body that sends its frames in order, then ends or never sends another.
struct Frames {
    frames: std::collections::VecDeque<hyper::body::Frame<Bytes>>,
    then_stall: bool,
}

impl Frames {
    /// `first`, then nothing ever again.
    fn stalling(first: impl Into<Bytes>) -> Self {
        Self {
            frames: [hyper::body::Frame::data(first.into())].into(),
            then_stall: true,
        }
    }

    /// `data`, then `trailers`, then the end.
    fn trailed(data: &'static [u8], trailers: HeaderMap) -> Self {
        Self {
            frames: [
                hyper::body::Frame::data(Bytes::from_static(data)),
                hyper::body::Frame::trailers(trailers),
            ]
            .into(),
            then_stall: false,
        }
    }
}

impl hyper::body::Body for Frames {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        match self.frames.pop_front() {
            Some(frame) => std::task::Poll::Ready(Some(Ok(frame))),
            None if self.then_stall => std::task::Poll::Pending,
            None => std::task::Poll::Ready(None),
        }
    }
}

/// Headers announcing `body` in full, and only its first half sent.
fn stalled(body: &[u8]) -> Reply {
    Response::builder()
        .status(200)
        .header("content-length", body.len())
        .body(Either::Right(Frames::stalling(Bytes::copy_from_slice(
            &body[..body.len() / 2],
        ))))
        .unwrap()
}

async fn chat_reply(chat: Chat) -> Option<Reply> {
    match chat {
        Chat::Unauthorized => return Some(reply(401, "{\"error\":\"unauthorized\"}")),
        Chat::Dropped => return None,
        Chat::Slow => tokio::time::sleep(Duration::from_millis(300)).await,
        Chat::FirstEventOnly => {
            let response = Response::builder()
                .status(200)
                .header("content-type", "text/event-stream")
                .body(Either::Right(Frames::stalling(Bytes::from_static(
                    FIRST_EVENT,
                ))));
            return Some(response.unwrap());
        }
        Chat::Trailed => {
            let mut trailers = HeaderMap::new();
            trailers.insert("x-kubetee-attestation-quote", HeaderValue::from_static("q"));
            trailers.insert("x-litellm-key-spend", HeaderValue::from_static("0.14"));
            trailers.insert("x-request-cost", HeaderValue::from_static("kept"));
            let response = Response::builder()
                .status(200)
                .header("content-type", "text/event-stream")
                .header(
                    "trailer",
                    "x-kubetee-attestation-quote, x-litellm-key-spend, x-request-cost",
                )
                .body(Either::Right(Frames::trailed(FIRST_EVENT, trailers)));
            return Some(response.unwrap());
        }
        Chat::Served | Chat::StalledModelList => {}
    }
    let response = Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("x-litellm-model-group", "served")
        .header("x-litellm-key-spend", "0.1405700124280008")
        .header("x-kubetee-backend", "served")
        .header("x-request-id", "served");
    Some(
        response
            .body(Either::Left(Full::new(Bytes::from_static(SSE.as_bytes()))))
            .unwrap(),
    )
}

async fn handle(
    upstream: Arc<Upstream>,
    request: Request<Incoming>,
) -> Result<Reply, std::io::Error> {
    let path = request.uri().path().to_owned();
    if path == "/v1/attestation" {
        upstream.attestations.fetch_add(1, Ordering::SeqCst);
        let (parts, body) = request.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        let query = parts.uri.query().unwrap_or_default().to_owned();
        upstream
            .attestation_requests
            .lock()
            .unwrap()
            .push((query, parts.headers, body.len()));
        return Ok(match upstream.evidence {
            Evidence::Unavailable => reply(502, "{\"error\":\"attestation agent unavailable\"}"),
            Evidence::Stalled => stalled(&attestation_body(Evidence::Genuine)),
            evidence => reply(200, attestation_body(evidence)),
        });
    }
    if path == MODELS {
        upstream.model_lists.fetch_add(1, Ordering::SeqCst);
        let authorized = request
            .headers()
            .get(AUTHORIZATION)
            .map(HeaderValue::as_bytes)
            == Some(b"Bearer kt".as_slice());
        let list = serde_json::json!({"object": "list", "data": [
            {"id": "z-ai/glm-5.3", "object": "model"},
            {"id": "minimax/h3", "object": "model"},
            {"id": "black-forest-labs/flux.2-klein-4b", "object": "model"},
        ]});
        return Ok(if matches!(upstream.chat, Chat::StalledModelList) {
            stalled(list.to_string().as_bytes())
        } else if authorized {
            reply(200, list.to_string())
        } else {
            reply(401, "{\"error\":\"no key\"}")
        });
    }
    upstream.chats.fetch_add(1, Ordering::SeqCst);
    let (parts, body) = request.into_parts();
    upstream.chat_headers.lock().unwrap().push(parts.headers);
    body.collect().await.unwrap();
    chat_reply(upstream.chat)
        .await
        .ok_or_else(|| std::io::Error::other("dropped"))
}

fn limits() -> Limits {
    Limits::default()
}

async fn serve(evidence: Evidence, chat: Chat, limits: Limits) -> (KubeteeVerifier, Arc<Upstream>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let upstream = Arc::new(Upstream {
        evidence,
        chat,
        accepts: AtomicUsize::new(0),
        attestations: AtomicUsize::new(0),
        chats: AtomicUsize::new(0),
        model_lists: AtomicUsize::new(0),
        chat_headers: Mutex::new(Vec::new()),
        attestation_requests: Mutex::new(Vec::new()),
    });
    let mut config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(TEST_LEAF.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(TEST_KEY.to_vec())),
            )
            .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = Arc::clone(&upstream);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            state.accepts.fetch_add(1, Ordering::SeqCst);
            let (acceptor, state) = (acceptor.clone(), Arc::clone(&state));
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(move |request| handle(Arc::clone(&state), request));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(TEST_ROOT.to_vec())).unwrap();
    let verifier = KubeteeVerifier::with_parts(
        roots,
        Some(address),
        Arc::new(FixtureCollateral),
        fixture_nonce,
        limits,
    );
    (verifier, upstream)
}

fn chat(selector: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(CHAT_COMPLETIONS)
        .header(SELECTOR_HEADER, selector)
        .header("content-type", "application/json")
        .header(AUTHORIZATION, "Bearer kt")
        .header("x-buyer-sentinel", "buyer")
        .body(Body::from(
            serde_json::json!({"model": selector, "stream": true}).to_string(),
        ))
        .unwrap()
}

/// Send one chat and read its body to the end, as Envoy does.
async fn round_trip(verifier: &KubeteeVerifier, selector: &str) -> (StatusCode, Bytes) {
    let response = verifier.forward(chat(selector)).await.unwrap();
    let status = response.status();
    (
        status,
        response.into_body().collect().await.unwrap().to_bytes(),
    )
}

fn counts(upstream: &Upstream) -> (usize, usize, usize) {
    (
        upstream.accepts.load(Ordering::SeqCst),
        upstream.attestations.load(Ordering::SeqCst),
        upstream.chats.load(Ordering::SeqCst),
    )
}

#[tokio::test]
async fn a_chat_streams_through_unchanged_without_supplier_headers() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    let response = verifier.forward(chat(TARGETS[2])).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().keys().all(|name| {
        !name.as_str().starts_with("x-kubetee-") && !name.as_str().starts_with("x-litellm-")
    }));
    assert_eq!(response.headers()["x-request-id"], "served");
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, SSE.as_bytes());
    assert_eq!(
        counts(&upstream),
        (1, 1, 1),
        "one connection, one quote, one chat"
    );
    let (query, _, _) = upstream.attestation_requests.lock().unwrap().remove(0);
    assert_eq!(query, format!("nonce={}", payload().nonce));
    let sent = upstream.chat_headers.lock().unwrap().remove(0);
    assert!(sent
        .keys()
        .all(|name| !name.as_str().starts_with("x-kubetee-")));
    assert!(!sent.contains_key(SELECTOR_HEADER));
}

#[tokio::test]
async fn an_attested_connection_is_reused_without_attesting_again() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    for selector in [TARGETS[0], TARGETS[1], TARGETS[5]] {
        assert_eq!(round_trip(&verifier, selector).await.1, SSE.as_bytes());
    }
    assert_eq!(counts(&upstream), (1, 1, 3));
    assert_eq!(verifier.idle_connections(), 1);
}

#[tokio::test]
async fn a_connection_returns_once_its_body_reports_its_end() {
    let (verifier, _) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    let response = verifier.forward(chat(TARGETS[0])).await.unwrap();
    let mut body = response.into_body();
    // A server writing the response stops polling once the body reports its end.
    while !hyper::body::Body::is_end_stream(&body) {
        body.frame().await.unwrap().unwrap();
    }
    drop(body);
    assert_eq!(verifier.idle_connections(), 1);
}

#[tokio::test]
async fn a_body_dropped_early_retires_its_connection() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    drop(verifier.forward(chat(TARGETS[0])).await.unwrap());
    assert_eq!(verifier.idle_connections(), 0);
    round_trip(&verifier, TARGETS[0]).await;
    assert_eq!(counts(&upstream), (2, 2, 2));
}

#[tokio::test]
async fn a_connection_that_expires_while_idle_is_not_reused() {
    let short = Limits {
        max_age: Duration::from_millis(300),
        ..Limits::default()
    };
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, short).await;
    round_trip(&verifier, TARGETS[0]).await;
    assert_eq!(verifier.idle_connections(), 1, "pooled while fresh");
    tokio::time::sleep(Duration::from_millis(400)).await;
    round_trip(&verifier, TARGETS[0]).await;
    assert_eq!(counts(&upstream), (2, 2, 2));
}

#[tokio::test]
async fn a_connection_is_renewed_after_its_request_limit() {
    let two = Limits {
        max_requests: 2,
        ..Limits::default()
    };
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, two).await;
    for _ in 0..3 {
        round_trip(&verifier, TARGETS[0]).await;
    }
    assert_eq!(counts(&upstream), (2, 2, 3));
}

#[tokio::test]
async fn the_idle_pool_is_capped() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Slow, limits()).await;
    let verifier = Arc::new(verifier);
    let burst = |verifier: Arc<KubeteeVerifier>| async move {
        let requests = (0..pool::MAX_IDLE + 2).map(|_| {
            let verifier = Arc::clone(&verifier);
            tokio::spawn(async move { round_trip(&verifier, TARGETS[0]).await })
        });
        for request in requests.collect::<Vec<_>>() {
            assert_eq!(request.await.unwrap().0, StatusCode::OK);
        }
    };
    burst(Arc::clone(&verifier)).await;
    assert_eq!(upstream.accepts.load(Ordering::SeqCst), pool::MAX_IDLE + 2);
    assert_eq!(verifier.idle_connections(), pool::MAX_IDLE);
    burst(Arc::clone(&verifier)).await;
    assert_eq!(
        upstream.accepts.load(Ordering::SeqCst),
        pool::MAX_IDLE + 4,
        "the second burst reuses every pooled connection"
    );
    assert_eq!(verifier.idle_connections(), pool::MAX_IDLE);
}

#[tokio::test]
async fn off_list_requests_are_refused_before_any_connection() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    let mut wrong_path = chat(TARGETS[0]);
    *wrong_path.uri_mut() = Uri::from_static("/v1/completions");
    let mut wrong_method = chat(TARGETS[0]);
    *wrong_method.method_mut() = Method::GET;
    let mut no_selector = chat(TARGETS[0]);
    no_selector.headers_mut().remove(SELECTOR_HEADER);
    let mut two_selectors = chat(TARGETS[0]);
    two_selectors
        .headers_mut()
        .append(SELECTOR_HEADER, HeaderValue::from_static("z-ai/glm-5.3"));
    let mut other_body_model = chat(TARGETS[1]);
    *other_body_model.body_mut() = Body::from(r#"{"model":"minimax/h3"}"#);
    let mut no_body_model = chat(TARGETS[1]);
    *no_body_model.body_mut() = Body::from(r#"{"messages":[]}"#);
    let mut not_json = chat(TARGETS[1]);
    *not_json.body_mut() = Body::from("model=z-ai/glm-5.3");
    for request in [
        other_body_model,
        no_body_model,
        not_json,
        chat("minimax/h3"),
        chat("black-forest-labs/flux.2-klein-4b"),
        wrong_path,
        wrong_method,
        no_selector,
        two_selectors,
    ] {
        assert!(verifier.forward(request).await.is_err());
    }
    tokio::task::yield_now().await;
    assert_eq!(counts(&upstream), (0, 0, 0));
}

#[tokio::test]
async fn a_connection_that_fails_attestation_never_carries_a_chat() {
    for (evidence, expected) in [
        (Evidence::Unavailable, "502"),
        (Evidence::OtherCertificate, "other than this connection's"),
        (Evidence::Replayed, "echoed a different nonce"),
    ] {
        let (verifier, upstream) = serve(evidence, Chat::Served, limits()).await;
        let error = verifier.forward(chat(TARGETS[0])).await.unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert_eq!(
            counts(&upstream),
            (3, 3, 0),
            "three attested attempts, no chat"
        );
        assert_eq!(verifier.idle_connections(), 0);
        for (_, headers, body) in upstream.attestation_requests.lock().unwrap().iter() {
            assert_eq!(*body, 0, "an attestation request carries no body");
            assert!(!headers.contains_key("x-buyer-sentinel"));
            assert!(!headers.contains_key(AUTHORIZATION));
        }
    }
}

fn quick_fetch() -> Limits {
    Limits {
        fetch_timeout: Duration::from_millis(300),
        ..Limits::default()
    }
}

#[tokio::test]
async fn an_attestation_body_that_stalls_times_out_and_is_retried() {
    let (verifier, upstream) = serve(Evidence::Stalled, Chat::Served, quick_fetch()).await;
    let result = tokio::time::timeout(Duration::from_secs(10), verifier.forward(chat(TARGETS[0])))
        .await
        .unwrap();
    let error = result.unwrap_err();
    assert!(format!("{error:#}").contains("timed out"), "{error:#}");
    assert_eq!(counts(&upstream), (3, 3, 0), "three attempts, no chat");
    assert_eq!(verifier.idle_connections(), 0);
}

#[tokio::test]
async fn a_model_list_body_that_stalls_times_out_and_retires_its_connection() {
    let (verifier, upstream) =
        serve(Evidence::Genuine, Chat::StalledModelList, quick_fetch()).await;
    let request = Request::builder()
        .uri(MODELS)
        .header(AUTHORIZATION, "Bearer kt")
        .body(Body::empty())
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), verifier.models(request))
        .await
        .unwrap();
    assert!(format!("{:#}", result.unwrap_err()).contains("timed out"));
    assert_eq!(verifier.idle_connections(), 0);
    assert_eq!(upstream.model_lists.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn each_event_reaches_the_caller_as_it_arrives() {
    let (verifier, _) = serve(Evidence::Genuine, Chat::FirstEventOnly, limits()).await;
    let response =
        tokio::time::timeout(Duration::from_secs(10), verifier.forward(chat(TARGETS[0])))
            .await
            .unwrap()
            .unwrap();
    let mut body = response.into_body();
    let first = tokio::time::timeout(Duration::from_secs(10), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.into_data().unwrap(), FIRST_EVENT);
}

#[tokio::test]
async fn supplier_trailers_are_removed_on_the_forwarding_path() {
    let (verifier, _) = serve(Evidence::Genuine, Chat::Trailed, limits()).await;
    let mut request = chat(TARGETS[0]);
    request
        .headers_mut()
        .insert("te", HeaderValue::from_static("trailers"));
    let response = verifier.forward(request).await.unwrap();
    let collected = response.into_body().collect().await.unwrap();
    let trailers = collected.trailers().cloned().unwrap();
    assert_eq!(trailers["x-request-cost"], "kept");
    assert!(!trailers.contains_key("x-kubetee-attestation-quote"));
    assert!(!trailers.contains_key("x-litellm-key-spend"));
    assert_eq!(collected.to_bytes(), FIRST_EVENT);
}

#[tokio::test]
async fn a_chat_body_that_stalls_is_refused_before_any_connection() {
    let slow_caller = Limits {
        request_read_timeout: Duration::from_millis(300),
        ..Limits::default()
    };
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, slow_caller).await;
    let mut request = chat(TARGETS[0]);
    *request.body_mut() = Body::new(Frames::stalling(Bytes::from_static(b"{\"model\":")));
    let result = tokio::time::timeout(Duration::from_secs(10), verifier.forward(request))
        .await
        .unwrap();
    assert!(format!("{:#}", result.unwrap_err()).contains("timed out"));
    assert_eq!(counts(&upstream), (0, 0, 0));
}

#[tokio::test]
async fn a_failed_chat_is_never_retried_and_its_connection_is_retired() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Dropped, limits()).await;
    assert!(verifier.forward(chat(TARGETS[0])).await.is_err());
    assert_eq!(counts(&upstream), (1, 1, 1));
    assert_eq!(verifier.idle_connections(), 0);
}

#[tokio::test]
async fn an_upstream_error_status_passes_through() {
    let (verifier, _) = serve(Evidence::Genuine, Chat::Unauthorized, limits()).await;
    let (status, body) = round_trip(&verifier, TARGETS[1]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, "{\"error\":\"unauthorized\"}".as_bytes());
}

#[tokio::test]
async fn the_model_list_is_fetched_on_an_attested_connection_and_narrowed() {
    let (verifier, upstream) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    let request = Request::builder()
        .uri(MODELS)
        .header(AUTHORIZATION, "Bearer kt")
        .body(Body::empty())
        .unwrap();
    let response = verifier.models(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let list: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        list["data"],
        serde_json::json!([
            {"id": "z-ai/glm-5.3", "object": "model"},
            {"id": "black-forest-labs/flux.2-klein-4b", "object": "model"},
        ])
    );
    let keyless = Request::builder().uri(MODELS).body(Body::empty()).unwrap();
    let response = verifier.models(keyless).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    round_trip(&verifier, TARGETS[0]).await;
    assert_eq!(
        counts(&upstream),
        (1, 1, 1),
        "one attested connection serves all three"
    );
}

#[tokio::test]
async fn the_model_list_is_never_fetched_on_a_connection_that_failed_attestation() {
    let (verifier, upstream) = serve(Evidence::OtherCertificate, Chat::Served, limits()).await;
    let request = Request::builder().uri(MODELS).body(Body::empty()).unwrap();
    assert!(verifier.models(request).await.is_err());
    assert_eq!(counts(&upstream), (3, 3, 0));
    assert_eq!(upstream.model_lists.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn preflight_reports_the_attested_replica() {
    let (verifier, _) = serve(Evidence::Genuine, Chat::Served, limits()).await;
    let attested = verifier.preflight().await.unwrap();
    assert_eq!(attested.pod, "litellm-5959f596d-l4qkl");
    assert_eq!(attested.measurements.rtmrs[3], [0; 48]);
    assert_eq!(
        verifier.idle_connections(),
        0,
        "a preflight connection is not pooled"
    );
}
