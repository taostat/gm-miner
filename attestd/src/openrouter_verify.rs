//! `OpenRouter` prompt-retention gate.
//!
//! `OpenRouter` is a broker: the prompt reaches whichever downstream provider
//! serves the model, and the account's settings decide whether a copy is kept.
//! The inference key cannot read those settings, so the gate measures the
//! effect instead — send a canary carrying a nonce, then ask `OpenRouter` to
//! read the prompt back. Whatever comes back is a prompt the account stored.
//! The same record says whether the generation went through a provider key
//! the operator brought (BYOK), which puts the prompt in the operator's own
//! provider logs; that is refused too. The gate runs before Envoy serves,
//! again on a timer, and — via [`spawn_generation_audit`] — on every
//! generation Envoy serves, because the settings can change while the worker
//! is live.

use std::collections::VecDeque;
use std::time::Duration;

use anyhow::{Context as _, Result};
use rand::RngCore as _;
use reqwest::StatusCode;
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

/// Upstream key env var; `;`-separated segments are separate accounts.
pub const KEY_ENV: &str = "OPENROUTER_API_KEY";

/// Canary models, cheapest first, all on the route's closed list. Four
/// vendors, so one provider's outage does not read as an account failure.
pub const CANARY_MODELS: [&str; 4] = [
    "deepseek/deepseek-v4-flash-0731",
    "qwen/qwen3.6-35b-a3b",
    "z-ai/glm-5.3-flash",
    "openai/gpt-5.4-nano",
];

pub const API_BASE_URL: &str = "https://openrouter.ai/api/v1";

/// Sized so a cycle that times out on every call — one completion, twelve
/// record polls, one readback — still fits three keys inside [`STALE_AFTER`].
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const RECORD_ATTEMPTS: u32 = 12;
const RECORD_DELAY: Duration = Duration::from_secs(5);

/// Longer than the Azure poll's 60s: each cycle spends real credit.
pub const VERIFY_INTERVAL: Duration = Duration::from_secs(900);

/// Two intervals without a successful proof is a stall, not a blip.
pub const STALE_AFTER: Duration = Duration::from_secs(VERIFY_INTERVAL.as_secs() * 2);

/// `OpenRouter` wrote the generation record 2.7-6.1s after the response
/// completed (measured); `/generation/content` answers 404 both before that
/// and when nothing was stored, so an earlier readback proves nothing.
const AUDIT_SETTLE: Duration = Duration::from_secs(8);
const AUDIT_ATTEMPTS: u32 = 4;
const AUDIT_QUEUE_DEPTH: usize = 4096;

/// Measured from the first failed readback after a verdict, not from the last
/// success, so an idle worker's first failure in an hour is not blind on the
/// spot.
const AUDIT_BLIND_LIMIT: Duration = STALE_AFTER;
const TRANSIENT_FAILURE_LIMIT: u32 = 3;

/// `Definitive` is a finding about the account and stops serving now.
/// `Transient` is a failure to reach a verdict, tolerated a bounded number of
/// times in a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    Transient,
    Definitive,
}

impl FailureKind {
    /// A refused key cannot prove anything about its account; every other
    /// non-success status is a reason to ask again.
    fn of_status(status: StatusCode) -> Self {
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            Self::Definitive
        } else {
            Self::Transient
        }
    }
}

#[derive(Debug)]
struct Failure {
    kind: FailureKind,
    message: String,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

fn definitive(message: String) -> anyhow::Error {
    anyhow::Error::new(Failure {
        kind: FailureKind::Definitive,
        message,
    })
}

fn transient(message: String) -> anyhow::Error {
    anyhow::Error::new(Failure {
        kind: FailureKind::Transient,
        message,
    })
}

/// A bare transport or decode error is transient. An error nothing marked is
/// definitive: an unknown failure inside a security gate must not be the
/// tolerated kind.
#[must_use]
pub fn classify(error: &anyhow::Error) -> FailureKind {
    for cause in error.chain() {
        if let Some(failure) = cause.downcast_ref::<Failure>() {
            return failure.kind;
        }
        if cause.downcast_ref::<reqwest::Error>().is_some() {
            return FailureKind::Transient;
        }
    }
    FailureKind::Definitive
}

fn retained_message(what: &str, id: &str) -> String {
    format!(
        "OpenRouter returned stored content for {what} {id}: this account retains prompt \
         content, so buyer prompts served through it are readable by a third party. \
         Turn off input/output logging in the OpenRouter dashboard \
         (https://openrouter.ai/settings/privacy), then redeploy"
    )
}

fn operator_key_message(what: &str, id: &str) -> String {
    format!(
        "OpenRouter routed {what} {id} through a provider key the account owner brought \
         (BYOK): the prompt is in the operator's own provider account, whatever OpenRouter \
         stored. Remove BYOK integrations at https://openrouter.ai/settings/integrations, \
         then redeploy"
    )
}

/// Every configured upstream key, in declaration order.
#[must_use]
pub fn keys_from_env() -> Vec<String> {
    std::env::var(KEY_ENV)
        .unwrap_or_default()
        .split(';')
        .map(|segment| segment.trim_matches(|c: char| c.is_ascii_whitespace()))
        .filter(|segment| !segment.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[derive(Deserialize)]
struct CompletionResponse {
    id: String,
}

#[derive(Deserialize)]
struct GenerationEnvelope {
    data: GenerationData,
}

#[derive(Deserialize)]
struct GenerationData {
    provider_name: Option<String>,
    data_region: Option<String>,
    is_byok: Option<bool>,
    provider_responses: Option<Vec<ProviderResponse>>,
}

#[derive(Deserialize)]
struct ProviderResponse {
    is_byok: Option<bool>,
}

impl GenerationData {
    /// BYOK is reported per generation and per provider attempt; a fallback
    /// hop through BYOK is as bad as a first.
    fn routed_through_operator_key(&self) -> bool {
        self.is_byok == Some(true)
            || self
                .provider_responses
                .iter()
                .flatten()
                .any(|response| response.is_byok == Some(true))
    }
}

#[derive(Deserialize)]
struct ContentEnvelope {
    data: Option<ContentData>,
}

#[derive(Deserialize)]
struct ContentData {
    input: Option<serde_json::Value>,
    output: Option<serde_json::Value>,
}

impl ContentData {
    fn holds_content(&self) -> bool {
        holds_content(self.input.as_ref()) || holds_content(self.output.as_ref())
    }
}

/// A 200 whose `input` and `output` are both empty says what a 404 says;
/// reading it as "stored" would take a healthy worker offline.
fn holds_content(value: Option<&serde_json::Value>) -> bool {
    match value {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::String(text)) => !text.is_empty(),
        Some(serde_json::Value::Array(items)) => !items.is_empty(),
        Some(serde_json::Value::Object(fields)) => !fields.is_empty(),
        Some(_) => true,
    }
}

/// A body that cannot be decoded is not "nothing stored".
fn stored_content(id: &str, body: &str) -> Result<bool> {
    let envelope: ContentEnvelope = serde_json::from_str(body).map_err(|error| {
        transient(format!(
            "OpenRouter stored-content response for {id} could not be decoded ({error}); \
             retention cannot be verified"
        ))
    })?;
    Ok(envelope.data.is_some_and(|data| data.holds_content()))
}

/// What one readback of a live generation established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditVerdict {
    Clean,
    Stored,
    /// Served through a provider key the operator brought (BYOK).
    OperatorKey,
    /// No record yet, so a 404 from the content endpoint would mean nothing.
    NotRecordedYet,
}

/// Who actually received the canary, for the log line.
#[derive(Debug)]
pub struct CanaryOutcome {
    pub generation_id: String,
    pub model: &'static str,
    pub provider_name: Option<String>,
    pub data_region: Option<String>,
}

#[derive(Clone)]
pub struct RetentionVerifier {
    client: reqwest::Client,
    base: String,
}

impl std::fmt::Debug for RetentionVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RetentionVerifier")
    }
}

impl RetentionVerifier {
    /// # Errors
    /// Returns an error when the HTTP client cannot be configured.
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .https_only(true)
            .build()
            .context("build OpenRouter verification client")?;
        Ok(Self::with_base(client, API_BASE_URL))
    }

    #[must_use]
    pub fn with_base(client: reqwest::Client, base: &str) -> Self {
        Self {
            client,
            base: base.trim_end_matches('/').to_owned(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// Prove that `key`'s account keeps no copy of a prompt it just served and
    /// routed it through no credential of the operator's own.
    ///
    /// # Errors
    /// Returns an error on a stored canary, a BYOK hop, a key that cannot read
    /// back its own generation, or an unreachable or unreadable broker;
    /// [`classify`] tells the kinds apart.
    pub async fn verify_key(&self, key: &str) -> Result<CanaryOutcome> {
        self.verify_key_with_nonce(key, &nonce_hex()).await
    }

    async fn verify_key_with_nonce(&self, key: &str, nonce: &str) -> Result<CanaryOutcome> {
        let (generation_id, model) = self
            .send_canary(key, nonce)
            .await
            .context("send OpenRouter retention canary")?;
        // Waiting for the record is what makes an empty content response mean
        // "nothing stored" rather than "not written yet".
        let data = self
            .await_generation_record(key, &generation_id)
            .await
            .context("await OpenRouter generation record")?;
        if data.routed_through_operator_key() {
            return Err(definitive(operator_key_message(
                "the retention canary",
                &generation_id,
            )));
        }
        self.assert_no_stored_content(key, &generation_id, nonce)
            .await?;
        Ok(CanaryOutcome {
            generation_id,
            model,
            provider_name: data.provider_name,
            data_region: data.data_region,
        })
    }

    /// Send the canary exactly the way Envoy forwards buyer traffic — no
    /// `provider` preference block, since buyer requests never carry one —
    /// moving down [`CANARY_MODELS`] when the broker refuses a model.
    async fn send_canary(&self, key: &str, nonce: &str) -> Result<(String, &'static str)> {
        let mut refused = Vec::new();
        for model in CANARY_MODELS {
            let body = serde_json::json!({
                "model": model,
                "max_tokens": 1,
                "temperature": 0,
                "messages": [{
                    "role": "user",
                    "content": format!("gm miner retention canary {nonce}"),
                }],
            });
            let response = self
                .client
                .post(self.url("/chat/completions"))
                .bearer_auth(key)
                .json(&body)
                .send()
                .await
                .context("POST OpenRouter chat completion")?;
            let status = response.status();
            if status.is_success() {
                let parsed: CompletionResponse = response
                    .json()
                    .await
                    .context("decode OpenRouter completion response")?;
                if parsed.id.is_empty() {
                    return Err(transient(format!(
                        "OpenRouter returned no generation id for the retention canary on {model}"
                    )));
                }
                return Ok((parsed.id, model));
            }
            if FailureKind::of_status(status) == FailureKind::Definitive {
                return Err(definitive(format!(
                    "OpenRouter refused the retention canary's key with HTTP {status}"
                )));
            }
            if status == StatusCode::PAYMENT_REQUIRED {
                return Err(transient(
                    "OpenRouter refused the retention canary with HTTP 402: the account has no \
                     credit"
                        .to_owned(),
                ));
            }
            tracing::warn!(
                model,
                %status,
                "OpenRouter refused a canary model; trying the next listed model",
            );
            refused.push(format!("{model}: HTTP {status}"));
        }
        Err(transient(format!(
            "OpenRouter refused every canary model ({})",
            refused.join(", ")
        )))
    }

    /// One readback `GET`. Transport failures and a refused key are errors;
    /// any other non-success status is handed back for the caller to wait on
    /// or give up on.
    async fn readback(
        &self,
        key: &str,
        path: &str,
        id: &str,
    ) -> Result<Result<reqwest::Response, StatusCode>> {
        let response = self
            .client
            .get(self.url(path))
            .bearer_auth(key)
            .query(&[("id", id)])
            .send()
            .await
            .with_context(|| format!("GET OpenRouter {path}"))?;
        let status = response.status();
        if status.is_success() {
            return Ok(Ok(response));
        }
        if FailureKind::of_status(status) == FailureKind::Definitive {
            return Err(definitive(format!(
                "OpenRouter refused {path} for {id} with HTTP {status}: the key cannot read \
                 back what its own account served"
            )));
        }
        Ok(Err(status))
    }

    async fn await_generation_record(&self, key: &str, id: &str) -> Result<GenerationData> {
        let mut last = None;
        for attempt in 1..=RECORD_ATTEMPTS {
            match self.readback(key, "/generation", id).await? {
                Ok(response) => return decode_record(response).await,
                Err(status) => last = Some(status),
            }
            if attempt < RECORD_ATTEMPTS {
                tokio::time::sleep(RECORD_DELAY).await;
            }
        }
        let last = last.map_or_else(|| "none".to_owned(), |status| status.to_string());
        Err(transient(format!(
            "OpenRouter never recorded generation {id} across {RECORD_ATTEMPTS} polls (last \
             HTTP {last}); retention cannot be verified, so the account is treated as retaining"
        )))
    }

    /// The stored prompt and completion for `id`, raw. `None` when nothing is
    /// stored — which is also the answer before the record is written.
    async fn read_content(&self, key: &str, id: &str) -> Result<Option<String>> {
        match self.readback(key, "/generation/content", id).await? {
            Ok(response) => response
                .text()
                .await
                .context("read OpenRouter stored-content response")
                .map(Some),
            Err(StatusCode::NOT_FOUND) => Ok(None),
            Err(status) => Err(transient(format!(
                "OpenRouter stored-content readback for {id} failed with HTTP {status}"
            ))),
        }
    }

    async fn assert_no_stored_content(&self, key: &str, id: &str, nonce: &str) -> Result<()> {
        let Some(body) = self.read_content(key, id).await? else {
            return Ok(());
        };
        // The nonce is checked on the raw body so no change of envelope can
        // hide it; the decode catches a stored prompt the broker transformed.
        if body.contains(nonce) || stored_content(id, &body)? {
            return Err(definitive(retained_message("the retention canary", id)));
        }
        Ok(())
    }

    /// Read one live generation back. The slot that served it is not known
    /// here and another account's generation reads as 404, so each key is
    /// tried until one recognises the id.
    ///
    /// # Errors
    /// Returns an error when a readback fails for a reason other than the
    /// record being absent; [`classify`] says whether it may be retried.
    pub async fn audit_generation(&self, keys: &[String], id: &str) -> Result<AuditVerdict> {
        for key in keys {
            let record = match self.readback(key, "/generation", id).await? {
                Ok(response) => decode_record(response).await?,
                Err(StatusCode::NOT_FOUND) => continue,
                Err(status) => {
                    return Err(transient(format!(
                        "OpenRouter generation metadata for {id} failed with HTTP {status}"
                    )))
                }
            };
            if record.routed_through_operator_key() {
                return Ok(AuditVerdict::OperatorKey);
            }
            return Ok(match self.read_content(key, id).await? {
                Some(body) if stored_content(id, &body)? => AuditVerdict::Stored,
                _ => AuditVerdict::Clean,
            });
        }
        Ok(AuditVerdict::NotRecordedYet)
    }
}

async fn decode_record(response: reqwest::Response) -> Result<GenerationData> {
    let envelope: GenerationEnvelope = response
        .json()
        .await
        .context("decode OpenRouter generation metadata")?;
    Ok(envelope.data)
}

/// Gate every configured account; `Ok(0)` when no key is configured.
///
/// # Errors
/// Returns an error when any configured account retains prompt content or
/// cannot be verified.
pub async fn verify_retention_from_env() -> Result<usize> {
    let keys = keys_from_env();
    if keys.is_empty() {
        return Ok(0);
    }
    let verifier = RetentionVerifier::new()?;
    for (index, key) in keys.iter().enumerate() {
        let slot = index + 1;
        let outcome = verifier
            .verify_key(key)
            .await
            .with_context(|| format!("verify OpenRouter prompt retention for key slot {slot}"))?;
        tracing::info!(
            slot,
            generation_id = %outcome.generation_id,
            model = outcome.model,
            provider_name = outcome.provider_name.as_deref().unwrap_or("<unreported>"),
            data_region = outcome.data_region.as_deref().unwrap_or("<unreported>"),
            "OpenRouter account retains no prompt content",
        );
    }
    Ok(keys.len())
}

/// Freshness of the last successful proof, on the Azure readiness anchor.
#[derive(Clone)]
pub struct RetentionReadiness {
    verified_at: Option<watch::Receiver<Instant>>,
    window: Duration,
}

impl RetentionReadiness {
    /// True when no key is configured, or the last proof is fresh.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        self.verified_at
            .as_ref()
            .is_none_or(|verified_at| Instant::now() < *verified_at.borrow() + self.window)
    }
}

/// Start re-verifying every configured account on [`VERIFY_INTERVAL`]. The
/// boot gate must have passed first: the stale horizon is anchored to now and
/// the first poll fires one interval later.
#[must_use]
pub fn spawn_periodic_retention_verification(
    verified_keys: usize,
    fatal_shutdown: oneshot::Sender<String>,
) -> (Option<tokio::task::JoinHandle<()>>, RetentionReadiness) {
    if verified_keys == 0 {
        return (
            None,
            RetentionReadiness {
                verified_at: None,
                window: Duration::ZERO,
            },
        );
    }
    let (tx, rx) = watch::channel(Instant::now());
    let readiness = RetentionReadiness {
        verified_at: Some(rx),
        window: STALE_AFTER,
    };
    tracing::info!(
        interval_secs = VERIFY_INTERVAL.as_secs(),
        stale_after_secs = STALE_AFTER.as_secs(),
        keys = verified_keys,
        "starting periodic OpenRouter prompt-retention verification",
    );
    (
        Some(tokio::spawn(run_periodic_retention_verification(
            tx,
            fatal_shutdown,
        ))),
        readiness,
    )
}

fn stale_message() -> String {
    format!(
        "OpenRouter prompt-retention proof is stale: no successful verification for {}s",
        STALE_AFTER.as_secs()
    )
}

async fn run_periodic_retention_verification(
    verified_at: watch::Sender<Instant>,
    fatal_shutdown: oneshot::Sender<String>,
) {
    let verifier = match RetentionVerifier::new() {
        Ok(verifier) => verifier,
        Err(error) => {
            let _ = fatal_shutdown.send(format!(
                "build OpenRouter verification HTTP client: {error:#}"
            ));
            return;
        }
    };
    let mut interval = tokio::time::interval(VERIFY_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;
    // Moved only by a success: failed cycles must not push the horizon out.
    let mut stale_deadline = *verified_at.borrow() + STALE_AFTER;
    let mut transient_failures = 0_u32;

    loop {
        if tokio::time::timeout_at(stale_deadline, interval.tick())
            .await
            .is_err()
        {
            let _ = fatal_shutdown.send(stale_message());
            return;
        }
        let Ok(result) = tokio::time::timeout_at(stale_deadline, verify_all(&verifier)).await
        else {
            let _ = fatal_shutdown.send(stale_message());
            return;
        };
        let error = match result {
            Ok(()) => {
                if transient_failures > 0 {
                    tracing::info!(
                        recovered_after = transient_failures,
                        "OpenRouter prompt-retention verification recovered",
                    );
                    transient_failures = 0;
                }
                let now = Instant::now();
                verified_at.send_replace(now);
                stale_deadline = now + STALE_AFTER;
                continue;
            }
            Err(error) => error,
        };
        if classify(&error) == FailureKind::Definitive {
            let _ = fatal_shutdown.send(format!("{error:#}"));
            return;
        }
        transient_failures += 1;
        if transient_failures >= TRANSIENT_FAILURE_LIMIT {
            let _ = fatal_shutdown.send(format!(
                "{TRANSIENT_FAILURE_LIMIT} consecutive transient failures, last: {error:#}"
            ));
            return;
        }
        tracing::warn!(
            transient_failures,
            limit = TRANSIENT_FAILURE_LIMIT,
            error = %format!("{error:#}"),
            "OpenRouter prompt-retention verification failed transiently",
        );
    }
}

async fn verify_all(verifier: &RetentionVerifier) -> Result<()> {
    for (index, key) in keys_from_env().iter().enumerate() {
        verifier
            .verify_key(key)
            .await
            .with_context(|| format!("OpenRouter key slot {}", index + 1))?;
    }
    Ok(())
}

/// The generation id Envoy hands over for one served `OpenRouter` response.
#[derive(Deserialize)]
pub struct AuditRequest {
    pub id: String,
}

#[derive(Clone, Debug)]
pub struct AuditQueue {
    submissions: mpsc::Sender<String>,
}

impl AuditQueue {
    /// Never blocks: the buyer already has the answer, and a full queue must
    /// not become back-pressure on the data plane.
    #[must_use]
    pub fn submit(&self, id: String) -> bool {
        if self.submissions.try_send(id).is_err() {
            tracing::warn!(
                depth = AUDIT_QUEUE_DEPTH,
                "OpenRouter audit queue is full; a served generation went unread",
            );
            return false;
        }
        true
    }
}

/// Start reading back every served generation; `(None, None)` when no key is
/// configured.
#[must_use]
pub fn spawn_generation_audit(
    verified_keys: usize,
    fatal_shutdown: oneshot::Sender<String>,
) -> (Option<AuditQueue>, Option<tokio::task::JoinHandle<()>>) {
    if verified_keys == 0 {
        return (None, None);
    }
    let (submissions, pending) = mpsc::channel(AUDIT_QUEUE_DEPTH);
    tracing::info!(
        settle_secs = AUDIT_SETTLE.as_secs(),
        blind_limit_secs = AUDIT_BLIND_LIMIT.as_secs(),
        "auditing every served OpenRouter generation",
    );
    (
        Some(AuditQueue { submissions }),
        Some(tokio::spawn(run_generation_audit(pending, fatal_shutdown))),
    )
}

struct PendingAudit {
    id: String,
    due: Instant,
    attempts: u32,
}

enum AuditStep {
    Continue,
    Fatal(String),
}

async fn run_generation_audit(
    mut pending: mpsc::Receiver<String>,
    fatal_shutdown: oneshot::Sender<String>,
) {
    let verifier = match RetentionVerifier::new() {
        Ok(verifier) => verifier,
        Err(error) => {
            let _ = fatal_shutdown.send(format!("build OpenRouter audit HTTP client: {error:#}"));
            return;
        }
    };
    let mut queue = VecDeque::new();
    let mut blind_since = None;
    loop {
        let next_due = queue.front().map(|audit: &PendingAudit| audit.due);
        tokio::select! {
            submitted = pending.recv() => {
                let Some(id) = submitted else { return };
                queue.push_back(PendingAudit {
                    id,
                    due: Instant::now() + AUDIT_SETTLE,
                    attempts: 0,
                });
            }
            () = sleep_until(next_due) => {
                let Some(audit) = queue.pop_front() else { continue };
                let result = verifier.audit_generation(&keys_from_env(), &audit.id).await;
                if let AuditStep::Fatal(reason) =
                    settle_audit(audit, result, &mut queue, &mut blind_since)
                {
                    let _ = fatal_shutdown.send(reason);
                    return;
                }
            }
        }
    }
}

/// `blind_since` opens on the first transient failure after a verdict and
/// closes on the next verdict of any kind: an audit that keeps failing is an
/// audit that is not happening.
fn settle_audit(
    audit: PendingAudit,
    result: Result<AuditVerdict>,
    queue: &mut VecDeque<PendingAudit>,
    blind_since: &mut Option<Instant>,
) -> AuditStep {
    let now = Instant::now();
    match result {
        Ok(AuditVerdict::Stored) => {
            AuditStep::Fatal(retained_message("served generation", &audit.id))
        }
        Ok(AuditVerdict::OperatorKey) => {
            AuditStep::Fatal(operator_key_message("served generation", &audit.id))
        }
        Ok(AuditVerdict::Clean) => {
            *blind_since = None;
            AuditStep::Continue
        }
        Ok(AuditVerdict::NotRecordedYet) => {
            *blind_since = None;
            retry_or_drop(audit, queue, now, "OpenRouter never recorded it")
        }
        Err(error) if classify(&error) == FailureKind::Definitive => {
            AuditStep::Fatal(format!("{error:#}"))
        }
        Err(error) => {
            let blind_for = now.duration_since(*blind_since.get_or_insert(now));
            if blind_for >= AUDIT_BLIND_LIMIT {
                return AuditStep::Fatal(format!(
                    "OpenRouter generation audit read nothing back for {}s; last failure: \
                     {error:#}",
                    blind_for.as_secs()
                ));
            }
            retry_or_drop(audit, queue, now, &format!("{error:#}"))
        }
    }
}

fn retry_or_drop(
    mut audit: PendingAudit,
    queue: &mut VecDeque<PendingAudit>,
    now: Instant,
    reason: &str,
) -> AuditStep {
    audit.attempts += 1;
    if audit.attempts < AUDIT_ATTEMPTS {
        audit.due = now + AUDIT_SETTLE;
        queue.push_back(audit);
    } else {
        tracing::warn!(
            generation_id = %audit.id,
            attempts = audit.attempts,
            reason,
            "OpenRouter generation audit gave up on a served generation",
        );
    }
    AuditStep::Continue
}

/// Wait until `due`, or forever while the queue is empty.
async fn sleep_until(due: Option<Instant>) {
    match due {
        Some(due) => tokio::time::sleep_until(due).await,
        None => std::future::pending().await,
    }
}

fn nonce_hex() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test fixtures intentionally fail hard on malformed local values"
)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const KEY: &str = "sk-or-v1-test";
    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn every_configured_account_is_gated_not_just_the_first() {
        // The env var is read back immediately and cleared before the next
        // assertion; no other test in this crate reads it.
        unsafe { std::env::set_var(KEY_ENV, " sk-a ;sk-b; ") };
        assert_eq!(keys_from_env(), vec!["sk-a".to_owned(), "sk-b".to_owned()]);
        unsafe { std::env::remove_var(KEY_ENV) };
        assert!(keys_from_env().is_empty());
    }

    #[test]
    fn a_nonce_is_long_enough_that_a_readback_match_cannot_be_chance() {
        let first = nonce_hex();
        assert_eq!(first.len(), 32);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(first, nonce_hex());
    }

    #[test]
    fn readiness_is_fresh_without_a_configured_key() {
        let readiness = RetentionReadiness {
            verified_at: None,
            window: Duration::ZERO,
        };
        assert!(readiness.is_fresh());
    }

    #[test]
    fn an_empty_readback_is_not_a_stored_prompt() {
        // A 200 whose input and output are empty says what a 404 says. Reading
        // it as "stored" would take a healthy worker offline.
        for empty in [
            serde_json::json!(null),
            serde_json::json!(""),
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            assert!(!holds_content(Some(&empty)), "{empty}");
        }
        assert!(!holds_content(None));
        assert!(holds_content(Some(&serde_json::json!({"prompt": "hi"}))));
        assert!(holds_content(Some(&serde_json::json!([{"role": "user"}]))));
    }

    /// A refused key is a finding; everything else is a reason to ask again.
    /// An error nothing marked must land on the side that stops serving.
    #[test]
    fn failures_are_classified_by_cause_not_by_message() {
        assert_eq!(
            FailureKind::of_status(StatusCode::UNAUTHORIZED),
            FailureKind::Definitive
        );
        assert_eq!(
            FailureKind::of_status(StatusCode::FORBIDDEN),
            FailureKind::Definitive
        );
        for status in [
            StatusCode::PAYMENT_REQUIRED,
            StatusCode::NOT_FOUND,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
        ] {
            assert_eq!(
                FailureKind::of_status(status),
                FailureKind::Transient,
                "{status}"
            );
        }
        let wrapped = transient("blip".to_owned()).context("outer");
        assert_eq!(classify(&wrapped), FailureKind::Transient);
        let wrapped = definitive("finding".to_owned()).context("outer");
        assert_eq!(classify(&wrapped), FailureKind::Definitive);
        assert_eq!(
            classify(&anyhow::anyhow!("unmarked")),
            FailureKind::Definitive
        );
    }

    async fn stub(server: &MockServer, verb: &str, route: &str, response: ResponseTemplate) {
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(response)
            .mount(server)
            .await;
    }

    fn verifier_for(server: &MockServer) -> RetentionVerifier {
        RetentionVerifier::with_base(reqwest::Client::new(), &server.uri())
    }

    async fn completion_and_record(server: &MockServer) {
        stub(
            server,
            "POST",
            "/chat/completions",
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "gen-1"})),
        )
        .await;
        stub(
            server,
            "GET",
            "/generation",
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"provider_name": "DigitalOcean", "is_byok": false}
            })),
        )
        .await;
    }

    async fn canary_with_content(content: ResponseTemplate) -> Result<CanaryOutcome> {
        let server = MockServer::start().await;
        completion_and_record(&server).await;
        stub(&server, "GET", "/generation/content", content).await;
        verifier_for(&server)
            .verify_key_with_nonce(KEY, NONCE)
            .await
    }

    #[tokio::test]
    async fn a_canary_nobody_stored_passes() {
        let outcome = canary_with_content(ResponseTemplate::new(404))
            .await
            .expect("an unstored canary is the passing case");
        assert_eq!(outcome.generation_id, "gen-1");
        assert_eq!(outcome.model, CANARY_MODELS[0]);
        assert_eq!(outcome.provider_name.as_deref(), Some("DigitalOcean"));
    }

    /// The nonce is read off the raw body: a stored prompt is a finding even
    /// when the envelope around it is not one this module understands.
    #[tokio::test]
    async fn a_canary_that_reads_back_is_a_definitive_finding() {
        for body in [
            format!(r#"{{"data":{{"input":"gm miner retention canary {NONCE}"}}}}"#),
            format!("<html>{NONCE}</html>"),
            r#"{"data":{"output":[{"role":"assistant","content":"x"}]}}"#.to_owned(),
        ] {
            let error = canary_with_content(ResponseTemplate::new(200).set_body_string(&body))
                .await
                .expect_err("stored content must fail the gate");
            assert_eq!(classify(&error), FailureKind::Definitive, "{body}");
            assert!(
                error.to_string().contains("retains prompt content"),
                "{error:#}"
            );
        }
    }

    /// The failure this exists to prevent: a 200 nobody can read is not a
    /// clean readback, it is an unknown one.
    #[tokio::test]
    async fn an_unreadable_readback_is_a_transient_failure_not_a_pass() {
        let error = canary_with_content(ResponseTemplate::new(200).set_body_string("not json"))
            .await
            .expect_err("an undecodable readback must not pass");
        assert_eq!(classify(&error), FailureKind::Transient);
        assert!(
            error.to_string().contains("could not be decoded"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn a_throttled_readback_is_transient_and_a_refused_key_is_definitive() {
        let error = canary_with_content(ResponseTemplate::new(429))
            .await
            .expect_err("a throttled readback is not a pass");
        assert_eq!(classify(&error), FailureKind::Transient);
        let error = canary_with_content(ResponseTemplate::new(403))
            .await
            .expect_err("a key that cannot read content proves nothing");
        assert_eq!(classify(&error), FailureKind::Definitive);
    }

    /// A BYOK hop is refused before content is even read: the prompt is in
    /// the operator's own provider account whatever `OpenRouter` stored.
    #[tokio::test]
    async fn a_canary_routed_through_the_operators_own_key_is_refused() {
        for record in [
            serde_json::json!({"data": {"is_byok": true}}),
            serde_json::json!({"data": {"provider_responses": [
                {"provider_name": "Makora", "is_byok": false},
                {"provider_name": "OpenAI", "is_byok": true},
            ]}}),
        ] {
            let server = MockServer::start().await;
            stub(
                &server,
                "POST",
                "/chat/completions",
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "gen-1"})),
            )
            .await;
            stub(
                &server,
                "GET",
                "/generation",
                ResponseTemplate::new(200).set_body_json(record.clone()),
            )
            .await;
            stub(
                &server,
                "GET",
                "/generation/content",
                ResponseTemplate::new(404),
            )
            .await;
            let error = verifier_for(&server)
                .verify_key_with_nonce(KEY, NONCE)
                .await
                .expect_err("BYOK must fail the gate");
            assert_eq!(classify(&error), FailureKind::Definitive, "{record}");
            assert!(error.to_string().contains("BYOK"), "{error:#}");
        }
    }

    #[tokio::test]
    async fn the_canary_moves_to_the_next_listed_model_when_one_is_refused() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_partial_json(
                serde_json::json!({"model": CANARY_MODELS[0]}),
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_partial_json(
                serde_json::json!({"model": CANARY_MODELS[1]}),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "gen-2"})),
            )
            .mount(&server)
            .await;
        stub(
            &server,
            "GET",
            "/generation",
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": {}})),
        )
        .await;
        stub(
            &server,
            "GET",
            "/generation/content",
            ResponseTemplate::new(404),
        )
        .await;
        let outcome = verifier_for(&server)
            .verify_key_with_nonce(KEY, NONCE)
            .await
            .expect("the second model must carry the canary");
        assert_eq!(outcome.model, CANARY_MODELS[1]);
        assert_eq!(outcome.generation_id, "gen-2");
    }

    /// A refused key refuses every model alike; trying the rest would only
    /// hide the finding behind three more requests.
    #[tokio::test]
    async fn a_refused_key_does_not_fall_through_the_model_list() {
        let server = MockServer::start().await;
        stub(
            &server,
            "POST",
            "/chat/completions",
            ResponseTemplate::new(401),
        )
        .await;
        let error = verifier_for(&server)
            .verify_key_with_nonce(KEY, NONCE)
            .await
            .expect_err("a refused key cannot prove anything");
        assert_eq!(classify(&error), FailureKind::Definitive);
        let requests = server.received_requests().await.expect("request log");
        assert_eq!(requests.len(), 1, "no fallback after a refused key");
    }

    async fn audit_against(
        metadata: ResponseTemplate,
        content: ResponseTemplate,
    ) -> Result<AuditVerdict> {
        let server = MockServer::start().await;
        stub(&server, "GET", "/generation/content", content).await;
        stub(&server, "GET", "/generation", metadata).await;
        verifier_for(&server)
            .audit_generation(&[KEY.to_owned()], "gen-1")
            .await
    }

    #[tokio::test]
    async fn a_served_generation_with_stored_input_takes_the_worker_down() {
        let verdict = audit_against(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": {}})),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"input": {"messages": [{"role": "user", "content": "buyer prompt"}]}}
            })),
        )
        .await
        .expect("audit must complete");
        assert_eq!(verdict, AuditVerdict::Stored);
    }

    #[tokio::test]
    async fn a_recorded_generation_with_no_content_is_clean() {
        let verdict = audit_against(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": {}})),
            ResponseTemplate::new(404),
        )
        .await
        .expect("audit must complete");
        assert_eq!(verdict, AuditVerdict::Clean);
    }

    /// The failure this ordering exists to prevent: content 404s before the
    /// record is written, exactly as it does when nothing was stored. Reading
    /// that as clean would pass every audit by asking too early.
    #[tokio::test]
    async fn an_unrecorded_generation_is_not_reported_clean() {
        let verdict = audit_against(ResponseTemplate::new(404), ResponseTemplate::new(404))
            .await
            .expect("audit must complete");
        assert_eq!(verdict, AuditVerdict::NotRecordedYet);
    }

    #[tokio::test]
    async fn a_served_generation_routed_through_the_operators_own_key_is_a_verdict() {
        let verdict = audit_against(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"is_byok": true}
            })),
            ResponseTemplate::new(404),
        )
        .await
        .expect("audit must complete");
        assert_eq!(verdict, AuditVerdict::OperatorKey);
    }

    #[tokio::test]
    async fn an_audit_the_broker_refuses_is_classified_for_the_loop() {
        let error = audit_against(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": {}})),
            ResponseTemplate::new(503),
        )
        .await
        .expect_err("a failed readback is not a verdict");
        assert_eq!(classify(&error), FailureKind::Transient);
        let error = audit_against(ResponseTemplate::new(401), ResponseTemplate::new(404))
            .await
            .expect_err("a refused key is not a verdict");
        assert_eq!(classify(&error), FailureKind::Definitive);
    }

    fn pending(id: &str, attempts: u32) -> PendingAudit {
        PendingAudit {
            id: id.to_owned(),
            due: Instant::now(),
            attempts,
        }
    }

    #[tokio::test]
    async fn a_transient_audit_failure_is_retried_then_dropped_with_a_warning() {
        let mut queue = VecDeque::new();
        let mut blind_since = None;
        let step = settle_audit(
            pending("gen-1", 0),
            Err(transient("blip".to_owned())),
            &mut queue,
            &mut blind_since,
        );
        assert!(matches!(step, AuditStep::Continue));
        assert_eq!(queue.len(), 1, "a transient failure is re-queued");
        assert!(blind_since.is_some(), "the blind window opens");

        let step = settle_audit(
            pending("gen-1", AUDIT_ATTEMPTS - 1),
            Err(transient("blip".to_owned())),
            &mut queue,
            &mut blind_since,
        );
        assert!(matches!(step, AuditStep::Continue));
        assert_eq!(queue.len(), 1, "the last attempt is dropped, not re-queued");

        let step = settle_audit(
            pending("gen-2", 0),
            Ok(AuditVerdict::Clean),
            &mut queue,
            &mut blind_since,
        );
        assert!(matches!(step, AuditStep::Continue));
        assert!(blind_since.is_none(), "a verdict closes the blind window");
    }

    #[tokio::test]
    async fn an_audit_blind_for_the_stale_horizon_takes_the_worker_down() {
        tokio::time::pause();
        let mut queue = VecDeque::new();
        let mut blind_since = None;
        let step = settle_audit(
            pending("gen-1", 0),
            Err(transient("blip".to_owned())),
            &mut queue,
            &mut blind_since,
        );
        assert!(matches!(step, AuditStep::Continue));
        tokio::time::advance(AUDIT_BLIND_LIMIT).await;
        let step = settle_audit(
            pending("gen-2", 0),
            Err(transient("blip".to_owned())),
            &mut queue,
            &mut blind_since,
        );
        let reason = match step {
            AuditStep::Fatal(reason) => reason,
            AuditStep::Continue => String::new(),
        };
        assert!(
            reason.contains("read nothing back"),
            "an audit blind for the whole horizon must be fatal: {reason:?}"
        );
    }

    #[tokio::test]
    async fn a_definitive_audit_failure_and_every_bad_verdict_are_fatal_at_once() {
        for result in [
            Err(definitive("refused".to_owned())),
            Ok(AuditVerdict::Stored),
            Ok(AuditVerdict::OperatorKey),
        ] {
            let mut queue = VecDeque::new();
            let mut blind_since = None;
            let step = settle_audit(pending("gen-1", 0), result, &mut queue, &mut blind_since);
            assert!(matches!(step, AuditStep::Fatal(_)));
            assert!(queue.is_empty());
        }
    }

    #[tokio::test]
    async fn a_full_audit_queue_sheds_instead_of_blocking_the_data_plane() {
        let (submissions, _pending) = mpsc::channel(1);
        let queue = AuditQueue { submissions };
        assert!(queue.submit("gen-1".to_owned()));
        assert!(!queue.submit("gen-2".to_owned()));
    }

    #[tokio::test]
    async fn readiness_goes_stale_two_intervals_after_the_last_proof() {
        tokio::time::pause();
        let (tx, rx) = watch::channel(Instant::now());
        let readiness = RetentionReadiness {
            verified_at: Some(rx),
            window: STALE_AFTER,
        };
        assert!(readiness.is_fresh());
        tokio::time::advance(STALE_AFTER + Duration::from_secs(1)).await;
        assert!(!readiness.is_fresh());
        let _ = tx.send(Instant::now());
        assert!(readiness.is_fresh());
    }
}
