//! Per-`(credential, chute)` admission and invocation-nonce caches.
//!
//! Chutes serves evidence under a small rate limit shared by every API
//! caller, so an instance is admitted once and reused until its admission
//! expires. While a chute is warm — served within the last [`ADMISSION_TTL`] —
//! a background task renews its admissions [`REFRESH_AHEAD`] before they
//! expire, so a request waits on evidence only when no admission is valid.
//! Each chute has one lock: concurrent requests wait for a single
//! discovery or admission instead of each spending an evidence call. A scope
//! is evicted only while no request holds it, so its lock is never split.
//! Issued nonces are remembered outside the scopes, for their full validity,
//! in a bounded ledger that refuses to issue when full.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use tokio::time::Instant;
use tracing::{error, warn};

use crate::chutes_verify::error::ChutesError;
use crate::chutes_verify::evidence::{DiscoveredInstance, Discovery};

/// Longest an admission is reused before evidence is fetched again.
pub const ADMISSION_TTL: Duration = Duration::from_secs(15 * 60);
/// How long before an admission expires a warm chute renews it: room for a
/// rate-limited attempt and a retry in the next window, with the jitter.
pub const REFRESH_AHEAD: Duration = Duration::from_secs(5 * 60);
// A request gives up waiting for its scope after this, well inside a renewal's headroom.
const SCOPE_WAIT: Duration = Duration::from_secs(REFRESH_AHEAD.as_secs() / 3);
// Spreads renewals of chutes served together across minutes.
const RENEW_JITTER: Duration = Duration::from_secs(60);
// Evidence valid for less than REFRESH_AHEAD would otherwise be renewed back to back.
const MIN_RENEWAL_INTERVAL: Duration = Duration::from_secs(2 * 60);
/// Evidence calls per credential per minute: one cold admission of every
/// target, under Chutes' limit of 60 shared by every caller.
pub const EVIDENCE_PER_MINUTE: usize = crate::chutes_verify::TARGETS.len();
// A chute below Chutes' evidence minimum stays below it until Chutes redeploys it.
const REFUSAL_BACKOFF: Duration = Duration::from_secs(30 * 60);
/// How long an instance that failed admission is skipped.
pub const REJECTION_TTL: Duration = Duration::from_secs(60);
/// Most `(credential, chute)` scopes held; the least recently used goes first.
pub const MAX_SCOPES: usize = 256;
/// Most nonces remembered as issued; beyond it no nonce is issued.
pub const MAX_ISSUED_NONCES: usize = 65_536;
// Chutes' advertised nonce lifetime is shortened so a nonce is never sent as it expires.
const NONCE_MARGIN: Duration = Duration::from_secs(5);
const MAX_ADMISSIONS_PER_REQUEST: usize = 2;
// A second discovery covers nonces that expired while an admission ran.
const MAX_DISCOVERIES_PER_REQUEST: usize = 2;
/// Discoveries per credential per minute. Chutes' nonces live 60s, so every
/// chute in use needs one a minute, plus one per 10 requests per instance.
pub const DISCOVERIES_PER_MINUTE: usize = 30;
const DISCOVERY_WINDOW: Duration = Duration::from_secs(60);
const BACKOFF_START: Duration = Duration::from_secs(5);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
// Chutes counts evidence calls in fixed wall-clock minutes; retry just after the next one opens.
const RATE_WINDOW: Duration = Duration::from_secs(60);
const RATE_WINDOW_SLACK: Duration = Duration::from_secs(1);
const RATE_JITTER: Duration = Duration::from_secs(5);
const MAX_CREDENTIALS: usize = 4_096;

/// Admission outcome for one discovered instance.
#[derive(Debug)]
pub struct Verdict {
    pub instance_id: String,
    pub e2e_pubkey: String,
    /// The instant the admission stops being usable, or why the instance failed.
    pub outcome: Result<Instant, String>,
}

/// The absolute deadline for evidence expiring at `expires_unix`, measured
/// from `anchor`, taken when the wall clock read `anchor_wall` after the Unix
/// epoch and before any evidence was fetched, and capped at [`ADMISSION_TTL`].
/// Sub-second wall time is kept so the deadline never passes the expiry.
#[must_use]
pub fn deadline(anchor: Instant, anchor_wall: Duration, expires_unix: u64) -> Instant {
    anchor
        + Duration::from_secs(expires_unix)
            .saturating_sub(anchor_wall)
            .min(ADMISSION_TTL)
}

/// Time from `wall` (since the Unix epoch) until just after Chutes' next
/// fixed rate-limit window opens.
fn until_next_window(wall: Duration) -> Duration {
    let into_window =
        Duration::from_nanos(u64::try_from(wall.as_nanos() % RATE_WINDOW.as_nanos()).unwrap_or(0));
    RATE_WINDOW.saturating_sub(into_window) + RATE_WINDOW_SLACK
}

// Retrying inside the same rate-limit window is certain to be refused again.
fn backoff_wait(error: &ChutesError, step: Duration, wall: Duration, spread: Duration) -> Duration {
    match error {
        ChutesError::RateLimited { .. } => step.max(until_next_window(wall) + spread),
        ChutesError::BelowEvidenceMinimum => REFUSAL_BACKOFF,
        _ => step,
    }
}

/// The wall clock and the jitter source, which tests replace.
#[derive(Clone)]
struct Clock {
    wall: Arc<dyn Fn() -> Duration + Send + Sync>,
    jitter: Arc<dyn Fn(Duration) -> Duration + Send + Sync>,
}

impl Default for Clock {
    fn default() -> Self {
        Self {
            wall: Arc::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
            }),
            jitter: Arc::new(|max: Duration| {
                use rand::RngExt as _;
                max.mul_f64(rand::rng().random::<f64>())
            }),
        }
    }
}

impl Clock {
    fn backoff_wait(&self, error: &ChutesError, step: Duration) -> Duration {
        backoff_wait(error, step, (self.wall)(), (self.jitter)(RATE_JITTER))
    }
}

/// One encrypted invocation of an admitted instance.
#[derive(Debug)]
pub struct Invocation {
    pub chute_id: &'static str,
    pub ticket: Ticket,
    pub stream: bool,
    pub blob: Vec<u8>,
}

/// An admitted instance key and one unused invocation nonce for it.
#[derive(Clone, PartialEq, Eq)]
pub struct Ticket {
    pub instance_id: String,
    pub e2e_pubkey: String,
    pub nonce: String,
}

impl std::fmt::Debug for Ticket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Ticket")
            .field("instance_id", &self.instance_id)
            .finish_non_exhaustive()
    }
}

/// The Chutes API calls admission and forwarding make.
#[async_trait]
pub trait ChutesApi: Send + Sync + 'static {
    /// `GET /e2e/instances/{chute_id}`.
    async fn discover(&self, api_key: &str, chute_id: &str) -> Result<Discovery, ChutesError>;

    /// Fetch evidence for `chute_id` under a fresh nonce and verify each of
    /// `instances` against it.
    async fn admit(
        &self,
        api_key: &str,
        chute_id: &str,
        instances: &[DiscoveredInstance],
    ) -> Result<Vec<Verdict>, ChutesError>;

    /// `POST /e2e/invoke`.
    async fn invoke(
        &self,
        api_key: &str,
        invocation: Invocation,
    ) -> Result<reqwest::Response, ChutesError>;
}

type InstanceKey = (String, String);
/// A chute under one credential, the credential held only as its SHA-256.
type ChuteScope = ([u8; 32], &'static str);

#[derive(Default)]
struct ChuteState {
    pool: Vec<DiscoveredInstance>,
    /// Last instant a pooled nonce is issued: its validity less a margin.
    issue_until: Option<Instant>,
    /// When the pooled nonces stop being valid at Chutes.
    valid_until: Option<Instant>,
    admitted: HashMap<InstanceKey, Instant>,
    rejected: HashMap<InstanceKey, (Instant, String)>,
    last_served: Option<Instant>,
    /// Counts recorded verdict batches.
    generation: u64,
    /// The batch that last decided each instance, so a renewal's success
    /// never overwrites a verdict recorded after the renewal began.
    decided: HashMap<InstanceKey, u64>,
    /// The generation a running renewal began at.
    renewal_since: Option<u64>,
    last_recorded: Option<Instant>,
    /// The task keeping this warm chute's admissions renewed.
    renewal: Option<tokio::task::AbortHandle>,
}

impl Drop for ChuteState {
    // An evicted scope takes its renewal, and the credential copy it holds, with it.
    fn drop(&mut self) {
        if let Some(renewal) = self.renewal.take() {
            renewal.abort();
        }
    }
}

impl ChuteState {
    fn prune(&mut self, now: Instant) {
        self.admitted.retain(|_, until| *until > now);
        self.rejected.retain(|_, (until, _)| *until > now);
        let (admitted, rejected, since) = (&self.admitted, &self.rejected, self.renewal_since);
        self.decided.retain(|key, at| {
            admitted.contains_key(key)
                || rejected.contains_key(key)
                || since.is_some_and(|since| *at > since)
        });
        if self.issue_until.is_none_or(|until| until <= now) {
            self.pool.clear();
        }
        self.pool.retain(|instance| !instance.nonces.is_empty());
    }

    // Callers prune first, so every admission and nonce seen here is unexpired.
    fn take_ticket(
        &mut self,
        ledger: &Mutex<NonceLedger>,
        chute_id: &'static str,
    ) -> Result<Option<Ticket>, ChutesError> {
        let Some(valid_until) = self.valid_until else {
            return Ok(None);
        };
        let mut ledger = ledger.lock().unwrap_or_else(PoisonError::into_inner);
        ledger.prune(Instant::now());
        for instance in &mut self.pool {
            if !self.admitted.contains_key(&key_of(instance)) {
                continue;
            }
            while let Some(nonce) = instance.nonces.pop() {
                if ledger.record(chute_id, &nonce, valid_until)? {
                    return Ok(Some(Ticket {
                        instance_id: instance.instance_id.clone(),
                        e2e_pubkey: instance.e2e_pubkey.clone(),
                        nonce,
                    }));
                }
            }
        }
        Ok(None)
    }

    fn unjudged(&self) -> Vec<DiscoveredInstance> {
        self.pool
            .iter()
            .filter(|instance| {
                let key = key_of(instance);
                !self.admitted.contains_key(&key) && !self.rejected.contains_key(&key)
            })
            .cloned()
            .collect()
    }

    fn warm(&self, now: Instant) -> bool {
        self.last_served
            .is_some_and(|served| served + ADMISSION_TTL > now)
    }

    /// Admitted instances whose admission ends by `by`, for re-admission.
    fn expiring(&self, by: Instant) -> Vec<DiscoveredInstance> {
        self.admitted
            .iter()
            .filter(|(_, until)| **until <= by)
            .map(|((instance_id, e2e_pubkey), _)| DiscoveredInstance {
                instance_id: instance_id.clone(),
                e2e_pubkey: e2e_pubkey.clone(),
                nonces: Vec::new(),
            })
            .collect()
    }

    /// Record verdicts from evidence fetched at generation `since` (`None`
    /// when no other verdict can have landed meanwhile). A rejection always
    /// applies; a success yields to any later verdict on the same instance.
    fn record(&mut self, verdicts: Vec<Verdict>, now: Instant, since: Option<u64>) {
        self.generation += 1;
        self.last_recorded = Some(now);
        for verdict in verdicts {
            let key = (verdict.instance_id, verdict.e2e_pubkey);
            match verdict.outcome {
                Ok(until) => {
                    let superseded = since
                        .is_some_and(|since| self.decided.get(&key).is_some_and(|at| *at > since));
                    if superseded {
                        continue;
                    }
                    self.admitted.insert(key.clone(), until);
                }
                Err(cause) => {
                    self.admitted.remove(&key);
                    self.rejected
                        .insert(key.clone(), (now + REJECTION_TTL, cause));
                }
            }
            self.decided.insert(key, self.generation);
        }
    }

    // Issuance ends a margin before the lifetime counted from the request;
    // retention runs a margin past the lifetime counted from the response, so
    // it outlasts the validity Chutes advertises from when it made the nonces.
    fn refill(&mut self, discovery: Discovery, asked: Instant, received: Instant) {
        let lifetime = discovery.nonce_lifetime();
        self.issue_until = Some(
            (asked + lifetime)
                .checked_sub(NONCE_MARGIN)
                .unwrap_or(asked),
        );
        self.valid_until = Some(received + lifetime + NONCE_MARGIN);
        self.pool = discovery.instances;
    }

    fn exhausted(&self, chute_id: &str) -> ChutesError {
        if self.rejected.is_empty() {
            return ChutesError::Unavailable(anyhow::anyhow!(
                "no admitted instance of chute {chute_id} has an unused, unexpired nonce"
            ));
        }
        let causes = self
            .rejected
            .iter()
            .map(|((instance_id, _), (_, cause))| format!("{instance_id}: {cause}"))
            .collect::<Vec<_>>()
            .join("; ");
        ChutesError::Rejected(anyhow::anyhow!(
            "no instance of chute {chute_id} passed admission ({causes})"
        ))
    }
}

fn key_of(instance: &DiscoveredInstance) -> InstanceKey {
    (instance.instance_id.clone(), instance.e2e_pubkey.clone())
}

/// Every nonce issued, per chute, until Chutes stops accepting it.
struct NonceLedger {
    issued: HashMap<(&'static str, String), Instant>,
    capacity: usize,
}

impl NonceLedger {
    fn prune(&mut self, now: Instant) {
        self.issued.retain(|_, until| *until > now);
        if self.issued.capacity() > 2 * self.issued.len() + 64 {
            self.issued.shrink_to_fit();
        }
    }

    /// Record `nonce` as issued; `false` when it already was.
    fn record(
        &mut self,
        chute_id: &'static str,
        nonce: &str,
        valid_until: Instant,
    ) -> Result<bool, ChutesError> {
        let key = (chute_id, nonce.to_owned());
        if self.issued.contains_key(&key) {
            return Ok(false);
        }
        if self.issued.len() >= self.capacity {
            return Err(ChutesError::Unavailable(anyhow::anyhow!(
                "{} unexpired nonces already issued; refusing to issue more",
                self.capacity
            )));
        }
        self.issued.insert(key, valid_until);
        Ok(true)
    }
}

/// Per-credential discovery rate, single-flight lock and per-chute backoff.
#[derive(Default)]
struct Budget {
    in_flight: Arc<tokio::sync::Mutex<()>>,
    recent: VecDeque<Instant>,
    evidence: VecDeque<Instant>,
    backoff: HashMap<&'static str, Backoff>,
    /// Backoff for evidence calls alone, from either path; serving a cached
    /// admission never clears it.
    evidence_backoff: HashMap<&'static str, Backoff>,
}

struct Backoff {
    until: Instant,
    step: Duration,
    cause: String,
}

impl Budget {
    fn prune(&mut self, now: Instant) {
        while self
            .recent
            .front()
            .is_some_and(|at| *at + DISCOVERY_WINDOW <= now)
        {
            self.recent.pop_front();
        }
        while self
            .evidence
            .front()
            .is_some_and(|at| *at + DISCOVERY_WINDOW <= now)
        {
            self.evidence.pop_front();
        }
        // A chute's backoff resets once it has gone two maximum steps without failing.
        self.backoff
            .retain(|_, backoff| backoff.until + 2 * BACKOFF_MAX > now);
        self.evidence_backoff
            .retain(|_, backoff| backoff.until + 2 * BACKOFF_MAX > now);
    }

    /// When evidence calls for `chute_id` may resume, while either backoff runs.
    fn evidence_blocked_until(&self, chute_id: &'static str, now: Instant) -> Option<Instant> {
        [&self.backoff, &self.evidence_backoff]
            .into_iter()
            .filter_map(|backoffs| backoffs.get(chute_id))
            .map(|backoff| backoff.until)
            .filter(|until| *until > now)
            .max()
    }

    fn check_backoff(&self, chute_id: &'static str, now: Instant) -> Result<(), ChutesError> {
        match self
            .backoff
            .get(chute_id)
            .filter(|backoff| backoff.until > now)
        {
            Some(backoff) => Err(ChutesError::Unavailable(anyhow::anyhow!(
                "chute {chute_id} is backing off after: {}",
                backoff.cause
            ))),
            None => Ok(()),
        }
    }

    fn check_rate(&self) -> Result<(), ChutesError> {
        if self.recent.len() >= DISCOVERIES_PER_MINUTE {
            return Err(ChutesError::Unavailable(anyhow::anyhow!(
                "discovery budget of {DISCOVERIES_PER_MINUTE} per minute is spent"
            )));
        }
        Ok(())
    }

    fn idle(&self) -> bool {
        self.recent.is_empty()
            && self.evidence.is_empty()
            && self.backoff.is_empty()
            && self.evidence_backoff.is_empty()
            && Arc::strong_count(&self.in_flight) == 1
    }
}

#[derive(Default)]
struct Discoveries {
    budgets: Mutex<HashMap<[u8; 32], Budget>>,
    clock: Clock,
}

impl Discoveries {
    fn with_budget<T>(
        &self,
        credential: [u8; 32],
        use_budget: impl FnOnce(&mut Budget, Instant) -> Result<T, ChutesError>,
    ) -> Result<T, ChutesError> {
        let now = Instant::now();
        let mut budgets = self.budgets.lock().unwrap_or_else(PoisonError::into_inner);
        budgets.retain(|_, budget| {
            budget.prune(now);
            !budget.idle()
        });
        if !budgets.contains_key(&credential) && budgets.len() >= MAX_CREDENTIALS {
            return Err(ChutesError::Unavailable(anyhow::anyhow!(
                "discovery budgets for {MAX_CREDENTIALS} credentials are in use"
            )));
        }
        use_budget(budgets.entry(credential).or_default(), now)
    }

    /// The credential's single-flight discovery lock, after a fail-fast check
    /// of the backoff and the per-minute budget.
    fn claim(
        &self,
        credential: [u8; 32],
        chute_id: &'static str,
    ) -> Result<Arc<tokio::sync::Mutex<()>>, ChutesError> {
        self.with_budget(credential, |budget, now| {
            budget.check_backoff(chute_id, now)?;
            budget.check_rate()?;
            Ok(Arc::clone(&budget.in_flight))
        })
    }

    /// Charge one discovery as it starts, holding the single-flight lock,
    /// rechecking the backoff and the budget at that moment.
    fn charge(&self, credential: [u8; 32], chute_id: &'static str) -> Result<(), ChutesError> {
        self.with_budget(credential, |budget, now| {
            budget.check_backoff(chute_id, now)?;
            budget.check_rate()?;
            budget.recent.push_back(now);
            Ok(())
        })
    }

    /// Charge one evidence call as it starts, within the per-minute cap, unless
    /// `chute_id` backs off; both are checked under the one budget lock.
    fn charge_evidence(
        &self,
        credential: [u8; 32],
        chute_id: &'static str,
    ) -> Result<(), ChutesError> {
        self.with_budget(credential, |budget, now| {
            budget.check_backoff(chute_id, now)?;
            if let Some(backoff) = budget
                .evidence_backoff
                .get(chute_id)
                .filter(|backoff| backoff.until > now)
            {
                return Err(ChutesError::Unavailable(anyhow::anyhow!(
                    "chute {chute_id} is backing off after: {}",
                    backoff.cause
                )));
            }
            if budget.evidence.len() >= EVIDENCE_PER_MINUTE {
                return Err(ChutesError::Unavailable(anyhow::anyhow!(
                    "evidence budget of {EVIDENCE_PER_MINUTE} per minute is spent"
                )));
            }
            budget.evidence.push_back(now);
            Ok(())
        })
    }

    fn failed(&self, credential: [u8; 32], chute_id: &'static str, error: &ChutesError) {
        let mut budgets = self.budgets.lock().unwrap_or_else(PoisonError::into_inner);
        let budget = budgets.entry(credential).or_default();
        let backoff = self.back_off(&budget.backoff, chute_id, error);
        // A rate limit or a refusal holds evidence calls even once a cached admission serves.
        let evidence_refused = match error {
            ChutesError::RateLimited { .. } | ChutesError::BelowEvidenceMinimum => true,
            ChutesError::BadRequest(_)
            | ChutesError::MissingCredential
            | ChutesError::Upstream { .. }
            | ChutesError::Unavailable(_)
            | ChutesError::Rejected(_)
            | ChutesError::BadResponse(_) => false,
        };
        if evidence_refused {
            let evidence = self.back_off(&budget.evidence_backoff, chute_id, error);
            budget.evidence_backoff.insert(chute_id, evidence);
        }
        budget.backoff.insert(chute_id, backoff);
    }

    /// Back off evidence calls for `chute_id` after a renewal failed.
    fn evidence_failed(&self, credential: [u8; 32], chute_id: &'static str, error: &ChutesError) {
        let mut budgets = self.budgets.lock().unwrap_or_else(PoisonError::into_inner);
        let budget = budgets.entry(credential).or_default();
        let backoff = self.back_off(&budget.evidence_backoff, chute_id, error);
        budget.evidence_backoff.insert(chute_id, backoff);
    }

    fn back_off(
        &self,
        current: &HashMap<&'static str, Backoff>,
        chute_id: &'static str,
        error: &ChutesError,
    ) -> Backoff {
        let existing = current.get(chute_id);
        let step = existing.map_or(BACKOFF_START, |backoff| (backoff.step * 2).min(BACKOFF_MAX));
        let until = Instant::now() + self.clock.backoff_wait(error, step);
        // An overlapping failure never shortens a longer backoff already recorded.
        match existing {
            Some(backoff) if backoff.until > until => Backoff {
                until: backoff.until,
                step,
                cause: backoff.cause.clone(),
            },
            Some(_) | None => Backoff {
                until,
                step,
                cause: error.to_string(),
            },
        }
    }

    fn evidence_blocked_until(
        &self,
        credential: [u8; 32],
        chute_id: &'static str,
    ) -> Option<Instant> {
        let now = Instant::now();
        let budgets = self.budgets.lock().unwrap_or_else(PoisonError::into_inner);
        budgets
            .get(&credential)?
            .evidence_blocked_until(chute_id, now)
    }

    fn succeeded(&self, credential: [u8; 32], chute_id: &'static str) {
        let mut budgets = self.budgets.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(budget) = budgets.get_mut(&credential) {
            budget.backoff.remove(chute_id);
        }
    }
}

struct Scope {
    state: Arc<tokio::sync::Mutex<ChuteState>>,
    last_used: Instant,
}

impl Scope {
    // The map holds one reference; any other is a request using the scope.
    fn in_use(&self) -> bool {
        Arc::strong_count(&self.state) > 1
    }
}

/// Admission cache over a [`ChutesApi`].
pub struct Admissions<A> {
    api: Arc<A>,
    scopes: Mutex<HashMap<ChuteScope, Scope>>,
    max_scopes: usize,
    ledger: Arc<Mutex<NonceLedger>>,
    discoveries: Arc<Discoveries>,
}

/// What a request's admission work needs, owned so it can run in its own task.
struct Issuer<A> {
    api: Arc<A>,
    ledger: Arc<Mutex<NonceLedger>>,
    discoveries: Arc<Discoveries>,
}

impl<A: ChutesApi> Issuer<A> {
    async fn issue(
        &self,
        state: &mut ChuteState,
        api_key: &str,
        chute_id: &'static str,
    ) -> Result<Ticket, ChutesError> {
        let credential = scope_of(api_key, chute_id).0;
        let mut discoveries = 0;
        let mut admissions = 0;
        loop {
            state.prune(Instant::now());
            if let Some(ticket) = state.take_ticket(&self.ledger, chute_id)? {
                self.discoveries.succeeded(credential, chute_id);
                return Ok(ticket);
            }
            let unjudged = state.unjudged();
            // Rediscovering in the same request helps only when the pool is used up.
            let may_discover = discoveries == 0 || state.pool.is_empty();
            if !unjudged.is_empty() && admissions < MAX_ADMISSIONS_PER_REQUEST {
                admissions += 1;
                self.discoveries.charge_evidence(credential, chute_id)?;
                let verdicts = self
                    .api
                    .admit(api_key, chute_id, &unjudged)
                    .await
                    .inspect_err(|error| {
                        self.discoveries.failed(credential, chute_id, error);
                    })?;
                state.record(verdicts, Instant::now(), None);
            } else if may_discover && discoveries < MAX_DISCOVERIES_PER_REQUEST {
                discoveries += 1;
                let in_flight = self.discoveries.claim(credential, chute_id)?;
                let _single_flight = in_flight.lock().await;
                self.discoveries.charge(credential, chute_id)?;
                let asked = Instant::now();
                let discovery =
                    self.api
                        .discover(api_key, chute_id)
                        .await
                        .inspect_err(|error| {
                            self.discoveries.failed(credential, chute_id, error);
                        })?;
                state.refill(discovery, asked, Instant::now());
            } else {
                let error = state.exhausted(chute_id);
                if discoveries + admissions > 0 {
                    self.discoveries.failed(credential, chute_id, &error);
                }
                return Err(error);
            }
        }
    }
}

impl<A: ChutesApi> Admissions<A> {
    pub fn new(api: Arc<A>) -> Self {
        Self::with_limits(api, MAX_SCOPES, MAX_ISSUED_NONCES)
    }

    fn with_limits(api: Arc<A>, max_scopes: usize, max_nonces: usize) -> Self {
        Self {
            api,
            scopes: Mutex::new(HashMap::new()),
            max_scopes,
            ledger: Arc::new(Mutex::new(NonceLedger {
                issued: HashMap::new(),
                capacity: max_nonces,
            })),
            discoveries: Arc::default(),
        }
    }

    /// An admitted instance and an unused nonce for `chute_id` under
    /// `api_key`, discovering and admitting only when the cache has none.
    /// Admission and nonce deadlines are rechecked immediately before the
    /// ticket is issued.
    ///
    /// # Errors
    ///
    /// Returns the discovery or admission error, or [`ChutesError::Rejected`]
    /// with every instance's cause when none passed. Admissions already cached
    /// keep serving while evidence is unavailable. A scope left with no
    /// admission after an error is dropped, so failing credentials are not
    /// kept. Fails closed when every scope is in use or the nonce ledger is full,
    /// or after waiting [`SCOPE_WAIT`] for the scope, which takes no backoff.
    pub async fn ticket(
        &self,
        api_key: &str,
        chute_id: &'static str,
    ) -> Result<Ticket, ChutesError> {
        let scope = scope_of(api_key, chute_id);
        let cell = self.scope(scope)?;
        // Held across issue() so concurrent requests share one evidence call per scope.
        let Ok(mut state) = tokio::time::timeout(SCOPE_WAIT, Arc::clone(&cell).lock_owned()).await
        else {
            return Err(ChutesError::Unavailable(anyhow::anyhow!(
                "waited {SCOPE_WAIT:?} for chute {chute_id} without starting admission"
            )));
        };
        let issuer = Issuer {
            api: Arc::clone(&self.api),
            ledger: Arc::clone(&self.ledger),
            discoveries: Arc::clone(&self.discoveries),
        };
        let key = api_key.to_owned();
        // Its own task, so a caller that goes away cannot drop verdicts or backoffs mid-batch.
        let admission = tokio::spawn(async move {
            let result = issuer.issue(&mut state, &key, chute_id).await;
            (state, result)
        });
        let (mut state, result) = match admission.await {
            Ok(done) => done,
            Err(failure) => {
                error!(chute = chute_id, cause = %failure, "Chutes admission task failed");
                // Verdicts the task verified are lost, so nothing cached may outlive it.
                self.invalidate(scope, &cell).await;
                return Err(ChutesError::Unavailable(anyhow::anyhow!(
                    "admission for chute {chute_id} failed: {failure}"
                )));
            }
        };
        match &result {
            Ok(_) => {
                state.last_served = Some(Instant::now());
                self.keep_warm(&mut state, &cell, api_key, chute_id);
            }
            // Rejections are kept so the instance is not re-fetched while its verdict stands.
            Err(_) if state.admitted.is_empty() && state.rejected.is_empty() => {
                // The owned guard holds its own reference to the scope.
                drop(state);
                self.forget(scope, &cell);
            }
            Err(_) => {}
        }
        result
    }

    fn keep_warm(
        &self,
        state: &mut ChuteState,
        cell: &Arc<tokio::sync::Mutex<ChuteState>>,
        api_key: &str,
        chute_id: &'static str,
    ) {
        if state.renewal.is_some() || state.admitted.is_empty() {
            return;
        }
        let renewal = tokio::spawn(renew_while_warm(
            Arc::clone(&self.api),
            Arc::clone(&self.discoveries),
            Arc::downgrade(cell),
            api_key.to_owned(),
            chute_id,
        ));
        state.renewal = Some(renewal.abort_handle());
    }

    fn scope(&self, scope: ChuteScope) -> Result<Arc<tokio::sync::Mutex<ChuteState>>, ChutesError> {
        let now = Instant::now();
        let mut scopes = self.scopes.lock().unwrap_or_else(PoisonError::into_inner);
        scopes.retain(|_, held| held.in_use() || held.last_used + ADMISSION_TTL > now);
        if !scopes.contains_key(&scope) && scopes.len() >= self.max_scopes {
            let idle = scopes
                .iter()
                .filter(|(_, held)| !held.in_use())
                .min_by_key(|(_, held)| held.last_used)
                .map(|(key, _)| *key)
                .ok_or_else(|| {
                    ChutesError::Unavailable(anyhow::anyhow!(
                        "all {} admission scopes are in use",
                        self.max_scopes
                    ))
                })?;
            scopes.remove(&idle);
        }
        let held = scopes.entry(scope).or_insert_with(|| Scope {
            state: Arc::default(),
            last_used: now,
        });
        held.last_used = now;
        Ok(Arc::clone(&held.state))
    }

    async fn invalidate(&self, scope: ChuteScope, cell: &Arc<tokio::sync::Mutex<ChuteState>>) {
        let mut state = cell.lock().await;
        if let Some(renewal) = state.renewal.take() {
            renewal.abort();
        }
        *state = ChuteState::default();
        drop(state);
        self.forget(scope, cell);
    }

    fn forget(&self, scope: ChuteScope, cell: &Arc<tokio::sync::Mutex<ChuteState>>) {
        let mut scopes = self.scopes.lock().unwrap_or_else(PoisonError::into_inner);
        // Only the map and this request hold it: no other request is waiting.
        if Arc::strong_count(cell) == 2
            && scopes
                .get(&scope)
                .is_some_and(|held| Arc::ptr_eq(&held.state, cell))
        {
            scopes.remove(&scope);
        }
    }

    #[cfg(test)]
    fn scope_count(&self) -> usize {
        self.scopes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    #[cfg(test)]
    fn backoff_step(&self, api_key: &str, chute_id: &'static str) -> Option<Duration> {
        let credential = scope_of(api_key, chute_id).0;
        let budgets = self
            .discoveries
            .budgets
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Some(budgets.get(&credential)?.backoff.get(chute_id)?.step)
    }

    #[cfg(test)]
    fn holds(&self, api_key: &str, chute_id: &'static str) -> bool {
        self.scopes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&scope_of(api_key, chute_id))
    }
}

/// Renew a chute's admissions [`REFRESH_AHEAD`] (less jitter) before the
/// earliest expires, for as long as the chute stays warm and its scope held.
/// Every attempt waits for [`MIN_RENEWAL_INTERVAL`] after the latest verdicts
/// and for any evidence backoff, both rechecked under the scope lock right
/// before evidence is fetched. A failure backs off evidence calls on both paths,
/// before the scope is locked again, while the current admissions keep serving.
/// Renewal is best effort: an admission that expires first stops serving until
/// a later renewal or request records a verdict.
async fn renew_while_warm<A: ChutesApi>(
    api: Arc<A>,
    discoveries: Arc<Discoveries>,
    // Weak, so the renewal never keeps a scope from eviction.
    cell: std::sync::Weak<tokio::sync::Mutex<ChuteState>>,
    api_key: String,
    chute_id: &'static str,
) {
    let credential = scope_of(&api_key, chute_id).0;
    let mut planned = None;
    loop {
        let Some(held) = cell.upgrade() else { return };
        let mut state = held.lock().await;
        let now = Instant::now();
        state.prune(now);
        let Some(earliest) = state.admitted.values().min().copied() else {
            state.renewal = None;
            return;
        };
        if !state.warm(now) {
            state.renewal = None;
            return;
        }
        let target = *planned.get_or_insert_with(|| {
            earliest
                .checked_sub(REFRESH_AHEAD + (discoveries.clock.jitter)(RENEW_JITTER))
                .unwrap_or(earliest)
        });
        let wake = [
            Some(target),
            state.last_recorded.map(|at| at + MIN_RENEWAL_INTERVAL),
            discoveries.evidence_blocked_until(credential, chute_id),
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(target);
        if wake > now {
            drop(state);
            drop(held);
            tokio::time::sleep_until(wake).await;
            continue;
        }
        planned = None;
        if let Err(error) = discoveries.charge_evidence(credential, chute_id) {
            discoveries.evidence_failed(credential, chute_id, &error);
            continue;
        }
        let due = state.expiring(now + REFRESH_AHEAD + RENEW_JITTER);
        let since = state.generation;
        state.renewal_since = Some(since);
        drop(state);
        drop(held);
        let verdicts = api.admit(&api_key, chute_id, &due).await;
        if let Err(error) = &verdicts {
            warn!(
                chute = chute_id,
                cause = %error,
                "Chutes admission renewal failed; the current admission keeps serving"
            );
            discoveries.evidence_failed(credential, chute_id, error);
        }
        let Some(held) = cell.upgrade() else { return };
        let mut state = held.lock().await;
        state.renewal_since = None;
        if let Ok(verdicts) = verdicts {
            state.record(verdicts, Instant::now(), Some(since));
        }
    }
}

fn scope_of(api_key: &str, chute_id: &'static str) -> ChuteScope {
    (Sha256::digest(api_key.as_bytes()).into(), chute_id)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test fixtures fail the test")]
pub(crate) mod tests {
    use super::*;
    use crate::chutes_verify::crypto::tests::Instance;
    use axum::http::StatusCode;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(crate) const CHUTE: &str = "08901219-159f-55a7-87cf-9d0d02744668";

    pub(crate) type Answer =
        Box<dyn Fn(&[u8]) -> axum::http::Response<reqwest::Body> + Send + Sync>;

    /// A scripted Chutes API counting the calls admission makes.
    pub(crate) struct FakeApi {
        pub(crate) instances: Mutex<Vec<(String, String)>>,
        pub(crate) nonces_per_instance: usize,
        pub(crate) evidence: Mutex<Result<(), StatusCode>>,
        pub(crate) rejected: Mutex<Vec<String>>,
        pub(crate) discoveries: AtomicUsize,
        pub(crate) admissions: AtomicUsize,
        pub(crate) admit_delay: Duration,
        pub(crate) valid_for: Duration,
        pub(crate) repeat_nonces: bool,
        pub(crate) failing_key: Option<&'static str>,
        pub(crate) slow_key: Option<&'static str>,
        pub(crate) discover_delay: Duration,
        pub(crate) chute_discover_delay: HashMap<&'static str, Duration>,
        pub(crate) discovery_starts: Mutex<Vec<Instant>>,
        pub(crate) admission_starts: Mutex<Vec<Instant>>,
        /// Per-call admission delays, used in order before `admit_delay`.
        pub(crate) admit_delays: Mutex<VecDeque<Duration>>,
        pub(crate) answer: Mutex<Option<Answer>>,
        pub(crate) invoked: Mutex<Vec<Invocation>>,
    }

    impl FakeApi {
        pub(crate) fn new(instances: usize) -> Self {
            let instances = (0..instances)
                .map(|index| (format!("instance-{index}"), Instance::new().public_b64))
                .collect();
            Self {
                instances: Mutex::new(instances),
                nonces_per_instance: 2,
                evidence: Mutex::new(Ok(())),
                rejected: Mutex::new(Vec::new()),
                discoveries: AtomicUsize::new(0),
                admissions: AtomicUsize::new(0),
                admit_delay: Duration::ZERO,
                valid_for: ADMISSION_TTL,
                repeat_nonces: false,
                failing_key: None,
                slow_key: None,
                discover_delay: Duration::ZERO,
                chute_discover_delay: HashMap::new(),
                discovery_starts: Mutex::new(Vec::new()),
                admission_starts: Mutex::new(Vec::new()),
                admit_delays: Mutex::new(VecDeque::new()),
                answer: Mutex::new(None),
                invoked: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ChutesApi for FakeApi {
        async fn discover(&self, api_key: &str, chute_id: &str) -> Result<Discovery, ChutesError> {
            if self.failing_key == Some(api_key) {
                return Err(ChutesError::Upstream {
                    stage: "discovery",
                    status: StatusCode::UNAUTHORIZED,
                });
            }
            let round = self.discoveries.fetch_add(1, Ordering::SeqCst);
            self.discovery_starts.lock().unwrap().push(Instant::now());
            let delay = self
                .chute_discover_delay
                .get(chute_id)
                .copied()
                .unwrap_or(self.discover_delay);
            tokio::time::sleep(delay).await;
            let round = if self.repeat_nonces { 0 } else { round };
            let instances = self
                .instances
                .lock()
                .unwrap()
                .iter()
                .map(|(instance_id, e2e_pubkey)| DiscoveredInstance {
                    instance_id: instance_id.clone(),
                    e2e_pubkey: e2e_pubkey.clone(),
                    nonces: (0..self.nonces_per_instance)
                        .map(|index| format!("{instance_id}-r{round}-n{index}"))
                        .collect(),
                })
                .collect();
            Ok(Discovery {
                instances,
                nonce_expires_in: 60,
            })
        }

        async fn admit(
            &self,
            api_key: &str,
            _: &str,
            instances: &[DiscoveredInstance],
        ) -> Result<Vec<Verdict>, ChutesError> {
            self.admissions.fetch_add(1, Ordering::SeqCst);
            let anchor = Instant::now();
            self.admission_starts.lock().unwrap().push(anchor);
            // Verdicts reflect the instance as it was when its evidence was fetched.
            let rejected = self.rejected.lock().unwrap().clone();
            let queued = self.admit_delays.lock().unwrap().pop_front();
            if let Some(delay) = queued {
                tokio::time::sleep(delay).await;
            } else if self.slow_key.is_none_or(|slow| slow == api_key) {
                tokio::time::sleep(self.admit_delay).await;
            }
            if let Err(status) = *self.evidence.lock().unwrap() {
                if status == StatusCode::TOO_MANY_REQUESTS {
                    return Err(ChutesError::RateLimited { stage: "evidence" });
                }
                if status == StatusCode::BAD_REQUEST {
                    return Err(ChutesError::BelowEvidenceMinimum);
                }
                return Err(ChutesError::Unavailable(anyhow::anyhow!(
                    "Chutes evidence answered {status}"
                )));
            }
            Ok(instances
                .iter()
                .map(|instance| Verdict {
                    instance_id: instance.instance_id.clone(),
                    e2e_pubkey: instance.e2e_pubkey.clone(),
                    outcome: if rejected.contains(&instance.instance_id) {
                        Err("MRTD is not in the published Chutes references".to_owned())
                    } else {
                        Ok(anchor + self.valid_for)
                    },
                })
                .collect())
        }

        async fn invoke(
            &self,
            _: &str,
            invocation: Invocation,
        ) -> Result<reqwest::Response, ChutesError> {
            let response = (self.answer.lock().unwrap().as_ref().unwrap())(&invocation.blob);
            self.invoked.lock().unwrap().push(invocation);
            Ok(reqwest::Response::from(response))
        }
    }

    fn many_chutes(count: usize) -> Vec<&'static str> {
        (0..count)
            .map(|index| &*Box::leak(format!("chute-{index}").into_boxed_str()))
            .collect()
    }

    /// A wall clock stopped `into_window` into a rate-limit window, and jitter
    /// taking each value of `jitters` in turn, then none.
    fn fixed_clock(into_window: Duration, jitters: Vec<f64>) -> Clock {
        let jitters = Mutex::new(VecDeque::from(jitters));
        Clock {
            wall: Arc::new(move || Duration::from_secs(1_800_000) + into_window),
            jitter: Arc::new(move |max: Duration| {
                max.mul_f64(jitters.lock().unwrap().pop_front().unwrap_or(0.0))
            }),
        }
    }

    fn cache_with_clock(api: FakeApi, clock: Clock) -> (Arc<FakeApi>, Admissions<FakeApi>) {
        let api = Arc::new(api);
        let mut admissions = Admissions::new(Arc::clone(&api));
        admissions.discoveries = Arc::new(Discoveries {
            clock,
            ..Discoveries::default()
        });
        (api, admissions)
    }

    fn cache(api: FakeApi) -> (Arc<FakeApi>, Admissions<FakeApi>) {
        let api = Arc::new(api);
        (Arc::clone(&api), Admissions::new(api))
    }

    fn cache_with(
        api: FakeApi,
        scopes: usize,
        nonces: usize,
    ) -> (Arc<FakeApi>, Admissions<FakeApi>) {
        let api = Arc::new(api);
        (
            Arc::clone(&api),
            Admissions::with_limits(api, scopes, nonces),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn one_admission_serves_every_nonce_until_it_expires() {
        let (api, admissions) = cache(FakeApi::new(1));
        let mut nonces = Vec::new();
        for _ in 0..6 {
            nonces.push(admissions.ticket("key", CHUTE).await.unwrap().nonce);
            tokio::time::advance(Duration::from_secs(30)).await;
        }
        nonces.sort();
        nonces.dedup();
        assert_eq!(nonces.len(), 6, "a nonce was handed out twice");
        assert_eq!(api.admissions.load(Ordering::SeqCst), 1);
        assert!(api.discoveries.load(Ordering::SeqCst) >= 3);

        tokio::time::advance(ADMISSION_TTL).await;
        admissions.ticket("key", CHUTE).await.unwrap();
        assert_eq!(api.admissions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_requests_share_one_admission() {
        let mut api = FakeApi::new(2);
        api.nonces_per_instance = 5;
        api.admit_delay = Duration::from_secs(3);
        let (api, admissions) = cache(api);
        let admissions = Arc::new(admissions);
        let tasks = (0..8)
            .map(|_| {
                let admissions = Arc::clone(&admissions);
                tokio::spawn(async move { admissions.ticket("key", CHUTE).await })
            })
            .collect::<Vec<_>>();
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(api.admissions.load(Ordering::SeqCst), 1);
        assert_eq!(api.discoveries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn credentials_do_not_share_admissions() {
        let (api, admissions) = cache(FakeApi::new(1));
        admissions.ticket("key-a", CHUTE).await.unwrap();
        admissions.ticket("key-b", CHUTE).await.unwrap();
        assert_eq!(api.admissions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn evidence_rate_limit_serves_the_cache_until_expiry_then_fails_closed() {
        let (api, admissions) = cache(FakeApi::new(1));
        admissions.ticket("key", CHUTE).await.unwrap();
        *api.evidence.lock().unwrap() = Err(StatusCode::TOO_MANY_REQUESTS);
        for _ in 0..4 {
            tokio::time::advance(Duration::from_secs(120)).await;
            admissions.ticket("key", CHUTE).await.unwrap();
        }
        tokio::time::advance(ADMISSION_TTL).await;
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(error.to_string().contains("429"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn rejected_instances_are_skipped_and_their_cause_reported() {
        let api = FakeApi::new(2);
        api.rejected.lock().unwrap().push("instance-0".to_owned());
        let (api, admissions) = cache(api);
        for _ in 0..2 {
            let ticket = admissions.ticket("key", CHUTE).await.unwrap();
            assert_eq!(ticket.instance_id, "instance-1");
        }
        api.rejected.lock().unwrap().push("instance-1".to_owned());
        tokio::time::advance(ADMISSION_TTL).await;
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
        assert!(error.to_string().contains("MRTD"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_rotated_instance_key_is_admitted_afresh() {
        let (api, admissions) = cache(FakeApi::new(1));
        admissions.ticket("key", CHUTE).await.unwrap();
        api.instances.lock().unwrap()[0].1 = Instance::new().public_b64;
        tokio::time::advance(Duration::from_secs(120)).await;
        let ticket = admissions.ticket("key", CHUTE).await.unwrap();
        assert_eq!(ticket.e2e_pubkey, api.instances.lock().unwrap()[0].1);
        assert_eq!(api.admissions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_verdict_expiring_during_a_slow_batch_issues_no_ticket() {
        let mut api = FakeApi::new(1);
        api.valid_for = Duration::from_secs(5 * 60);
        api.admit_delay = Duration::from_secs(10 * 60);
        let (_, admissions) = cache(api);
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(error.to_string().contains("unexpired"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_batch_does_not_extend_an_admission() {
        let mut api = FakeApi::new(1);
        api.valid_for = Duration::from_secs(12 * 60);
        api.admit_delay = Duration::from_secs(10 * 60);
        let (api, admissions) = cache(api);
        admissions.ticket("key", CHUTE).await.unwrap();
        settle().await;
        // The first ticket also starts a renewal, which is still running.
        let before = api.admissions.load(Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(3 * 60)).await;
        admissions.ticket("key", CHUTE).await.unwrap();
        assert_eq!(
            api.admissions.load(Ordering::SeqCst),
            before + 1,
            "admission outlived its evidence"
        );
    }

    async fn settle() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    // Past the latest instant a warm chute's first renewal can start.
    const FIRST_RENEWAL: Duration = Duration::from_secs(10 * 60);

    #[tokio::test(start_paused = true)]
    async fn a_warm_chute_is_renewed_before_expiry_without_a_request_waiting() {
        let (api, admissions) = cache(FakeApi::new(1));
        admissions.ticket("key", CHUTE).await.unwrap();
        tokio::time::advance(Duration::from_secs(5 * 60)).await;
        admissions.ticket("key", CHUTE).await.unwrap();
        tokio::time::advance(Duration::from_secs(5 * 60)).await;
        settle().await;
        assert_eq!(api.admissions.load(Ordering::SeqCst), 2, "no renewal ran");

        *api.evidence.lock().unwrap() = Err(StatusCode::TOO_MANY_REQUESTS);
        tokio::time::advance(Duration::from_secs(5 * 60 + 1)).await;
        admissions.ticket("key", CHUTE).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_rate_limited_renewal_keeps_serving_and_retries_as_the_next_window_opens() {
        let mut api = FakeApi::new(1);
        api.nonces_per_instance = 10;
        let clock = fixed_clock(Duration::from_millis(500), Vec::new());
        let (api, admissions) = cache_with_clock(api, clock);
        admissions.ticket("key", CHUTE).await.unwrap();
        *api.evidence.lock().unwrap() = Err(StatusCode::TOO_MANY_REQUESTS);
        tokio::time::advance(FIRST_RENEWAL).await;
        settle().await;
        for _ in 0..5 {
            admissions.ticket("key", CHUTE).await.unwrap();
            settle().await;
        }
        assert_eq!(api.admissions.load(Ordering::SeqCst), 2);

        *api.evidence.lock().unwrap() = Ok(());
        tokio::time::advance(Duration::from_secs(60)).await;
        settle().await;
        assert_eq!(
            api.admissions.load(Ordering::SeqCst),
            2,
            "retried inside the window"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(api.admissions.load(Ordering::SeqCst), 3);
        tokio::time::advance(ADMISSION_TTL.saturating_sub(FIRST_RENEWAL)).await;
        admissions.ticket("key", CHUTE).await.unwrap();
        assert_eq!(api.admissions.load(Ordering::SeqCst), 3, "renewal was lost");
    }

    #[tokio::test(start_paused = true)]
    async fn renewals_of_chutes_served_together_are_spread_by_their_jitter() {
        let mut api = FakeApi::new(1);
        api.nonces_per_instance = 1;
        let jitters = vec![0.0, 0.2, 0.4, 0.6, 0.8, 1.0];
        let chutes = jitters.len();
        let (api, admissions) = cache_with_clock(api, fixed_clock(Duration::ZERO, jitters));
        for target in &crate::chutes_verify::TARGETS[..chutes] {
            admissions.ticket("key", target.chute_id).await.unwrap();
        }
        let served = Instant::now();
        for _ in 0..FIRST_RENEWAL.as_secs() {
            tokio::time::advance(Duration::from_secs(1)).await;
            settle().await;
        }
        let mut renewals = api
            .admission_starts
            .lock()
            .unwrap()
            .iter()
            .filter(|start| **start > served)
            .map(|start| (*start - served).as_secs())
            .collect::<Vec<_>>();
        renewals.sort_unstable();
        assert_eq!(renewals, [540, 552, 564, 576, 588, 600]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stale_renewal_never_overturns_a_newer_rejection() {
        let api = FakeApi::new(1);
        api.admit_delays
            .lock()
            .unwrap()
            .extend([Duration::ZERO, Duration::from_secs(7 * 60)]);
        let (api, admissions) = cache_with_clock(api, fixed_clock(Duration::ZERO, Vec::new()));
        admissions.ticket("key", CHUTE).await.unwrap();
        // A request midway keeps the scope, and the renewal it owns, past the first admission.
        tokio::time::advance(Duration::from_secs(5 * 60)).await;
        admissions.ticket("key", CHUTE).await.unwrap();
        tokio::time::advance(FIRST_RENEWAL.saturating_sub(Duration::from_secs(5 * 60))).await;
        settle().await;
        assert_eq!(
            api.admissions.load(Ordering::SeqCst),
            2,
            "no renewal started"
        );

        api.rejected.lock().unwrap().push("instance-0".to_owned());
        tokio::time::advance(REFRESH_AHEAD + Duration::from_secs(1)).await;
        admissions.ticket("key", CHUTE).await.unwrap_err();
        tokio::time::advance(Duration::from_secs(3 * 60)).await;
        settle().await;
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert!(error.to_string().contains("MRTD"), "{error:#}");
    }

    #[tokio::test(start_paused = true)]
    async fn short_lived_evidence_is_not_renewed_back_to_back() {
        let mut api = FakeApi::new(1);
        api.valid_for = Duration::from_secs(3 * 60);
        let (api, admissions) = cache_with_clock(api, fixed_clock(Duration::ZERO, Vec::new()));
        admissions.ticket("key", CHUTE).await.unwrap();
        for _ in 0..60 {
            tokio::time::advance(Duration::from_secs(10)).await;
            settle().await;
        }
        assert_eq!(api.admissions.load(Ordering::SeqCst), 6);
    }

    #[tokio::test(start_paused = true)]
    async fn a_renewal_refused_below_the_evidence_minimum_waits_out_the_refusal() {
        let (api, admissions) =
            cache_with_clock(FakeApi::new(1), fixed_clock(Duration::ZERO, Vec::new()));
        admissions.ticket("key", CHUTE).await.unwrap();
        *api.evidence.lock().unwrap() = Err(StatusCode::BAD_REQUEST);
        tokio::time::advance(FIRST_RENEWAL).await;
        settle().await;
        for _ in 0..4 {
            tokio::time::advance(Duration::from_secs(60)).await;
            settle().await;
            admissions.ticket("key", CHUTE).await.unwrap();
        }
        assert_eq!(api.admissions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_renewal_waits_out_the_request_path_backoff() {
        let (api, admissions) =
            cache_with_clock(FakeApi::new(1), fixed_clock(Duration::ZERO, Vec::new()));
        admissions.ticket("key", CHUTE).await.unwrap();
        tokio::time::advance(Duration::from_secs(9 * 60)).await;
        admissions.discoveries.failed(
            scope_of("key", CHUTE).0,
            CHUTE,
            &ChutesError::BelowEvidenceMinimum,
        );
        tokio::time::advance(Duration::from_secs(5 * 60)).await;
        settle().await;
        assert_eq!(api.admissions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_later_transient_failure_does_not_shorten_an_evidence_refusal() {
        let mut api = FakeApi::new(1);
        api.nonces_per_instance = 4;
        let (api, admissions) = cache_with_clock(api, fixed_clock(Duration::ZERO, Vec::new()));
        admissions.ticket("key", CHUTE).await.unwrap();
        let credential = scope_of("key", CHUTE).0;
        admissions
            .discoveries
            .failed(credential, CHUTE, &ChutesError::BelowEvidenceMinimum);
        admissions.ticket("key", CHUTE).await.unwrap();
        admissions.discoveries.evidence_failed(
            credential,
            CHUTE,
            &ChutesError::Unavailable(anyhow::anyhow!("overlapping renewal failed")),
        );
        tokio::time::advance(Duration::from_secs(20 * 60)).await;
        settle().await;
        assert_eq!(api.admissions.load(Ordering::SeqCst), 1, "renewed early");
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert!(error.to_string().contains("backing off"), "{error}");
        assert_eq!(api.admissions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn an_evidence_refusal_keeps_its_deadline_and_cause_through_later_failures() {
        let (_, admissions) =
            cache_with_clock(FakeApi::new(1), fixed_clock(Duration::ZERO, Vec::new()));
        let credential = scope_of("key", CHUTE).0;
        let discoveries = &admissions.discoveries;
        let refused_at = Instant::now();
        discoveries.failed(credential, CHUTE, &ChutesError::BelowEvidenceMinimum);
        for _ in 0..6 {
            discoveries.evidence_failed(
                credential,
                CHUTE,
                &ChutesError::Unavailable(anyhow::anyhow!("overlapping renewal failed")),
            );
        }
        let (step, cause) = {
            let budgets = discoveries.budgets.lock().unwrap();
            let backoff = &budgets[&credential].evidence_backoff[CHUTE];
            (backoff.step, backoff.cause.clone())
        };
        assert_eq!(step, BACKOFF_MAX);
        assert!(cause.contains("evidence minimum"), "{cause}");
        let resumes = refused_at + REFUSAL_BACKOFF;
        assert_eq!(
            discoveries.evidence_blocked_until(credential, CHUTE),
            Some(resumes)
        );
        tokio::time::sleep_until(resumes - Duration::from_millis(1)).await;
        assert!(discoveries.charge_evidence(credential, CHUTE).is_err());
        tokio::time::sleep_until(resumes).await;
        discoveries.charge_evidence(credential, CHUTE).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn requests_queued_ahead_of_a_renewal_let_it_record_before_expiry() {
        let mut api = FakeApi::new(1);
        api.nonces_per_instance = 1;
        api.discover_delay = Duration::from_secs(29);
        let (api, admissions) = cache_with_clock(api, fixed_clock(Duration::ZERO, Vec::new()));
        let admissions = Arc::new(admissions);
        admissions.ticket("key", CHUTE).await.unwrap();
        let expires = api.admission_starts.lock().unwrap()[0] + ADMISSION_TTL;
        let renewal_due = expires - REFRESH_AHEAD;
        tokio::time::sleep_until(renewal_due - Duration::from_secs(1)).await;
        // tokio's Mutex is fair: waiters take the lock in the order they called lock().
        let queued = (0..11)
            .map(|_| {
                let admissions = Arc::clone(&admissions);
                tokio::spawn(async move { admissions.ticket("key", CHUTE).await })
            })
            .collect::<Vec<_>>();
        let cell = admissions.scope(scope_of("key", CHUTE)).unwrap();
        let mut renewed = false;
        while !renewed && Instant::now() < expires {
            tokio::time::sleep(Duration::from_secs(1)).await;
            renewed = cell
                .try_lock()
                .is_ok_and(|state| state.admitted.values().any(|until| *until > expires));
        }
        assert!(
            renewed,
            "the renewal recorded no verdict before the admission expired"
        );
        for request in queued {
            let _ = request.await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn requests_arriving_during_a_renewal_let_it_record_before_expiry() {
        let mut api = FakeApi::new(1);
        api.nonces_per_instance = 1;
        api.discover_delay = Duration::from_secs(29);
        api.admit_delays
            .lock()
            .unwrap()
            .extend([Duration::ZERO, Duration::from_secs(90)]);
        let (api, admissions) = cache_with_clock(api, fixed_clock(Duration::ZERO, Vec::new()));
        let admissions = Arc::new(admissions);
        admissions.ticket("key", CHUTE).await.unwrap();
        let expires = api.admission_starts.lock().unwrap()[0] + ADMISSION_TTL;
        tokio::time::sleep_until(expires - REFRESH_AHEAD - Duration::from_secs(1)).await;
        let spawn_requests = || {
            (0..11)
                .map(|_| {
                    let admissions = Arc::clone(&admissions);
                    tokio::spawn(async move { admissions.ticket("key", CHUTE).await })
                })
                .collect::<Vec<_>>()
        };
        let mut requests = spawn_requests();
        while api.admission_starts.lock().unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        // tokio's Mutex is fair, so these queue ahead of the renewal recording its verdicts.
        requests.extend(spawn_requests());
        let cell = admissions.scope(scope_of("key", CHUTE)).unwrap();
        let mut renewed = false;
        while !renewed && Instant::now() < expires {
            tokio::time::sleep(Duration::from_secs(1)).await;
            renewed = cell
                .try_lock()
                .is_ok_and(|state| state.admitted.values().any(|until| *until > expires));
        }
        assert!(
            renewed,
            "the renewal recorded no verdict before the admission expired"
        );
        for request in requests {
            let _ = request.await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_holding_the_scope_starts_no_evidence_call_after_a_renewal_429() {
        let mut api = FakeApi::new(1);
        api.nonces_per_instance = 1;
        api.discover_delay = Duration::from_secs(30);
        api.admit_delays
            .lock()
            .unwrap()
            .extend([Duration::ZERO, Duration::from_secs(20)]);
        let (api, admissions) = cache_with_clock(api, fixed_clock(Duration::ZERO, Vec::new()));
        let admissions = Arc::new(admissions);
        admissions.ticket("key", CHUTE).await.unwrap();
        let renewal_due = api.admission_starts.lock().unwrap()[0] + ADMISSION_TTL - REFRESH_AHEAD;
        tokio::time::sleep_until(renewal_due + Duration::from_secs(1)).await;
        assert_eq!(
            api.admissions.load(Ordering::SeqCst),
            2,
            "no renewal started"
        );
        *api.evidence.lock().unwrap() = Err(StatusCode::TOO_MANY_REQUESTS);
        *api.instances.lock().unwrap() = vec![second_instance()];
        // The request holds the scope through a discovery that outlasts the renewal's call.
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert!(error.to_string().contains("backing off"), "{error}");
        assert_eq!(api.admissions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_request_records_its_rejection_ahead_of_an_older_renewal() {
        let mut api = FakeApi::new(1);
        api.valid_for = 3 * MINUTE;
        api.admit_delays.lock().unwrap().extend([
            Duration::ZERO,
            Duration::from_secs(90),
            5 * MINUTE,
        ]);
        let (api, admissions) = cache_with_clock(api, fixed_clock(Duration::ZERO, Vec::new()));
        admissions.ticket("key", CHUTE).await.unwrap();
        tokio::time::advance(MIN_RENEWAL_INTERVAL).await;
        settle().await;
        assert_eq!(
            api.admissions.load(Ordering::SeqCst),
            2,
            "no renewal started"
        );

        // The renewal fetched evidence before the rejection; the request fetches it after.
        api.rejected.lock().unwrap().push("instance-0".to_owned());
        tokio::time::advance(Duration::from_secs(61)).await;
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert!(error.to_string().contains("MRTD"), "{error:#}");
        settle().await;
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert!(error.to_string().contains("MRTD"), "{error:#}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_request_still_records_its_rejection_ahead_of_an_older_renewal() {
        let mut api = FakeApi::new(1);
        api.valid_for = 3 * MINUTE;
        api.admit_delays.lock().unwrap().extend([
            Duration::ZERO,
            Duration::from_secs(90),
            5 * MINUTE,
        ]);
        let (api, admissions) = cache_with_clock(api, fixed_clock(Duration::ZERO, Vec::new()));
        let admissions = Arc::new(admissions);
        admissions.ticket("key", CHUTE).await.unwrap();
        tokio::time::advance(MIN_RENEWAL_INTERVAL).await;
        settle().await;
        assert_eq!(
            api.admissions.load(Ordering::SeqCst),
            2,
            "no renewal started"
        );

        // The renewal fetched evidence before the rejection; the request fetches it after.
        api.rejected.lock().unwrap().push("instance-0".to_owned());
        tokio::time::advance(Duration::from_secs(61)).await;
        let request = {
            let admissions = Arc::clone(&admissions);
            tokio::spawn(async move { admissions.ticket("key", CHUTE).await })
        };
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(
            api.admissions.load(Ordering::SeqCst),
            3,
            "the request never checked"
        );
        request.abort();
        tokio::time::sleep(Duration::from_secs(30)).await;
        let served = admissions.ticket("key", CHUTE).await;
        assert!(
            served.is_err(),
            "the older renewal re-admitted a rejected instance"
        );
        tokio::time::sleep(5 * MINUTE).await;
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert!(error.to_string().contains("MRTD"), "{error:#}");
    }

    #[tokio::test(start_paused = true)]
    async fn an_evidence_charge_honours_a_backoff_recorded_just_before_it() {
        let (_, admissions) =
            cache_with_clock(FakeApi::new(1), fixed_clock(Duration::ZERO, Vec::new()));
        let credential = scope_of("key", CHUTE).0;
        let discoveries = &admissions.discoveries;
        discoveries.evidence_failed(
            credential,
            CHUTE,
            &ChutesError::RateLimited { stage: "evidence" },
        );
        let error = discoveries.charge_evidence(credential, CHUTE).unwrap_err();
        assert!(error.to_string().contains("backing off"), "{error}");
        let charged = discoveries.budgets.lock().unwrap()[&credential]
            .evidence
            .len();
        assert_eq!(charged, 0, "a refused call was charged");
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_that_never_got_the_scope_takes_no_backoff() {
        let (api, admissions) = cache(FakeApi::new(1));
        let cell = admissions.scope(scope_of("key", CHUTE)).unwrap();
        let held = cell.lock().await;
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert!(error.to_string().contains("waited"), "{error}");
        drop(held);
        assert_eq!(admissions.backoff_step("key", CHUTE), None);
        admissions.ticket("key", CHUTE).await.unwrap();
        assert_eq!(api.discoveries.load(Ordering::SeqCst), 1);
    }

    const MINUTE: Duration = Duration::from_secs(60);

    /// Serve at t0 and t5, so the scope and its renewal outlive the first admission.
    async fn served_twice(admissions: &Admissions<FakeApi>) {
        admissions.ticket("key", CHUTE).await.unwrap();
        tokio::time::advance(5 * MINUTE).await;
        admissions.ticket("key", CHUTE).await.unwrap();
    }

    fn only_instance(api: &FakeApi, instance: (String, String)) -> Vec<(String, String)> {
        std::mem::replace(&mut *api.instances.lock().unwrap(), vec![instance])
    }

    fn second_instance() -> (String, String) {
        ("instance-1".to_owned(), Instance::new().public_b64)
    }

    #[tokio::test(start_paused = true)]
    async fn a_renewal_rejection_holds_though_another_instance_was_admitted_meanwhile() {
        let api = FakeApi::new(1);
        api.admit_delays
            .lock()
            .unwrap()
            .extend([Duration::ZERO, 2 * MINUTE]);
        let (api, admissions) = cache_with_clock(api, fixed_clock(Duration::ZERO, Vec::new()));
        served_twice(&admissions).await;
        api.rejected.lock().unwrap().push("instance-0".to_owned());
        tokio::time::advance(5 * MINUTE).await;
        settle().await;
        assert_eq!(
            api.admissions.load(Ordering::SeqCst),
            2,
            "no renewal started"
        );

        tokio::time::advance(MINUTE).await;
        let second = second_instance();
        let first = only_instance(&api, second.clone());
        let ticket = admissions.ticket("key", CHUTE).await.unwrap();
        assert_eq!(ticket.instance_id, "instance-1");
        api.instances.lock().unwrap().splice(0..0, first);

        tokio::time::advance(MINUTE + Duration::from_secs(1)).await;
        settle().await;
        let ticket = admissions.ticket("key", CHUTE).await.unwrap();
        assert_eq!(
            ticket.instance_id, "instance-1",
            "a failed instance was served"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_refusal_recorded_while_a_renewal_waits_for_the_scope_stops_it() {
        let api = FakeApi::new(1);
        api.admit_delays
            .lock()
            .unwrap()
            .extend([Duration::ZERO, 2 * MINUTE]);
        let (api, admissions) = cache_with_clock(api, fixed_clock(Duration::ZERO, Vec::new()));
        let admissions = Arc::new(admissions);
        served_twice(&admissions).await;
        tokio::time::advance(4 * MINUTE).await;
        only_instance(&api, second_instance());
        *api.evidence.lock().unwrap() = Err(StatusCode::BAD_REQUEST);
        let slow = {
            let admissions = Arc::clone(&admissions);
            tokio::spawn(async move { admissions.ticket("key", CHUTE).await })
        };
        settle().await;
        tokio::time::advance(3 * MINUTE).await;
        settle().await;
        slow.await.unwrap().unwrap_err();
        settle().await;
        assert_eq!(api.admissions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_cached_ticket_does_not_lift_a_refusal_found_by_a_renewal() {
        let (api, admissions) =
            cache_with_clock(FakeApi::new(1), fixed_clock(Duration::ZERO, Vec::new()));
        served_twice(&admissions).await;
        *api.evidence.lock().unwrap() = Err(StatusCode::BAD_REQUEST);
        tokio::time::advance(5 * MINUTE).await;
        settle().await;
        assert_eq!(api.admissions.load(Ordering::SeqCst), 2);
        tokio::time::advance(2 * MINUTE).await;
        admissions.ticket("key", CHUTE).await.unwrap();
        tokio::time::advance(3 * MINUTE + Duration::from_secs(1)).await;
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert!(error.to_string().contains("backing off"), "{error:#}");
        assert_eq!(api.admissions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn the_renewal_floor_counts_verdicts_recorded_while_it_slept() {
        let (api, admissions) =
            cache_with_clock(FakeApi::new(1), fixed_clock(Duration::ZERO, Vec::new()));
        served_twice(&admissions).await;
        tokio::time::advance(4 * MINUTE).await;
        let first = only_instance(&api, second_instance());
        admissions.ticket("key", CHUTE).await.unwrap();
        api.instances.lock().unwrap().splice(0..0, first);
        assert_eq!(api.admissions.load(Ordering::SeqCst), 2);

        tokio::time::advance(MINUTE + Duration::from_secs(30)).await;
        settle().await;
        assert_eq!(
            api.admissions.load(Ordering::SeqCst),
            2,
            "renewed within the floor"
        );
        tokio::time::advance(Duration::from_secs(31)).await;
        settle().await;
        assert_eq!(api.admissions.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn evicting_a_scope_stops_its_renewal() {
        let mut api = FakeApi::new(1);
        api.failing_key = Some("other");
        let (api, admissions) = cache_with(api, 1, MAX_ISSUED_NONCES);
        admissions.ticket("key", CHUTE).await.unwrap();
        settle().await;
        assert_eq!(Arc::strong_count(&api), 3, "no renewal is running");
        admissions.ticket("other", CHUTE).await.unwrap_err();
        assert!(!admissions.holds("key", CHUTE), "the scope was not evicted");
        settle().await;
        assert_eq!(Arc::strong_count(&api), 2, "the renewal outlived its scope");
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_chute_is_not_renewed() {
        let (api, admissions) = cache(FakeApi::new(1));
        admissions.ticket("key", CHUTE).await.unwrap();
        for _ in 0..12 {
            tokio::time::advance(Duration::from_secs(5 * 60)).await;
            settle().await;
        }
        assert_eq!(
            api.admissions.load(Ordering::SeqCst),
            2,
            "renewed past one admission lifetime after the last request"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn evidence_calls_are_capped_per_credential() {
        let mut api = FakeApi::new(1);
        api.nonces_per_instance = 1;
        let (api, admissions) = cache(api);
        let chutes = many_chutes(EVIDENCE_PER_MINUTE + 1);
        for chute in &chutes[..EVIDENCE_PER_MINUTE] {
            admissions.ticket("key", chute).await.unwrap();
        }
        let chute = chutes[EVIDENCE_PER_MINUTE];
        let error = admissions.ticket("key", chute).await.unwrap_err();
        assert!(error.to_string().contains("evidence budget"), "{error}");
        assert_eq!(api.admissions.load(Ordering::SeqCst), EVIDENCE_PER_MINUTE);
        admissions.ticket("other-key", chute).await.unwrap();
        tokio::time::advance(DISCOVERY_WINDOW).await;
        admissions.ticket("key", chute).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn one_credential_serves_every_target_and_a_hot_chute_in_the_same_minute() {
        let mut api = FakeApi::new(1);
        api.nonces_per_instance = 10;
        let (api, admissions) = cache(api);
        for target in crate::chutes_verify::TARGETS {
            admissions.ticket("key", target.chute_id).await.unwrap();
        }
        for _ in 0..40 {
            admissions.ticket("key", CHUTE).await.unwrap();
        }
        assert_eq!(api.admissions.load(Ordering::SeqCst), TARGETS_SERVED);
        assert_eq!(api.discoveries.load(Ordering::SeqCst), TARGETS_SERVED + 4);
    }

    const TARGETS_SERVED: usize = crate::chutes_verify::TARGETS.len();

    #[tokio::test(start_paused = true)]
    async fn a_chute_below_the_evidence_minimum_is_not_asked_again_for_long() {
        let (api, admissions) = cache(FakeApi::new(1));
        *api.evidence.lock().unwrap() = Err(StatusCode::BAD_REQUEST);
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
        tokio::time::advance(4 * BACKOFF_MAX).await;
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert!(error.to_string().contains("backing off"), "{error}");
        assert_eq!(api.admissions.load(Ordering::SeqCst), 1);
        tokio::time::advance(REFUSAL_BACKOFF).await;
        admissions.ticket("key", CHUTE).await.unwrap_err();
        assert_eq!(api.admissions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_renewal_that_rejects_an_instance_withdraws_its_admission() {
        let (api, admissions) = cache(FakeApi::new(2));
        admissions.ticket("key", CHUTE).await.unwrap();
        api.rejected.lock().unwrap().push("instance-0".to_owned());
        tokio::time::advance(FIRST_RENEWAL).await;
        settle().await;
        for _ in 0..3 {
            let ticket = admissions.ticket("key", CHUTE).await.unwrap();
            assert_eq!(ticket.instance_id, "instance-1");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_rejected_instance_is_not_refetched_while_its_verdict_stands() {
        let api = FakeApi::new(1);
        api.rejected.lock().unwrap().push("instance-0".to_owned());
        let (api, admissions) = cache(api);
        admissions.ticket("key", CHUTE).await.unwrap_err();
        tokio::time::advance(BACKOFF_START).await;
        admissions.ticket("key", CHUTE).await.unwrap_err();
        assert_eq!(api.admissions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_rate_limit_backs_off_to_the_next_wall_clock_window() {
        let limited = ChutesError::RateLimited { stage: "evidence" };
        let other = ChutesError::Unavailable(anyhow::anyhow!("NRAS unreachable"));
        let at = |millis| Duration::from_millis(millis);
        assert_eq!(
            backoff_wait(&limited, BACKOFF_START, at(1_800_000), Duration::ZERO),
            RATE_WINDOW + RATE_WINDOW_SLACK
        );
        assert_eq!(
            backoff_wait(&limited, BACKOFF_START, at(1_800_500), Duration::ZERO),
            at(60_500)
        );
        assert_eq!(
            backoff_wait(&limited, BACKOFF_START, at(1_859_900), Duration::ZERO),
            BACKOFF_START
        );
        assert_eq!(
            backoff_wait(&other, BACKOFF_START, at(1_800_500), Duration::ZERO),
            BACKOFF_START
        );
        assert_eq!(
            backoff_wait(
                &ChutesError::BelowEvidenceMinimum,
                BACKOFF_START,
                at(1_800_500),
                Duration::ZERO
            ),
            REFUSAL_BACKOFF
        );
    }

    #[test]
    fn deadlines_keep_sub_second_wall_time_and_are_capped() {
        let anchor = Instant::now();
        let wall = |millis| Duration::from_millis(millis);
        assert_eq!(
            deadline(anchor, wall(1_000_900), 1_060),
            anchor + Duration::from_millis(59_100)
        );
        assert_eq!(deadline(anchor, wall(1_000_000), 900), anchor);
        assert_eq!(
            deadline(anchor, wall(1_000_000), 1_000_000),
            anchor + ADMISSION_TTL
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_refresh_never_reissues_a_consumed_nonce() {
        let mut api = FakeApi::new(1);
        api.repeat_nonces = true;
        let (api, admissions) = cache(api);
        let first = admissions.ticket("key", CHUTE).await.unwrap().nonce;
        let second = admissions.ticket("key", CHUTE).await.unwrap().nonce;
        assert_ne!(first, second);
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            api.discoveries.load(Ordering::SeqCst) >= 2,
            "no refresh ran"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn failing_credentials_are_not_retained() {
        let mut api = FakeApi::new(1);
        api.failing_key = Some("bad");
        let (_, admissions) = cache(api);
        let error = admissions.ticket("bad", CHUTE).await.unwrap_err();
        assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(admissions.scope_count(), 0);
        admissions.ticket("good", CHUTE).await.unwrap();
        assert_eq!(admissions.scope_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn scopes_are_bounded_and_evicted_when_idle() {
        let (_, admissions) = cache(FakeApi::new(1));
        for index in 0..MAX_SCOPES + 10 {
            admissions
                .ticket(&format!("key-{index}"), CHUTE)
                .await
                .unwrap();
        }
        assert_eq!(admissions.scope_count(), MAX_SCOPES);
        tokio::time::advance(ADMISSION_TTL).await;
        admissions.ticket("fresh", CHUTE).await.unwrap();
        assert_eq!(admissions.scope_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn leftover_nonces_of_a_rejected_instance_do_not_block_a_refresh() {
        let api = FakeApi::new(2);
        api.rejected.lock().unwrap().push("instance-1".to_owned());
        let (api, admissions) = cache(api);
        for _ in 0..3 {
            let ticket = admissions.ticket("key", CHUTE).await.unwrap();
            assert_eq!(ticket.instance_id, "instance-0");
        }
        assert_eq!(api.discoveries.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn issued_nonces_are_remembered_across_scope_eviction() {
        let mut api = FakeApi::new(1);
        api.repeat_nonces = true;
        let (_, admissions) = cache_with(api, 2, MAX_ISSUED_NONCES);
        admissions.ticket("a", CHUTE).await.unwrap();
        admissions.ticket("a", CHUTE).await.unwrap();
        for other in ["b", "c"] {
            tokio::time::advance(Duration::from_secs(1)).await;
            admissions.ticket(other, CHUTE).await.unwrap_err();
        }
        assert!(
            !admissions.holds("a", CHUTE),
            "the idle scope was not evicted"
        );
        let error = admissions.ticket("a", CHUTE).await.unwrap_err();
        assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test(start_paused = true)]
    async fn issued_nonces_are_remembered_for_their_full_validity() {
        let mut api = FakeApi::new(1);
        api.repeat_nonces = true;
        let (_, admissions) = cache(api);
        admissions.ticket("key", CHUTE).await.unwrap();
        admissions.ticket("key", CHUTE).await.unwrap();
        tokio::time::advance(Duration::from_secs(57)).await;
        assert!(admissions.ticket("key", CHUTE).await.is_err());
        tokio::time::advance(Duration::from_secs(9)).await;
        admissions.ticket("key", CHUTE).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_scope_in_use_is_never_evicted() {
        let mut api = FakeApi::new(1);
        api.admit_delay = Duration::from_secs(10);
        api.slow_key = Some("busy");
        let (api, admissions) = cache_with(api, 1, MAX_ISSUED_NONCES);
        let admissions = Arc::new(admissions);
        let busy = {
            let admissions = Arc::clone(&admissions);
            tokio::spawn(async move { admissions.ticket("busy", CHUTE).await })
        };
        while api.admissions.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        let error = admissions.ticket("other", CHUTE).await.unwrap_err();
        assert!(error.to_string().contains("in use"), "{error}");
        assert!(admissions.holds("busy", CHUTE));
        busy.await.unwrap().unwrap();
        admissions.ticket("other", CHUTE).await.unwrap();
        assert!(!admissions.holds("busy", CHUTE));
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_nonce_ledger_refuses_to_issue() {
        let mut api = FakeApi::new(1);
        api.nonces_per_instance = 5;
        let (_, admissions) = cache_with(api, MAX_SCOPES, 3);
        for _ in 0..3 {
            admissions.ticket("key", CHUTE).await.unwrap();
        }
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert!(error.to_string().contains("refusing"), "{error}");
        tokio::time::advance(Duration::from_secs(66)).await;
        admissions.ticket("key", CHUTE).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn nonces_are_retained_past_validity_counted_from_the_response() {
        let mut api = FakeApi::new(1);
        api.repeat_nonces = true;
        api.discover_delay = Duration::from_secs(2);
        let (_, admissions) = cache(api);
        admissions.ticket("key", CHUTE).await.unwrap();
        admissions.ticket("key", CHUTE).await.unwrap();
        // Retention outlasts the advertised validity counted from receipt.
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(admissions.ticket("key", CHUTE).await.is_err());
        tokio::time::advance(Duration::from_secs(8)).await;
        admissions.ticket("key", CHUTE).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn discovery_budget_is_shared_per_credential_and_fails_fast() {
        let mut api = FakeApi::new(1);
        api.nonces_per_instance = 1;
        let (api, admissions) = cache(api);
        for _ in 0..DISCOVERIES_PER_MINUTE {
            admissions.ticket("key", CHUTE).await.unwrap();
        }
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(error.to_string().contains("budget"), "{error}");
        assert_eq!(
            api.discoveries.load(Ordering::SeqCst),
            DISCOVERIES_PER_MINUTE
        );
        admissions.ticket("other-key", CHUTE).await.unwrap();
        tokio::time::advance(DISCOVERY_WINDOW).await;
        admissions.ticket("key", CHUTE).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_chute_with_no_admissible_instance_backs_off() {
        let api = FakeApi::new(1);
        api.rejected.lock().unwrap().push("instance-0".to_owned());
        let (api, admissions) = cache(api);
        admissions.ticket("key", CHUTE).await.unwrap_err();
        assert_eq!(api.discoveries.load(Ordering::SeqCst), 1);
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert!(error.to_string().contains("backing off"), "{error}");
        assert_eq!(api.discoveries.load(Ordering::SeqCst), 1);

        tokio::time::advance(BACKOFF_START + REJECTION_TTL).await;
        admissions.ticket("key", CHUTE).await.unwrap_err();
        assert_eq!(api.discoveries.load(Ordering::SeqCst), 2);
        tokio::time::advance(BACKOFF_START).await;
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert!(
            error.to_string().contains("backing off"),
            "the backoff did not grow: {error}"
        );

        api.rejected.lock().unwrap().clear();
        tokio::time::advance(REJECTION_TTL).await;
        admissions.ticket("key", CHUTE).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn discoveries_are_charged_when_they_run() {
        let mut api = FakeApi::new(1);
        api.nonces_per_instance = 1;
        api.discover_delay = Duration::from_secs(5);
        let (api, admissions) = cache(api);
        let admissions = Arc::new(admissions);
        let chutes = many_chutes(DISCOVERIES_PER_MINUTE + 5);
        let spawn_round = || {
            chutes
                .iter()
                .map(|&chute| {
                    let admissions = Arc::clone(&admissions);
                    tokio::spawn(async move { admissions.ticket("key", chute).await })
                })
                .collect::<Vec<_>>()
        };
        let mut tasks = spawn_round();
        tokio::time::sleep(Duration::from_secs(30)).await;
        tasks.extend(spawn_round());
        for task in tasks {
            let _ = task.await.unwrap();
        }
        let starts = api.discovery_starts.lock().unwrap().clone();
        assert!(starts.len() >= DISCOVERIES_PER_MINUTE);
        for first in &starts {
            let in_window = starts
                .iter()
                .filter(|start| *start >= first && **start < *first + DISCOVERY_WINDOW)
                .count();
            assert!(
                in_window <= DISCOVERIES_PER_MINUTE,
                "{in_window} discoveries in one minute"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn any_issued_ticket_clears_the_backoff() {
        let (api, admissions) = cache(FakeApi::new(1));
        admissions.ticket("key", CHUTE).await.unwrap();
        let credential = scope_of("key", CHUTE).0;
        admissions.discoveries.failed(
            credential,
            CHUTE,
            &ChutesError::Unavailable(anyhow::anyhow!("earlier failure")),
        );
        assert_eq!(admissions.backoff_step("key", CHUTE), Some(BACKOFF_START));
        tokio::time::advance(BACKOFF_START).await;
        admissions.ticket("key", CHUTE).await.unwrap();
        assert_eq!(
            api.discoveries.load(Ordering::SeqCst),
            1,
            "served from the retained pool"
        );
        assert_eq!(admissions.backoff_step("key", CHUTE), None);
    }

    #[tokio::test(start_paused = true)]
    async fn an_admission_failure_backs_off_before_any_outbound_call() {
        let (api, admissions) = cache(FakeApi::new(1));
        *api.evidence.lock().unwrap() = Err(StatusCode::TOO_MANY_REQUESTS);
        admissions.ticket("key", CHUTE).await.unwrap_err();
        assert_eq!(api.admissions.load(Ordering::SeqCst), 1);
        let error = admissions.ticket("key", CHUTE).await.unwrap_err();
        assert!(error.to_string().contains("backing off"), "{error}");
        assert_eq!(api.admissions.load(Ordering::SeqCst), 1);
        assert_eq!(api.discoveries.load(Ordering::SeqCst), 1);
    }

    fn most_starts_in_a_window(starts: &[Instant]) -> usize {
        starts
            .iter()
            .map(|first| {
                starts
                    .iter()
                    .filter(|start| *start >= first && **start < *first + DISCOVERY_WINDOW)
                    .count()
            })
            .max()
            .unwrap_or(0)
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_discovery_does_not_let_queued_ones_escape_the_budget() {
        let targets = many_chutes(2 * DISCOVERIES_PER_MINUTE - 3);
        let mut api = FakeApi::new(1);
        api.nonces_per_instance = 1;
        api.discover_delay = Duration::from_secs(1);
        api.chute_discover_delay
            .insert(targets[0], Duration::from_secs(20));
        let (api, admissions) = cache(api);
        let admissions = Arc::new(admissions);
        let spawn = |chutes: Vec<&'static str>| {
            chutes
                .into_iter()
                .map(|chute| {
                    let admissions = Arc::clone(&admissions);
                    tokio::spawn(async move { admissions.ticket("key", chute).await })
                })
                .collect::<Vec<_>>()
        };
        let mut tasks = spawn(targets[..DISCOVERIES_PER_MINUTE].to_vec());
        tokio::time::sleep(Duration::from_secs(61)).await;
        tasks.extend(spawn(targets[DISCOVERIES_PER_MINUTE - 3..].to_vec()));
        for task in tasks {
            let _ = task.await.unwrap();
        }
        let starts = api.discovery_starts.lock().unwrap().clone();
        assert!(
            starts.len() > DISCOVERIES_PER_MINUTE,
            "the second round never ran"
        );
        assert!(most_starts_in_a_window(&starts) <= DISCOVERIES_PER_MINUTE);
    }
}
