//! Per-`(credential, chute)` admission and invocation-nonce caches.
//!
//! Chutes serves evidence under a small rate limit shared by every API
//! caller, so an instance is admitted once and reused until its admission
//! expires. Each chute has one lock: concurrent requests wait for a single
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

use crate::chutes_verify::error::ChutesError;
use crate::chutes_verify::evidence::{DiscoveredInstance, Discovery};

/// Longest an admission is reused before evidence is fetched again.
pub const ADMISSION_TTL: Duration = Duration::from_secs(15 * 60);
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
/// Discoveries per credential per minute, under Chutes' 10 rpm limit.
pub const DISCOVERIES_PER_MINUTE: usize = 8;
const DISCOVERY_WINDOW: Duration = Duration::from_secs(60);
const BACKOFF_START: Duration = Duration::from_secs(5);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
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
}

impl ChuteState {
    fn prune(&mut self, now: Instant) {
        self.admitted.retain(|_, until| *until > now);
        self.rejected.retain(|_, (until, _)| *until > now);
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

    fn record(&mut self, verdicts: Vec<Verdict>, now: Instant) {
        for verdict in verdicts {
            let key = (verdict.instance_id, verdict.e2e_pubkey);
            match verdict.outcome {
                Ok(until) => {
                    self.admitted.insert(key, until);
                }
                Err(cause) => {
                    self.rejected.insert(key, (now + REJECTION_TTL, cause));
                }
            }
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
    backoff: HashMap<&'static str, Backoff>,
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
        // A chute's backoff resets once it has gone two maximum steps without failing.
        self.backoff
            .retain(|_, backoff| backoff.until + 2 * BACKOFF_MAX > now);
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
        self.recent.is_empty() && self.backoff.is_empty() && Arc::strong_count(&self.in_flight) == 1
    }
}

#[derive(Default)]
struct Discoveries {
    budgets: Mutex<HashMap<[u8; 32], Budget>>,
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

    /// Fail fast while `chute_id` backs off. Runs before every outbound
    /// discovery, evidence or NRAS call.
    fn gate(&self, credential: [u8; 32], chute_id: &'static str) -> Result<(), ChutesError> {
        self.with_budget(credential, |budget, now| {
            budget.check_backoff(chute_id, now)
        })
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

    fn failed(&self, credential: [u8; 32], chute_id: &'static str, cause: String) {
        let now = Instant::now();
        let mut budgets = self.budgets.lock().unwrap_or_else(PoisonError::into_inner);
        let budget = budgets.entry(credential).or_default();
        let step = budget
            .backoff
            .get(chute_id)
            .map_or(BACKOFF_START, |backoff| (backoff.step * 2).min(BACKOFF_MAX));
        budget.backoff.insert(
            chute_id,
            Backoff {
                until: now + step,
                step,
                cause,
            },
        );
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
    ledger: Mutex<NonceLedger>,
    discoveries: Discoveries,
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
            ledger: Mutex::new(NonceLedger {
                issued: HashMap::new(),
                capacity: max_nonces,
            }),
            discoveries: Discoveries::default(),
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
    /// kept. Fails closed when every scope is in use or the nonce ledger is full.
    pub async fn ticket(
        &self,
        api_key: &str,
        chute_id: &'static str,
    ) -> Result<Ticket, ChutesError> {
        let scope = scope_of(api_key, chute_id);
        let cell = self.scope(scope)?;
        let mut state = cell.lock().await;
        let result = self.issue(&mut state, api_key, chute_id).await;
        if result.is_err() && state.admitted.is_empty() {
            self.forget(scope, &cell);
        }
        result
    }

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
                self.discoveries.gate(credential, chute_id)?;
                let verdicts = self
                    .api
                    .admit(api_key, chute_id, &unjudged)
                    .await
                    .inspect_err(|error| {
                        self.discoveries
                            .failed(credential, chute_id, error.to_string());
                    })?;
                state.record(verdicts, Instant::now());
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
                            self.discoveries
                                .failed(credential, chute_id, error.to_string());
                        })?;
                state.refill(discovery, asked, Instant::now());
            } else {
                let error = state.exhausted(chute_id);
                if discoveries + admissions > 0 {
                    self.discoveries
                        .failed(credential, chute_id, error.to_string());
                }
                return Err(error);
            }
        }
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
            if self.slow_key.is_none_or(|slow| slow == api_key) {
                tokio::time::sleep(self.admit_delay).await;
            }
            if let Err(status) = *self.evidence.lock().unwrap() {
                return Err(ChutesError::Unavailable(anyhow::anyhow!(
                    "Chutes evidence answered {status}"
                )));
            }
            let rejected = self.rejected.lock().unwrap().clone();
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
        assert_eq!(api.admissions.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(3 * 60)).await;
        admissions.ticket("key", CHUTE).await.unwrap();
        assert_eq!(
            api.admissions.load(Ordering::SeqCst),
            2,
            "admission outlived its evidence"
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
        let spawn_round = || {
            crate::chutes_verify::TARGETS
                .iter()
                .map(|target| {
                    let admissions = Arc::clone(&admissions);
                    tokio::spawn(async move { admissions.ticket("key", target.chute_id).await })
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
        admissions
            .discoveries
            .failed(credential, CHUTE, "earlier failure".to_owned());
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
        let targets = crate::chutes_verify::TARGETS.map(|target| target.chute_id);
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
        let mut tasks = spawn(targets[..8].to_vec());
        tokio::time::sleep(Duration::from_secs(61)).await;
        tasks.extend(spawn(targets[5..13].to_vec()));
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
