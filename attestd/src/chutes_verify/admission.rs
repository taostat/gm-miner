//! Per-`(credential, chute)` admission and invocation-nonce caches.
//!
//! Chutes serves evidence under a small rate limit shared by every API
//! caller, so an instance is admitted once and reused until its admission
//! expires. Each chute has one lock: concurrent requests wait for a single
//! discovery or admission instead of each spending an evidence call.

use std::collections::HashMap;
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
// Chutes' advertised nonce lifetime is shortened so a nonce is never sent as it expires.
const NONCE_MARGIN: Duration = Duration::from_secs(5);
const MAX_ADMISSIONS_PER_REQUEST: usize = 2;

/// Admission outcome for one discovered instance.
#[derive(Debug)]
pub struct Verdict {
    pub instance_id: String,
    pub e2e_pubkey: String,
    /// How long the admission may be reused, or why the instance failed.
    pub outcome: Result<Duration, String>,
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
    pool_expires: Option<Instant>,
    admitted: HashMap<InstanceKey, Instant>,
    rejected: HashMap<InstanceKey, (Instant, String)>,
}

impl ChuteState {
    fn prune(&mut self, now: Instant) {
        self.admitted.retain(|_, until| *until > now);
        self.rejected.retain(|_, (until, _)| *until > now);
        if self.pool_expires.is_none_or(|expires| expires <= now) {
            self.pool.clear();
        }
        self.pool.retain(|instance| !instance.nonces.is_empty());
    }

    fn take_ticket(&mut self) -> Option<Ticket> {
        let admitted = &self.admitted;
        let instance = self
            .pool
            .iter_mut()
            .find(|instance| admitted.contains_key(&key_of(instance)))?;
        let nonce = instance.nonces.pop()?;
        Some(Ticket {
            instance_id: instance.instance_id.clone(),
            e2e_pubkey: instance.e2e_pubkey.clone(),
            nonce,
        })
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
                Ok(valid_for) => {
                    self.admitted
                        .insert(key, now + valid_for.min(ADMISSION_TTL));
                }
                Err(cause) => {
                    self.rejected.insert(key, (now + REJECTION_TTL, cause));
                }
            }
        }
    }

    fn exhausted(&self, chute_id: &str) -> ChutesError {
        if self.rejected.is_empty() {
            return ChutesError::Unavailable(anyhow::anyhow!(
                "no admitted instance of chute {chute_id} has an unused nonce"
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

/// Admission cache over a [`ChutesApi`].
pub struct Admissions<A> {
    api: Arc<A>,
    chutes: Mutex<HashMap<ChuteScope, Arc<tokio::sync::Mutex<ChuteState>>>>,
}

impl<A: ChutesApi> Admissions<A> {
    pub fn new(api: Arc<A>) -> Self {
        Self {
            api,
            chutes: Mutex::new(HashMap::new()),
        }
    }

    /// An admitted instance and an unused nonce for `chute_id` under
    /// `api_key`, discovering and admitting only when the cache has none.
    ///
    /// # Errors
    ///
    /// Returns the discovery or admission error, or [`ChutesError::Rejected`]
    /// with every instance's cause when none passed. Admissions already cached
    /// keep serving while evidence is unavailable.
    pub async fn ticket(
        &self,
        api_key: &str,
        chute_id: &'static str,
    ) -> Result<Ticket, ChutesError> {
        let cell = self.chute(api_key, chute_id);
        let mut state = cell.lock().await;
        state.prune(Instant::now());
        let mut refreshed = false;
        let mut admissions = 0;
        loop {
            if let Some(ticket) = state.take_ticket() {
                return Ok(ticket);
            }
            let unjudged = state.unjudged();
            if !unjudged.is_empty() && admissions < MAX_ADMISSIONS_PER_REQUEST {
                admissions += 1;
                let verdicts = self.api.admit(api_key, chute_id, &unjudged).await?;
                state.record(verdicts, Instant::now());
            } else if !refreshed {
                refreshed = true;
                let discovery = self.api.discover(api_key, chute_id).await?;
                let lifetime = discovery.nonce_lifetime().saturating_sub(NONCE_MARGIN);
                state.pool = discovery.instances;
                state.pool_expires = Some(Instant::now() + lifetime);
                state.prune(Instant::now());
            } else {
                return Err(state.exhausted(chute_id));
            }
        }
    }

    fn chute(&self, api_key: &str, chute_id: &'static str) -> Arc<tokio::sync::Mutex<ChuteState>> {
        let scope: [u8; 32] = Sha256::digest(api_key.as_bytes()).into();
        let mut chutes = self.chutes.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(chutes.entry((scope, chute_id)).or_default())
    }
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
                answer: Mutex::new(None),
                invoked: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ChutesApi for FakeApi {
        async fn discover(&self, _: &str, _: &str) -> Result<Discovery, ChutesError> {
            let round = self.discoveries.fetch_add(1, Ordering::SeqCst);
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
            _: &str,
            _: &str,
            instances: &[DiscoveredInstance],
        ) -> Result<Vec<Verdict>, ChutesError> {
            self.admissions.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.admit_delay).await;
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
                        Ok(ADMISSION_TTL)
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
}
