use std::{
    future::Future,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use axum::http::HeaderMap;
use futures_util::StreamExt;
use rand::RngExt as _;
use reqwest::{header::CONTENT_TYPE, Client, StatusCode};
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Map, Value};
use tokio::{
    sync::{watch, RwLock},
    time::Instant as TokioInstant,
};

use crate::strict_json::parse_unique_json;

pub(crate) const MAX_BODY_BYTES: usize = 1024 * 1024;
pub(crate) const REFRESH_INTERVAL: Duration = Duration::from_secs(60);
pub(crate) const ON_DEMAND_MIN_INTERVAL: Duration = Duration::from_secs(3);
pub(crate) const REFRESH_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const RETRY_INITIAL_DELAY: Duration = Duration::from_secs(3);
pub(crate) const RETRY_MAX_DELAY: Duration = Duration::from_secs(35);
pub(crate) const FRESHNESS_TTL: Duration = Duration::from_secs(15 * 60);

const _: () = assert!(
    REFRESH_TIMEOUT.as_millis() + RETRY_MAX_DELAY.as_millis() + RETRY_MAX_DELAY.as_millis() / 4
        < REFRESH_INTERVAL.as_millis()
);

#[derive(Clone, Copy, Debug)]
pub(crate) enum RefreshStatus {
    InFlight {
        generation: u64,
        deadline: TokioInstant,
    },
    FailureBackoff {
        generation: u64,
        until: TokioInstant,
    },
    OnDemandGap {
        generation: u64,
        until: TokioInstant,
    },
}

impl RefreshStatus {
    pub(crate) fn generation(self) -> u64 {
        match self {
            Self::InFlight { generation, .. }
            | Self::FailureBackoff { generation, .. }
            | Self::OnDemandGap { generation, .. } => generation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CachedSnapshot<T> {
    snapshot: Arc<T>,
    fetched_at: Instant,
}

impl<T> CachedSnapshot<T> {
    pub(crate) fn snapshot(&self) -> &Arc<T> {
        &self.snapshot
    }

    pub(crate) fn is_fresh(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.fetched_at) <= FRESHNESS_TTL
    }
}

pub(crate) trait RegistryCache<T>: Send + Sync + 'static {
    fn publish(&mut self, snapshot: T, fetched_at: Instant) -> Result<(), &'static str>;
    fn current_cached(&self) -> Option<&CachedSnapshot<T>>;
}

#[derive(Debug)]
pub(crate) struct SnapshotCache<T> {
    current: Option<CachedSnapshot<T>>,
}

impl<T> Default for SnapshotCache<T> {
    fn default() -> Self {
        Self { current: None }
    }
}

impl<T> SnapshotCache<T> {
    pub(crate) fn publish(&mut self, snapshot: T, fetched_at: Instant) {
        self.current = Some(CachedSnapshot {
            snapshot: Arc::new(snapshot),
            fetched_at,
        });
    }

    pub(crate) fn current(&self) -> Option<Arc<T>> {
        self.current
            .as_ref()
            .map(|cached| Arc::clone(cached.snapshot()))
    }

    pub(crate) fn is_fresh(&self, now: Instant) -> bool {
        self.current
            .as_ref()
            .is_some_and(|cached| cached.is_fresh(now))
    }

    #[cfg(test)]
    pub(crate) fn clear(&mut self) {
        self.current = None;
    }

    #[cfg(test)]
    pub(crate) fn age(&mut self, now: Instant, age: Duration) {
        if let Some(cached) = &mut self.current {
            cached.fetched_at = now.checked_sub(age).unwrap_or(now);
        }
    }

    #[cfg(test)]
    pub(crate) fn edit_snapshot(&mut self, edit: impl FnOnce(&mut T))
    where
        T: Clone,
    {
        if let Some(cached) = &mut self.current {
            edit(Arc::make_mut(&mut cached.snapshot));
        }
    }
}

impl<T: Send + Sync + 'static> RegistryCache<T> for SnapshotCache<T> {
    fn publish(&mut self, snapshot: T, fetched_at: Instant) -> Result<(), &'static str> {
        SnapshotCache::publish(self, snapshot, fetched_at);
        Ok(())
    }

    fn current_cached(&self) -> Option<&CachedSnapshot<T>> {
        self.current.as_ref()
    }
}

pub(crate) struct RegistrySnapshot<T, C = SnapshotCache<T>> {
    client: Client,
    url: String,
    network: String,
    cache: Arc<RwLock<C>>,
    started: Arc<OnceLock<()>>,
    nudge: watch::Sender<u64>,
    status: watch::Sender<RefreshStatus>,
    parser: fn(&[u8], &str) -> Result<T, &'static str>,
    label: &'static str,
}

impl<T, C> Clone for RegistrySnapshot<T, C> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            url: self.url.clone(),
            network: self.network.clone(),
            cache: Arc::clone(&self.cache),
            started: Arc::clone(&self.started),
            nudge: self.nudge.clone(),
            status: self.status.clone(),
            parser: self.parser,
            label: self.label,
        }
    }
}

impl<T, C> RegistrySnapshot<T, C>
where
    T: Send + Sync + 'static,
    C: RegistryCache<T>,
{
    pub(crate) fn new(
        client: Client,
        url: String,
        network: String,
        cache: C,
        parser: fn(&[u8], &str) -> Result<T, &'static str>,
        label: &'static str,
    ) -> Self {
        let (nudge, status) = new_refresh_channels();
        Self {
            client,
            url,
            network,
            cache: Arc::new(RwLock::new(cache)),
            started: Arc::new(OnceLock::new()),
            nudge,
            status,
            parser,
            label,
        }
    }

    pub(crate) fn start(&self) {
        let source = self.clone();
        start_refresh_loop(
            &self.started,
            &self.nudge,
            self.status.clone(),
            self.label,
            move || {
                let source = source.clone();
                async move { source.refresh().await }
            },
        );
    }

    pub(crate) async fn wait_for_refresh(&self) {
        let status = self.status.subscribe();
        self.start();
        wait_for_refresh(&self.nudge, status).await;
    }

    pub(crate) async fn refresh(&self) -> Result<(), &'static str> {
        let body = fetch_registry_body(&self.client, &self.url).await?;
        let snapshot = (self.parser)(&body, &self.network)?;
        self.cache.write().await.publish(snapshot, Instant::now())
    }

    pub(crate) async fn current(&self) -> Option<Arc<T>> {
        self.cache
            .read()
            .await
            .current_cached()
            .map(|cached| Arc::clone(cached.snapshot()))
    }

    pub(crate) async fn fresh(&self) -> Option<Arc<T>> {
        let now = Instant::now();
        self.cache
            .read()
            .await
            .current_cached()
            .filter(|cached| cached.is_fresh(now))
            .map(|cached| Arc::clone(cached.snapshot()))
    }

    pub(crate) async fn is_fresh(&self) -> bool {
        self.cache
            .read()
            .await
            .current_cached()
            .is_some_and(|cached| cached.is_fresh(Instant::now()))
    }

    pub(crate) async fn with_cache<R, F>(&self, read: F) -> R
    where
        R: Send,
        F: FnOnce(&C, Instant) -> R + Send,
    {
        read(&*self.cache.read().await, Instant::now())
    }

    #[cfg(test)]
    pub(crate) fn cache_for_test(&self) -> Arc<RwLock<C>> {
        Arc::clone(&self.cache)
    }

    #[cfg(test)]
    pub(crate) fn status_for_test(&self) -> watch::Receiver<RefreshStatus> {
        self.status.subscribe()
    }

    #[cfg(test)]
    pub(crate) fn with_url(mut self, url: &str) -> Self {
        self.url = url.to_owned();
        self
    }
}

pub(crate) fn registry_url_for_network(network: &str) -> Option<&'static str> {
    match network {
        "mainnet" => Some("https://registry.saygm.com"),
        "testnet" => Some("https://test-registry.saygm.com"),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BoundedBodyError {
    Read,
    TooLarge,
}

pub(crate) async fn read_bounded_body(
    response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, BoundedBodyError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(BoundedBodyError::TooLarge);
    }
    let mut body = Vec::new();
    let mut source = response.bytes_stream();
    while let Some(chunk) = source.next().await {
        let chunk = chunk.map_err(|_| BoundedBodyError::Read)?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(BoundedBodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(crate) fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

pub(crate) fn valid_model_id(value: &str, extra: &[u8]) -> bool {
    value.len() <= 256
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'-' | b'_' | b':')
                || extra.contains(&byte)
        })
}

pub(crate) fn registry_http_client() -> Result<Client, &'static str> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| "failed to configure fixed registry TLS versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Client::builder()
        .no_proxy()
        .https_only(true)
        .http1_only()
        .pool_max_idle_per_host(0)
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .use_preconfigured_tls(tls)
        .build()
        .map_err(|_| "failed to initialize fixed registry transport")
}

pub(crate) async fn fetch_registry_body(
    client: &Client,
    url: &str,
) -> Result<Vec<u8>, &'static str> {
    let response = client
        .get(url)
        .timeout(REFRESH_TIMEOUT)
        .send()
        .await
        .map_err(|_| "fixed registry binding fetch failed")?;
    if response.status() != StatusCode::OK {
        return Err("fixed registry binding fetch returned a non-200 status");
    }
    if !is_json_content_type(response.headers()) {
        return Err("fixed registry binding response is not JSON");
    }
    read_bounded_body(response, MAX_BODY_BYTES)
        .await
        .map_err(|error| match error {
            BoundedBodyError::Read => "registry binding response body failed",
            BoundedBodyError::TooLarge => "registry binding response exceeds the size limit",
        })
}

pub(crate) fn parse_envelope(
    bytes: &[u8],
    expected_network: &str,
    keys: &[&str],
) -> Result<Map<String, Value>, &'static str> {
    let value =
        parse_unique_json(bytes).map_err(|_| "registry binding response is invalid JSON")?;
    let Value::Object(object) = value else {
        return Err("registry binding response has an invalid envelope");
    };
    if !object_has_exact_keys(&object, keys) {
        return Err("registry binding response has an invalid envelope");
    }
    if object.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("registry binding schema version is unsupported");
    }
    if object.get("network").and_then(Value::as_str) != Some(expected_network) {
        return Err("registry binding response is for a different network");
    }
    Ok(object)
}

pub(crate) fn object_has_exact_keys(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

pub(crate) fn initial_refresh_status() -> RefreshStatus {
    RefreshStatus::OnDemandGap {
        generation: 0,
        until: TokioInstant::now(),
    }
}

pub(crate) fn new_refresh_channels() -> (watch::Sender<u64>, watch::Sender<RefreshStatus>) {
    let (nudge, _) = watch::channel(0);
    let (status, _) = watch::channel(initial_refresh_status());
    (nudge, status)
}

pub(crate) fn next_delay(failures: u32, jitter_fraction: f64) -> Duration {
    debug_assert!((0.0..=1.0).contains(&jitter_fraction));
    let shift = failures.saturating_sub(1);
    let base_seconds = RETRY_INITIAL_DELAY
        .as_secs()
        .checked_shl(shift)
        .unwrap_or(u64::MAX)
        .min(RETRY_MAX_DELAY.as_secs());
    let base = Duration::from_secs(base_seconds);
    base.saturating_add(base.mul_f64(jitter_fraction / 4.0))
}

pub(crate) fn start_refresh_loop<F, Fut>(
    started: &Arc<OnceLock<()>>,
    nudge: &watch::Sender<u64>,
    status: watch::Sender<RefreshStatus>,
    label: &'static str,
    refresher: F,
) where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), &'static str>> + Send + 'static,
{
    started.get_or_init(|| {
        tokio::spawn(run_refresh_loop(
            Arc::new(refresher),
            nudge.subscribe(),
            status,
            label,
        ));
    });
}

pub(crate) async fn wait_for_refresh(
    nudge: &watch::Sender<u64>,
    mut status: watch::Receiver<RefreshStatus>,
) {
    let initial = *status.borrow_and_update();
    let generation = initial.generation();
    let now = TokioInstant::now();
    let deadline = match initial {
        RefreshStatus::InFlight { deadline, .. } => deadline,
        RefreshStatus::FailureBackoff { until, .. } if now < until => return,
        RefreshStatus::OnDemandGap { until, .. } => until.max(now) + REFRESH_TIMEOUT,
        RefreshStatus::FailureBackoff { .. } => now + REFRESH_TIMEOUT,
    };
    let _ = tokio::time::timeout_at(deadline, async {
        loop {
            let current = *status.borrow_and_update();
            if current.generation() != generation {
                return;
            }
            let should_nudge = match current {
                RefreshStatus::InFlight { .. } => false,
                RefreshStatus::FailureBackoff { until, .. } if TokioInstant::now() < until => {
                    return
                }
                RefreshStatus::OnDemandGap { until, .. } if TokioInstant::now() < until => {
                    tokio::select! {
                        () = tokio::time::sleep_until(until) => {}
                        changed = status.changed() => {
                            if changed.is_err() {
                                return;
                            }
                        }
                    }
                    continue;
                }
                RefreshStatus::FailureBackoff { .. } | RefreshStatus::OnDemandGap { .. } => true,
            };
            if should_nudge {
                nudge.send_modify(|requested| *requested = (*requested).max(generation));
            }
            if status.changed().await.is_err() {
                return;
            }
        }
    })
    .await;
}

async fn run_refresh_loop<F, Fut>(
    refresher: Arc<F>,
    mut nudge: watch::Receiver<u64>,
    status: watch::Sender<RefreshStatus>,
    label: &'static str,
) where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), &'static str>> + Send + 'static,
{
    let mut failures = 0_u32;
    let mut last_completed_at = None;
    let mut next_attempt_at = None;
    let mut generation = status.borrow().generation();
    let mut nudge_pending = false;
    loop {
        if nudge.has_changed().unwrap_or(false) {
            nudge_pending = *nudge.borrow_and_update() >= generation;
        }
        let now = TokioInstant::now();
        let periodic_at = next_attempt_at.unwrap_or(now);
        let demand_at = nudge_pending.then(|| {
            let min_interval_at =
                last_completed_at.map_or(now, |completed| completed + ON_DEMAND_MIN_INTERVAL);
            let backoff_at = if failures > 0 {
                next_attempt_at.unwrap_or(now)
            } else {
                now
            };
            min_interval_at.max(backoff_at)
        });
        let wake_at = demand_at.map_or(periodic_at, |demand| periodic_at.min(demand));
        if now < wake_at {
            tokio::select! {
                () = tokio::time::sleep_until(wake_at) => {}
                changed = nudge.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    nudge_pending = *nudge.borrow_and_update() >= generation;
                    continue;
                }
            }
        }
        let now = TokioInstant::now();
        let periodic_due = next_attempt_at.is_none_or(|next| now >= next);
        let demand_due = demand_at.is_some_and(|demand| now >= demand);
        if periodic_due || demand_due {
            let _ = nudge.borrow_and_update();
            status.send_replace(RefreshStatus::InFlight {
                generation,
                deadline: now + REFRESH_TIMEOUT,
            });
            let result = refresher().await;
            let completed_at = TokioInstant::now();
            last_completed_at = Some(completed_at);
            let delay = if result.is_ok() {
                failures = 0;
                REFRESH_INTERVAL
            } else {
                failures = failures.saturating_add(1);
                next_delay(failures, rand::rng().random::<f64>())
            };
            let next_attempt = completed_at + delay;
            next_attempt_at = Some(next_attempt);
            generation = generation.wrapping_add(1);
            let next_status = if result.is_ok() {
                RefreshStatus::OnDemandGap {
                    generation,
                    until: completed_at + ON_DEMAND_MIN_INTERVAL,
                }
            } else {
                RefreshStatus::FailureBackoff {
                    generation,
                    until: next_attempt,
                }
            };
            status.send_replace(next_status);
            nudge_pending = *nudge.borrow_and_update() >= generation;
            if let Err(error) = result {
                tracing::warn!(error, "{} model bindings refresh was rejected", label);
            }
        }
    }
}
