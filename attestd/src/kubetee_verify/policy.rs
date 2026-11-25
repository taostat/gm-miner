//! AMD platform verification, separate from `KubeTEE` workload authorization.
//!
//! AMD ARK authenticates ASK; ASK authenticates VCEK; VCEK authenticates the
//! report. KDS also binds chip generation + measured TCB to the VCEK's custom
//! extensions. Valid hardware evidence never bypasses workload policy.

use std::fmt::{Display, Formatter};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use asn1_rs::FromDer as _;
use futures_util::StreamExt as _;
use reqwest::{redirect::Policy, Client};
use sev::certs::snp::{
    builtin::{genoa, milan, turin},
    ca, Certificate, Verifiable,
};
use sev::firmware::guest::AttestationReport;
use tokio::sync::watch;
use url::Url;

const HWID_OID: &str = "1.3.6.1.4.1.3704.1.4";
const MICROCODE_OID: &str = "1.3.6.1.4.1.3704.1.3.8";
const SNP_OID: &str = "1.3.6.1.4.1.3704.1.3.3";
const TEE_OID: &str = "1.3.6.1.4.1.3704.1.3.2";
const BOOTLOADER_OID: &str = "1.3.6.1.4.1.3704.1.3.1";
const FMC_OID: &str = "1.3.6.1.4.1.3704.1.3.9";
const MAX_KDS_CERT_SIZE: usize = 1 << 20;
const KDS_TIMEOUT: Duration = Duration::from_secs(20);
const KDS_BACKOFF_MAX: Duration = Duration::from_secs(300);
const VCEK_CACHE_CAPACITY: usize = 128;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub(crate) enum Generation {
    Milan,
    Genoa,
    Turin,
}
impl Generation {
    fn name(self) -> &'static str {
        match self {
            Self::Milan => "Milan",
            Self::Genoa => "Genoa",
            Self::Turin => "Turin",
        }
    }
    fn has_fmc(self) -> bool {
        matches!(self, Self::Turin)
    }
    fn sb_3059_mitigation_bit(self) -> u32 {
        match self {
            Self::Milan => 8,
            Self::Genoa => 6,
            Self::Turin => 12,
        }
    }
    pub(crate) fn of(report: &AttestationReport) -> Result<Self> {
        let family = report.cpuid_fam_id.with_context(|| {
            format!(
                "SNP report v{} lacks its CPU family; CoCo requires v3+",
                report.version
            )
        })?;
        let model = report.cpuid_mod_id.context("SNP report has no CPU model")?;
        match (family, model) {
            (0x19, 0x00..=0x0f) => Ok(Self::Milan),
            (0x19, 0x10..=0x1f | 0xa0..=0xaf) => Ok(Self::Genoa),
            (0x1a, 0x00..=0x11) => Ok(Self::Turin),
            _ => bail!("unsupported AMD family={family:#x} model={model:#x}"),
        }
    }
    fn root(self) -> Result<Certificate> {
        Certificate::from_pem(match self {
            Self::Milan => milan::ARK,
            Self::Genoa => genoa::ARK,
            Self::Turin => turin::ARK,
        })
        .map_err(|error| anyhow::Error::from(error).context("decode built-in AMD root"))
    }
    fn ask(self) -> Result<Certificate> {
        Certificate::from_pem(match self {
            Self::Milan => milan::ASK,
            Self::Genoa => genoa::ASK,
            Self::Turin => turin::ASK,
        })
        .map_err(|error| anyhow::Error::from(error).context("decode built-in AMD intermediate"))
    }
}
impl Display for Generation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

pub(crate) trait AmdEndpoint: Send + Sync {
    fn fetch(&self, url: Url) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
}
pub(crate) struct Kds;
impl AmdEndpoint for Kds {
    async fn fetch(&self, url: Url) -> Result<Vec<u8>> {
        ensure!(
            url.scheme() == "https" && url.host_str() == Some("kdsintf.amd.com"),
            "unrecognized AMD KDS URL"
        );
        fetch_url(kds_client()?, url).await
    }
}

static KDS_CLIENT: OnceLock<std::result::Result<Client, String>> = OnceLock::new();
static VCEK_CACHE: OnceLock<VcekCache> = OnceLock::new();

fn kds_client() -> Result<&'static Client> {
    KDS_CLIENT
        .get_or_init(|| {
            Client::builder()
                .no_proxy()
                .redirect(Policy::none())
                .timeout(KDS_TIMEOUT)
                .build()
                .map_err(|error| format!("build AMD KDS HTTP client: {error}"))
        })
        .as_ref()
        .map_err(|error| anyhow::anyhow!(error.clone()))
}

async fn fetch_url(client: &Client, url: Url) -> Result<Vec<u8>> {
    let response = client
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("AMD KDS {url}"))?;
    let status = response.status();
    ensure!(status.is_success(), "AMD KDS {url} returned {status}");

    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read AMD KDS response")?;
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_KDS_CERT_SIZE,
            "AMD KDS response exceeds the 1 MiB certificate limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    ensure!(!bytes.is_empty(), "AMD KDS returned an empty certificate");
    Ok(bytes)
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct VcekCacheKey {
    product: Generation,
    chip_id: [u8; 64],
    bootloader: u8,
    tee: u8,
    snp: u8,
    microcode: u8,
    fmc: Option<u8>,
}

impl VcekCacheKey {
    fn for_report(product: Generation, report: &AttestationReport) -> Self {
        let tcb = report.reported_tcb;
        Self {
            product,
            chip_id: report.chip_id,
            bootloader: tcb.bootloader,
            tee: tcb.tee,
            snp: tcb.snp,
            microcode: tcb.microcode,
            fmc: tcb.fmc,
        }
    }
}

pub(crate) struct VcekCache {
    capacity: usize,
    entries: Mutex<VcekCacheEntries>,
}

impl Default for VcekCache {
    fn default() -> Self {
        Self::with_capacity(VCEK_CACHE_CAPACITY)
    }
}

impl VcekCache {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: Mutex::new(VcekCacheEntries::default()),
        }
    }
}

#[derive(Default)]
struct VcekCacheEntries {
    // Only fully verified VCEKs enter `certificates`; flights and failures
    // are bounded coordination records for the same report-derived keys.
    certificates: HashMap<VcekCacheKey, CachedVcek>,
    failures: HashMap<VcekCacheKey, FailedFetch>,
    in_flight: HashMap<VcekCacheKey, Arc<VcekCacheEntry>>,
    access_sequence: u64,
}

struct CachedVcek {
    certificate_der: Arc<[u8]>,
    last_used: u64,
}

struct FailedFetch {
    failures: u32,
    retry_after: tokio::time::Instant,
    last_used: u64,
}

impl VcekCacheEntries {
    fn next_access(&mut self) -> u64 {
        self.access_sequence = self.access_sequence.wrapping_add(1);
        self.access_sequence
    }

    fn remove_expired_failures(&mut self, now: tokio::time::Instant, except: &VcekCacheKey) {
        self.failures
            .retain(|key, failure| key == except || failure.retry_after > now);
    }

    fn len(&self) -> usize {
        self.certificates.len() + self.failures.len() + self.in_flight.len()
    }

    fn make_room(&mut self, capacity: usize) -> Result<()> {
        while self.len() >= capacity {
            let oldest_certificate = self
                .certificates
                .iter()
                .min_by_key(|(_, cached)| cached.last_used)
                .map(|(key, cached)| (key.clone(), cached.last_used));
            let oldest_failure = self
                .failures
                .iter()
                .min_by_key(|(_, failure)| failure.last_used)
                .map(|(key, failure)| (key.clone(), failure.last_used));

            match (oldest_certificate, oldest_failure) {
                (Some((key, _)), Some((failed_key, failed_used))) => {
                    let certificate_used = self.certificates[&key].last_used;
                    if certificate_used <= failed_used {
                        self.certificates.remove(&key);
                    } else {
                        self.failures.remove(&failed_key);
                    }
                }
                (Some((key, _)), None) => {
                    self.certificates.remove(&key);
                }
                (None, Some((key, _))) => {
                    self.failures.remove(&key);
                }
                (None, None) => bail!("AMD VCEK cache is full of active fetches"),
            }
        }
        Ok(())
    }
}

struct VcekCacheEntry {
    changed: watch::Sender<u64>,
}

impl VcekCacheEntry {
    fn new() -> Self {
        let (changed, _) = watch::channel(0);
        Self { changed }
    }
}

impl VcekCache {
    async fn get_or_fetch<E, F>(
        &self,
        endpoint: &E,
        key: VcekCacheKey,
        url: Url,
        validate_certificate: F,
    ) -> Result<Arc<[u8]>>
    where
        E: AmdEndpoint,
        F: Fn(&[u8]) -> Result<()>,
    {
        enum Lookup {
            Cached(Arc<[u8]>),
            Wait(watch::Receiver<u64>),
            Fetch(Arc<VcekCacheEntry>, u32),
        }

        loop {
            let lookup = {
                let mut entries = self
                    .entries
                    .lock()
                    .map_err(|_| anyhow::anyhow!("AMD VCEK cache lock is poisoned"))?;
                let now = tokio::time::Instant::now();
                entries.remove_expired_failures(now, &key);

                if let Some(cached) = entries.certificates.get(&key) {
                    let certificate = Arc::clone(&cached.certificate_der);
                    let last_used = entries.next_access();
                    if let Some(cached) = entries.certificates.get_mut(&key) {
                        cached.last_used = last_used;
                    }
                    Lookup::Cached(certificate)
                } else if let Some(failure) = entries.failures.get(&key) {
                    if now < failure.retry_after {
                        bail!(
                            "AMD KDS VCEK fetch is backing off for {:?}",
                            failure.retry_after.duration_since(now)
                        );
                    }
                    let failures = failure.failures;
                    entries.failures.remove(&key);
                    if let Some(entry) = entries.in_flight.get(&key) {
                        Lookup::Wait(entry.changed.subscribe())
                    } else {
                        entries.make_room(self.capacity)?;
                        let entry = Arc::new(VcekCacheEntry::new());
                        entries.in_flight.insert(key.clone(), Arc::clone(&entry));
                        Lookup::Fetch(entry, failures)
                    }
                } else if let Some(entry) = entries.in_flight.get(&key) {
                    Lookup::Wait(entry.changed.subscribe())
                } else {
                    entries.make_room(self.capacity)?;
                    let entry = Arc::new(VcekCacheEntry::new());
                    entries.in_flight.insert(key.clone(), Arc::clone(&entry));
                    Lookup::Fetch(entry, 0)
                }
            };

            match lookup {
                Lookup::Cached(certificate) => {
                    validate_certificate(&certificate).context("validate cached AMD VCEK")?;
                    return Ok(certificate);
                }
                Lookup::Wait(mut changed) => {
                    changed
                        .changed()
                        .await
                        .context("AMD VCEK cache fetch ended without notification")?;
                }
                Lookup::Fetch(entry, failures) => {
                    let mut fetch_leader = VcekFetchLeader {
                        cache: self,
                        key: key.clone(),
                        entry,
                        failures,
                        active: true,
                    };
                    let fetched = async {
                        let certificate = endpoint.fetch(url.clone()).await?;
                        ensure!(
                            !certificate.is_empty() && certificate.len() <= MAX_KDS_CERT_SIZE,
                            "AMD KDS returned an invalid certificate size"
                        );
                        validate_certificate(&certificate)?;
                        Ok::<_, anyhow::Error>(Arc::<[u8]>::from(certificate))
                    }
                    .await;
                    return fetch_leader.finish(fetched);
                }
            }
        }
    }

    #[cfg(test)]
    fn counts(&self) -> (usize, usize, usize) {
        self.entries.lock().map_or((0, 0, 0), |entries| {
            (
                entries.certificates.len(),
                entries.failures.len(),
                entries.in_flight.len(),
            )
        })
    }

    #[cfg(test)]
    fn waiter_count(&self, key: &VcekCacheKey) -> usize {
        self.entries.lock().map_or(0, |entries| {
            entries
                .in_flight
                .get(key)
                .map_or(0, |entry| entry.changed.receiver_count())
        })
    }
}

struct VcekFetchLeader<'a> {
    cache: &'a VcekCache,
    key: VcekCacheKey,
    entry: Arc<VcekCacheEntry>,
    failures: u32,
    active: bool,
}

impl VcekFetchLeader<'_> {
    fn finish(&mut self, fetched: Result<Arc<[u8]>>) -> Result<Arc<[u8]>> {
        let result = {
            let mut entries = self
                .cache
                .entries
                .lock()
                .map_err(|_| anyhow::anyhow!("AMD VCEK cache lock is poisoned"))?;
            let owns_flight = entries
                .in_flight
                .get(&self.key)
                .is_some_and(|entry| Arc::ptr_eq(entry, &self.entry));
            ensure!(owns_flight, "AMD VCEK cache fetch lost ownership");
            entries.in_flight.remove(&self.key);

            match fetched {
                Ok(certificate) => {
                    let last_used = entries.next_access();
                    entries.certificates.insert(
                        self.key.clone(),
                        CachedVcek {
                            certificate_der: Arc::clone(&certificate),
                            last_used,
                        },
                    );
                    Ok(certificate)
                }
                Err(error) => {
                    let failures = self.failures.saturating_add(1);
                    let backoff = kds_backoff(failures);
                    let last_used = entries.next_access();
                    entries.failures.insert(
                        self.key.clone(),
                        FailedFetch {
                            failures,
                            retry_after: tokio::time::Instant::now() + backoff,
                            last_used,
                        },
                    );
                    Err(error).with_context(|| {
                        format!("AMD KDS VCEK fetch failed; retry after {backoff:?}")
                    })
                }
            }
        };
        self.active = false;
        self.entry
            .changed
            .send_modify(|version| *version = version.wrapping_add(1));
        result
    }
}

impl Drop for VcekFetchLeader<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut entries) = self.cache.entries.lock() {
            let owns_flight = entries
                .in_flight
                .get(&self.key)
                .is_some_and(|entry| Arc::ptr_eq(entry, &self.entry));
            if owns_flight {
                entries.in_flight.remove(&self.key);
            }
        }
        self.entry
            .changed
            .send_modify(|version| *version = version.wrapping_add(1));
    }
}

fn kds_backoff(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(8);
    Duration::from_secs((1_u64 << exponent).min(KDS_BACKOFF_MAX.as_secs()))
}

pub(crate) fn shared_vcek_cache() -> &'static VcekCache {
    VCEK_CACHE.get_or_init(VcekCache::default)
}

fn der(certificate: &Certificate) -> Result<Vec<u8>> {
    certificate
        .to_der()
        .map_err(|error| anyhow::Error::from(error).context("encode AMD certificate"))
}
pub(crate) fn subject(certificate: &Certificate) -> Result<String> {
    let der = der(certificate)?;
    let (_, certificate) =
        x509_parser::parse_x509_certificate(&der).context("parse AMD certificate")?;
    let names: Vec<String> = certificate
        .subject()
        .iter_common_name()
        .map(|name| name.as_str().map(ToOwned::to_owned))
        .collect::<std::result::Result<_, _>>()?;
    ensure!(names.len() == 1, "AMD VEK needs a unique subject CN");
    names.into_iter().next().context("missing AMD VEK subject")
}
fn extension<'a>(
    certificate: &'a x509_parser::certificate::X509Certificate<'a>,
    name: &str,
) -> Result<&'a [u8]> {
    let oid = name.parse::<asn1_rs::Oid>()?;
    Ok(certificate
        .get_extension_unique(&oid)?
        .with_context(|| format!("missing AMD extension {name}"))?
        .value)
}
fn octets<const N: usize>(certificate: &Certificate) -> Result<[u8; N]> {
    let der = der(certificate)?;
    let (_, certificate) = x509_parser::parse_x509_certificate(&der).context("parse AMD VCEK")?;
    let value = extension(&certificate, HWID_OID)?;
    // CoCo accepts both the current DER OCTET STRING and legacy raw hwID.
    if value.len() == N {
        return value
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid AMD chip-ID extension"));
    }
    let (_, integer) =
        asn1_rs::OctetString::from_der(value).map_err(|error| anyhow::anyhow!("{error}"))?;
    integer
        .as_ref()
        .try_into()
        .context("invalid AMD chip-ID extension")
}
fn integer(certificate: &Certificate, name: &str) -> Result<u8> {
    let der = der(certificate)?;
    let (_, certificate) = x509_parser::parse_x509_certificate(&der).context("parse AMD VCEK")?;
    let (_, integer) = asn1_rs::Integer::from_der(extension(&certificate, name)?)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    integer.as_u8().map_err(Into::into)
}

/// Verify AMD's ARK -> ASK -> VCEK chain and the VCEK-signed report with the
/// upstream `sev` crate and its pure-Rust crypto backend.
pub(crate) fn verify_report_chain(
    chain: &sev::certs::snp::Chain,
    report: &AttestationReport,
) -> Result<()> {
    (chain, report).verify()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VekKind {
    Vcek,
    Vlek,
}
pub(crate) fn vek_kind(vek: &Certificate) -> Result<VekKind> {
    match subject(vek)?.as_str() {
        "VCEK" | "SEV-VCEK" => Ok(VekKind::Vcek),
        "VLEK" | "SEV-VLEK" => Ok(VekKind::Vlek),
        other => bail!("unexpected AMD VEK subject {other}"),
    }
}

/// Use `CoCo`'s standard certificate-table extraction, then pin the root rather
/// than accepting a CA certificate chosen by the endpoint. Missing tables use
/// the independently fetched KDS key. VEK validity is checked in
/// `verify_vek_with_cache`.
pub(crate) fn chain_from_table(
    entries: &[sev::firmware::host::CertTableEntry],
) -> Result<Option<Certificate>> {
    if entries.is_empty() {
        return Ok(None);
    }
    let certificate = entries
        .iter()
        .find(|e| {
            matches!(
                e.cert_type,
                sev::firmware::host::CertType::VCEK | sev::firmware::host::CertType::VLEK
            )
        })
        .map(|e| Certificate::from_der(&e.data))
        .transpose()
        .map_err(|error| anyhow::Error::from(error).context("decode SNP endorsement key"))?;
    Ok(certificate)
}

pub(crate) async fn verify_vek_with_cache(
    report: &AttestationReport,
    endpoint: &impl AmdEndpoint,
    cache: &VcekCache,
) -> Result<Certificate> {
    let generation = Generation::of(report)?;
    let chip_id = if generation.has_fmc() {
        hex::encode(&report.chip_id[..8])
    } else {
        hex::encode(report.chip_id)
    };
    let tcb = &report.reported_tcb;
    let mut url = Url::parse(&format!(
        "https://kdsintf.amd.com/vcek/v1/{generation}/{chip_id}"
    ))?;
    url.query_pairs_mut()
        .append_pair("blSPL", &tcb.bootloader.to_string())
        .append_pair("teeSPL", &tcb.tee.to_string())
        .append_pair("snpSPL", &tcb.snp.to_string())
        .append_pair("ucodeSPL", &tcb.microcode.to_string());
    if generation.has_fmc() {
        url.query_pairs_mut().append_pair(
            "fmcSPL",
            &tcb.fmc.context("Turin report is missing FMC")?.to_string(),
        );
    }
    let key = VcekCacheKey::for_report(generation, report);
    let der = cache
        .get_or_fetch(endpoint, key, url, |bytes| {
            validate_vek_certificate(report, generation, bytes).map(|_| ())
        })
        .await?;
    let vek = Certificate::from_der(&der)
        .map_err(anyhow::Error::from)
        .context("parse cached AMD KDS VCEK")?;
    let ca = ca::Chain {
        ark: generation.root()?,
        ask: generation.ask()?,
    };
    let chain = sev::certs::snp::Chain {
        ca,
        vek: vek.clone(),
    };
    // The certificate may be cached; the report signature is always checked
    // with the current connection's freshly fetched report.
    verify_report_chain(&chain, report)?;
    Ok(vek)
}

fn validate_vek_certificate(
    report: &AttestationReport,
    generation: Generation,
    der: &[u8],
) -> Result<Certificate> {
    let tcb = &report.reported_tcb;
    let vek = Certificate::from_der(der)
        .map_err(anyhow::Error::from)
        .context("parse AMD KDS VCEK")?;
    ensure!(
        matches!(subject(&vek)?.as_str(), "SEV-VCEK" | "VCEK"),
        "unexpected AMD KDS endorsement key subject"
    );
    // AMD VCEK spec (57230, §3.1): Family 19h has a 64-byte hwID;
    // Turin / Family 1Ah has exactly the report's first 8 bytes.
    if generation.has_fmc() {
        ensure!(
            octets::<8>(&vek)? == report.chip_id[..8],
            "Turin VCEK chip ID does not match the report"
        );
    } else {
        ensure!(
            octets::<64>(&vek)? == report.chip_id,
            "VCEK chip ID does not match the report"
        );
    }
    ensure!(
        integer(&vek, MICROCODE_OID)? == tcb.microcode,
        "VCEK microcode is not the report's measured TCB"
    );
    ensure!(
        integer(&vek, SNP_OID)? == tcb.snp,
        "VCEK SNP firmware is not the report's measured TCB"
    );
    ensure!(
        integer(&vek, TEE_OID)? == tcb.tee,
        "VCEK TEE is not the report's measured TCB"
    );
    ensure!(
        integer(&vek, BOOTLOADER_OID)? == tcb.bootloader,
        "VCEK boot loader is not the report's measured TCB"
    );
    if generation.has_fmc() {
        ensure!(
            integer(&vek, FMC_OID)? == tcb.fmc.context("Turin report is missing FMC")?,
            "VCEK FMC is not the report's measured TCB"
        );
    }
    let ca = ca::Chain {
        ark: generation.root()?,
        ask: generation.ask()?,
    };
    (&ca).verify().context("AMD ARK/ASK chain is invalid")?;
    let chain = sev::certs::snp::Chain {
        ca,
        vek: vek.clone(),
    };
    (&chain)
        .verify()
        .context("AMD ARK/ASK/VCEK chain is invalid")?;
    Ok(vek)
}

/// Exact release tuples measured in the candidate guest. Updated only after
/// genuine candidate appraisal, never from host-written JSON claims alone.
/// Only the measured active `LiteLLM` v1.110.2 / `CoCo` v0.23.0 composition is
/// authorized. Future releases require a new signed reference and client review.
static RELEASES: &[Release] = &[Release {
    measurement: [
        0x20, 0xf0, 0xe1, 0x83, 0xb7, 0x84, 0x4c, 0xc8, 0x35, 0x11, 0x8d, 0x80, 0x46, 0x99, 0xab,
        0x8b, 0x6c, 0xda, 0xb2, 0x97, 0x41, 0x4d, 0x8f, 0x54, 0xd7, 0x03, 0x31, 0x37, 0x8f, 0xf0,
        0xd7, 0xfd, 0xd8, 0xa7, 0x54, 0x8a, 0x02, 0x53, 0xba, 0x56, 0x1b, 0xec, 0x21, 0xe1, 0x3a,
        0x0d, 0xcc, 0x67,
    ],
    host_data: [
        0x5b, 0xd1, 0xfe, 0x02, 0x8a, 0x63, 0x2b, 0x9e, 0xfc, 0x6e, 0xce, 0xed, 0xcb, 0xf5, 0xa3,
        0x44, 0xb1, 0x3e, 0xd1, 0xda, 0xb6, 0xc1, 0xb3, 0xa8, 0x29, 0x5f, 0x0f, 0xf2, 0x0a, 0xeb,
        0xe3, 0xaa,
    ],
    supported_generations: &[Generation::Genoa, Generation::Turin],
}];

// AMD-SB-3038 and the newer AMD-SB-3059 publish progressively higher
// mitigation TCB[SNP] values: Milan 0x1F, Genoa 0x1E, and Turin 0x8.
static SNP_TCB_FLOORS: &[TcbSnpFloor] = &[
    TcbSnpFloor {
        generation: Generation::Milan,
        minimum: 0x1f,
    },
    TcbSnpFloor {
        generation: Generation::Genoa,
        minimum: 0x1e,
    },
    TcbSnpFloor {
        generation: Generation::Turin,
        minimum: 0x08,
    },
];

struct Release {
    measurement: [u8; 48],
    host_data: [u8; 32],
    supported_generations: &'static [Generation],
}
#[derive(Clone, Copy)]
struct TcbSnpFloor {
    generation: Generation,
    minimum: u8,
}

fn snp_tcb_floor(generation: Generation) -> Result<u8> {
    SNP_TCB_FLOORS
        .iter()
        .find(|floor| floor.generation == generation)
        .map(|floor| floor.minimum)
        .with_context(|| format!("no AMD-published SNP TCB floor for {generation}"))
}

fn require_sb_3059_mitigation(report: &AttestationReport, generation: Generation) -> Result<()> {
    ensure!(
        report.version >= 5,
        "SNP report version {} lacks AMD-SB-3059 mitigation vectors",
        report.version
    );
    let launch = report
        .launch_mit_vector
        .context("SNP report lacks launch_mit_vector")?;
    let current = report
        .current_mit_vector
        .context("SNP report lacks current_mit_vector")?;
    // AMD-SB-3059 assigns bits 8/6/12 to Milan/Genoa/Turin. AMD SNP ABI §3.5
    // defines these vectors as verified mitigation state, separate from TCB[SNP].
    let bit = generation.sb_3059_mitigation_bit();
    let mask = 1_u64 << bit;
    ensure!(
        launch & mask != 0,
        "AMD-SB-3059 mitigation bit {bit} is absent from launch_mit_vector"
    );
    ensure!(
        current & mask != 0,
        "AMD-SB-3059 mitigation bit {bit} is absent from current_mit_vector"
    );
    Ok(())
}

pub(crate) fn accept(report: &AttestationReport) -> Result<()> {
    ensure!(
        (3..=5).contains(&report.version),
        "unsupported SNP report version"
    );
    ensure!(report.vmpl == 0, "SNP report VMPL is not zero");
    ensure!(!report.policy.debug_allowed(), "SNP guest permits debug");
    ensure!(
        !report.policy.migrate_ma_allowed(),
        "SNP guest permits migration"
    );
    let generation = Generation::of(report)?;
    let minimum = snp_tcb_floor(generation)?;
    ensure!(
        report.launch_tcb.snp >= minimum,
        "SNP launch TCB is below AMD's {generation} minimum TCB[SNP] {minimum:#04x}"
    );
    ensure!(
        report.reported_tcb.snp >= minimum,
        "SNP reported TCB is below AMD's {generation} minimum TCB[SNP] {minimum:#04x}"
    );
    require_sb_3059_mitigation(report, generation)?;
    ensure!(
        RELEASES
            .iter()
            .filter(|release| {
                release.measurement == report.measurement && release.host_data == report.host_data
            })
            .any(|release| release.supported_generations.contains(&generation)),
        "SNP guest measurements are outside the explicit KubeTEE release policy"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests use checked fixture values")]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::Value;

    use super::*;

    struct CountingEndpoint {
        calls: Arc<AtomicUsize>,
        response: std::result::Result<Vec<u8>, &'static str>,
        delay: Duration,
    }

    impl AmdEndpoint for CountingEndpoint {
        async fn fetch(&self, _url: Url) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.response.clone().map_err(anyhow::Error::msg)
        }
    }

    struct CancelLeaderEndpoint {
        calls: AtomicUsize,
        leader_started: tokio::sync::Notify,
    }

    impl AmdEndpoint for CancelLeaderEndpoint {
        async fn fetch(&self, _url: Url) -> Result<Vec<u8>> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.leader_started.notify_one();
                std::future::pending::<()>().await;
            }
            Ok(b"test-vcek".to_vec())
        }
    }

    fn test_key(chip: u8, product: Generation, snp: u8) -> VcekCacheKey {
        VcekCacheKey {
            product,
            chip_id: [chip; 64],
            bootloader: 1,
            tee: 2,
            snp,
            microcode: 3,
            fmc: None,
        }
    }

    fn test_url() -> Url {
        Url::parse("https://kdsintf.amd.com/vcek/test").unwrap()
    }

    #[test]
    fn the_active_snp_release_pin_is_valid_and_distinct_from_raw_toml_hashes() {
        let release = &RELEASES[0];
        assert_eq!(release.host_data.len(), 32);
        assert_eq!(release.measurement.len(), 48);
        assert_eq!(
            hex::encode(release.host_data),
            "5bd1fe028a632b9efc6eceedcbf5a344b13ed1dab6c1b3a8295f0ff20aebe3aa"
        );
    }

    #[test]
    fn unsuccessful_fallback_does_not_assume_snp_hardware_verification() {
        let report = AttestationReport::default();
        assert!(accept(&report).is_err());
    }

    fn production_turin_report() -> AttestationReport {
        let response: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/kubetee/snp/production-turin-evidence.json"
        ))
        .unwrap();
        crate::kubetee_verify::snp::report(&response["evidence"]["snp"]).unwrap()
    }

    #[test]
    fn amd_bulletin_floors_cover_milan_genoa_and_turin() {
        assert_eq!(snp_tcb_floor(Generation::Milan).unwrap(), 0x1f);
        assert_eq!(snp_tcb_floor(Generation::Genoa).unwrap(), 0x1e);
        assert_eq!(snp_tcb_floor(Generation::Turin).unwrap(), 0x08);
        assert_eq!(Generation::Milan.sb_3059_mitigation_bit(), 8);
        assert_eq!(Generation::Genoa.sb_3059_mitigation_bit(), 6);
        assert_eq!(Generation::Turin.sb_3059_mitigation_bit(), 12);
    }

    fn release_eligible_turin_report() -> AttestationReport {
        let mut report = production_turin_report();
        report.launch_tcb.snp = 0x08;
        report.reported_tcb.snp = 0x08;
        report.policy.set_smt_allowed(false);
        let mitigation = 1_u64 << Generation::Turin.sb_3059_mitigation_bit();
        report.launch_mit_vector = Some(mitigation);
        report.current_mit_vector = Some(mitigation);
        report
    }

    #[test]
    fn vcek_cache_key_derives_each_report_tuple_component() {
        let base_report = production_turin_report();
        let base_key = VcekCacheKey::for_report(Generation::Turin, &base_report);

        let identical_report = production_turin_report();
        assert_eq!(base_report, identical_report);
        assert!(
            base_key == VcekCacheKey::for_report(Generation::Turin, &identical_report),
            "identical reports must produce equal cache keys"
        );

        // Product is supplied separately from the report; hold the report fixed.
        assert!(
            base_key != VcekCacheKey::for_report(Generation::Genoa, &base_report),
            "product must isolate cache keys"
        );

        let mut changed_report = base_report;
        changed_report.chip_id[0] ^= 1;
        assert!(
            base_key != VcekCacheKey::for_report(Generation::Turin, &changed_report),
            "chip ID must isolate cache keys"
        );

        let mut changed_report = base_report;
        changed_report.reported_tcb.bootloader ^= 1;
        assert!(
            base_key != VcekCacheKey::for_report(Generation::Turin, &changed_report),
            "bootloader TCB must isolate cache keys"
        );

        let mut changed_report = base_report;
        changed_report.reported_tcb.tee ^= 1;
        assert!(
            base_key != VcekCacheKey::for_report(Generation::Turin, &changed_report),
            "TEE TCB must isolate cache keys"
        );

        let mut changed_report = base_report;
        changed_report.reported_tcb.snp ^= 1;
        assert!(
            base_key != VcekCacheKey::for_report(Generation::Turin, &changed_report),
            "SNP TCB must isolate cache keys"
        );

        let mut changed_report = base_report;
        changed_report.reported_tcb.microcode ^= 1;
        assert!(
            base_key != VcekCacheKey::for_report(Generation::Turin, &changed_report),
            "microcode TCB must isolate cache keys"
        );

        let mut changed_report = base_report;
        changed_report.reported_tcb.fmc = Some(
            changed_report
                .reported_tcb
                .fmc
                .map_or(1, |version| version.wrapping_add(1)),
        );
        assert!(
            base_key != VcekCacheKey::for_report(Generation::Turin, &changed_report),
            "FMC TCB must isolate cache keys"
        );
    }

    #[test]
    fn launch_and_reported_tcb_must_each_meet_the_amd_floor() {
        let mut report = release_eligible_turin_report();
        assert!(accept(&report).is_ok());

        report.launch_tcb.snp = 0x07;
        let error = accept(&report).unwrap_err();
        assert!(error.to_string().contains("launch TCB"), "{error}");

        report.launch_tcb.snp = 0x08;
        report.reported_tcb.snp = 0x07;
        let error = accept(&report).unwrap_err();
        assert!(error.to_string().contains("reported TCB"), "{error}");
    }

    #[test]
    fn amd_sb_3059_bit_must_be_set_in_both_mitigation_vectors() {
        let mut report = release_eligible_turin_report();
        report.launch_mit_vector = Some(0);
        let error = accept(&report).unwrap_err();
        assert!(error.to_string().contains("launch_mit_vector"), "{error}");

        report.launch_mit_vector = Some(1_u64 << 12);
        report.current_mit_vector = Some(0);
        let error = accept(&report).unwrap_err();
        assert!(error.to_string().contains("current_mit_vector"), "{error}");
    }

    #[test]
    fn mitigation_vectors_missing_from_report_versions_fail_closed() {
        for version in [3, 4] {
            let mut report = release_eligible_turin_report();
            report.version = version;
            report.launch_mit_vector = None;
            report.current_mit_vector = None;
            let error = accept(&report).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("lacks AMD-SB-3059 mitigation vectors"),
                "version {version}: {error}"
            );
        }
    }

    #[test]
    fn missing_mitigation_vector_fields_fail_closed() {
        let mut report = release_eligible_turin_report();
        report.launch_mit_vector = None;
        let error = accept(&report).unwrap_err();
        assert!(format!("{error:#}").contains("lacks launch_mit_vector"));

        report.launch_mit_vector = Some(1_u64 << 12);
        report.current_mit_vector = None;
        let error = accept(&report).unwrap_err();
        assert!(format!("{error:#}").contains("lacks current_mit_vector"));
    }

    #[test]
    fn a_turin_report_below_the_published_snp_floor_is_rejected() {
        let report = production_turin_report();
        assert_eq!(report.reported_tcb.snp, 0x06);
        let error = accept(&report).unwrap_err();
        assert!(error.to_string().contains("launch TCB"), "{error}");
    }

    #[tokio::test]
    async fn vcek_cache_reuses_validated_certificates_for_the_same_tuple() {
        let calls = Arc::new(AtomicUsize::new(0));
        let endpoint = CountingEndpoint {
            calls: Arc::clone(&calls),
            response: Ok(b"test-vcek".to_vec()),
            delay: Duration::ZERO,
        };
        let cache = VcekCache::default();
        let key = test_key(1, Generation::Turin, 8);
        let validate = |bytes: &[u8]| {
            ensure!(bytes == b"test-vcek", "unexpected test certificate");
            Ok(())
        };
        let first = cache
            .get_or_fetch(&endpoint, key.clone(), test_url(), validate)
            .await
            .unwrap();
        let second = cache
            .get_or_fetch(&endpoint, key, test_url(), validate)
            .await
            .unwrap();
        assert_eq!(&*first, b"test-vcek");
        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn vcek_cache_keys_are_isolated_by_each_report_tuple_component() {
        let calls = Arc::new(AtomicUsize::new(0));
        let endpoint = CountingEndpoint {
            calls: Arc::clone(&calls),
            response: Ok(b"test-vcek".to_vec()),
            delay: Duration::ZERO,
        };
        let cache = VcekCache::default();
        let base = test_key(1, Generation::Turin, 8);
        let mut product = base.clone();
        product.product = Generation::Genoa;
        let mut chip_id = base.clone();
        chip_id.chip_id = [2; 64];
        let mut bootloader = base.clone();
        bootloader.bootloader = 2;
        let mut tee = base.clone();
        tee.tee = 3;
        let mut snp = base.clone();
        snp.snp = 9;
        let mut microcode = base.clone();
        microcode.microcode = 4;
        let mut fmc = base.clone();
        fmc.fmc = Some(5);
        let keys = [base, product, chip_id, bootloader, tee, snp, microcode, fmc];
        let validate = |bytes: &[u8]| {
            ensure!(bytes == b"test-vcek", "unexpected test certificate");
            Ok(())
        };

        for key in keys {
            cache
                .get_or_fetch(&endpoint, key, test_url(), validate)
                .await
                .unwrap();
        }

        assert_eq!(calls.load(Ordering::SeqCst), 8);
        assert_eq!(cache.counts(), (8, 0, 0));
    }

    #[tokio::test]
    async fn vcek_cache_bounds_failed_keys_from_a_hostile_endpoint() {
        let calls = Arc::new(AtomicUsize::new(0));
        let endpoint = CountingEndpoint {
            calls: Arc::clone(&calls),
            response: Ok(b"untrusted-vcek".to_vec()),
            delay: Duration::ZERO,
        };
        let capacity = 8;
        let cache = VcekCache::with_capacity(capacity);
        let validate = |_: &[u8]| -> Result<()> { bail!("certificate verification failed") };

        for chip in 0_u16..=u8::MAX.into() {
            let key = test_key(u8::try_from(chip).unwrap(), Generation::Turin, 8);
            assert!(cache
                .get_or_fetch(&endpoint, key, test_url(), validate)
                .await
                .is_err());
            let (certificates, failures, flights) = cache.counts();
            assert!(certificates + failures + flights <= capacity);
        }

        assert_eq!(calls.load(Ordering::SeqCst), 256);
        assert_eq!(cache.counts(), (0, capacity, 0));
        let oldest_key = test_key(0, Generation::Turin, 8);
        assert!(cache
            .get_or_fetch(&endpoint, oldest_key, test_url(), validate)
            .await
            .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 257);
        assert_eq!(cache.counts(), (0, capacity, 0));
    }

    #[tokio::test]
    async fn vcek_cache_evicts_the_least_recently_used_verified_certificate() {
        let calls = Arc::new(AtomicUsize::new(0));
        let endpoint = CountingEndpoint {
            calls: Arc::clone(&calls),
            response: Ok(b"test-vcek".to_vec()),
            delay: Duration::ZERO,
        };
        let cache = VcekCache::with_capacity(2);
        let first = test_key(31, Generation::Turin, 8);
        let second = test_key(32, Generation::Turin, 8);
        let third = test_key(33, Generation::Turin, 8);
        let validate = |bytes: &[u8]| {
            ensure!(bytes == b"test-vcek", "unexpected test certificate");
            Ok(())
        };

        for key in [first.clone(), second.clone()] {
            cache
                .get_or_fetch(&endpoint, key, test_url(), validate)
                .await
                .unwrap();
        }
        cache
            .get_or_fetch(&endpoint, first.clone(), test_url(), validate)
            .await
            .unwrap();
        cache
            .get_or_fetch(&endpoint, third, test_url(), validate)
            .await
            .unwrap();
        assert_eq!(cache.counts(), (2, 0, 0));

        cache
            .get_or_fetch(&endpoint, first, test_url(), validate)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        cache
            .get_or_fetch(&endpoint, second, test_url(), validate)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(cache.counts(), (2, 0, 0));
    }

    #[tokio::test]
    async fn cancelled_fetch_leader_wakes_waiter_to_fetch_again() {
        let endpoint = Arc::new(CancelLeaderEndpoint {
            calls: AtomicUsize::new(0),
            leader_started: tokio::sync::Notify::new(),
        });
        let cache = Arc::new(VcekCache::default());
        let key = test_key(11, Generation::Turin, 8);
        let validate = |bytes: &[u8]| {
            ensure!(bytes == b"test-vcek", "unexpected test certificate");
            Ok(())
        };

        let leader_endpoint = Arc::clone(&endpoint);
        let leader_cache = Arc::clone(&cache);
        let leader_key = key.clone();
        let leader = tokio::spawn(async move {
            leader_cache
                .get_or_fetch(&*leader_endpoint, leader_key, test_url(), validate)
                .await
        });
        endpoint.leader_started.notified().await;

        let waiter_endpoint = Arc::clone(&endpoint);
        let waiter_cache = Arc::clone(&cache);
        let waiter_key = key.clone();
        let waiter = tokio::spawn(async move {
            waiter_cache
                .get_or_fetch(&*waiter_endpoint, waiter_key, test_url(), validate)
                .await
        });
        let subscribed = tokio::time::timeout(Duration::from_secs(1), async {
            while cache.waiter_count(&key) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(subscribed.is_ok(), "waiter did not join the active fetch");

        leader.abort();
        assert!(leader.await.is_err());
        let recovered = tokio::time::timeout(Duration::from_secs(1), waiter).await;
        assert!(
            recovered.is_ok(),
            "waiter did not recover after cancellation"
        );
        assert!(recovered.unwrap().unwrap().is_ok());
        assert_eq!(endpoint.calls.load(Ordering::SeqCst), 2);
        assert_eq!(cache.counts(), (1, 0, 0));
    }

    #[tokio::test]
    async fn vcek_cache_fetches_once_for_concurrent_requests() {
        let calls = Arc::new(AtomicUsize::new(0));
        let endpoint = CountingEndpoint {
            calls: Arc::clone(&calls),
            response: Ok(b"test-vcek".to_vec()),
            delay: Duration::from_millis(30),
        };
        let cache = VcekCache::default();
        let key = test_key(2, Generation::Genoa, 30);
        let validate = |bytes: &[u8]| {
            ensure!(bytes == b"test-vcek", "unexpected test certificate");
            Ok(())
        };
        let (first, second) = tokio::join!(
            cache.get_or_fetch(&endpoint, key.clone(), test_url(), validate),
            cache.get_or_fetch(&endpoint, key, test_url(), validate),
        );
        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_vcek_fetches_use_exponential_backoff() {
        let calls = Arc::new(AtomicUsize::new(0));
        let endpoint = CountingEndpoint {
            calls: Arc::clone(&calls),
            response: Err("offline"),
            delay: Duration::ZERO,
        };
        let cache = VcekCache::default();
        let key = test_key(3, Generation::Milan, 31);
        let validate = |_: &[u8]| Ok(());

        let first = cache
            .get_or_fetch(&endpoint, key.clone(), test_url(), validate)
            .await
            .unwrap_err();
        assert!(format!("{first:#}").contains("retry after 1s"));
        assert_eq!(cache.counts(), (0, 1, 0));
        let waiting = cache
            .get_or_fetch(&endpoint, key.clone(), test_url(), validate)
            .await
            .unwrap_err();
        assert!(format!("{waiting:#}").contains("backing off"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_secs(1)).await;
        let second = cache
            .get_or_fetch(&endpoint, key.clone(), test_url(), validate)
            .await
            .unwrap_err();
        assert!(format!("{second:#}").contains("retry after 2s"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(cache
            .get_or_fetch(&endpoint, key, test_url(), validate)
            .await
            .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn expired_failure_entries_are_removed_on_the_next_cache_operation() {
        let failed_endpoint = CountingEndpoint {
            calls: Arc::new(AtomicUsize::new(0)),
            response: Err("offline"),
            delay: Duration::ZERO,
        };
        let cache = VcekCache::default();
        let failed_key = test_key(19, Generation::Milan, 31);
        assert!(cache
            .get_or_fetch(&failed_endpoint, failed_key, test_url(), |_: &[u8]| Ok(()))
            .await
            .is_err());
        assert_eq!(cache.counts(), (0, 1, 0));

        tokio::time::advance(Duration::from_secs(1)).await;
        let success_endpoint = CountingEndpoint {
            calls: Arc::new(AtomicUsize::new(0)),
            response: Ok(b"test-vcek".to_vec()),
            delay: Duration::ZERO,
        };
        assert!(cache
            .get_or_fetch(
                &success_endpoint,
                test_key(20, Generation::Milan, 31),
                test_url(),
                |bytes: &[u8]| {
                    ensure!(bytes == b"test-vcek", "unexpected test certificate");
                    Ok(())
                }
            )
            .await
            .is_ok());
        assert_eq!(cache.counts(), (1, 0, 0));
    }

    #[tokio::test]
    async fn shared_kds_client_does_not_follow_redirects() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let server_requests = Arc::clone(&requests);
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut request = [0_u8; 1024];
                let read = stream.read(&mut request).await.unwrap_or_default();
                if read == 0 {
                    continue;
                }
                server_requests.fetch_add(1, Ordering::SeqCst);
                let response = if request.starts_with(b"GET /redirect ") {
                    b"HTTP/1.1 302 Found\r\nLocation: /target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                        .as_slice()
                };
                if stream.write_all(response).await.is_err() {
                    break;
                }
            }
        });
        let url = Url::parse(&format!("http://{address}/redirect")).unwrap();
        let error = fetch_url(kds_client().unwrap(), url).await.unwrap_err();
        assert!(error.to_string().contains("302"), "{error:#}");
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn kds_response_size_is_limited_while_streaming() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            if stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .is_err()
            {
                return;
            }
            let chunk = vec![b'x'; 8192];
            for _ in 0..=(MAX_KDS_CERT_SIZE / chunk.len()) {
                let frame = format!("{:X}\r\n", chunk.len());
                if stream.write_all(frame.as_bytes()).await.is_err()
                    || stream.write_all(&chunk).await.is_err()
                    || stream.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let url = Url::parse(&format!("http://{address}/certificate")).unwrap();
        let bounded = tokio::time::timeout(
            Duration::from_secs(1),
            fetch_url(kds_client().unwrap(), url),
        )
        .await;
        assert!(bounded.is_ok(), "size enforcement waited for response EOF");
        let error = bounded.unwrap().unwrap_err();
        assert!(error.to_string().contains("1 MiB"), "{error:#}");
        server.abort();
        let _ = server.await;
    }
}
