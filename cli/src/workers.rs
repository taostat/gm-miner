//! The hotkey's workers as the registry sees them: which of them is worker #1,
//! and the health view for the rest (suspension recovery state and upstream key
//! slots the registry could not verify).

use chrono::{DateTime, Utc};

use crate::config::WorkerRecord;
use crate::types::WorkerEntry;

/// The miner's worker #1: the oldest worker the registry still lists as live.
///
/// `POST /miners/register` — what `deploy` and `register-image` call — refreshes
/// *this* worker's row, so it is the only worker those two commands may target.
/// The registry deregisters workers without the CLI ever hearing about it, so
/// worker #1 can only be read from the live list, never from a local record's
/// position.
///
/// Oldest is `created_at`, tie-broken by the ULID `worker_id` — ULIDs are
/// lexicographically time-ordered, so the tiebreak is also the fallback for a
/// registry build that does not emit `created_at`.
#[must_use]
pub fn first_live_worker_id(live: &[WorkerEntry]) -> Option<&str> {
    live.iter()
        .min_by_key(|w| (w.created_at.as_deref().unwrap_or(""), w.worker_id.as_str()))
        .map(|w| w.worker_id.as_str())
}

/// Whether the locally-tracked `tracked` is a *secondary* worker — one that
/// `deploy` / `register-image` must refuse, because routing it through
/// `POST /miners/register` would overwrite worker #1's endpoint and secret.
///
/// `live` is the registry's current worker list (`GET /miners/{hotkey}/workers`)
/// and is the only source of truth here. Three cases:
///
/// * **Not yet registered** (empty `worker_id`) — the registry has never seen
///   it, so only the local `provisional_secondary` flag can tell a failed
///   `worker add` from an in-flight worker-#1 (re)deploy.
/// * **Registered but no longer live** — the registry deregistered it. Local
///   records are never pruned, so this record is a ghost: a deploy under its
///   name registers a fresh worker exactly as an untracked `--app-name` would,
///   and there is nothing to overwrite. Not secondary.
/// * **Live** — secondary iff it is not the oldest live worker
///   ([`first_live_worker_id`]).
#[must_use]
pub fn is_secondary_live(tracked: &WorkerRecord, live: &[WorkerEntry]) -> bool {
    if tracked.worker_id.is_empty() {
        return tracked.provisional_secondary;
    }
    if !live.iter().any(|w| w.worker_id == tracked.worker_id) {
        return false;
    }
    first_live_worker_id(live) != Some(tracked.worker_id.as_str())
}

/// The recovery view for a worker that is suspended or carrying a dead key.
/// A healthy worker renders nothing, so the common case stays a clean table.
#[must_use]
pub fn worker_health_lines(
    worker: &WorkerEntry,
    consecutive_ok_required: u32,
    now: DateTime<Utc>,
) -> Vec<String> {
    let dead = dead_slot_lines(worker);
    // `suspended_at` is only ever set, never cleared, so a restored worker still
    // carries a stale one — `status` is the only truthful source.
    let suspended = worker.status == "suspended";
    if !suspended && dead.is_empty() {
        return Vec::new();
    }

    let mut lines = vec![
        String::new(),
        format!("{} ({})", worker.worker_id, worker.status),
    ];
    if suspended {
        if let Some(since) = worker.suspended_at.as_deref() {
            lines.push(format!("  suspended since : {since}"));
        }
        if let Some(seen) = worker.last_seen_at.as_deref() {
            lines.push(format!("  last seen       : {seen}"));
        }
        match worker.next_probe_at.as_deref() {
            Some(next) => lines.push(format!(
                "  next re-probe   : {next}{}",
                relative_suffix(next, now)
            )),
            None => lines.push("  next re-probe   : on the next control-loop cycle".to_owned()),
        }
        // A registry that predates the threshold omits it, and "0 of 0 probes"
        // reads as nonsense — report only what that registry actually told us.
        if consecutive_ok_required > 0 {
            lines.push(format!(
                "  to recover      : {} of {} consecutive good probes so far (re-probe attempt {})",
                worker.consecutive_ok, consecutive_ok_required, worker.suspended_reprobe_attempt,
            ));
        } else {
            lines.push(format!(
                "  to recover      : {} consecutive good probes so far (re-probe attempt {})",
                worker.consecutive_ok, worker.suspended_reprobe_attempt,
            ));
        }
        lines.push(
            "  The registry re-probes on its own — fix the worker and it restores itself."
                .to_owned(),
        );
    }
    lines.extend(dead);
    lines
}

/// Name the upstream key slots the registry could not verify.
///
/// The slot id is HMAC-derived from the key, so the operator can re-derive it
/// locally to identify which of its keys this is.
#[must_use]
pub fn dead_slot_lines(worker: &WorkerEntry) -> Vec<String> {
    let mut lines = Vec::new();
    for (provider, slots) in &worker.provider_slot_status {
        for (slot_id, state) in slots {
            if state.status.as_deref() == Some("verified") {
                continue;
            }
            lines.push(format!(
                "  unverified key  : {provider} slot {slot_id} — the registry could not use this key"
            ));
        }
    }
    lines
}

/// Empty when the timestamp does not parse — a display aid must never fail the
/// command.
#[must_use]
pub fn relative_suffix(timestamp: &str, now: DateTime<Utc>) -> String {
    let Ok(at) = DateTime::parse_from_rfc3339(timestamp) else {
        return String::new();
    };
    let delta = at.with_timezone(&Utc) - now;
    let secs = delta.num_seconds();
    if secs <= 0 {
        return " (due now)".to_owned();
    }
    if secs < 60 {
        return format!(" (in {secs}s)");
    }
    format!(" (in {}m)", secs / 60)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::{
        first_live_worker_id, is_secondary_live, worker_health_lines, DateTime, Utc, WorkerEntry,
        WorkerRecord,
    };

    fn worker_entry(status: &str) -> WorkerEntry {
        serde_json::from_value(serde_json::json!({
            "worker_id": "01J0A",
            "endpoint": "https://w1.example.org:8443",
            "status": status,
            "last_attestation_at": null,
        }))
        .expect("decode minimal worker entry")
    }

    /// A live worker row as `GET /miners/{hotkey}/workers` returns it.
    fn live(worker_id: &str, created_at: &str) -> WorkerEntry {
        serde_json::from_value(serde_json::json!({
            "worker_id": worker_id,
            "endpoint": format!("https://{worker_id}.example.org"),
            "status": "active",
            "last_attestation_at": null,
            "created_at": created_at,
        }))
        .expect("decode live worker entry")
    }

    fn record(worker_id: &str, app_name: &str) -> WorkerRecord {
        WorkerRecord {
            worker_id: worker_id.to_owned(),
            app_id: format!("app_{app_name}"),
            app_name: app_name.to_owned(),
            node_secret: "s".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn first_live_worker_is_the_oldest_row_not_the_first_returned() {
        let workers = vec![
            live("01J0C", "2026-07-03T00:00:00Z"),
            live("01J0A", "2026-07-01T00:00:00Z"),
            live("01J0B", "2026-07-02T00:00:00Z"),
        ];
        assert_eq!(first_live_worker_id(&workers), Some("01J0A"));
        assert_eq!(first_live_worker_id(&[]), None);
    }

    #[test]
    fn first_live_worker_falls_back_to_the_ulid_without_created_at() {
        // A registry build that omits `created_at` still orders correctly:
        // ULIDs are lexicographically time-ordered.
        let workers = vec![worker_entry("active"), {
            let mut older = worker_entry("active");
            older.worker_id = "01J00".to_owned();
            older
        }];
        assert_eq!(first_live_worker_id(&workers), Some("01J00"));
    }

    /// Regression: the deregistered workers ahead of the live one in the local
    /// list must not make the live one look secondary.
    ///
    /// The operator's config held three testnet records — two whose registry
    /// rows were deregistered, then the one live worker. A positional check
    /// called the live worker "worker #2" and refused to redeploy the only
    /// worker actually serving.
    #[test]
    fn the_only_live_worker_is_never_secondary_whatever_its_local_position() {
        let workers = vec![live("01J0Z", "2026-07-03T00:00:00Z")];

        // Position 1 and 2 locally, both deregistered: ghosts, not worker #1.
        assert!(!is_secondary_live(&record("01J0A", "gm-miner-2"), &workers));
        assert!(!is_secondary_live(
            &record("01J0B", "gm-miner-slots"),
            &workers
        ));
        // Position 3 locally, and the registry's only live worker.
        assert!(!is_secondary_live(
            &record("01J0Z", "gm-miner-zai"),
            &workers
        ));
    }

    /// The invariant the guard exists for: a genuinely-secondary *live* worker
    /// must stay off `/miners/register`, which would overwrite worker #1.
    #[test]
    fn a_live_worker_that_is_not_the_oldest_is_secondary() {
        let workers = vec![
            live("01J0A", "2026-07-01T00:00:00Z"),
            live("01J0B", "2026-07-02T00:00:00Z"),
        ];
        assert!(!is_secondary_live(&record("01J0A", "gm-miner-1"), &workers));
        assert!(is_secondary_live(&record("01J0B", "gm-miner-2"), &workers));
    }

    #[test]
    fn provisional_stubs_are_classified_by_their_flag_alone() {
        let workers = vec![live("01J0A", "2026-07-01T00:00:00Z")];

        // An in-flight worker-#1 (re)deploy: retryable through `deploy`.
        let primary_stub = record("", "gm-miner-1b");
        assert!(!is_secondary_live(&primary_stub, &workers));

        // A `worker add` that launched a CVM but never registered: still must
        // not be routed through the worker-#1 path.
        let secondary_stub = WorkerRecord {
            provisional_secondary: true,
            ..record("", "gm-miner-3")
        };
        assert!(is_secondary_live(&secondary_stub, &workers));
        // …and with no live workers at all (a wiped registry), unchanged.
        assert!(is_secondary_live(&secondary_stub, &[]));
        assert!(!is_secondary_live(&primary_stub, &[]));
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-11T09:00:00+00:00")
            .expect("parse fixed now")
            .with_timezone(&Utc)
    }

    #[test]
    fn healthy_worker_renders_no_health_block() {
        assert!(worker_health_lines(&worker_entry("active"), 2, now()).is_empty());
    }

    #[test]
    fn a_restored_worker_with_a_stale_suspended_at_renders_nothing() {
        let mut worker = worker_entry("active");
        worker.suspended_at = Some("2026-07-11T08:30:00+00:00".to_owned());
        worker.suspended_reprobe_attempt = 3;

        assert!(worker_health_lines(&worker, 2, now()).is_empty());
    }

    #[test]
    fn suspended_worker_reports_next_probe_and_recovery_threshold() {
        let mut worker = worker_entry("suspended");
        worker.suspended_at = Some("2026-07-11T08:30:00+00:00".to_owned());
        worker.next_probe_at = Some("2026-07-11T09:02:00+00:00".to_owned());
        worker.consecutive_ok = 1;
        worker.suspended_reprobe_attempt = 3;

        let rendered = worker_health_lines(&worker, 2, now()).join("\n");
        assert!(rendered.contains("01J0A (suspended)"));
        assert!(rendered.contains("suspended since : 2026-07-11T08:30:00+00:00"));
        assert!(rendered.contains("next re-probe   : 2026-07-11T09:02:00+00:00 (in 2m)"));
        assert!(rendered.contains("1 of 2 consecutive good probes"));
        assert!(rendered.contains("re-probe attempt 3"));
    }

    #[test]
    fn an_old_registry_omitting_the_threshold_does_not_render_zero_of_zero() {
        let mut worker = worker_entry("suspended");
        worker.consecutive_ok = 1;

        let rendered = worker_health_lines(&worker, 0, now()).join("\n");
        assert!(rendered.contains("1 consecutive good probes"));
        assert!(!rendered.contains("of 0"));
    }

    #[test]
    fn a_due_probe_reads_due_now_and_an_unparseable_one_is_dropped() {
        let mut worker = worker_entry("suspended");
        worker.next_probe_at = Some("2026-07-11T08:59:00+00:00".to_owned());
        assert!(worker_health_lines(&worker, 2, now())
            .join("\n")
            .contains("(due now)"));

        worker.next_probe_at = Some("not-a-timestamp".to_owned());
        let rendered = worker_health_lines(&worker, 2, now()).join("\n");
        assert!(rendered.contains("next re-probe   : not-a-timestamp"));
        assert!(!rendered.contains("(in "));
    }

    #[test]
    fn an_active_worker_with_a_dead_key_slot_still_reports_it() {
        let mut worker = worker_entry("active");
        worker.provider_slot_status = serde_json::from_value(serde_json::json!({
            "openai": {
                "AAAAAAAAAAAA": {"status": "verified"},
                "BBBBBBBBBBBB": {"status": "unverified"},
            }
        }))
        .expect("decode slot status");

        let rendered = worker_health_lines(&worker, 2, now()).join("\n");
        assert!(rendered.contains("01J0A (active)"));
        assert!(rendered.contains("unverified key  : openai slot BBBBBBBBBBBB"));
        assert!(!rendered.contains("AAAAAAAAAAAA"));
        assert!(!rendered.contains("suspended since"));
    }

    #[test]
    fn a_suspended_worker_with_a_dead_slot_gets_one_header() {
        let mut worker = worker_entry("suspended");
        worker.provider_slot_status = serde_json::from_value(serde_json::json!({
            "openai": {"BBBBBBBBBBBB": {"status": "unverified"}}
        }))
        .expect("decode slot status");

        let lines = worker_health_lines(&worker, 2, now());
        assert_eq!(
            lines.iter().filter(|l| l.contains("01J0A (")).count(),
            1,
            "one header, not one per block: {lines:?}"
        );
    }
}
