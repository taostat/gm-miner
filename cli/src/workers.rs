//! Render the health view for a hotkey's workers: suspension recovery state and
//! upstream key slots the registry could not verify.

use chrono::{DateTime, Utc};

use crate::types::WorkerEntry;

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
    use super::{worker_health_lines, DateTime, Utc, WorkerEntry};

    fn worker_entry(status: &str) -> WorkerEntry {
        serde_json::from_value(serde_json::json!({
            "worker_id": "01J0A",
            "endpoint": "https://w1.example.org:8443",
            "status": status,
            "last_attestation_at": null,
        }))
        .expect("decode minimal worker entry")
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
