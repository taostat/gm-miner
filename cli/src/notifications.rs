//! `gmcli notifications list`: the miner's pull inbox on the registry.
//!
//! Reads `GET /miners/me/notifications/messages`, newest first, paged by an
//! id cursor. Needs no notification channel: events recorded by the registry
//! are included even when push delivery is disabled.

use std::fmt::Write as _;

use anyhow::{bail, Context as _, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;

use crate::{client::RegistryClient, network::Network};

pub const MESSAGES_PATH: &str = "/miners/me/notifications/messages";
/// The registry's largest page.
pub const MAX_PAGE_SIZE: u32 = 100;
pub const DEFAULT_PAGE_SIZE: u32 = 20;
/// `--all` stops here so a long history cannot turn into an unbounded crawl.
pub const ALL_CAP: usize = 1_000;

const INDENT: &str = "  ";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Notification {
    pub id: u64,
    pub occurred_at: DateTime<Utc>,
    pub event_type: String,
    pub reason_code: Option<String>,
    pub human_text: String,
    pub subject_type: String,
    pub subject_id: String,
    pub delivered: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NotificationPage {
    pub hotkey: String,
    pub notifications: Vec<Notification>,
    pub next_before: Option<u64>,
}

/// What to fetch: one page from an optional cursor, or every page up to [`ALL_CAP`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listing {
    Page { limit: u32, before: Option<u64> },
    All,
}

/// The notifications fetched and the cursor that continues past them, if any.
#[derive(Debug, Clone)]
pub struct Inbox {
    pub hotkey: String,
    pub notifications: Vec<Notification>,
    pub next_before: Option<u64>,
}

fn page_path(limit: u32, before: Option<u64>) -> String {
    match before {
        Some(before) => format!("{MESSAGES_PATH}?limit={limit}&before={before}"),
        None => format!("{MESSAGES_PATH}?limit={limit}"),
    }
}

fn is_unreachable(err: &anyhow::Error) -> bool {
    err.chain()
        .any(<dyn std::error::Error>::is::<reqwest::Error>)
}

async fn error_detail(resp: reqwest::Response) -> String {
    let body = resp.text().await.unwrap_or_default();
    let detail = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|json| {
            json.get("detail").map(|detail| {
                detail
                    .as_str()
                    .map_or_else(|| detail.to_string(), str::to_owned)
            })
        })
        .unwrap_or(body);
    escape_controls(&detail)
}

/// Fetch one page.
///
/// # Errors
/// Fails with an actionable message when the registry is unreachable, the
/// login is missing or expired, the registry predates the inbox, or it
/// answers with any other non-success status or an invalid page.
pub async fn fetch_page(
    client: &mut RegistryClient,
    limit: u32,
    before: Option<u64>,
) -> Result<NotificationPage> {
    let network = client.config.resolved_network();
    let api_url = client.config.api_url();
    let path = page_path(limit, before);
    let resp = match client.get(&path).await {
        Ok(resp) => resp,
        Err(err) if is_unreachable(&err) => {
            return Err(err.context(format!(
                "could not reach the {network} registry at {api_url} — check your connection, \
                 or pass --network / --api-url to target another registry"
            )));
        }
        Err(err) => return Err(err),
    };
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        bail!(
            "the {network} registry at {api_url} does not serve the notifications inbox yet \
             (404 for {MESSAGES_PATH})"
        );
    }
    if !status.is_success() {
        let detail = error_detail(resp).await;
        bail!("reading notifications from the {network} registry failed ({status}): {detail}");
    }
    let page = resp
        .json::<NotificationPage>()
        .await
        .with_context(|| format!("parse {MESSAGES_PATH} response"))?;
    validate_page(&page, limit, before)?;
    Ok(page)
}

// The registry orders by descending id and uses the last id as its cursor.
// Validate before displaying anything, including for single-page reads. This
// also guarantees every --all request adds at least one new row or terminates.
fn validate_page(page: &NotificationPage, limit: u32, before: Option<u64>) -> Result<()> {
    let mut previous = before;
    let ordered = page.notifications.iter().all(|notification| {
        let valid = notification.id > 0
            && i64::try_from(notification.id).is_ok()
            && previous.is_none_or(|id| notification.id < id);
        previous = Some(notification.id);
        valid
    });
    let valid_cursor = page.next_before.is_none_or(|cursor| {
        cursor > 0
            && page
                .notifications
                .last()
                .is_some_and(|last| last.id == cursor)
    });
    if page.notifications.len() > limit as usize || !ordered || !valid_cursor {
        bail!(
            "invalid notifications page from {MESSAGES_PATH}: expected at most {limit} \
             messages with positive signed BIGINT ids in descending order below the requested cursor, with next_before \
             naming the last message; retry or contact the registry operator"
        );
    }
    Ok(())
}

/// Fetch what `listing` asks for.
///
/// # Errors
/// Propagates [`fetch_page`]'s errors, including invalid pagination responses.
pub async fn fetch_inbox(client: &mut RegistryClient, listing: Listing) -> Result<Inbox> {
    let (limit, before) = match listing {
        Listing::Page { limit, before } => (limit, before),
        Listing::All => (MAX_PAGE_SIZE, None),
    };
    let first = fetch_page(client, limit, before).await?;
    let mut inbox = Inbox {
        hotkey: first.hotkey,
        notifications: first.notifications,
        next_before: first.next_before,
    };
    if listing != Listing::All {
        return Ok(inbox);
    }
    while let Some(cursor) = inbox.next_before {
        if inbox.notifications.len() >= ALL_CAP {
            break;
        }
        let page = fetch_page(client, MAX_PAGE_SIZE, Some(cursor)).await?;
        inbox.notifications.extend(page.notifications);
        inbox.next_before = page.next_before;
    }
    if inbox.notifications.len() > ALL_CAP {
        inbox.notifications.truncate(ALL_CAP);
        inbox.next_before = inbox.notifications.last().map(|n| n.id);
    }
    Ok(inbox)
}

/// Escape terminal controls (including C1 and bidi controls) as visible text.
/// Message line breaks are handled separately by the renderer.
fn escape_controls(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if ch.is_control()
            || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            out.extend(ch.escape_default());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Wrap in terminal columns, breaking long URLs/identifiers when necessary.
fn wrap(text: &str, width: usize) -> Vec<String> {
    textwrap::wrap(
        text,
        textwrap::Options::new(width.max(1)).word_splitter(textwrap::WordSplitter::NoHyphenation),
    )
    .into_iter()
    .map(std::borrow::Cow::into_owned)
    .collect()
}

fn render_one(out: &mut String, notification: &Notification, width: usize) {
    let at = notification
        .occurred_at
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut heading = format!("{at}  {}", notification.event_type);
    if let Some(reason) = &notification.reason_code {
        let _ = write!(heading, " ({reason})");
    }
    let _ = write!(
        heading,
        "  [{} {}]",
        notification.subject_type, notification.subject_id
    );
    for line in wrap(&escape_controls(&heading), width) {
        let _ = writeln!(out, "{line}");
    }
    let indent = if width > INDENT.len() + 1 { INDENT } else { "" };
    for paragraph in notification.human_text.lines() {
        for line in wrap(
            &escape_controls(paragraph),
            width.saturating_sub(indent.len()),
        ) {
            let _ = writeln!(out, "{indent}{line}");
        }
    }
}

/// Render validated inbox order with UTC times and escaped terminal controls,
/// wrapping headings and text to `width` terminal columns.
#[must_use]
pub fn render_inbox(inbox: &Inbox, network: Network, width: usize) -> String {
    let mut out = String::new();
    if inbox.notifications.is_empty() {
        let empty = format!(
            "No notifications for {} on {network}.",
            escape_controls(&inbox.hotkey)
        );
        for line in wrap(&empty, width) {
            let _ = writeln!(out, "{line}");
        }
        return out;
    }
    for (index, notification) in inbox.notifications.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        render_one(&mut out, notification, width);
    }
    if let Some(before) = inbox.next_before {
        out.push('\n');
        for line in wrap(
            &format!("Older notifications: gmcli notifications list --before {before}"),
            width,
        ) {
            let _ = writeln!(out, "{line}");
        }
    }
    out
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test assertions")]
mod tests {
    use super::{render_inbox, wrap, Inbox, Notification};
    use crate::network::Network;

    fn notification(id: u64, text: &str) -> Notification {
        Notification {
            id,
            occurred_at: "2026-10-01T12:01:00Z".parse().unwrap(),
            event_type: "worker.suspended".to_owned(),
            reason_code: Some("attestation_failed".to_owned()),
            human_text: text.to_owned(),
            subject_type: "worker".to_owned(),
            subject_id: "wkr-1".to_owned(),
            delivered: false,
        }
    }

    #[test]
    fn wrap_keeps_every_line_within_width_and_every_word() {
        let text = "one two three four five six seven eight nine ten eleven twelve";
        let lines = wrap(text, 14);
        assert!(
            lines.iter().all(|line| line.chars().count() <= 14),
            "{lines:?}"
        );
        assert_eq!(lines.join(" "), text);
    }

    #[test]
    fn wrap_breaks_overlong_words_without_losing_text() {
        let word = "https://example.org/a/very/long/path";
        let lines = wrap(word, 10);
        assert!(
            lines.iter().all(|line| line.chars().count() <= 10),
            "{lines:?}"
        );
        assert_eq!(lines.concat(), word);
    }

    #[test]
    fn wrap_counts_wide_glyphs_in_terminal_columns() {
        let lines = wrap("界界界界界", 4);
        assert!(
            lines.iter().all(|line| line.chars().count() * 2 <= 4),
            "{lines:?}"
        );
        assert_eq!(lines.concat(), "界界界界界");
    }

    #[test]
    fn wrap_keeps_the_messages_own_line_breaks() {
        assert_eq!(wrap("first line\nsecond", 40), ["first line", "second"]);
    }

    #[test]
    fn render_shows_time_type_reason_subject_and_text() {
        let inbox = Inbox {
            hotkey: "5Hk".to_owned(),
            notifications: vec![notification(7, "Worker wkr-1 was suspended.")],
            next_before: None,
        };
        assert_eq!(
            render_inbox(&inbox, Network::Testnet, 78),
            "2026-10-01T12:01:00Z  worker.suspended (attestation_failed)  [worker wkr-1]\n  \
             Worker wkr-1 was suspended.\n"
        );
    }

    #[test]
    fn render_names_the_cursor_when_more_remain() {
        let inbox = Inbox {
            hotkey: "5Hk".to_owned(),
            notifications: vec![notification(9, "a"), notification(8, "b")],
            next_before: Some(8),
        };
        let text = render_inbox(&inbox, Network::Mainnet, 78);
        assert!(
            text.ends_with("\nOlder notifications: gmcli notifications list --before 8\n"),
            "{text}"
        );
    }

    #[test]
    fn render_says_so_when_there_is_nothing() {
        let inbox = Inbox {
            hotkey: "5Hk".to_owned(),
            notifications: Vec::new(),
            next_before: None,
        };
        assert_eq!(
            render_inbox(&inbox, Network::Mainnet, 78),
            "No notifications for 5Hk on mainnet.\n"
        );
    }

    #[test]
    fn narrow_output_wraps_headings_body_cursor_and_empty_inbox() {
        let mut message = notification(
            1,
            "first line\n\n界界界界界 https://example.org/a/very/long/path",
        );
        message.subject_id = "worker-with-an-extremely-long-identifier".to_owned();
        for notifications in [vec![message], vec![]] {
            let inbox = Inbox {
                hotkey: "a-hotkey-too-long-for-a-narrow-terminal".to_owned(),
                notifications,
                next_before: Some(1),
            };
            for width in [4, 12, 24, 40] {
                let rendered = render_inbox(&inbox, Network::Mainnet, width);
                for line in rendered.lines() {
                    let columns: usize = line.chars().map(|c| if c == '界' { 2 } else { 1 }).sum();
                    assert!(columns <= width, "width {width}: {line:?}");
                }
            }
        }
    }
}
