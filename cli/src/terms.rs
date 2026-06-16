//! Provider-ToS acceptable-use acceptance gate.
//!
//! Before a miner's provider keys are baked into a TEE for the first time,
//! `gmcli deploy` requires a one-time acknowledgment that the operator's
//! provider accounts and keys permit supplying capacity through gm. The
//! acceptance is recorded both locally (to suppress re-prompts) and
//! server-side on the registry's miner record (the tamper-resistant copy).
//!
//! The acceptance is a representation by the operator, not a signature — in
//! keeping with the CLI's "never touch the wallet" ethos, nothing here reads
//! a key or produces a cryptographic artifact.

use std::io::IsTerminal as _;

use anyhow::{bail, Result};

/// Current terms version. Bump this when [`TERMS_SUMMARY`] or the linked
/// Terms doc changes materially: a stored acceptance whose version differs
/// from this one no longer satisfies the gate, so the operator re-accepts.
pub const CURRENT_TERMS_VERSION: &str = "2026-06-16";

/// Canonical URL of the full miner Terms / acceptable-use document the
/// summary points to. The doc is the source of truth; the summary is a
/// précis shown inline so a deploy never dumps the whole text.
pub const TERMS_DOC_URL: &str = "https://github.com/taostat/gm-miner/blob/main/docs/miner-terms.md";

/// One-paragraph précis of the operator's representation, shown inline at
/// the gate. The full text lives at [`TERMS_DOC_URL`].
pub const TERMS_SUMMARY: &str =
    "By proceeding you confirm that your provider accounts and API keys permit \
you to supply capacity through gm, and that doing so does not breach the \
provider's terms. You are solely responsible for your accounts' compliance; \
gm is not liable for any action a provider takes against your account.";

/// Environment variable that records acceptance for non-interactive deploys,
/// equivalent to passing `--accept-terms`.
pub const ACCEPT_TERMS_ENV: &str = "GMCLI_ACCEPT_TERMS";

/// Whether `value` reads as an affirmative env flag (`1`/`true`/`yes`,
/// case-insensitive). An unset or empty value is not affirmative.
#[must_use]
pub fn env_accepts(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes" | "y")
    )
}

/// Whether a stored acceptance version satisfies the current gate.
///
/// Satisfied only when a version is present and equals
/// [`CURRENT_TERMS_VERSION`]; a missing or stale version re-prompts.
#[must_use]
pub fn is_current(stored_version: Option<&str>) -> bool {
    stored_version == Some(CURRENT_TERMS_VERSION)
}

/// Decision on whether the deploy must stop at the terms gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Acceptance already on record for the current version — proceed silently.
    AlreadyAccepted,
    /// Freshly accepted this run — proceed and persist the acceptance.
    AcceptedNow,
}

/// Render the summary block shown to the operator at the gate.
#[must_use]
pub fn summary_block() -> String {
    format!(
        "\n  gm miner terms (version {CURRENT_TERMS_VERSION}):\n\n  {TERMS_SUMMARY}\n\n  \
         Full terms: {TERMS_DOC_URL}\n"
    )
}

/// Run the acceptance gate.
///
/// Returns [`Gate::AlreadyAccepted`] without prompting when `stored_version`
/// already matches [`CURRENT_TERMS_VERSION`]. Otherwise it prints the summary
/// and records acceptance immediately when `accept_flag` is set or the
/// [`ACCEPT_TERMS_ENV`] env is affirmative; failing that it prompts on an
/// interactive terminal. Acceptance is kept explicit: a bare `--yes`
/// (skip-prompts) does *not* accept the terms on its own — a non-interactive
/// session that did not pass `--accept-terms` fails with guidance rather than
/// silently agreeing to legal wording or hanging on a prompt.
///
/// # Errors
/// Returns an error when acceptance is required but cannot be obtained — a
/// non-interactive run without `--accept-terms`/env, an explicit decline, or
/// an I/O failure reading the response.
pub fn gate(stored_version: Option<&str>, accept_flag: bool) -> Result<Gate> {
    if is_current(stored_version) {
        return Ok(Gate::AlreadyAccepted);
    }

    print!("{}", summary_block());

    if accept_flag || env_accepts(std::env::var(ACCEPT_TERMS_ENV).ok().as_deref()) {
        println!("  Terms accepted (version {CURRENT_TERMS_VERSION}).\n");
        return Ok(Gate::AcceptedNow);
    }

    if !std::io::stdin().is_terminal() {
        bail!(
            "the gm miner terms must be accepted before deploy, but this is a \
             non-interactive session.\n  \
             re-run with `--accept-terms` (or set {ACCEPT_TERMS_ENV}=1) to record \
             acceptance of version {CURRENT_TERMS_VERSION}"
        );
    }

    prompt_accept(&mut std::io::stdin().lock(), &mut std::io::stdout().lock())
}

/// Prompt `Accept? [y/N]` on `out`, reading one line from `input`.
///
/// Anything other than `y`/`yes` (case-insensitive) declines. Split out so
/// the interactive path can be tested against in-memory buffers.
///
/// # Errors
/// Returns an error when the response cannot be read, or when the operator
/// declines.
pub fn prompt_accept(
    input: &mut impl std::io::BufRead,
    out: &mut impl std::io::Write,
) -> Result<Gate> {
    write!(out, "  Accept these terms to continue? [y/N]: ")?;
    out.flush()?;

    let mut line = String::new();
    input.read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    if answer == "y" || answer == "yes" {
        writeln!(out, "  Terms accepted (version {CURRENT_TERMS_VERSION}).\n")?;
        return Ok(Gate::AcceptedNow);
    }

    bail!(
        "deploy declined: the gm miner terms (version {CURRENT_TERMS_VERSION}) \
         were not accepted"
    );
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::{env_accepts, is_current, prompt_accept, Gate, CURRENT_TERMS_VERSION};

    #[test]
    fn is_current_only_for_matching_version() {
        assert!(is_current(Some(CURRENT_TERMS_VERSION)));
        assert!(!is_current(None));
        assert!(!is_current(Some("1970-01-01")));
    }

    #[test]
    fn env_accepts_affirmative_values_only() {
        for v in ["1", "true", "TRUE", "yes", "Y", " true "] {
            assert!(env_accepts(Some(v)), "{v:?} should accept");
        }
        for v in ["", "0", "false", "no", "maybe"] {
            assert!(!env_accepts(Some(v)), "{v:?} should not accept");
        }
        assert!(!env_accepts(None));
    }

    #[test]
    fn prompt_accepts_on_yes() {
        let mut input = std::io::Cursor::new(b"y\n");
        let mut out: Vec<u8> = Vec::new();
        let gate = prompt_accept(&mut input, &mut out).expect("y accepts");
        assert_eq!(gate, Gate::AcceptedNow);
        assert!(String::from_utf8_lossy(&out).contains("accepted"));
    }

    #[test]
    fn prompt_declines_on_anything_else() {
        for answer in [&b"n\n"[..], b"\n", b"nope\n"] {
            let mut input = std::io::Cursor::new(answer);
            let mut out: Vec<u8> = Vec::new();
            let err = prompt_accept(&mut input, &mut out).expect_err("non-yes declines");
            assert!(err.to_string().contains("declined"));
        }
    }
}
