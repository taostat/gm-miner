//! Terms-of-service confirmation gate for OAuth subscription auth.
//!
//! Using a personal `ChatGPT` Plus / Claude Pro subscription to serve
//! third-party traffic may violate the provider's `ToS` — see
//! `docs/auth-modes.md`. Before a `gm-miner deploy` proceeds with a
//! `--paste-codex-auth` / `--paste-claude-auth` flag, the operator must
//! confirm they accept that risk by typing the exact string "I understand".

use std::io::{BufRead, Write};

use anyhow::{bail, Result};

/// The banner text shown to the operator before they may continue.
///
/// Kept as a `&'static str` so the integration test (and any docs that
/// quote it) reads from one source of truth.
pub const TOS_BANNER: &str = "\
\u{26a0} Subscription-based authentication uses your personal ChatGPT Plus / Claude Pro account. \
Using a personal subscription to serve third-party gm traffic may violate the provider's terms of service. \
By proceeding you accept this risk on your own behalf. gm provides the technical rails; \
ToS compliance is your responsibility.

Type 'I understand' to continue:";

/// Exact phrase the operator must type to proceed.
pub const TOS_CONFIRM_PHRASE: &str = "I understand";

/// Print the `ToS` banner to `out` and require the operator to type the
/// confirmation phrase verbatim on `input`.
///
/// `input` is the reader to consume one line from; `out` is the writer
/// the banner is printed to. The CLI binary wires them to stdin and
/// stderr respectively so the prompt never pollutes stdout (which a
/// caller may be parsing for the rest of the deploy's JSON output).
///
/// Returns `Ok(())` only when the operator types exactly
/// [`TOS_CONFIRM_PHRASE`] (trailing newline ignored). Any other input
/// — including a trimmed lowercase match — is an error.
///
/// # Errors
/// Returns an error if reading from `input` fails, writing the prompt
/// fails, or the operator's input does not match the exact phrase.
pub fn require_confirmation<R: BufRead, W: Write>(input: &mut R, out: &mut W) -> Result<()> {
    writeln!(out, "{TOS_BANNER}")?;
    out.flush()?;

    let mut line = String::new();
    let read = input.read_line(&mut line)?;
    if read == 0 {
        bail!(
            "no input received on the ToS confirmation prompt; \
             type exactly '{TOS_CONFIRM_PHRASE}' to continue"
        );
    }

    let typed = line.trim_end_matches(['\r', '\n']);
    if typed != TOS_CONFIRM_PHRASE {
        bail!(
            "ToS confirmation declined (typed {typed:?}); \
             type exactly '{TOS_CONFIRM_PHRASE}' to continue"
        );
    }
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn run(typed: &str) -> Result<String> {
        let mut input = Cursor::new(typed.as_bytes().to_vec());
        let mut out: Vec<u8> = Vec::new();
        require_confirmation(&mut input, &mut out)?;
        Ok(String::from_utf8(out).unwrap())
    }

    #[test]
    fn exact_phrase_passes() {
        let out = run("I understand\n").unwrap();
        assert!(out.contains(TOS_CONFIRM_PHRASE));
        assert!(out.contains("personal ChatGPT Plus / Claude Pro account"));
    }

    #[test]
    fn exact_phrase_without_newline_passes() {
        // A terminal pipe may submit without a trailing newline; the
        // operator's intent is still clear.
        run("I understand").unwrap();
    }

    #[test]
    fn lowercase_is_rejected() {
        let err = run("i understand\n").unwrap_err();
        assert!(err.to_string().contains("ToS confirmation declined"));
    }

    #[test]
    fn yes_is_rejected() {
        let err = run("yes\n").unwrap_err();
        assert!(err.to_string().contains("ToS confirmation declined"));
    }

    #[test]
    fn empty_input_is_rejected() {
        let err = run("").unwrap_err();
        assert!(err.to_string().contains("no input received"));
    }

    #[test]
    fn trailing_whitespace_is_rejected() {
        // Type the phrase plus a trailing space — must not pass.
        let err = run("I understand \n").unwrap_err();
        assert!(err.to_string().contains("ToS confirmation declined"));
    }
}
