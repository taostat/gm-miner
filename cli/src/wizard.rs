//! Interactive prompt primitives for the `gmcli init` onboarding wizard.
//!
//! The wizard walks a miner through the lifecycle one step at a time. Each
//! step shows the exact command it will run and asks `[Y/n/skip]`:
//!   - **Y** (the default): run the step now.
//!   - **n**: stop the wizard here.
//!   - **skip**: leave this step and move to the next.
//!
//! Steps the wizard detects as already done are reported `[ok]` and never
//! prompt — a returning miner breezes through. These primitives are the
//! input layer; the orchestration (which steps, in what order, and the
//! detect-and-skip predicates) lives in the binary.

use std::io::{IsTerminal as _, Write as _};

use anyhow::{Context, Result};

/// The miner's answer to a wizard step's `[Y/n/skip]` prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepChoice {
    /// Run this step now.
    Run,
    /// Skip this step and continue to the next.
    Skip,
    /// Stop the wizard.
    Stop,
}

/// Show a step's heading and the exact command it runs, then ask
/// `[Y/n/skip]`.
///
/// `assume_yes` and a non-TTY both answer [`StepChoice::Run`] without
/// prompting, so `gmcli init --yes` (or a piped stdin) drives the whole
/// flow non-interactively. A bare Enter is `Run` (the capitalised default).
///
/// # Errors
/// Returns an error if stdin cannot be read.
pub fn ask_step(title: &str, command: &str, assume_yes: bool) -> Result<StepChoice> {
    println!("\n── {title} ──");
    println!("  $ {command}");

    if assume_yes || !std::io::stdin().is_terminal() {
        return Ok(StepChoice::Run);
    }

    print!("Run it now? [Y/n/skip] ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("read wizard choice")?;
    Ok(parse_choice(&line))
}

/// Map a raw `[Y/n/skip]` answer to a [`StepChoice`]. A bare Enter (empty)
/// and any unrecognised answer default to [`StepChoice::Run`]; `s`/`skip`
/// skip; `n`/`no` stop.
fn parse_choice(line: &str) -> StepChoice {
    match line.trim().to_lowercase().as_str() {
        "s" | "skip" => StepChoice::Skip,
        "n" | "no" => StepChoice::Stop,
        _ => StepChoice::Run,
    }
}

/// Print the `[ok]` marker for a step the wizard detected as already done.
pub fn already_done(title: &str, detail: &str) {
    println!("\n── {title} ──");
    if detail.is_empty() {
        println!("  [ok] already done — skipping");
    } else {
        println!("  [ok] {detail} — skipping");
    }
}

/// Prompt for a single line of free text, returning the trimmed value.
///
/// `assume_yes` and a non-TTY both skip the prompt and return `None` so the
/// caller can fall back to a default or bail. An empty answer also returns
/// `None`.
///
/// # Errors
/// Returns an error if stdin cannot be read.
pub fn prompt_line(question: &str, assume_yes: bool) -> Result<Option<String>> {
    if assume_yes || !std::io::stdin().is_terminal() {
        return Ok(None);
    }
    print!("{question} ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("read wizard input")?;
    let value = line.trim().to_owned();
    Ok((!value.is_empty()).then_some(value))
}

#[cfg(test)]
mod tests {
    use super::{parse_choice, StepChoice};

    #[test]
    fn parse_choice_defaults_to_run() {
        assert_eq!(parse_choice(""), StepChoice::Run);
        assert_eq!(parse_choice("\n"), StepChoice::Run);
        assert_eq!(parse_choice("y"), StepChoice::Run);
        assert_eq!(parse_choice("YES"), StepChoice::Run);
        assert_eq!(parse_choice("garbage"), StepChoice::Run);
    }

    #[test]
    fn parse_choice_recognises_skip() {
        assert_eq!(parse_choice("s"), StepChoice::Skip);
        assert_eq!(parse_choice("skip"), StepChoice::Skip);
        assert_eq!(parse_choice("  SKIP  "), StepChoice::Skip);
    }

    #[test]
    fn parse_choice_recognises_stop() {
        assert_eq!(parse_choice("n"), StepChoice::Stop);
        assert_eq!(parse_choice("no"), StepChoice::Stop);
    }
}
