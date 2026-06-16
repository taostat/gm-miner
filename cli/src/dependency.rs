//! Reusable external-tool preflight: detect a required CLI on PATH and, when
//! it is missing, offer to install it.
//!
//! `gmcli` bridges to external tools rather than reimplementing them —
//! `phala` for deploy, `btcli` for assisted hotkey registration. Both need the
//! same primitive: is the tool present, and if not, can we install it for the
//! operator? [`ensure_dependency`] is that primitive, parameterised by a
//! [`Dependency`] descriptor so a new tool slots in by value, not by a new
//! copy of the detection-and-install dance.

use std::io::{IsTerminal as _, Write as _};

use anyhow::{bail, Context, Result};

/// An external CLI `gmcli` shells out to.
///
/// `name` is the executable as invoked on PATH. `purpose` is the one-line
/// "what it's for" shown before offering to install. `installer` is the
/// command run on the operator's yes; `prereq` is the tool the installer
/// itself needs (e.g. `pipx` for `btcli`) — when that is missing we cannot
/// self-install and print guidance instead.
#[derive(Debug, Clone, Copy)]
pub struct Dependency {
    pub name: &'static str,
    pub purpose: &'static str,
    pub installer: InstallCommand,
    pub prereq: Prerequisite,
}

/// The command that installs a [`Dependency`], split into program + args so it
/// runs without a shell.
#[derive(Debug, Clone, Copy)]
pub struct InstallCommand {
    pub program: &'static str,
    pub args: &'static [&'static str],
    /// Shown verbatim as the copy-paste fallback when we can't auto-install.
    pub display: &'static str,
}

/// The tool an installer depends on, and where to get it when it is absent.
#[derive(Debug, Clone, Copy)]
pub struct Prerequisite {
    pub name: &'static str,
    pub hint: &'static str,
}

/// `btcli` (bittensor-cli) — owns the wallet and signs the on-chain
/// registration extrinsic. `gmcli` never touches wallet keys.
pub const BTCLI: Dependency = Dependency {
    name: "btcli",
    purpose: "btcli (bittensor-cli) signs the on-chain hotkey registration — \
              it owns your wallet keys; gmcli never sees them",
    installer: InstallCommand {
        program: "pipx",
        args: &["install", "bittensor-cli"],
        display: "pipx install bittensor-cli",
    },
    prereq: Prerequisite {
        name: "pipx",
        hint: "install Python and pipx first (https://pipx.pypa.io), \
               then re-run — or install btcli yourself: pipx install bittensor-cli",
    },
};

/// Whether `tool` resolves to a runnable executable on PATH. Probed by
/// `tool --version`, the convention every CLI gmcli bridges to supports.
#[must_use]
pub fn on_path(tool: &str) -> bool {
    std::process::Command::new(tool)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Prompt the operator with `question` and return their yes/no answer.
///
/// `assume_yes` and a non-TTY stdin both short-circuit to `default_yes` without
/// prompting — a non-interactive run must never block on input. `default_yes`
/// also picks the answer for a bare Enter and shapes the `[Y/n]`/`[y/N]` hint.
///
/// # Errors
/// Returns an error if stdin can't be read.
pub fn confirm(question: &str, default_yes: bool, assume_yes: bool) -> Result<bool> {
    if assume_yes || !std::io::stdin().is_terminal() {
        return Ok(assume_yes || default_yes);
    }
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    print!("{question} {hint} ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("read confirmation")?;
    let answer = line.trim().to_lowercase();
    if answer.is_empty() {
        return Ok(default_yes);
    }
    Ok(answer == "y" || answer == "yes")
}

/// Ensure `dep` is installed, offering to install it when it is missing.
///
/// `assume_yes` (the command's `--yes`) and a non-TTY stdin both suppress the
/// prompt: in those non-interactive contexts we never block on input. With
/// `assume_yes` we proceed straight to the install; without it (a plain pipe)
/// we print guidance and fail rather than guess consent.
///
/// # Errors
/// Returns an error when the tool is missing and cannot be installed — no
/// consent, no installer prerequisite, or the install command itself failing —
/// always with the copy-paste command so the operator can finish by hand.
pub fn ensure_dependency(dep: &Dependency, assume_yes: bool) -> Result<()> {
    if on_path(dep.name) {
        return Ok(());
    }

    println!("{} is not installed.", dep.name);
    println!("  {}", dep.purpose);

    // Default to no: a bare Enter or a non-interactive shell declines, so we
    // never install without an explicit yes (or `--yes`).
    if !confirm(&format!("install {} now?", dep.name), false, assume_yes)? {
        bail!(
            "`{}` is required for this command but was not found on PATH.\n  \
             install it with: {}",
            dep.name,
            dep.installer.display
        );
    }

    if !on_path(dep.prereq.name) {
        bail!(
            "can't install `{}` automatically: its installer needs `{}`, \
             which is not on PATH.\n  {}",
            dep.name,
            dep.prereq.name,
            dep.prereq.hint
        );
    }

    run_installer(dep)?;

    if on_path(dep.name) {
        println!("{} installed.", dep.name);
        Ok(())
    } else {
        bail!(
            "ran `{}` but `{}` is still not on PATH — open a new shell or check \
             the installer output above, then re-run.",
            dep.installer.display,
            dep.name
        )
    }
}

/// Run the installer, streaming its output through so the operator sees pip's
/// progress and any error verbatim.
fn run_installer(dep: &Dependency) -> Result<()> {
    println!("running: {}", dep.installer.display);
    let status = std::process::Command::new(dep.installer.program)
        .args(dep.installer.args)
        .status()
        .with_context(|| format!("run `{}`", dep.installer.display))?;
    if !status.success() {
        bail!(
            "`{}` failed — install `{}` yourself and re-run.",
            dep.installer.display,
            dep.name
        );
    }
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::{confirm, ensure_dependency, on_path, BTCLI};

    #[test]
    fn missing_dep_without_consent_fails_with_install_hint() {
        // A dependency that cannot exist on PATH, in a non-interactive context
        // (assume_yes=false): no prompt, guidance-only failure carrying the
        // copy-paste install command.
        let mut dep = BTCLI;
        dep.name = "gm-miner-no-such-tool-xyz";
        let err = ensure_dependency(&dep, false).expect_err("missing tool must fail");
        let msg = format!("{err}");
        assert!(msg.contains("pipx install bittensor-cli"), "got: {msg}");
        assert!(msg.contains("gm-miner-no-such-tool-xyz"), "got: {msg}");
    }

    #[test]
    fn present_dep_is_a_noop() {
        // `cargo` is on PATH in any build/test environment; ensure_dependency
        // must return Ok without attempting an install.
        let mut dep = BTCLI;
        dep.name = "cargo";
        assert!(ensure_dependency(&dep, true).is_ok());
    }

    #[test]
    fn on_path_detects_cargo_and_rejects_nonsense() {
        assert!(on_path("cargo"));
        assert!(!on_path("gm-miner-no-such-tool-xyz"));
    }

    #[test]
    fn confirm_assume_yes_skips_prompt() {
        // --yes always proceeds regardless of the default.
        assert!(confirm("anything?", false, true).expect("confirm"));
        assert!(confirm("anything?", true, true).expect("confirm"));
    }

    #[test]
    fn confirm_non_tty_returns_default() {
        // The test harness's stdin is not a TTY: confirm must not block, and
        // returns the default rather than prompting.
        assert!(!confirm("install?", false, false).expect("confirm"));
        assert!(confirm("proceed?", true, false).expect("confirm"));
    }
}
