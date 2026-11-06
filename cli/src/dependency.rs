//! Reusable external-tool preflight: detect a required CLI on PATH and, when
//! it is missing or outdated, offer to install or upgrade it.
//!
//! `gmcli` bridges to external tools rather than reimplementing them —
//! `phala` for deploy, `btcli` for read-only wallet/metagraph checks during
//! hotkey setup. Both need the same primitive: is the tool present, and if not,
//! can we install it for the operator? [`ensure_dependency`] is that primitive,
//! parameterised by a [`Dependency`] descriptor so a new tool slots in by value,
//! not by a new copy of the detection-and-install dance.

use std::{
    io::{IsTerminal as _, Write as _},
    process::{Command, Output},
};

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
    /// Minimum supported semantic version, when a CLI feature requires it.
    pub min_version: Option<&'static str>,
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

/// `btcli` (bittensor-cli) — reads the local wallet list and subnet metagraph.
/// The operator runs wallet-signing commands themselves.
pub const BTCLI: Dependency = Dependency {
    name: "btcli",
    purpose: "btcli (bittensor-cli) reads your local wallet list and subnet \
              metagraph; run any wallet-signing command yourself",
    installer: InstallCommand {
        program: "pipx",
        args: &["install", "bittensor-cli"],
        display: "pipx install bittensor-cli",
    },
    prereq: Prerequisite {
        name: "pipx",
        hint: "install Python and pipx first (https://pipx.pypa.io), then re-run",
    },
    min_version: None,
};

/// `phala` (Phala Cloud CLI) — submits the compose stack to Phala Cloud and
/// reports the CVM's measured hashes. The runtime dependency of `gmcli deploy`.
/// Phala CLI 1.1.19 added the `--kms-contract-id` option used for new CVMs.
pub const PHALA: Dependency = Dependency {
    name: "phala",
    purpose: "the phala CLI submits your miner to Phala Cloud and reports the \
              CVM's measured hashes that gmcli verifies against the registry",
    installer: InstallCommand {
        program: "npm",
        args: &["install", "-g", "phala"],
        display: "npm install -g phala",
    },
    prereq: Prerequisite {
        name: "npm",
        hint: "install Node.js and npm first (https://nodejs.org), then re-run",
    },
    min_version: Some("1.1.19"),
};

/// Whether `tool` resolves to a runnable executable on PATH. Probed by
/// `tool --version`, the convention every CLI gmcli bridges to supports.
#[must_use]
pub fn on_path(tool: &str) -> bool {
    version_command_output(tool).is_some_and(|output| output.status.success())
}

/// Whether a CLI's `--version` output is at least `minimum` under semver.
///
/// A leading `v` is accepted because several CLI tools print versions that
/// way. Unparseable versions fail closed.
#[must_use]
pub fn version_meets_minimum(version_output: &str, minimum: &str) -> bool {
    let trimmed = version_output.trim();
    let output_version = trimmed.strip_prefix('v').unwrap_or(trimmed);
    let Ok(output_version) = semver::Version::parse(output_version) else {
        return false;
    };
    let Ok(minimum) = semver::Version::parse(minimum) else {
        return false;
    };
    output_version >= minimum
}

/// Check that a dependency is present and meets its declared minimum version.
/// This check is non-interactive and never installs anything.
///
/// # Errors
/// Returns an actionable error when the executable is missing or outdated.
pub fn check_dependency(dep: &Dependency) -> Result<()> {
    match dependency_availability(dep) {
        DependencyAvailability::Available => Ok(()),
        DependencyAvailability::Missing => {
            if let Some(minimum) = dep.min_version {
                bail!(
                    "`{}` version {minimum} or newer is required for this command but was not found on PATH.\n  install it with: {}",
                    dep.name,
                    dep.installer.display
                );
            }
            bail!(
                "`{}` is required for this command but was not found on PATH.\n  install it with: {}",
                dep.name,
                dep.installer.display
            );
        }
        DependencyAvailability::Unsupported => bail!(
            "`{}` must be version {} or newer for this command.\n  install or upgrade it with: {}",
            dep.name,
            dep.min_version.unwrap_or("a supported version"),
            dep.installer.display
        ),
    }
}

/// Check only whether a dependency can run, ignoring its optional version
/// floor. Recovery commands use this when they need the tool but do not create
/// a new CVM.
///
/// # Errors
/// Returns an actionable error when the executable is missing or fails its
/// `--version` command.
pub fn check_dependency_presence(dep: &Dependency) -> Result<()> {
    if on_path(dep.name) {
        Ok(())
    } else {
        bail!(
            "`{}` is required for this command but was not found on PATH.\n  install it with: {}",
            dep.name,
            dep.installer.display
        )
    }
}

fn version_command_output(tool: &str) -> Option<Output> {
    let working_dir = tempfile::tempdir().ok()?;
    Command::new(tool)
        .current_dir(working_dir.path())
        .arg("--version")
        .output()
        .ok()
}

#[derive(Debug, PartialEq, Eq)]
enum DependencyAvailability {
    Available,
    Missing,
    Unsupported,
}

fn dependency_availability(dep: &Dependency) -> DependencyAvailability {
    let Some(output) = version_command_output(dep.name) else {
        return DependencyAvailability::Missing;
    };
    if !output.status.success() {
        return DependencyAvailability::Missing;
    }
    let Some(minimum) = dep.min_version else {
        return DependencyAvailability::Available;
    };
    let version_bytes = if output.stdout.is_empty() {
        &output.stderr
    } else {
        &output.stdout
    };
    let version_output = String::from_utf8_lossy(version_bytes);
    if version_meets_minimum(&version_output, minimum) {
        DependencyAvailability::Available
    } else {
        DependencyAvailability::Unsupported
    }
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

/// Ensure `dep` is installed at a supported version, offering to install or
/// upgrade it when it is missing or outdated.
///
/// `assume_yes` (the command's `--yes`) and a non-TTY stdin both suppress the
/// prompt: in those non-interactive contexts we never block on input. With
/// `assume_yes` we proceed straight to the install; without it (a plain pipe)
/// we print guidance and fail rather than guess consent.
///
/// # Errors
/// Returns an error when the tool is missing or outdated and cannot be brought
/// up to date — no consent, no installer prerequisite, or the install command
/// itself failing — always with the copy-paste command so the operator can
/// finish by hand.
pub fn ensure_dependency(dep: &Dependency, assume_yes: bool) -> Result<()> {
    let availability = dependency_availability(dep);
    if availability == DependencyAvailability::Available {
        return Ok(());
    }

    match availability {
        DependencyAvailability::Missing => {
            let minimum = dep.min_version.map_or_else(String::new, |version| {
                format!(" (version {version} or newer required)")
            });
            println!("{} is not installed{minimum}.", dep.name);
        }
        DependencyAvailability::Unsupported => println!(
            "{} does not meet the required version {}.",
            dep.name,
            dep.min_version.unwrap_or("a supported version")
        ),
        DependencyAvailability::Available => return Ok(()),
    }
    println!("  {}", dep.purpose);

    // Default to no: a bare Enter or a non-interactive shell declines, so we
    // never install without an explicit yes (or `--yes`).
    let action = if dep.min_version.is_some() {
        "install or upgrade"
    } else {
        "install"
    };
    if !confirm(&format!("{action} {} now?", dep.name), false, assume_yes)? {
        let requirement = dep.min_version.map_or_else(String::new, |version| {
            format!(" version {version} or newer")
        });
        bail!(
            "`{}`{requirement} is required for this command.\n  {action} it with: {}",
            dep.name,
            dep.installer.display
        );
    }

    if !on_path(dep.prereq.name) {
        bail!(
            "can't install `{}` automatically: its installer needs `{}`, \
             which is not on PATH.\n  {}\n  Or install it yourself with: {}",
            dep.name,
            dep.prereq.name,
            dep.prereq.hint,
            dep.installer.display
        );
    }

    run_installer(dep)?;

    if dependency_availability(dep) == DependencyAvailability::Available {
        println!("{} installed.", dep.name);
        Ok(())
    } else {
        bail!(
            "ran `{}` but `{}` is still missing or does not meet the required version — \
             open a new shell or check the installer output above, then re-run.",
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
    use super::{confirm, ensure_dependency, on_path, version_meets_minimum, BTCLI};

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
    fn version_comparison_observes_semver_minimum() {
        for (output, expected) in [
            ("v1.1.18", false),
            ("1.1.19", true),
            ("1.1.19+build", true),
            ("1.1.19-rc.1", false),
            ("2.0.0", true),
            ("garbage", false),
        ] {
            assert_eq!(
                version_meets_minimum(output, "1.1.19"),
                expected,
                "version output: {output}"
            );
        }
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
