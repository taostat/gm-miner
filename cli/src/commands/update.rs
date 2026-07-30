use anyhow::{bail, Context as _, Result};
use axoupdater::AxoUpdater;

const INSTALL_CMD: &str = "curl --proto '=https' --tlsv1.2 -LsSf https://github.com/taostat/gm-miner/releases/latest/download/gmcli-installer.sh | sh";

pub(crate) async fn cmd_update() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");

    // `new_for` matches against the app name cargo-dist wrote into the receipt,
    // which is the package name because the package is named after the binary.
    let mut updater = AxoUpdater::new_for(env!("CARGO_PKG_NAME"));
    updater.load_receipt().context(format!(
        "no install receipt found, so gmcli cannot tell where it was installed from.\n\
         Reinstall with the installer to get one:\n  {INSTALL_CMD}"
    ))?;

    // A shell-install receipt can sit beside a gmcli built by cargo. axoupdater
    // answers "no update needed" there rather than replace a binary it did not
    // install — true, but it reads as "you are current".
    if !updater.check_receipt_is_for_this_executable()? {
        bail!(
            "this gmcli ({current}) is not the one the install receipt describes — it was \
             probably built from source or installed by a package manager.\nUpgrade it the \
             same way you installed it."
        );
    }

    println!("gmcli {current} — checking for a newer release...");

    let updated = updater
        .run()
        .await
        .context("upgrading gmcli from its latest GitHub release")?;

    match updated {
        Some(update) => println!(
            "Updated gmcli {current} -> {} ({}), installed to {}.",
            update.new_version, update.new_version_tag, update.install_prefix
        ),
        None => println!("gmcli {current} is already the latest release."),
    }
    Ok(())
}
