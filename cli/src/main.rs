//! gm-miner CLI - Phase 0 scaffold.
//!
//! Phase 1 W4 fills in the subcommands described in
//! `taostat/gm/workstreams.md` under W4 (login, register-image,
//! list-products, declare-product, update-prices, status).

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "gm-miner", version, about = "gm miner CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Placeholder for `gm-miner login` (Phase 1 W4).
    Version,
}

fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            tracing::info!(
                "phase 0 gm-miner CLI scaffold v{}; commands land in W4",
                env!("CARGO_PKG_VERSION")
            );
        }
    }
}
