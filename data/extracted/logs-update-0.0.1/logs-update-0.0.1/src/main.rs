use std::process;

use anyhow::Result;

fn main() {
    if let Err(error) = run_cli() {
        eprintln!("error: {error:#}");
        process::exit(1);
    }
}

fn run_cli() -> Result<()> {
    log_upgrades::run()
}
