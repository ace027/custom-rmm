//! Offline signing CLI. The only tool that produces trust signatures.

mod aaguid;
mod card_backend;
mod cli;
mod drafts;
mod file_backend;

use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(cli::exit_code(&e))
        }
    }
}
