// SPDX-License-Identifier: MPL-2.0

use std::{future::Future, process};

pub mod bind;

pub fn run<E>(serve: impl FnOnce() -> Result<(), E>) -> process::ExitCode
where
    E: std::error::Error,
{
    prologue();

    handle_serve(serve())
}

pub async fn run_async<E, O>(serve: impl FnOnce() -> O) -> process::ExitCode
where
    E: std::error::Error,
    O: Future<Output = Result<(), E>>,
{
    prologue();

    handle_serve(serve().await)
}

fn prologue() {
    if let Err(e) = try_setup_tracing() {
        eprintln!("Failed to setup tracing: {}", e);
    }

    tracing::info!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}

fn handle_serve<E: std::error::Error>(result: Result<(), E>) -> process::ExitCode {
    if let Err(e) = result {
        tracing::error!("{}", e);

        process::ExitCode::FAILURE
    } else {
        process::ExitCode::SUCCESS
    }
}

fn try_setup_tracing() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tracing_subscriber::filter::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter({
            match EnvFilter::try_from_default_env() {
                Ok(filter) => {
                    println!(
                        "Using tracing filter from ${}: \"{}\"",
                        EnvFilter::DEFAULT_ENV,
                        std::env::var(EnvFilter::DEFAULT_ENV).unwrap(),
                    );

                    filter
                }
                Err(e) => {
                    eprintln!("Failed to parse ${}: {}", EnvFilter::DEFAULT_ENV, e);
                    println!("Using default tracing filter");

                    EnvFilter::default()
                }
            }
            // *hyper* is very noisy.
            .add_directive("hyper=error".parse()?)
            // We don't need to hear from *mio* either.
            .add_directive("mio=error".parse()?)
        })
        .with_thread_names(false)
        .try_init()
}
