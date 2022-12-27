// SPDX-License-Identifier: MPL-2.0

#![feature(byte_slice_trim_ascii, let_else)]

use std::{future::Future, process};

pub async fn run<E, O>(serve: impl Fn() -> O) -> process::ExitCode
where
    E: std::error::Error,
    O: Future<Output = Result<(), E>>,
{
    if let Err(e) = try_setup_tracing() {
        eprintln!("Failed to setup tracing: {}", e);
    }

    tracing::info!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    if let Err(e) = serve().await {
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
        })
        .with_thread_names(false)
        .try_init()
}
