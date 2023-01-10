// SPDX-License-Identifier: MPL-2.0

use std::{convert::Infallible, sync::{atomic::{self, AtomicBool}, Arc}};

fn main() -> std::process::ExitCode {
    norepi_site_util::run(|| {
        let mut server = norepi_site_db_hosts::Server::open("ipv4.db").unwrap();

        let should_quit = Arc::new(AtomicBool::new(false));
        {
            let should_quit = Arc::clone(&should_quit);
            ctrlc::set_handler(move || {
                should_quit.store(true, atomic::Ordering::Relaxed);
            })
            .expect("failed to set SIGINT handler");
        }
        server.serve(|| should_quit.load(atomic::Ordering::Relaxed)).unwrap();

        Ok::<_, Infallible>(())
    })
}
