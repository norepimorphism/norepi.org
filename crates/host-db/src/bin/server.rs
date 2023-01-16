// SPDX-License-Identifier: MPL-2.0

use std::sync::{atomic::{self, AtomicBool}, Arc};

use error_stack::ResultExt as _;

fn main() -> std::process::ExitCode {
    #[derive(thiserror::Error, Debug)]
    enum Error {
        #[error("failed to open server")]
        Open,
        #[error("Server::serve() failed")]
        Serve,
    }

    norepi_site_util::run(|| {
        let table_dir = dirs::home_dir().unwrap_or_default();
        let mut server = norepi_site_host_db::Server::open(table_dir.join("ipv4.db"))
            .change_context(Error::Open)?;

        let should_quit = Arc::new(AtomicBool::new(false));
        {
            let should_quit = Arc::clone(&should_quit);
            ctrlc::set_handler(move || {
                should_quit.store(true, atomic::Ordering::Relaxed);
            })
            .expect("failed to set SIGINT handler");
        }

        server.serve(|| should_quit.load(atomic::Ordering::Relaxed)).change_context(Error::Serve)
    })
}
