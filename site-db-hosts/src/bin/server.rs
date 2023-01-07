// SPDX-License-Identifier: MPL-2.0

use std::convert::Infallible;

fn main() -> std::process::ExitCode {
    norepi_site_util::run(|| {
        let mut server = norepi_site_db_hosts::Server::open("ipv4.db").unwrap();
        server.serve().unwrap();

        Ok::<_, Infallible>(())
    })
}
