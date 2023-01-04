// SPDX-License-Identifier: MPL-2.0

fn main() {
    let mut server = norepi_site_db_remote::Server::open("ipv4.db").unwrap();
    server.start().unwrap();
}
