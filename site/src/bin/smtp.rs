// SPDX-License-Identifier: MPL-2.0

use std::net::{SocketAddr, TcpListener};

fn main() {
    let local_addr: SocketAddr = ([0; 4], 587).into();
    let sock = TcpListener::bind(local_addr).expect("failed to bind to socket");

    loop {
        if let Ok((_stream, remote_addr)) = sock.accept() {
            tracing::trace!("incoming request from {}", remote_addr);
            if let Some(entry) = norepi_site::blocklist::find(&remote_addr.ip()) {
                tracing::warn!("request was blocked: {:#?}", entry);
                // TODO
            } else {
                // TODO
            }
        }
    }
}
