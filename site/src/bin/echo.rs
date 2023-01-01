// SPDX-License-Identifier: MPL-2.0

use std::{io::{Read as _, Write as _}, net::{SocketAddr, TcpListener}};

fn main() {
    let local_addr: SocketAddr = ([0; 4], 7).into();
    let sock = TcpListener::bind(local_addr).expect("failed to bind to socket");

    loop {
        if let Ok((mut stream, remote_addr)) = sock.accept() {
            tracing::trace!("incoming request from {}", remote_addr);
            if let Some(entry) = norepi_site::blocklist::find(&remote_addr.ip()) {
                tracing::warn!("request was blocked: {:#?}", entry);
                // TODO
            } else {
                let mut input = Vec::new();
                tracing::debug!("{:?}", input);
                if stream.read_to_end(&mut input).is_ok() {
                    let _ = stream.write_all(&input);
                }
            }
        }
    }
}
