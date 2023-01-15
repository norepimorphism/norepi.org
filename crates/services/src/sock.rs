// SPDX-License-Identifier: MPL-2.0

use std::net::{Ipv4Addr, SocketAddr};

use hyper::server::conn::AddrIncoming;

pub fn bind(port: u16) -> hyper::Result<AddrIncoming> {
    AddrIncoming::bind(&public_addr(port))
}

fn public_addr(port: u16) -> SocketAddr {
    (Ipv4Addr::UNSPECIFIED, port).into()
}
