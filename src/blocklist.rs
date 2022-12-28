// SPDX-License-Identifier: MPL-2.0

use std::net::SocketAddr;

#[derive(Debug)]
pub struct Entry {
    pub date: chrono::Utc,
    pub reason: &'static str,
}

pub fn find(_remote_addr: SocketAddr) -> Option<Entry> {
    None
}
