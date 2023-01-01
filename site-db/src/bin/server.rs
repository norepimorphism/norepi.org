// SPDX-License-Identifier: MPL-2.0

use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, path::PathBuf};

fn main() {

}

pub enum GetValueError {
    Corrupted(bincode::Error),
}

pub struct LoadError {
    reason: LoadErrorReason,
    inner: sled::Error,
}

impl LoadError {
    pub fn reason(&self) -> &LoadErrorReason {
        &self.reason
    }
}

pub enum LoadErrorReason {
    FailedToOpenDatabase { path: PathBuf },
    FailedToOpenTree { name: &'static str },
}

impl KnownRemoteHosts {
    pub fn load() -> Result<Self, LoadError> {
        let path = dirs::home_dir().unwrap_or_default().join("known-remote-hosts");

        let db = sled::Config::new()
            .path(path.as_path())
            .use_compression(false)
            .mode(sled::Mode::LowSpace)
            .open()
            .map_err(|e| {
                LoadError {
                    reason: LoadErrorReason::FailedToOpenDatabase { path },
                    inner: e,
                }
            })?;

        let open_tree = |name| {
            db.open_tree(name).map_err(|e| {
                LoadError {
                    reason: LoadErrorReason::FailedToOpenTree { name },
                    inner: e,
                }
            })
            .map(KnownRemoteHostTree)
        };
        let ipv4 = open_tree("ipv4").map(KnownRemoteIpv4Hosts)?;
        let ipv6 = open_tree("ipv6").map(KnownRemoteIpv6Hosts)?;

        Ok(Self { db, ipv4, ipv6 })

    }
}

pub struct KnownRemoteHosts {
    db: sled::Db,
    ipv4: KnownRemoteIpv4Hosts,
    ipv6: KnownRemoteIpv6Hosts,
}

impl KnownRemoteHosts {
    pub fn ipv4(&self) -> &KnownRemoteIpv4Hosts {
        &self.ipv4
    }

    pub fn ipv6(&self) -> &KnownRemoteIpv6Hosts {
        &self.ipv6
    }
}

type GetKnownRemoteHostResult = Option<Result<KnownRemoteHost, GetValueError>>;

impl KnownRemoteHosts {
    pub fn get(&self, addr: &IpAddr) -> GetKnownRemoteHostResult {
        match addr {
            IpAddr::V4(addr) => self.get_v4(addr),
            IpAddr::V6(addr) => self.get_v6(addr),
        }
    }

    pub fn get_v4(&self, addr: &Ipv4Addr) -> GetKnownRemoteHostResult {
        self.ipv4.get(addr)
    }

    pub fn get_v6(&self, addr: &Ipv6Addr) -> GetKnownRemoteHostResult {
        if let Some(addr) = addr.to_ipv4() {
            return self.get_v4(&addr);
        }

        self.ipv6.get(addr)
    }
}

pub struct KnownRemoteIpv4Hosts(KnownRemoteHostTree);

impl KnownRemoteIpv4Hosts {
    pub fn get(&self, addr: &Ipv4Addr) -> GetKnownRemoteHostResult {
        self.0.get(addr.octets())
    }
}

pub struct KnownRemoteIpv6Hosts(KnownRemoteHostTree);

impl KnownRemoteIpv6Hosts {
    pub fn get(&self, addr: &Ipv6Addr) -> GetKnownRemoteHostResult {
        self.0.get(addr.octets())
    }
}

struct KnownRemoteHostTree(sled::Tree);

impl KnownRemoteHostTree {
    fn get<K: AsRef<[u8]>>(&self, key: K) -> Option<Result<KnownRemoteHost, GetValueError>> {
        let value = self.0.get(key).ok().flatten()?;

        Some(bincode::deserialize(value.as_ref()).map_err(GetValueError::Corrupted))
    }
}
