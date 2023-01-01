// SPDX-License-Identifier: MPL-2.0

pub mod blocklist;
pub mod ty;

use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, path::PathBuf};

use bitflags::bitflags;

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

#[derive(Default, serde::Deserialize)]
pub struct KnownRemoteHost {
    blocklist_entry: blocklist::Entry,
    offenses: HostOffenses,
}

impl KnownRemoteHost {
    pub fn blocklist_entry(&self) -> &blocklist::Entry {
        &self.blocklist_entry
    }

    pub fn is_blocked(&self) -> bool {
        self.is_banned() || self.is_suspended()
    }

    pub fn is_suspended(&self) -> bool {
        self.blocklist_entry.suspensions.contains_active()
    }

    pub fn is_banned(&self) -> bool {
        self.blocklist_entry.ban.is_some()
    }

    pub fn offenses(&self) -> HostOffenses {
        self.offenses
    }
}

pub enum SuspendHostError {
    AlreadyBlocked,
    FailedToPush(blocklist::PushSuspensionError),
}

impl KnownRemoteHost {
    pub fn suspend(&mut self, duration: impl ty::Duration) -> Result<(), SuspendHostError> {
        if self.is_blocked() {
            Err(SuspendHostError::AlreadyBlocked)
        } else {
            let sus = blocklist::Suspension::for_duration_from_now(duration);

            self.blocklist_entry.suspensions.push(sus).map_err(SuspendHostError::FailedToPush)
        }
    }
}

pub enum BanHostError {
    AlreadyBlocked,
}

impl KnownRemoteHost {
    pub fn ban(&mut self) -> Result<(), BanHostError> {
        if self.is_blocked() {
            Err(BanHostError::AlreadyBlocked)
        } else {
            self.blocklist_entry.ban = Some(blocklist::Ban::now());

            Ok(())
        }
    }
}

impl Default for HostOffenses {
    fn default() -> Self {
        HostOffenses::empty()
    }
}

bitflags! {
    #[derive(serde::Deserialize)]
    pub struct HostOffenses: u32 {
        const ATTEMPTED_TO_ACCESS_ADMIN_PANEL = 1 << 0;
    }
}

struct KnownRemoteHostTree(sled::Tree);

impl KnownRemoteHostTree {
    fn get<K: AsRef<[u8]>>(&self, key: K) -> Option<Result<KnownRemoteHost, GetValueError>> {
        let value = self.0.get(key).ok().flatten()?;

        Some(bincode::deserialize(value.as_ref()).map_err(GetValueError::Corrupted))
    }
}
