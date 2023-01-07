// SPDX-License-Identifier: MPL-2.0

//! Known remote hosts.

#![feature(generic_const_exprs, mem_copy_fn, nonzero_min_max, slice_as_chunks, unchecked_math)]

use bitflags::bitflags;
use norepi_site_db_types::{Duration, Timestamp};

pub use server::Server;

pub mod client;
#[cfg(any(target_pointer_width = "32", target_pointer_width = "64", target_pointer_width = "128"))]
pub mod server;
mod wire;

static SOCKET_NAME: &str = "/tmp/site-db-hosts";

impl Host {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default)]
pub struct Host {
    blocklist_entry: BlocklistEntry,
    offenses: HostOffenses,
}

impl Host {
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

#[derive(Debug)]
pub enum SuspendHostError {
    AlreadyBlocked,
    FailedToPush(PushSuspensionError),
}

impl Host {
    pub fn suspend(&mut self, duration: impl Duration) -> Result<(), SuspendHostError> {
        if self.is_blocked() {
            Err(SuspendHostError::AlreadyBlocked)
        } else {
            let sus = Suspension::for_duration_from_now(duration);

            self.blocklist_entry.suspensions.push(sus).map_err(SuspendHostError::FailedToPush)
        }
    }
}

#[derive(Debug)]
pub enum BanHostError {
    AlreadyBlocked,
}

impl Host {
    pub fn ban(&mut self) -> Result<(), BanHostError> {
        if self.is_blocked() {
            Err(BanHostError::AlreadyBlocked)
        } else {
            self.blocklist_entry.ban = Some(Ban::now());

            Ok(())
        }
    }

    pub fn blocklist_entry(&self) -> &BlocklistEntry {
        &self.blocklist_entry
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default)]
pub struct BlocklistEntry {
    pub suspensions: Suspensions,
    pub ban: Option<Ban>,
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default)]
pub enum Suspensions {
    #[default]
    Zero,
    One(Suspension),
    Two(Suspension, Suspension),
}

impl Suspensions {
    pub fn contains_active(&self) -> bool {
        match self.last() {
            None => false,
            Some(sus) => sus.is_active(),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Zero)
    }

    pub fn is_full(&self) -> bool {
        matches!(self, Self::Two(..))
    }

    pub fn first(&self) -> Option<&Suspension> {
        match self {
            Self::Zero => None,
            Self::One(it) => Some(it),
            Self::Two(it, _) => Some(it),
        }
    }

    pub fn second(&self) -> Option<&Suspension> {
        match self {
            Self::Zero => None,
            Self::One(_) => None,
            Self::Two(_, it) => Some(it),
        }
    }

    pub fn last(&self) -> Option<&Suspension> {
        match self {
            Self::Zero => None,
            Self::One(it) => Some(it),
            Self::Two(_, it) => Some(it),
        }
    }

    pub fn push(&mut self, sus: Suspension) -> Result<(), PushSuspensionError> {
        // TODO: Don't clone. We might have to change the representation entirely to avoid this.
        *self = self.clone().join(sus)?;

        Ok(())
    }

    pub fn join(self, sus: Suspension) -> Result<Self, PushSuspensionError> {
        if self.is_full() {
            Err(PushSuspensionError::Full)
        } else {
            // SAFETY: TODO
            Ok(unsafe { self.join_unchecked(sus) })
        }
    }

    pub unsafe fn join_unchecked(self, sus: Suspension) -> Self {
        match self {
            Self::Zero => Self::One(sus),
            Self::One(first) => Self::Two(first, sus),
            Self::Two(..) => std::hint::unreachable_unchecked(),
        }
    }
}

#[derive(Debug)]
pub enum PushSuspensionError {
    Full,
}

impl Suspension {
    pub fn for_days_from_now(days: chrono::Days) -> Self {
        Self::for_duration_from_now(days)
    }

    pub fn for_months_from_now(months: chrono::Months) -> Self {
        Self::for_duration_from_now(months)
    }

    pub fn for_duration_from_now(duration: impl Duration) -> Self {
        let now = Timestamp::now();

        Self {
            end: now + duration,
            start: now,
            comment: String::new(),
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
pub struct Suspension {
    start: Timestamp,
    end: Timestamp,
    comment: String,
}

impl Suspension {
    pub fn start(&self) -> Timestamp {
        self.start
    }

    pub fn end(&self) -> Timestamp {
        self.end
    }

    pub fn comment(&self) -> &str {
        self.comment.as_str()
    }

    pub fn is_active(&self) -> bool {
        self.end.passed()
    }
}

impl Ban {
    pub fn now() -> Self {
        Self {
            start: Timestamp::now(),
            comment: String::new(),
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct Ban {
    start: Timestamp,
    comment: String,
}

impl Ban {
    pub fn start(&self) -> Timestamp {
        self.start
    }

    pub fn comment(&self) -> &str {
        self.comment.as_str()
    }
}


impl Default for HostOffenses {
    fn default() -> Self {
        HostOffenses::empty()
    }
}

bitflags! {
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct HostOffenses: u32 {
        const ATTEMPTED_TO_ACCESS_ADMIN_PANEL = 1 << 0;
    }
}
