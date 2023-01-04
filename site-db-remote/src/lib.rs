// SPDX-License-Identifier: MPL-2.0

//! Known remote hosts.

#![feature(mem_copy_fn, nonzero_min_max, unchecked_math)]

use bitflags::bitflags;
use norepi_site_db_types::{Duration, PascalString, Timestamp};

pub use server::Server;

pub mod client;
#[cfg(any(target_pointer_width = "32", target_pointer_width = "64", target_pointer_width = "128"))]
pub mod server;

static SOCKET_NAME: &str = "site-db-remote";

#[derive(Debug)]
enum DecodeRequestError {
    InvalidProtocol,
    InvalidIntent,
}

impl Request {
    fn decode(value: [u8; 2]) -> Result<Self, DecodeRequestError> {
        Ok(Self {
            proto: Protocol::decode(value[0]).ok_or(DecodeRequestError::InvalidProtocol)?,
            intent: RequestIntent::decode(value[1]).ok_or(DecodeRequestError::InvalidIntent)?,
        })
    }
}

#[derive(Clone, Copy)]
pub struct Request {
    proto: Protocol,
    intent: RequestIntent,
}

impl Request {
    fn encode(self) -> [u8; 2] {
        [self.proto.encode(), self.intent.encode()]
    }
}

impl Protocol {
    fn decode(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Any),
            1 => Some(Self::Ipv4),
            2 => Some(Self::Ipv6),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub enum Protocol {
    Any,
    Ipv4,
    Ipv6,
}

impl Protocol {
    fn encode(self) -> u8 {
        match self {
            Self::Any => 0,
            Self::Ipv4 => 1,
            Self::Ipv6 => 2,
        }
    }
}

impl RequestIntent {
    fn decode(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::GetHost),
            1 => Some(Self::SetHost),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub enum RequestIntent {
    GetHost,
    SetHost,
}

impl RequestIntent {
    fn encode(self) -> u8 {
        match self {
            Self::GetHost => 0,
            Self::SetHost => 1,
        }
    }
}

#[repr(C)]
#[derive(bytemuck::Pod, bytemuck::Zeroable, Copy, Clone, Default)]
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

#[repr(C)]
#[derive(bytemuck::Pod, bytemuck::Zeroable, Copy, Clone, Default)]
pub struct BlocklistEntry {
    pub suspensions: Suspensions,
    pub ban: Option<Ban>,
}

#[derive(Copy, Clone, Default)]
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
            comment: PascalString::new(),
        }
    }
}

#[repr(C)]
#[derive(bytemuck::Pod, bytemuck::Zeroable, Copy, Clone)]
pub struct Suspension {
    start: Timestamp,
    end: Timestamp,
    comment: PascalString,
}

impl Suspension {
    pub fn start(&self) -> Timestamp {
        self.start
    }

    pub fn end(&self) -> Timestamp {
        self.end
    }

    pub fn comment(&self) -> &PascalString {
        &self.comment
    }

    pub fn is_active(&self) -> bool {
        self.end.passed()
    }
}

impl Ban {
    pub fn now() -> Self {
        Self {
            start: Timestamp::now(),
            comment: PascalString::new(),
        }
    }
}

#[repr(C)]
#[derive(bytemuck::Pod, bytemuck::Zeroable, Clone, Copy)]
pub struct Ban {
    start: Timestamp,
    comment: PascalString,
}

impl Ban {
    pub fn start(&self) -> Timestamp {
        self.start
    }

    pub fn comment(&self) -> &PascalString {
        &self.comment
    }
}


impl Default for HostOffenses {
    fn default() -> Self {
        HostOffenses::empty()
    }
}

bitflags! {
    #[repr(C)]
    #[derive(bytemuck::Pod, bytemuck::Zeroable)]
    pub struct HostOffenses: u32 {
        const ATTEMPTED_TO_ACCESS_ADMIN_PANEL = 1 << 0;
    }
}
