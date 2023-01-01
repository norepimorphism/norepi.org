// SPDX-License-Identifier: MPL-2.0

pub mod blocklist;
pub mod ty;

use bitflags::bitflags;

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
