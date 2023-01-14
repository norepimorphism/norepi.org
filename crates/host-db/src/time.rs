// SPDX-License-Identifier: MPL-2.0

use std::ops::Add;

pub type UtcDateTime = chrono::DateTime<chrono::Utc>;

pub trait Duration {
    fn checked_add(self, date: UtcDateTime) -> Option<UtcDateTime>;
}

impl Duration for chrono::Days {
    fn checked_add(self, date: UtcDateTime) -> Option<UtcDateTime> {
        date.checked_add_days(self)
    }
}

impl Duration for chrono::Months {
    fn checked_add(self, date: UtcDateTime) -> Option<UtcDateTime> {
        date.checked_add_months(self)
    }
}

impl Timestamp {
    pub fn now() -> Self {
        chrono::Utc::now().into()
    }
}

impl From<&UtcDateTime> for Timestamp {
    fn from(datetime: &UtcDateTime) -> Self {
        Self(datetime.timestamp())
    }
}

impl From<UtcDateTime> for Timestamp {
    fn from(datetime: UtcDateTime) -> Self {
        Self(datetime.timestamp())
    }
}

#[repr(transparent)]
#[derive(serde::Deserialize, serde::Serialize, Clone, Copy, Debug)]
pub struct Timestamp(i64);

impl Timestamp {
    pub fn passed(&self) -> bool {
        self.is_before(Self::now())
    }

    pub fn is_before(&self, other: Self) -> bool {
        self.0 < other.0
    }

    pub fn is_after(&self, other: Self) -> bool {
        self.0 > other.0
    }
}

impl<D: Duration> Add<D> for Timestamp {
    type Output = Self;

    fn add(self, duration: D) -> Self::Output {
        // TODO: Don't unwrap.
        duration.checked_add(UtcDateTime::from(self)).unwrap().into()
    }
}

impl From<Timestamp> for UtcDateTime {
    fn from(timestamp: Timestamp) -> Self {
        // TODO: Don't unwrap.
        let datetime = chrono::NaiveDateTime::from_timestamp_opt(timestamp.0, 0).unwrap();

        chrono::DateTime::from_utc(datetime, chrono::offset::Utc)
    }
}
