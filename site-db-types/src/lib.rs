// SPDX-License-Identifier: MPL-2.0

/// Custom data types for use in a database.

use std::{fmt, ops::Add};

pub use backing::Backing;

pub mod backing;

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
#[derive(Clone, Copy, serde::Deserialize)]
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

impl Default for PascalString {
    fn default() -> Self {
        Self::new()
    }
}

impl PascalString {
    const CAPACITY: usize = 512 - std::mem::align_of::<u8>();

    /// Creates an empty string.
    pub fn new() -> Self {
        Self {
            len: 0,
            content: [0; Self::CAPACITY],
        }
    }
}

/// A length-prefixed, fixed-capacity ASCII string for use in databases.
#[derive(Clone, serde::Deserialize)]
pub struct PascalString {
    len: u8,
    #[serde(with = "serde_big_array::BigArray")]
    content: [u8; Self::CAPACITY],
}

impl fmt::Display for PascalString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(String::from_utf8_lossy(self.as_bytes()).as_ref())
    }
}

impl PascalString {
    /// Determines if the length of this string is zero.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The length, in ASCII characters, of this string.
    pub fn len(&self) -> u8 {
        self.len
    }

    /// An immutable reference to the content of this string.
    pub fn as_bytes(&self) -> &[u8] {
        &self.content[..usize::from(self.len)]
    }

    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(self.as_bytes())
    }
}
