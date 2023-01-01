// SPDX-License-Identifier: MPL-2.0

use super::ty::{Duration, PascalString, Timestamp};

#[derive(Default, serde::Deserialize)]
pub struct Entry {
    pub suspensions: Suspensions,
    pub ban: Option<Ban>,
}

#[derive(Clone, Default, serde::Deserialize)]
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
}

impl Suspension {
    pub fn for_duration_from_now(duration: impl Duration) -> Self {
        let now = Timestamp::now();

        Self {
            end: now + duration,
            start: now,
            comment: PascalString::new(),
        }
    }
}

#[derive(Clone, serde::Deserialize)]
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

#[derive(serde::Deserialize)]
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
