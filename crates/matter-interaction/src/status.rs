//! Interaction Model status codes — Matter Core Spec §8.10 (Status Codes).

#![forbid(unsafe_code)]

/// An Interaction Model status, as carried by a `StatusIB`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImStatus {
    /// `SUCCESS` (0x00).
    Success,
    /// Any non-zero IM status code (e.g. 0x01 `FAILURE`, 0x86
    /// `UNSUPPORTED_ATTRIBUTE`, 0x88 `INVALID_ACTION`). The raw code is
    /// preserved so callers can log or branch on it.
    Failure(u8),
}

impl ImStatus {
    /// Map a raw IM status byte to [`ImStatus`].
    #[must_use]
    pub fn from_u8(code: u8) -> Self {
        if code == 0x00 {
            Self::Success
        } else {
            Self::Failure(code)
        }
    }

    /// `true` iff this is [`ImStatus::Success`].
    #[must_use]
    pub fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_success_and_failure_codes() {
        assert_eq!(ImStatus::from_u8(0x00), ImStatus::Success);
        assert!(matches!(ImStatus::from_u8(0x01), ImStatus::Failure(0x01)));
        assert!(matches!(ImStatus::from_u8(0x88), ImStatus::Failure(0x88)));
    }

    #[test]
    fn is_success_only_for_zero() {
        assert!(ImStatus::from_u8(0x00).is_success());
        assert!(!ImStatus::from_u8(0x01).is_success());
    }
}
