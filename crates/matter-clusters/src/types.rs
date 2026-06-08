//! Hand-written support types referenced by generated cluster code.

/// A value that may be explicitly null on the wire (Matter quality `X`).
///
/// Distinct from [`Option`]: `Option<T>` models an **optional** element
/// (its tag is absent entirely), whereas `Nullable<T>` models a **present**
/// element whose TLV value is the null type. A field that is both optional
/// and nullable is `Option<Nullable<T>>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nullable<T> {
    /// The wire carried an explicit TLV null.
    Null,
    /// The wire carried a concrete value.
    Value(T),
}

impl<T> Nullable<T> {
    /// Returns the contained value, or `None` if null.
    pub fn value(self) -> Option<T> {
        match self {
            Nullable::Null => None,
            Nullable::Value(v) => Some(v),
        }
    }

    /// Returns `true` if this is [`Nullable::Null`].
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Nullable::Null)
    }
}

impl<T> From<Option<T>> for Nullable<T> {
    fn from(o: Option<T>) -> Self {
        match o {
            Some(v) => Nullable::Value(v),
            None => Nullable::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_and_is_null() {
        assert_eq!(Nullable::Value(7u8).value(), Some(7));
        assert!(Nullable::<u8>::Null.value().is_none());
        assert!(Nullable::<u8>::Null.is_null());
        assert!(!Nullable::Value(7u8).is_null());
    }

    #[test]
    fn from_option() {
        assert_eq!(Nullable::from(Some(3u8)), Nullable::Value(3));
        assert_eq!(Nullable::<u8>::from(None), Nullable::Null);
    }
}
