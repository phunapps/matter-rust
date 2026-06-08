//! Shared types used across generated cluster modules.

/// A value that may be null on the wire (Matter spec quality `X`).
///
/// `Nullable<T>` maps directly to the TLV null element for `Null` and to the
/// appropriate TLV scalar for `Value(T)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Nullable<T> {
    /// The wire value was TLV null.
    Null,
    /// The wire value was a non-null element of type `T`.
    Value(T),
}
