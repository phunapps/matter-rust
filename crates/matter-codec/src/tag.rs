//! Matter TLV tag forms.
//!
//! Five tag forms exist in the spec (§A.2): anonymous, context-specific,
//! common-profile, implicit-profile, and fully-qualified. Phase 1 of
//! `matter-codec` implements only `Anonymous` and `Context`; the remaining
//! variants will be added in phase 2.

/// A Matter TLV tag.
///
/// The enum is marked `#[non_exhaustive]` so adding the remaining variants
/// in a later phase is not a breaking change for downstream `match`
/// expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Tag {
    /// No tag bytes follow the control octet.
    Anonymous,

    /// One tag byte follows, carrying the context-specific tag number.
    Context(u8),
}
