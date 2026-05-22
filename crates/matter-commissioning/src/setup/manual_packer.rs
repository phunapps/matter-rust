//! Bit-level pack / unpack of the 11- and 21-digit manual pairing codes
//! (Matter Core Spec §5.1.4).
//!
//! Private to the `setup` module. Digit-chunk math, Verhoeff check digit
//! invocation, and 11/21-form dispatch live here.
