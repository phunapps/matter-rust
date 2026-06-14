//! Fuzz target: `TlvReader::read_value` must not panic on any input.
//!
//! Run locally with `cargo +nightly fuzz run fuzz_decode`. The weekly
//! CI workflow at `.github/workflows/fuzz.yml` runs this for 5 minutes
//! every Monday.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reader = matter_codec::TlvReader::new(data);
    // `read_value` may return an Error — that's expected for adversarial
    // input. What it MUST NOT do is panic. libFuzzer treats any panic
    // (including arithmetic overflow, slice bounds, unwrap-on-None) as a
    // crash and saves the input under `artifacts/`.
    let _ = reader.read_value();

    // Also exercise skip_container: open the first element; if it is a
    // container, draining it must not panic or loop forever on adversarial
    // input. (depth/budget are enforced by next().)
    let mut sr = matter_codec::TlvReader::new(data);
    if let Ok(Some(matter_codec::Element::ContainerStart { .. })) = sr.next() {
        let _ = sr.skip_container();
    }
});
