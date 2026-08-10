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

    // Interleaved streaming walk: alternate next() with skip_container() on
    // every other ContainerStart. Exercises the raw-walk skip against the
    // event-driven reader on the same adversarial input; must never panic
    // or loop forever (depth and bounds are enforced internally).
    let mut ir = matter_codec::TlvReader::new(data);
    let mut skip_toggle = false;
    loop {
        match ir.next() {
            Ok(Some(matter_codec::Element::ContainerStart { .. })) => {
                if skip_toggle && ir.skip_container().is_err() {
                    break;
                }
                skip_toggle = !skip_toggle;
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
});
