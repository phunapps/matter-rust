//! Key material stays out of `Debug` output.
//!
//! [`GroupKeySet`](crate::group::GroupKeySet),
//! [`GroupKeySetConfig`](crate::state::GroupKeySetConfig) and
//! [`IcdRegistration`](crate::icd::IcdRegistration) each hold a 16-byte
//! symmetric key (a group epoch key, or the ICD Check-In key). A `{:?}` log of
//! one must not leak it, so their `Debug` prints `<redacted>` for the key and
//! everything else exactly as the old derive did.
//!
//! No assertion here prints a `{:?}` rendering or a key on failure: a failing
//! redaction would print the very bytes it failed to hide. Hence `assert!`
//! with static messages throughout, never `assert_eq!`.

use crate::group::GroupKeySet;
use crate::icd::IcdRegistration;
use crate::state::GroupKeySetConfig;

/// A synthetic 16-byte key whose renderings cannot occur by accident: the
/// bytes are `0xC0..=0xCF`, so the decimal list is `192, 193, …, 207` and the
/// hex list is `c0, c1, …, cf`. Nothing else in these structs prints like that.
fn synthetic_key() -> [u8; 16] {
    core::array::from_fn(|i| {
        // `i < 16`, so the cast is lossless and the sum stays below 0xD0.
        #[allow(clippy::cast_possible_truncation)]
        let offset = i as u8;
        0xC0 + offset
    })
}

/// Assert that `shown` (a `{:?}`-family rendering) carries the `"<redacted>"`
/// placeholder and none of `key`'s renderings: its `Debug` byte list (decimal,
/// as `[u8]` prints), that list in hex (`{:x?}`, both cases), and the bytes as
/// one run of hex digits (both cases). Never prints `shown` or `key`.
fn assert_redacted(shown: &str, key: &[u8]) {
    use core::fmt::Write as _;

    assert!(
        shown.contains("\"<redacted>\""),
        "the placeholder is missing"
    );

    let decimal = format!("{key:?}");
    let decimal = decimal.trim_start_matches('[').trim_end_matches(']');
    assert!(!shown.contains(decimal), "the key's Debug byte list leaked");

    let hex_lower = format!("{key:x?}");
    let hex_lower = hex_lower.trim_start_matches('[').trim_end_matches(']');
    assert!(
        !shown.contains(hex_lower),
        "the key's {{:x?}} byte list leaked"
    );
    let hex_upper = format!("{key:X?}");
    let hex_upper = hex_upper.trim_start_matches('[').trim_end_matches(']');
    assert!(
        !shown.contains(hex_upper),
        "the key's {{:X?}} byte list leaked"
    );

    let run = key.iter().fold(String::new(), |mut run, b| {
        // Writing into a `String` cannot fail, so the `fmt::Result` is moot.
        let _ = write!(run, "{b:02x}");
        run
    });
    assert!(!shown.contains(&run), "the key leaked as lowercase hex");
    assert!(
        !shown.contains(&run.to_uppercase()),
        "the key leaked as uppercase hex"
    );
}

/// Check every `Debug` flavour of `value`: plain, alternate (`{:#?}`) and the
/// hex-integer flags (`{:x?}` / `{:X?}`), which the derive would have pushed
/// down into the key's byte list.
fn assert_all_renderings_redacted<T: core::fmt::Debug>(value: &T, key: &[u8]) {
    assert_redacted(&format!("{value:?}"), key);
    assert_redacted(&format!("{value:#?}"), key);
    assert_redacted(&format!("{value:x?}"), key);
    assert_redacted(&format!("{value:X?}"), key);
}

#[test]
fn group_key_set_debug_redacts_the_epoch_key() {
    let key = synthetic_key();
    let set = GroupKeySet::new(0x0042, key.to_vec(), 1234);

    // Same struct name, field names and field order as the old derive; only
    // the key's value changes.
    assert!(
        format!("{set:?}")
            == "GroupKeySet { key_set_id: 66, epoch_key: \"<redacted>\", \
                epoch_start_time: 1234 }",
        "unexpected GroupKeySet rendering"
    );
    assert_all_renderings_redacted(&set, &key);
    // The value itself is untouched: only its rendering is hidden.
    assert!(set.epoch_key == key, "the epoch key was altered");
}

#[test]
fn group_key_set_config_debug_redacts_the_epoch_key() {
    let key = synthetic_key();
    let config = GroupKeySetConfig::new(0x0042, key, 1234);

    assert!(
        format!("{config:?}")
            == "GroupKeySetConfig { key_set_id: 66, epoch_key: \"<redacted>\", \
                epoch_start_time: 1234 }",
        "unexpected GroupKeySetConfig rendering"
    );
    assert_all_renderings_redacted(&config, &key);
    assert!(config.epoch_key == key, "the epoch key was altered");
}

#[test]
fn icd_registration_debug_redacts_the_check_in_key() {
    let key = synthetic_key();
    let registration = IcdRegistration::new(0x1111, 0x2222, 0x3333, key, 7);

    assert!(
        format!("{registration:?}")
            == "IcdRegistration { node_id: 4369, check_in_node_id: 8738, \
                monitored_subject: 13107, key: \"<redacted>\", start_counter: 7 }",
        "unexpected IcdRegistration rendering"
    );
    assert_all_renderings_redacted(&registration, &key);
    assert!(registration.key == key, "the check-in key was altered");
}

#[test]
fn redaction_reaches_through_containers() {
    // A caller is as likely to log a `Vec` or `Option` of these as a single
    // value; the container's derived `Debug` goes through the redacting one.
    let key = synthetic_key();
    let sets = vec![GroupKeySet::new(1, key.to_vec(), 0)];
    assert_all_renderings_redacted(&sets, &key);
    let configs = Some(GroupKeySetConfig::new(1, key, 0));
    assert_all_renderings_redacted(&configs, &key);
    let registrations = vec![IcdRegistration::new(1, 2, 3, key, 0)];
    assert_all_renderings_redacted(&registrations, &key);
}
