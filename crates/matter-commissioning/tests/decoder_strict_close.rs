//! The command-response decoders require one complete struct and find its
//! real end.
//!
//! Each decoder takes a command-fields blob. In a commissioning run that blob
//! comes from `parse_invoke_response`, which re-encodes it from a closed
//! container, so it is already well-formed there. The decoders are public,
//! though, and take arbitrary bytes. Two gaps are closed:
//!
//! - **Strict close.** Every strict prefix and any trailing bytes are
//!   rejected, as chip's `MessageParser::ExitContainer` rejects them on the
//!   message itself.
//! - **Nested containers.** Several decoders ignored a `ContainerStart`
//!   without skipping its body. The members of an unknown container field
//!   were then read as top-level fields, and its end-of-container ended the
//!   struct early. That path *is* reachable from a device: a response
//!   carrying a container-typed field from a newer revision either failed
//!   to decode or had its fields misattributed.

#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code: CLAUDE.md carve-out.

use matter_codec::{Tag, TlvWriter};
use matter_commissioning::clusters::general_commissioning::{
    decode_arm_fail_safe_response, decode_basic_commissioning_info,
    decode_set_regulatory_config_response,
};
use matter_commissioning::clusters::network_commissioning::{
    decode_connect_network_response, decode_network_config_response,
};
use matter_commissioning::noc::commands::{
    decode_attestation_response, decode_certificate_chain_response, decode_csr_response,
    decode_noc_response,
};
use matter_commissioning::Stage;

const SUFFIXES: &[&[u8]] = &[&[0x00], &[0x04, 0x00], &[0x15, 0x18], &[0x18], &[0xFF]];

fn assert_strict(name: &str, full: &[u8], accepts: impl Fn(&[u8]) -> bool) {
    assert!(accepts(full), "{name}: the full struct must decode");
    for suffix in SUFFIXES {
        let mut tailed = full.to_vec();
        tailed.extend_from_slice(suffix);
        assert!(
            !accepts(&tailed),
            "{name}: accepted with trailing bytes {suffix:02x?}"
        );
    }
    for n in 0..full.len() {
        assert!(
            !accepts(&full[..n]),
            "{name}: prefix of {n} / {} bytes accepted (truncated struct)",
            full.len()
        );
    }
}

/// Encode an anonymous struct. `decoy` first writes an unknown context-9
/// struct that holds `decoy`'s fields under the *real* fields' tags, the
/// shape a newer-revision container field could take. Then `fields` writes
/// the real members.
fn encode(
    decoy: Option<&dyn Fn(&mut TlvWriter<'_>)>,
    fields: &dyn Fn(&mut TlvWriter<'_>),
) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).unwrap();
    if let Some(decoy) = decoy {
        w.start_structure(Tag::Context(9)).unwrap();
        decoy(&mut w);
        w.end_container().unwrap();
    }
    fields(&mut w);
    w.end_container().unwrap();
    buf
}

fn sig(fill: u8) -> [u8; 64] {
    [fill; 64]
}

#[test]
fn attestation_response() {
    let real = |w: &mut TlvWriter<'_>| {
        w.put_bytes(Tag::Context(0), b"elements").unwrap();
        w.put_bytes(Tag::Context(1), &sig(0xAA)).unwrap();
    };
    let decoy = |w: &mut TlvWriter<'_>| {
        w.put_bytes(Tag::Context(0), b"decoy").unwrap();
    };
    assert_strict("AttestationResponse", &encode(None, &real), |b| {
        decode_attestation_response(b).is_ok()
    });
    let got = decode_attestation_response(&encode(Some(&decoy), &real)).unwrap();
    assert_eq!(got.attestation_elements, b"elements");
    assert_eq!(got.signature, sig(0xAA));
}

#[test]
fn certificate_chain_response() {
    let real = |w: &mut TlvWriter<'_>| {
        w.put_bytes(Tag::Context(0), b"der").unwrap();
    };
    let decoy = |w: &mut TlvWriter<'_>| {
        w.put_bytes(Tag::Context(0), b"decoy").unwrap();
    };
    assert_strict("CertificateChainResponse", &encode(None, &real), |b| {
        decode_certificate_chain_response(b).is_ok()
    });
    let got = decode_certificate_chain_response(&encode(Some(&decoy), &real)).unwrap();
    assert_eq!(got.certificate, b"der");
}

#[test]
fn csr_response() {
    let real = |w: &mut TlvWriter<'_>| {
        w.put_bytes(Tag::Context(0), b"nocsr").unwrap();
        w.put_bytes(Tag::Context(1), &sig(0xBB)).unwrap();
    };
    let decoy = |w: &mut TlvWriter<'_>| {
        w.put_bytes(Tag::Context(0), b"decoy").unwrap();
    };
    assert_strict("CSRResponse", &encode(None, &real), |b| {
        decode_csr_response(b).is_ok()
    });
    let got = decode_csr_response(&encode(Some(&decoy), &real)).unwrap();
    assert_eq!(got.nocsr_elements, b"nocsr");
    assert_eq!(got.attestation_signature, sig(0xBB));
}

#[test]
fn noc_response() {
    let real = |w: &mut TlvWriter<'_>| {
        w.put_uint(Tag::Context(0), 0).unwrap();
        w.put_uint(Tag::Context(1), 3).unwrap();
        w.put_utf8(Tag::Context(2), "ok").unwrap();
    };
    let decoy = |w: &mut TlvWriter<'_>| {
        w.put_uint(Tag::Context(0), 9).unwrap();
        w.put_uint(Tag::Context(1), 9).unwrap();
    };
    assert_strict("NOCResponse", &encode(None, &real), |b| {
        decode_noc_response(b).is_ok()
    });
    let got = decode_noc_response(&encode(Some(&decoy), &real)).unwrap();
    assert_eq!((got.status, got.fabric_index), (0, Some(3)));
    assert_eq!(got.debug_text.as_deref(), Some("ok"));
}

#[test]
fn arm_fail_safe_and_set_regulatory_config_responses() {
    let real = |w: &mut TlvWriter<'_>| {
        w.put_uint(Tag::Context(0), 0).unwrap();
        w.put_utf8(Tag::Context(1), "").unwrap();
    };
    let decoy = |w: &mut TlvWriter<'_>| {
        w.put_uint(Tag::Context(0), 4).unwrap();
    };
    let full = encode(None, &real);
    assert_strict("ArmFailSafeResponse", &full, |b| {
        decode_arm_fail_safe_response(b).is_ok()
    });
    assert_strict("SetRegulatoryConfigResponse", &full, |b| {
        decode_set_regulatory_config_response(b).is_ok()
    });
    let got = decode_arm_fail_safe_response(&encode(Some(&decoy), &real)).unwrap();
    assert_eq!(got.error_code, 0);
}

#[test]
fn basic_commissioning_info() {
    let real = |w: &mut TlvWriter<'_>| {
        w.put_uint(Tag::Context(0), 60).unwrap();
        w.put_uint(Tag::Context(1), 900).unwrap();
    };
    let decoy = |w: &mut TlvWriter<'_>| {
        w.put_uint(Tag::Context(0), 1).unwrap();
        w.put_uint(Tag::Context(1), 1).unwrap();
    };
    assert_strict("BasicCommissioningInfo", &encode(None, &real), |b| {
        decode_basic_commissioning_info(b).is_some()
    });
    let got = decode_basic_commissioning_info(&encode(Some(&decoy), &real)).unwrap();
    assert_eq!(got.failsafe_expiry_length_seconds, 60);
    assert_eq!(got.max_cumulative_failsafe_seconds, 900);
}

#[test]
fn network_config_response() {
    let real = |w: &mut TlvWriter<'_>| {
        w.put_uint(Tag::Context(0), 0).unwrap();
        w.put_utf8(Tag::Context(1), "ok").unwrap();
        w.put_uint(Tag::Context(2), 0).unwrap();
    };
    let decoy = |w: &mut TlvWriter<'_>| {
        w.put_uint(Tag::Context(0), 7).unwrap();
    };
    assert_strict("NetworkConfigResponse", &encode(None, &real), |b| {
        decode_network_config_response(Stage::NetworkSetup, b).is_ok()
    });
    let got =
        decode_network_config_response(Stage::NetworkSetup, &encode(Some(&decoy), &real)).unwrap();
    assert_eq!(got.networking_status, 0);
}

#[test]
fn connect_network_response() {
    let real = |w: &mut TlvWriter<'_>| {
        w.put_uint(Tag::Context(0), 0).unwrap();
        w.put_utf8(Tag::Context(1), "ok").unwrap();
        w.put_int(Tag::Context(2), -1).unwrap();
    };
    let decoy = |w: &mut TlvWriter<'_>| {
        w.put_uint(Tag::Context(0), 7).unwrap();
    };
    assert_strict("ConnectNetworkResponse", &encode(None, &real), |b| {
        decode_connect_network_response(Stage::NetworkSetup, b).is_ok()
    });
    let got =
        decode_connect_network_response(Stage::NetworkSetup, &encode(Some(&decoy), &real)).unwrap();
    assert_eq!((got.networking_status, got.error_value), (0, Some(-1)));
}
