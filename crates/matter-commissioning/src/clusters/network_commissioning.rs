//! `NetworkCommissioning` cluster (id `0x0031`) command + response
//! codecs.
//!
//! Spec §11.9. M6.5 ships the Wi-Fi subset: `AddOrUpdateWiFiNetwork`,
//! `ConnectNetwork`, plus the `FeatureMap` attribute read for
//! Wi-Fi/Ethernet/Thread branching. `ScanNetworks`, Thread commands,
//! and `RemoveNetwork`/`ReorderNetworks` are deferred per the M6.5 spec.

#![forbid(unsafe_code)]

use crate::state_machine::{CommissioningError, Stage};

/// Cluster ID: `0x0031`.
pub const CLUSTER_ID: u32 = 0x0031;

/// Command IDs (Matter Core Spec §11.9.6).
pub mod command_id {
    /// `AddOrUpdateWiFiNetwork` request.
    pub const ADD_OR_UPDATE_WIFI_NETWORK: u32 = 0x02;
    /// `ConnectNetwork` request.
    pub const CONNECT_NETWORK: u32 = 0x06;
}

/// Response IDs (Matter Core Spec §11.9.6).
pub mod response_id {
    /// `NetworkConfigResponse` — emitted for
    /// `AddOrUpdateWiFiNetwork` / `RemoveNetwork` / `ReorderNetworks`.
    pub const NETWORK_CONFIG_RESPONSE: u32 = 0x05;
    /// `ConnectNetworkResponse`.
    pub const CONNECT_NETWORK_RESPONSE: u32 = 0x07;
}

/// Attribute IDs.
pub mod attribute_id {
    /// Universal Matter cluster meta-attribute. Spec §7.13.
    pub const FEATURE_MAP: u32 = 0xFFFC;
}

bitflags::bitflags! {
    /// Bits from `NetworkCommissioning::FeatureMap` (spec §11.9.4).
    ///
    /// Bit 0 = `WiFiNetworkInterface`, bit 1 = `ThreadNetworkInterface`,
    /// bit 2 = `EthernetNetworkInterface`. Higher bits reserved.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    pub struct WiFiNetworkFeature: u32 {
        /// Device exposes a Wi-Fi network interface.
        const WIFI     = 1 << 0;
        /// Device exposes a Thread network interface.
        const THREAD   = 1 << 1;
        /// Device exposes an Ethernet network interface.
        const ETHERNET = 1 << 2;
    }
}

/// Encode `AddOrUpdateWiFiNetwork` (spec §11.9.6.3).
///
/// `ssid` must be 1–32 bytes; `credentials` 0–64 bytes. The encoder
/// does NOT validate lengths — callers (state machine `Commissioner`)
/// validate at config-load time.
#[must_use]
#[allow(clippy::expect_used, clippy::missing_panics_doc)] // Vec-backed TlvWriter is infallible.
pub fn encode_add_or_update_wifi_network(
    ssid: &[u8],
    credentials: &[u8],
    breadcrumb: u64,
) -> Vec<u8> {
    use matter_codec::{Tag, TlvWriter};
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous)
        .expect("infallible: vec writer");
    w.put_bytes(Tag::Context(0), ssid)
        .expect("infallible: vec writer");
    w.put_bytes(Tag::Context(1), credentials)
        .expect("infallible: vec writer");
    w.put_uint(Tag::Context(2), breadcrumb)
        .expect("infallible: vec writer");
    w.end_container().expect("infallible: vec writer");
    buf
}

/// Encode `ConnectNetwork` (spec §11.9.6.6).
///
/// `network_id` is the SSID bytes for Wi-Fi networks (re-uses the
/// `ssid` field as the network identity per spec §11.9.5.2). For
/// Wi-Fi commissioning the value is identical to the SSID supplied
/// to `encode_add_or_update_wifi_network`.
#[must_use]
#[allow(clippy::expect_used, clippy::missing_panics_doc)] // Vec-backed TlvWriter is infallible.
pub fn encode_connect_network(network_id: &[u8], breadcrumb: u64) -> Vec<u8> {
    use matter_codec::{Tag, TlvWriter};
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous)
        .expect("infallible: vec writer");
    w.put_bytes(Tag::Context(0), network_id)
        .expect("infallible: vec writer");
    w.put_uint(Tag::Context(1), breadcrumb)
        .expect("infallible: vec writer");
    w.end_container().expect("infallible: vec writer");
    buf
}

/// Decode the `NetworkCommissioning::FeatureMap` attribute value.
///
/// Expects the bare TLV encoding of the u32 attribute value (no
/// `AttributeReportIB` envelope). The state machine's M6.6 driver
/// unwraps the Interaction Model envelope and delivers just the value
/// TLV to `Commissioner::on_response`.
///
/// # Errors
///
/// Returns `CommissioningError::MalformedResponse(Stage::NetworkCommissioning)`
/// if the bytes are not a well-formed unsigned-integer TLV element. (The
/// stage name changes to `Stage::ReadNetworkCommissioningInfo` in M6.5.2.)
pub fn decode_feature_map(tlv: &[u8]) -> Result<WiFiNetworkFeature, CommissioningError> {
    use matter_codec::{Element, TlvReader, Value};
    let mut reader = TlvReader::new(tlv);
    match reader
        .next()
        .map_err(|_| CommissioningError::MalformedResponse(Stage::NetworkCommissioning))?
    {
        Some(Element::Scalar {
            value: Value::Uint(raw),
            ..
        }) => {
            let truncated = u32::try_from(raw).map_err(|_| {
                CommissioningError::MalformedResponse(Stage::NetworkCommissioning)
            })?;
            Ok(WiFiNetworkFeature::from_bits_truncate(truncated))
        }
        _ => Err(CommissioningError::MalformedResponse(
            Stage::NetworkCommissioning,
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;

    #[test]
    fn feature_bits_disjoint() {
        assert_eq!(WiFiNetworkFeature::WIFI.bits(), 0b001);
        assert_eq!(WiFiNetworkFeature::THREAD.bits(), 0b010);
        assert_eq!(WiFiNetworkFeature::ETHERNET.bits(), 0b100);
    }

    #[test]
    fn cluster_id_is_0x0031() {
        assert_eq!(CLUSTER_ID, 0x0031);
    }

    #[test]
    fn add_or_update_wifi_network_matter_no_creds_matches_spec_bytes() {
        let bytes = encode_add_or_update_wifi_network(b"matter", b"", 0);
        assert_eq!(
            bytes,
            vec![
                0x15,
                0x30, 0x00, 0x06, b'm', b'a', b't', b't', b'e', b'r',
                0x30, 0x01, 0x00,
                0x24, 0x02, 0x00,
                0x18,
            ],
            "encoded bytes: {:02x?}",
            bytes,
        );
    }

    #[test]
    fn add_or_update_wifi_network_with_creds_includes_passphrase_bytes() {
        let bytes = encode_add_or_update_wifi_network(b"matter", b"hunter22", 1);
        // Check structural invariants without hand-computing the full byte string.
        assert_eq!(bytes.first(), Some(&0x15));
        assert_eq!(bytes.last(), Some(&0x18));
        let window = b"hunter22";
        assert!(
            bytes.windows(window.len()).any(|w| w == window),
            "credentials should appear in the payload literal",
        );
    }

    #[test]
    fn connect_network_matter_matches_spec_bytes() {
        let bytes = encode_connect_network(b"matter", 0);
        assert_eq!(
            bytes,
            vec![
                0x15,
                0x30, 0x00, 0x06, b'm', b'a', b't', b't', b'e', b'r',
                0x24, 0x01, 0x00,
                0x18,
            ],
            "encoded bytes: {:02x?}",
            bytes,
        );
    }

    #[test]
    fn decode_feature_map_round_trips_all_8_combinations() {
        // TLV encoding for u32 value `v` (anonymous tag, minimum width):
        // - 0 ..= 0xFF        → 0x04 0xVV               (uint-1B)
        // - 0x100 ..= 0xFFFF  → 0x05 0xLO 0xHI          (uint-2B)
        // For all 3-bit values (0..=7) we hit the uint-1B branch.
        for raw in 0u8..8 {
            let tlv = vec![0x04, raw];
            let decoded =
                decode_feature_map(&tlv).expect("happy path decodes");
            assert_eq!(decoded.bits(), u32::from(raw));
        }
    }

    #[test]
    fn decode_feature_map_rejects_non_uint_tlv() {
        // Octet-string TLV — wrong element type.
        let tlv = vec![0x10, 0x00];
        let err = decode_feature_map(&tlv).expect_err("should fail");
        assert!(
            matches!(err, CommissioningError::MalformedResponse(_)),
            "got {err:?}",
        );
    }

    #[test]
    fn decode_feature_map_truncates_high_bits_safely() {
        // Reserved bits ignored — only WIFI|THREAD|ETHERNET (bits 0-2) recognised.
        // raw value 0x0F = WIFI|THREAD|ETHERNET + bit 3 (reserved). Bit 3 dropped
        // by from_bits_truncate.
        let tlv = vec![0x04, 0x0F];
        let decoded = decode_feature_map(&tlv).expect("decodes");
        assert_eq!(
            decoded,
            WiFiNetworkFeature::WIFI | WiFiNetworkFeature::THREAD | WiFiNetworkFeature::ETHERNET,
        );
    }
}
