//! `NetworkCommissioning` cluster (id `0x0031`) command + response
//! codecs.
//!
//! Spec §11.9. M6.5 ships the Wi-Fi subset: `AddOrUpdateWiFiNetwork`,
//! `ConnectNetwork`, plus the `FeatureMap` attribute read for
//! Wi-Fi/Ethernet/Thread branching. `ScanNetworks`, Thread commands,
//! and `RemoveNetwork`/`ReorderNetworks` are deferred per the M6.5 spec.

#![forbid(unsafe_code)]

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
}
