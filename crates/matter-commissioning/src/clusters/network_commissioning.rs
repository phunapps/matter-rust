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
}
