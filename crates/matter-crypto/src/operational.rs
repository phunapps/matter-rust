//! Operational identity derivations (Matter Core Spec §4.3).
//!
//! Composes `ring`'s HKDF — this crate never implements primitives.

use ring::hkdf;

use crate::error::{Error, Result};

/// HKDF info label for the Compressed Fabric Identifier (Matter Core Spec §4.3.2.2).
const COMPRESSED_FABRIC_INFO: &[u8] = b"CompressedFabric";

/// `KeyType` adapter for a fixed 8-byte HKDF output.
///
/// `ring::hkdf::Prk::expand` requires a type implementing [`hkdf::KeyType`]
/// to enforce that the output length is known at the type level.  We use a
/// unit struct instead of a lambda so the implementation compiles on stable
/// Rust without any RPIT dance.
struct Len8;

impl hkdf::KeyType for Len8 {
    fn len(&self) -> usize {
        8
    }
}

/// Derive the 8-byte Compressed Fabric Identifier from the fabric Root CA
/// public key and the fabric id (Matter Core Spec §4.3.2.2).
///
/// `root_public_key` is the RCAC public key in SEC1 *uncompressed* form
/// (`0x04 || X || Y`, 65 bytes).  The HKDF inputs are:
///
/// - **IKM**: the 64-byte `X || Y` — the leading `0x04` byte is dropped, as
///   specified in the Matter Core Spec and confirmed in connectedhomeip
///   `Crypto::GenerateCompressedFabricId` (`rootPublicKey + 1, 64`) and
///   matter.js `Fabric` (which slices off the first byte before the HKDF
///   call).
/// - **Salt**: `fabric_id` encoded as an 8-byte **big-endian** integer.
/// - **Info**: the ASCII literal `"CompressedFabric"`.
/// - **Output length**: 8 bytes.
///
/// Byte-parity confirmed against the Matter Core Spec §4.3.2.2 worked example
/// (via connectedhomeip `TestCompressedFabricIdentifier`); see the in-tree test
/// and `test-vectors/operational/compressed_fabric_id.json`. The *operational
/// mDNS instance-name* format that consumes this value is validated separately
/// in M6.6.3b.
///
/// # Errors
///
/// Returns [`Error::KeyDerivationFailed`] if the internal HKDF `expand` or
/// `fill` call fails.  For the fixed 8-byte output length this should never
/// occur in practice; the error path exists to satisfy the `Result` contract
/// rather than using `unwrap`.
pub fn derive_compressed_fabric_id(root_public_key: &[u8; 65], fabric_id: u64) -> Result<[u8; 8]> {
    // Salt = fabric_id as 8-byte big-endian (Matter Core Spec §4.3.2.2).
    let salt_bytes = fabric_id.to_be_bytes();

    // IKM = X || Y (64 bytes): drop the leading 0x04 SEC1 prefix byte.
    let ikm = &root_public_key[1..];

    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt_bytes).extract(ikm);

    let okm = prk
        .expand(&[COMPRESSED_FABRIC_INFO], Len8)
        .map_err(|_| Error::KeyDerivationFailed)?;

    let mut out = [0u8; 8];
    okm.fill(&mut out).map_err(|_| Error::KeyDerivationFailed)?;

    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;

    /// Byte-parity against the Matter Core Spec §4.3.2.2 (Compressed Fabric
    /// Identifier) worked example, as encoded in connectedhomeip
    /// `TestChipCryptoPAL.cpp::TestCompressedFabricIdentifier`
    /// (`kRootPublicKey` / `kFabricId` / `kExpectedCompressedFabricIdentifier`).
    /// Vector also stored at `test-vectors/operational/compressed_fabric_id.json`.
    #[test]
    fn compressed_fabric_id_matches_spec_vector() {
        let mut root_pub = [0u8; 65];
        let hex = "044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641cb8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfacfa";
        for (i, byte) in root_pub.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let fabric_id: u64 = 0x2906_C908_D115_D362;
        let got = derive_compressed_fabric_id(&root_pub, fabric_id).unwrap();
        assert_eq!(got, [0x87, 0xe1, 0xb0, 0x04, 0xe2, 0x35, 0xa1, 0x30]);
    }
}
