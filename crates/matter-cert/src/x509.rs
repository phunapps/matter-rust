//! Matter TLV → X.509 DER `TBSCertificate` conversion.
//!
//! Real Matter certificates carry signatures over the X.509 DER form
//! of the certificate, not over the Matter TLV form. This module maps
//! a parsed [`crate::MatterCertificate`] into a byte-identical
//! representation of matter.js's `Certificate.asUnsignedDer()` output,
//! which `MatterCertificate::verify_signed_by` then hands to `ring`.
//!
//! See `docs/superpowers/specs/2026-05-18-matter-x509-conversion-design.md`
//! for the full design and the byte-parity rationale.

// The OID constants are defined now for completeness and documentation value;
// they are wired into the encoder in Tasks 3–9. Suppress dead-code warnings
// for the skeleton phase only — remove this attribute when the encoder lands.
#![allow(dead_code)]

use der::asn1::ObjectIdentifier;

use crate::certificate::MatterCertificate;
use crate::error::{Error, Result};

// =============================================================================
// Matter-specific DN attribute OIDs (CSA arc 1.3.6.1.4.1.37244)
// =============================================================================
//
// Values pinned from matter.js's asn.js (dist/cjs/certificate/kinds/definitions/asn.js).
// The .d.ts comments are authoritative:
//   /** matter-node-id            = ASN.1 OID 1.3.6.1.4.1.37244.1.1 */
//   /** matter-firmware-signing-id = ASN.1 OID 1.3.6.1.4.1.37244.1.2 */
//   /** matter-icac-id            = ASN.1 OID 1.3.6.1.4.1.37244.1.3 */
//   /** matter-rcac-id            = ASN.1 OID 1.3.6.1.4.1.37244.1.4 */
//   /** matter-fabric-id          = ASN.1 OID 1.3.6.1.4.1.37244.1.5 */
//   /** matter-noc-cat            = ASN.1 OID 1.3.6.1.4.1.37244.1.6 */
//   /** matter-vvs-id             = ASN.1 OID 1.3.6.1.4.1.37244.1.7 */  ← present in matter.js; not in the plan template
//   /** matter-oid-vid            = ASN.1 OID 1.3.6.1.4.1.37244.2.1 */
//   /** matter-oid-pid            = ASN.1 OID 1.3.6.1.4.1.37244.2.2 */
/// Operational-certificate attribute: Matter node-id.
const OID_MATTER_NODE_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.1");

/// Operational-certificate attribute: Matter firmware-signing-id.
const OID_MATTER_FIRMWARE_SIGNING_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.2");

/// Operational-certificate attribute: Matter ICAC id.
const OID_MATTER_ICAC_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.3");

/// Operational-certificate attribute: Matter RCAC id.
const OID_MATTER_RCAC_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.4");

/// Operational-certificate attribute: Matter fabric-id.
const OID_MATTER_FABRIC_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.5");

/// Operational-certificate attribute: Matter NOC CASE Authenticated Tag.
const OID_MATTER_NOC_CAT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.6");

/// Operational-certificate attribute: Matter VVS id.
///
/// Present in matter.js (arc `.1.7`) but absent from the plan template.
/// Included here for completeness; used in Vendor Verification Service
/// certificates introduced in a later Matter specification revision.
const OID_MATTER_VVS_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.7");

/// Attestation-certificate attribute: Matter vendor-id.
const OID_MATTER_VENDOR_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.2.1");

/// Attestation-certificate attribute: Matter product-id.
const OID_MATTER_PRODUCT_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.2.2");

// =============================================================================
// Standard X.509 DN attribute OIDs (RFC 5280 / X.520)
// =============================================================================

const OID_X520_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_X520_SURNAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.4");
const OID_X520_SERIAL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");
const OID_X520_COUNTRY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
const OID_X520_LOCALITY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.7");
const OID_X520_STATE_OR_PROVINCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.8");
const OID_X520_ORG: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const OID_X520_ORG_UNIT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
const OID_X520_TITLE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.12");
const OID_X520_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.41");
const OID_X520_GIVEN_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.42");
const OID_X520_INITIALS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.43");
const OID_X520_GENERATION_QUALIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.44");
const OID_X520_DN_QUALIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.46");
const OID_X520_PSEUDONYM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.65");
const OID_DOMAIN_COMPONENT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.9.2342.19200300.100.1.25");

// =============================================================================
// X.509 extension OIDs (RFC 5280)
// =============================================================================

const OID_EXT_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const OID_EXT_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_EXT_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_EXT_AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.35");

// =============================================================================
// Algorithm + curve OIDs
// =============================================================================

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_EC_CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

// =============================================================================
// Top-level entry point
// =============================================================================

/// Build the X.509 DER `TBSCertificate` for `cert`.
///
/// Byte-identical to matter.js's `Certificate.asUnsignedDer()` for the
/// same input. Used internally by `MatterCertificate::verify_signed_by`
/// and exposed publicly via `MatterCertificate::to_x509_tbs_der`.
pub(crate) fn matter_cert_to_x509_tbs_der(cert: &MatterCertificate) -> Result<Vec<u8>> {
    // Filled in by Task 9.
    let _ = cert;
    Err(Error::SignatureVerificationFailed) // placeholder so the file compiles
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    // Per-encoder tests added in Tasks 3–9.
}
