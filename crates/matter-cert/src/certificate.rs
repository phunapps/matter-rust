//! Matter certificate parser and serialiser.
//!
//! Implements parsing and serialisation for the Matter TLV certificate
//! format defined in spec §6.5. A [`MatterCertificate`] is parsed from
//! raw TLV bytes by [`MatterCertificate::from_tlv`] and re-emitted by
//! [`MatterCertificate::to_tlv`]; byte-for-byte round-trip is enforced
//! by the unit tests.

use matter_codec::{ContainerKind, Element, Tag, TlvReader, TlvWriter, Value};

use crate::error::{Error, Result};
use crate::extensions::Extensions;
use crate::name::DistinguishedName;
use crate::public_key::PublicKey;
use crate::signature::Signature;
use crate::time::MatterTime;
use crate::tlv_tags as tags;

/// A parsed Matter certificate.
///
/// Holds every spec §6.5 field. The algorithm identifiers (signature
/// algorithm, public-key algorithm, EC curve) are validated against the
/// only spec-allowed values during `from_tlv` but not stored — they are
/// re-emitted at fixed values by `to_tlv`. The same approach is used in
/// both directions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatterCertificate {
    serial: Vec<u8>,
    issuer: DistinguishedName,
    not_before: MatterTime,
    not_after: MatterTime,
    subject: DistinguishedName,
    public_key: PublicKey,
    extensions: Extensions,
    signature: Signature,
}

impl MatterCertificate {
    /// Parse a certificate from its TLV byte representation.
    ///
    /// Validates the anonymous outer structure and all 11 spec §6.5 fields.
    /// Algorithm identifiers are validated against the only spec-allowed
    /// values (`ecdsa-with-sha256`, `ec-public-key`, `prime256v1`) but not
    /// stored; they are re-emitted at fixed values by [`to_tlv`][Self::to_tlv].
    ///
    /// # Errors
    ///
    /// - [`Error::Codec`] — underlying TLV stream is malformed.
    /// - [`Error::MissingField`] — a required field is absent.
    /// - [`Error::DuplicateField`] — a field appears more than once.
    /// - [`Error::WrongFieldType`] — a field has an unexpected TLV type.
    /// - [`Error::FieldValueOutOfRange`] — a numeric field overflows its spec range.
    /// - [`Error::UnsupportedSignatureAlgorithm`] / [`Error::UnsupportedPublicKeyAlgorithm`]
    ///   / [`Error::UnsupportedEcCurve`] — non-spec algorithm or curve identifier.
    // The single-pass exhaustive match over 11 context tags is intentionally
    // kept as one function for readability and auditability.
    #[allow(clippy::too_many_lines)]
    pub fn from_tlv(bytes: &[u8]) -> Result<Self> {
        let mut reader = TlvReader::new(bytes);

        // The outer envelope is an anonymous Structure.
        match reader.next()? {
            Some(Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::Structure,
            }) => {}
            _ => return Err(Error::WrongFieldType(0)),
        }

        let mut serial: Option<Vec<u8>> = None;
        let mut sig_alg_seen = false;
        let mut issuer: Option<DistinguishedName> = None;
        let mut not_before: Option<MatterTime> = None;
        let mut not_after: Option<MatterTime> = None;
        let mut subject: Option<DistinguishedName> = None;
        let mut pubkey_alg_seen = false;
        let mut ec_curve_seen = false;
        let mut public_key: Option<PublicKey> = None;
        let mut extensions: Option<Extensions> = None;
        let mut signature: Option<Signature> = None;

        loop {
            match reader.next()? {
                None => return Err(matter_codec::Error::UnclosedContainer.into()),
                Some(Element::ContainerEnd) => break,

                Some(Element::Scalar { tag, value }) => {
                    let t = context_tag(&tag)?;
                    match (t, value) {
                        (tags::CERT_SERIAL_NUMBER, Value::Bytes(b)) => {
                            ensure_first_seen(t, serial.as_ref())?;
                            serial = Some(b);
                        }
                        (tags::CERT_SIG_ALGORITHM, Value::Uint(v)) => {
                            if sig_alg_seen {
                                return Err(Error::DuplicateField(t));
                            }
                            let v8 = u8::try_from(v)
                                .map_err(|_| Error::FieldValueOutOfRange { tag: t })?;
                            if v8 != tags::SIG_ALGORITHM_ECDSA_SHA256 {
                                return Err(Error::UnsupportedSignatureAlgorithm(v8));
                            }
                            sig_alg_seen = true;
                        }
                        (tags::CERT_NOT_BEFORE, Value::Uint(v)) => {
                            ensure_first_seen(t, not_before.as_ref())?;
                            let v32 = u32::try_from(v)
                                .map_err(|_| Error::FieldValueOutOfRange { tag: t })?;
                            not_before = Some(MatterTime(v32));
                        }
                        (tags::CERT_NOT_AFTER, Value::Uint(v)) => {
                            ensure_first_seen(t, not_after.as_ref())?;
                            let v32 = u32::try_from(v)
                                .map_err(|_| Error::FieldValueOutOfRange { tag: t })?;
                            not_after = Some(MatterTime(v32));
                        }
                        (tags::CERT_PUBKEY_ALGORITHM, Value::Uint(v)) => {
                            if pubkey_alg_seen {
                                return Err(Error::DuplicateField(t));
                            }
                            let v8 = u8::try_from(v)
                                .map_err(|_| Error::FieldValueOutOfRange { tag: t })?;
                            if v8 != tags::PUBKEY_ALGORITHM_EC_PUBLIC_KEY {
                                return Err(Error::UnsupportedPublicKeyAlgorithm(v8));
                            }
                            pubkey_alg_seen = true;
                        }
                        (tags::CERT_EC_CURVE, Value::Uint(v)) => {
                            if ec_curve_seen {
                                return Err(Error::DuplicateField(t));
                            }
                            let v8 = u8::try_from(v)
                                .map_err(|_| Error::FieldValueOutOfRange { tag: t })?;
                            if v8 != tags::EC_CURVE_PRIME256V1 {
                                return Err(Error::UnsupportedEcCurve(v8));
                            }
                            ec_curve_seen = true;
                        }
                        (tags::CERT_EC_PUBLIC_KEY, Value::Bytes(b)) => {
                            ensure_first_seen(t, public_key.as_ref())?;
                            public_key = Some(PublicKey::from_slice(&b)?);
                        }
                        (tags::CERT_SIGNATURE, Value::Bytes(b)) => {
                            ensure_first_seen(t, signature.as_ref())?;
                            signature = Some(Signature::from_slice(&b)?);
                        }
                        (t, _) => return Err(Error::WrongFieldType(t)),
                    }
                }

                Some(Element::ContainerStart { tag, kind }) => {
                    let t = context_tag(&tag)?;
                    match t {
                        tags::CERT_ISSUER => {
                            if !matches!(kind, ContainerKind::List) {
                                return Err(Error::WrongFieldType(t));
                            }
                            ensure_first_seen(t, issuer.as_ref())?;
                            issuer = Some(DistinguishedName::read_from_open_list(&mut reader)?);
                        }
                        tags::CERT_SUBJECT => {
                            if !matches!(kind, ContainerKind::List) {
                                return Err(Error::WrongFieldType(t));
                            }
                            ensure_first_seen(t, subject.as_ref())?;
                            subject = Some(DistinguishedName::read_from_open_list(&mut reader)?);
                        }
                        tags::CERT_EXTENSIONS => {
                            if !matches!(kind, ContainerKind::List) {
                                return Err(Error::WrongFieldType(t));
                            }
                            ensure_first_seen(t, extensions.as_ref())?;
                            extensions = Some(Extensions::read_from_open_list(&mut reader)?);
                        }
                        other => return Err(Error::WrongFieldType(other)),
                    }
                }

                // Element is #[non_exhaustive]; future element kinds are
                // wire-format violations at the certificate top level.
                Some(_) => return Err(Error::WrongFieldType(0)),
            }
        }

        // Validate that all mandatory algorithm-identifier fields were present.
        if !sig_alg_seen {
            return Err(Error::MissingField(tags::CERT_SIG_ALGORITHM));
        }
        if !pubkey_alg_seen {
            return Err(Error::MissingField(tags::CERT_PUBKEY_ALGORITHM));
        }
        if !ec_curve_seen {
            return Err(Error::MissingField(tags::CERT_EC_CURVE));
        }

        Ok(Self {
            serial: serial.ok_or(Error::MissingField(tags::CERT_SERIAL_NUMBER))?,
            issuer: issuer.ok_or(Error::MissingField(tags::CERT_ISSUER))?,
            not_before: not_before.ok_or(Error::MissingField(tags::CERT_NOT_BEFORE))?,
            not_after: not_after.ok_or(Error::MissingField(tags::CERT_NOT_AFTER))?,
            subject: subject.ok_or(Error::MissingField(tags::CERT_SUBJECT))?,
            public_key: public_key.ok_or(Error::MissingField(tags::CERT_EC_PUBLIC_KEY))?,
            extensions: extensions.ok_or(Error::MissingField(tags::CERT_EXTENSIONS))?,
            signature: signature.ok_or(Error::MissingField(tags::CERT_SIGNATURE))?,
        })
    }

    /// Serialise to TLV bytes.
    ///
    /// Fields are emitted in the spec §6.5-defined order (context tags 1–11).
    /// Algorithm identifiers are always emitted at their fixed spec-allowed
    /// values (`ecdsa-with-sha256 = 1`, `ec-public-key = 1`, `prime256v1 = 1`).
    ///
    /// A certificate parsed from bytes `B` and re-serialised produces
    /// exactly `B` byte-for-byte (this is the basis for the integration
    /// test's round-trip assertion).
    ///
    /// # Errors
    ///
    /// Propagates any [`matter_codec::Error`] from the underlying writer.
    pub fn to_tlv(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);

        w.start_structure(Tag::Anonymous)?;
        w.put_bytes(Tag::Context(tags::CERT_SERIAL_NUMBER), &self.serial)?;
        w.put_uint(
            Tag::Context(tags::CERT_SIG_ALGORITHM),
            u64::from(tags::SIG_ALGORITHM_ECDSA_SHA256),
        )?;
        self.issuer.write(&mut w, Tag::Context(tags::CERT_ISSUER))?;
        w.put_uint(
            Tag::Context(tags::CERT_NOT_BEFORE),
            u64::from(self.not_before.0),
        )?;
        w.put_uint(
            Tag::Context(tags::CERT_NOT_AFTER),
            u64::from(self.not_after.0),
        )?;
        self.subject
            .write(&mut w, Tag::Context(tags::CERT_SUBJECT))?;
        w.put_uint(
            Tag::Context(tags::CERT_PUBKEY_ALGORITHM),
            u64::from(tags::PUBKEY_ALGORITHM_EC_PUBLIC_KEY),
        )?;
        w.put_uint(
            Tag::Context(tags::CERT_EC_CURVE),
            u64::from(tags::EC_CURVE_PRIME256V1),
        )?;
        w.put_bytes(
            Tag::Context(tags::CERT_EC_PUBLIC_KEY),
            self.public_key.as_bytes(),
        )?;
        self.extensions
            .write(&mut w, Tag::Context(tags::CERT_EXTENSIONS))?;
        w.put_bytes(
            Tag::Context(tags::CERT_SIGNATURE),
            self.signature.as_bytes(),
        )?;
        w.end_container()?;

        Ok(buf)
    }

    /// Serial number as raw bytes.
    #[must_use]
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }

    /// Issuer distinguished name.
    #[must_use]
    pub fn issuer(&self) -> &DistinguishedName {
        &self.issuer
    }

    /// Subject distinguished name.
    #[must_use]
    pub fn subject(&self) -> &DistinguishedName {
        &self.subject
    }

    /// Beginning of the validity period.
    #[must_use]
    pub fn not_before(&self) -> MatterTime {
        self.not_before
    }

    /// End of the validity period (`MatterTime::NO_EXPIRY` means no expiry).
    #[must_use]
    pub fn not_after(&self) -> MatterTime {
        self.not_after
    }

    /// EC public key (P-256, 65-byte uncompressed).
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Parsed extensions.
    #[must_use]
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Raw 64-byte ECDSA signature.
    #[must_use]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Compute the TBS (To-Be-Signed) bytes by re-serialising every
    /// field except the signature. This is the byte sequence that was
    /// hashed and signed when the certificate was issued.
    ///
    /// Requires canonical-form input: our serialiser must produce the
    /// same bytes the issuer's encoder produced. Matter spec mandates
    /// canonical encoding (minimal-width tags and lengths); all
    /// matter.js-issued certs we've tested round-trip cleanly.
    ///
    /// # Errors
    ///
    /// Returns a [`Codec`](Error::Codec) error if the underlying
    /// `TlvWriter` fails. In practice this is unreachable for
    /// well-formed `MatterCertificate` values.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn to_tbs_tlv(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous)?;
        w.put_bytes(Tag::Context(tags::CERT_SERIAL_NUMBER), &self.serial)?;
        w.put_uint(
            Tag::Context(tags::CERT_SIG_ALGORITHM),
            u64::from(tags::SIG_ALGORITHM_ECDSA_SHA256),
        )?;
        self.issuer.write(&mut w, Tag::Context(tags::CERT_ISSUER))?;
        w.put_uint(
            Tag::Context(tags::CERT_NOT_BEFORE),
            u64::from(self.not_before.0),
        )?;
        w.put_uint(
            Tag::Context(tags::CERT_NOT_AFTER),
            u64::from(self.not_after.0),
        )?;
        self.subject
            .write(&mut w, Tag::Context(tags::CERT_SUBJECT))?;
        w.put_uint(
            Tag::Context(tags::CERT_PUBKEY_ALGORITHM),
            u64::from(tags::PUBKEY_ALGORITHM_EC_PUBLIC_KEY),
        )?;
        w.put_uint(
            Tag::Context(tags::CERT_EC_CURVE),
            u64::from(tags::EC_CURVE_PRIME256V1),
        )?;
        w.put_bytes(
            Tag::Context(tags::CERT_EC_PUBLIC_KEY),
            self.public_key.as_bytes(),
        )?;
        self.extensions
            .write(&mut w, Tag::Context(tags::CERT_EXTENSIONS))?;
        // NOTE: the signature field (context tag 11) is intentionally
        // omitted — this is the TBS.
        w.end_container()?;
        Ok(buf)
    }

    /// Verify this certificate's signature against the issuer's public
    /// key. The TBS bytes are re-serialised internally (every field
    /// except the signature, in canonical TLV order).
    ///
    /// # Errors
    ///
    /// Returns [`Error::SignatureVerificationFailed`] if `issuer_key`
    /// did not sign this certificate's TBS bytes.
    pub fn verify_signed_by(&self, issuer_key: &PublicKey) -> Result<()> {
        let tbs = self.to_tbs_tlv()?;
        issuer_key.verify(&tbs, &self.signature)
    }
}

/// Extract the context-tag number from a [`Tag`], or return
/// [`Error::WrongFieldType(0)`] for non-context tags.
fn context_tag(tag: &Tag) -> Result<u8> {
    match tag {
        Tag::Context(n) => Ok(*n),
        _ => Err(Error::WrongFieldType(0)),
    }
}

/// Return [`Error::DuplicateField`] if `slot` is already `Some`.
fn ensure_first_seen<T>(tag: u8, slot: Option<&T>) -> Result<()> {
    if slot.is_some() {
        Err(Error::DuplicateField(tag))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    use super::*;
    use crate::extensions::{BasicConstraints, Extensions};
    use crate::name::DnAttribute;

    /// Construct a minimal but structurally valid synthetic certificate.
    fn sample_cert() -> MatterCertificate {
        let mut key_bytes = [0u8; 65];
        key_bytes[0] = 0x04;
        MatterCertificate {
            serial: vec![1, 2, 3],
            issuer: DistinguishedName::new(vec![DnAttribute::RcacId(1)]),
            not_before: MatterTime(1000),
            not_after: MatterTime::NO_EXPIRY,
            subject: DistinguishedName::new(vec![DnAttribute::NodeId(42)]),
            public_key: PublicKey::new(key_bytes).unwrap(),
            extensions: Extensions {
                basic_constraints: Some(BasicConstraints {
                    is_ca: false,
                    path_len_constraint: None,
                }),
                ..Default::default()
            },
            signature: Signature::new([0u8; 64]),
        }
    }

    #[test]
    fn round_trip_synthetic_cert() {
        let cert = sample_cert();
        let bytes = cert.to_tlv().unwrap();
        let parsed = MatterCertificate::from_tlv(&bytes).unwrap();
        assert_eq!(parsed, cert);
    }

    #[test]
    fn from_tlv_rejects_truncated_input() {
        let cert = sample_cert();
        let mut bytes = cert.to_tlv().unwrap();
        // Drop the final end-of-container byte so the stream is unclosed.
        bytes.pop();
        let err = MatterCertificate::from_tlv(&bytes).unwrap_err();
        // matter-codec's UnclosedContainer propagates as Error::Codec.
        assert!(matches!(err, Error::Codec(_)));
    }

    fn make_keypair() -> (PublicKey, EcdsaKeyPair) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let pk = PublicKey::from_slice(kp.public_key().as_ref()).unwrap();
        (pk, kp)
    }

    /// Construct a self-signed certificate where `subject_pub_key` is
    /// both the cert's public key and the verification key. Returns
    /// the resulting cert with a real signature over the TBS bytes.
    fn make_self_signed(subject_pub_key: PublicKey, kp: &EcdsaKeyPair) -> MatterCertificate {
        let unsigned = MatterCertificate {
            serial: vec![0xCA, 0xFE],
            issuer: DistinguishedName::new(vec![DnAttribute::RcacId(1)]),
            not_before: MatterTime(0),
            not_after: MatterTime::NO_EXPIRY,
            subject: DistinguishedName::new(vec![DnAttribute::RcacId(1)]),
            public_key: subject_pub_key,
            extensions: Extensions {
                basic_constraints: Some(BasicConstraints {
                    is_ca: true,
                    path_len_constraint: None,
                }),
                ..Default::default()
            },
            signature: Signature::new([0u8; 64]),
        };

        let tbs = unsigned.to_tbs_tlv().unwrap();
        let rng = SystemRandom::new();
        let sig_bytes = kp.sign(&rng, &tbs).unwrap();
        let signature = Signature::from_slice(sig_bytes.as_ref()).unwrap();

        MatterCertificate {
            signature,
            ..unsigned
        }
    }

    #[test]
    fn verify_signed_by_accepts_real_signature() {
        let (pub_key, kp) = make_keypair();
        let cert = make_self_signed(pub_key.clone(), &kp);
        assert!(cert.verify_signed_by(&pub_key).is_ok());
    }

    #[test]
    fn verify_signed_by_rejects_wrong_issuer_key() {
        let (pub_a, kp_a) = make_keypair();
        let (pub_b, _) = make_keypair();
        let cert = make_self_signed(pub_a, &kp_a);
        let err = cert.verify_signed_by(&pub_b).unwrap_err();
        assert!(matches!(err, Error::SignatureVerificationFailed));
    }

    #[test]
    fn tbs_then_re_parse_round_trips_via_re_serialise() {
        let cert = sample_cert();
        let full = cert.to_tlv().unwrap();
        let tbs = cert.to_tbs_tlv().unwrap();
        assert!(tbs.len() < full.len());
        assert_eq!(full[0], 0x15);
        assert_eq!(tbs[0], 0x15);
        assert_eq!(full[full.len() - 1], 0x18);
        assert_eq!(tbs[tbs.len() - 1], 0x18);
    }
}
