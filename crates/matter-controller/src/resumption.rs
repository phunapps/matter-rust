//! (De)serialization of [`matter_crypto::ResumptionRecord`] for the opaque
//! `DeviceEntry.resumption_record` bytes (snapshot context tag 2).
//!
//! The record is persisted after every completed CASE connect so a peer that
//! later initiates CASE *to us* (the OTA requestor querying our provider
//! server is the canonical case) can present its resumption id and be matched
//! against the stored record via `CaseResponder::accept_resumption`.
//!
//! Layout (anonymous TLV structure; all tags context-numbered):
//!
//! | tag | field                | type                     |
//! |-----|----------------------|--------------------------|
//! | 0   | id                   | bytes (16)               |
//! | 1   | shared_secret        | bytes (32)               |
//! | 2   | peer node_id         | uint                     |
//! | 3   | peer fabric_id       | uint                     |
//! | 4   | peer NOC             | bytes (Matter cert TLV)  |
//! | 5   | peer session_id      | uint                     |
//! | 6   | expires_at           | uint (optional; Matter epoch seconds) |

use matter_cert::{MatterCertificate, MatterTime};
use matter_codec::{Tag, TlvReader, TlvWriter, Value};
use matter_crypto::{PeerInfo, ResumptionId, ResumptionRecord};

use crate::error::Error;

/// Serialize a [`ResumptionRecord`] into the opaque bytes stored in
/// `DeviceEntry.resumption_record`.
///
/// # Errors
///
/// [`Error::Cert`] if the peer NOC fails to re-serialize, or [`Error::Codec`]
/// on TLV encoding failure.
pub(crate) fn serialize_record(record: &ResumptionRecord) -> Result<Vec<u8>, Error> {
    let mut members = vec![
        (Tag::Context(0), Value::Bytes(record.id.0.to_vec())),
        (Tag::Context(1), Value::Bytes(record.shared_secret.to_vec())),
        (Tag::Context(2), Value::Uint(record.peer.node_id)),
        (Tag::Context(3), Value::Uint(record.peer.fabric_id)),
        (Tag::Context(4), Value::Bytes(record.peer.noc.to_tlv()?)),
        (
            Tag::Context(5),
            Value::Uint(u64::from(record.peer.session_id)),
        ),
    ];
    if let Some(t) = record.expires_at {
        members.push((Tag::Context(6), Value::Uint(t.to_unix_secs())));
    }
    let mut out = Vec::new();
    let mut w = TlvWriter::new(&mut out);
    w.write_value(Tag::Anonymous, &Value::Structure(members))?;
    Ok(out)
}

/// Deserialize the opaque `DeviceEntry.resumption_record` bytes back into a
/// [`ResumptionRecord`].
///
/// # Errors
///
/// [`Error::Snapshot`] if the structure is malformed, [`Error::Codec`] on TLV
/// decode failure, or [`Error::Cert`] if the embedded peer NOC fails to parse.
pub(crate) fn deserialize_record(bytes: &[u8]) -> Result<ResumptionRecord, Error> {
    let mut r = TlvReader::new(bytes);
    let (_tag, value) = r.read_value()?;
    let Value::Structure(members) = value else {
        return Err(Error::Snapshot(
            "resumption record: expected structure".into(),
        ));
    };
    let get = |ctx: u8| {
        members
            .iter()
            .find(|(t, _)| *t == Tag::Context(ctx))
            .map(|(_, v)| v)
    };
    let get_bytes = |ctx: u8| match get(ctx) {
        Some(Value::Bytes(b)) => Ok(b.as_slice()),
        _ => Err(Error::Snapshot(format!(
            "resumption record: missing or non-bytes at context {ctx}"
        ))),
    };
    let get_uint = |ctx: u8| match get(ctx) {
        Some(Value::Uint(n)) => Ok(*n),
        _ => Err(Error::Snapshot(format!(
            "resumption record: missing or non-uint at context {ctx}"
        ))),
    };

    let id: [u8; 16] = get_bytes(0)?
        .try_into()
        .map_err(|_| Error::Snapshot("resumption record: id must be 16 bytes".into()))?;
    let shared_secret: [u8; 32] = get_bytes(1)?
        .try_into()
        .map_err(|_| Error::Snapshot("resumption record: secret must be 32 bytes".into()))?;
    let node_id = get_uint(2)?;
    let fabric_id = get_uint(3)?;
    let noc = MatterCertificate::from_tlv(get_bytes(4)?)?;
    let session_id = u16::try_from(get_uint(5)?)
        .map_err(|_| Error::Snapshot("resumption record: session_id exceeds u16".into()))?;
    let expires_at = match get(6) {
        Some(Value::Uint(secs)) => Some(MatterTime::from_unix_secs(*secs)),
        _ => None,
    };

    Ok(ResumptionRecord {
        id: ResumptionId(id),
        shared_secret,
        peer: PeerInfo {
            node_id,
            fabric_id,
            noc,
            session_id,
        },
        expires_at,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test code: CLAUDE.md carve-out.
mod tests {
    use super::*;

    /// Build a minimal record around a real certificate (reuses the fabric
    /// factory so the NOC round-trips through `to_tlv`/`from_tlv`).
    fn sample_record(expires_at: Option<MatterTime>) -> ResumptionRecord {
        let fabric = crate::fabric::create_fabric(
            &crate::fabric::FabricConfig {
                fabric_id: 0x1122_3344_5566_7788,
                rcac_id: 1,
                commissioner_node_id: 1,
                validity: (
                    MatterTime::from_unix_secs(1_700_000_000),
                    MatterTime::NO_EXPIRY,
                ),
            },
            &matter_commissioning::SystemNocRng,
        )
        .unwrap();
        ResumptionRecord {
            id: ResumptionId([0xA5; 16]),
            shared_secret: [0x5A; 32],
            peer: PeerInfo {
                node_id: 0xDEAD_BEEF,
                fabric_id: 0x1122_3344_5566_7788,
                noc: fabric.commissioner.noc.clone(),
                session_id: 0x1234,
            },
            expires_at,
        }
    }

    #[test]
    fn record_round_trips() {
        let record = sample_record(None);
        let bytes = serialize_record(&record).unwrap();
        let back = deserialize_record(&bytes).unwrap();
        assert_eq!(back.id, record.id);
        assert_eq!(back.shared_secret, record.shared_secret);
        assert_eq!(back.peer.node_id, record.peer.node_id);
        assert_eq!(back.peer.fabric_id, record.peer.fabric_id);
        assert_eq!(back.peer.session_id, record.peer.session_id);
        assert_eq!(
            back.peer.noc.to_tlv().unwrap(),
            record.peer.noc.to_tlv().unwrap()
        );
        assert_eq!(back.expires_at, record.expires_at);
    }

    #[test]
    fn record_round_trips_with_expiry() {
        let record = sample_record(Some(MatterTime::from_unix_secs(2_000_000_000)));
        let bytes = serialize_record(&record).unwrap();
        let back = deserialize_record(&bytes).unwrap();
        assert_eq!(back.expires_at, record.expires_at);
    }

    #[test]
    fn truncated_bytes_are_rejected() {
        let record = sample_record(None);
        let bytes = serialize_record(&record).unwrap();
        assert!(deserialize_record(&bytes[..bytes.len() / 2]).is_err());
    }

    #[test]
    fn wrong_secret_length_is_rejected() {
        // Hand-build a structure whose secret is 16 bytes (the pre-widening
        // format) — must be rejected, not silently mis-sized.
        let record = sample_record(None);
        let members = vec![
            (Tag::Context(0), Value::Bytes(record.id.0.to_vec())),
            (Tag::Context(1), Value::Bytes(vec![0x5A; 16])),
            (Tag::Context(2), Value::Uint(record.peer.node_id)),
            (Tag::Context(3), Value::Uint(record.peer.fabric_id)),
            (
                Tag::Context(4),
                Value::Bytes(record.peer.noc.to_tlv().unwrap()),
            ),
            (Tag::Context(5), Value::Uint(0)),
        ];
        let mut out = Vec::new();
        let mut w = TlvWriter::new(&mut out);
        w.write_value(Tag::Anonymous, &Value::Structure(members))
            .unwrap();
        assert!(deserialize_record(&out).is_err());
    }
}
