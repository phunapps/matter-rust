//! Versioned TLV serialization of [`ControllerState`].
//!
//! Layout (all members context-tagged):
//! ```text
//! root: Structure { C0: version(u8), C1: Array[fabric] }
//! fabric: Structure {
//!   C0: fabric_id(uint), C1: ipk(bytes16), C2: rcac_cert(bytes,TLV),
//!   C3: rcac_pkcs8(bytes), C4: commissioner(struct), C5: Array[device]
//! }
//! commissioner: Structure { C0: node_id(uint), C1: op_pkcs8(bytes), C2: noc(bytes,TLV) }
//! device: Structure {
//!   C0: node_id(uint), C1: peer_noc_public_key(bytes65),
//!   C2: resumption_record(bytes, optional), C3: last_known_addr(utf8, optional)
//! }
//! ```

use matter_cert::MatterCertificate;
use matter_codec::{Tag, TlvWriter, Value};

use crate::error::Error;
use crate::state::{CommissionerIdentity, ControllerState, DeviceEntry, FabricEntry};

/// Current snapshot schema version.
pub const SNAPSHOT_VERSION: u8 = 1;

/// Serialize controller state into an opaque TLV blob.
///
/// # Errors
///
/// Returns [`Error::Cert`] if a certificate fails to serialize, or
/// [`Error::Codec`] if TLV encoding fails.
pub fn serialize(state: &ControllerState) -> Result<Vec<u8>, Error> {
    let mut fabrics = Vec::with_capacity(state.fabrics.len());
    for f in &state.fabrics {
        fabrics.push(fabric_to_value(f)?);
    }
    let root = Value::Structure(vec![
        (Tag::Context(0), Value::Uint(u64::from(SNAPSHOT_VERSION))),
        (Tag::Context(1), Value::Array(fabrics)),
    ]);

    let mut out = Vec::new();
    let mut w = TlvWriter::new(&mut out);
    w.write_value(Tag::Anonymous, &root)?;
    Ok(out)
}

fn fabric_to_value(f: &FabricEntry) -> Result<Value, Error> {
    let devices = f.devices.iter().map(device_to_value).collect();
    Ok(Value::Structure(vec![
        (Tag::Context(0), Value::Uint(f.fabric_id)),
        (Tag::Context(1), Value::Bytes(f.ipk.to_vec())),
        (Tag::Context(2), Value::Bytes(f.rcac_cert.to_tlv()?)),
        (Tag::Context(3), Value::Bytes(f.rcac_pkcs8.clone())),
        (Tag::Context(4), commissioner_to_value(&f.commissioner)?),
        (Tag::Context(5), Value::Array(devices)),
    ]))
}

fn commissioner_to_value(c: &CommissionerIdentity) -> Result<Value, Error> {
    Ok(Value::Structure(vec![
        (Tag::Context(0), Value::Uint(c.node_id)),
        (Tag::Context(1), Value::Bytes(c.operational_pkcs8.clone())),
        (Tag::Context(2), Value::Bytes(c.noc.to_tlv()?)),
    ]))
}

fn device_to_value(d: &DeviceEntry) -> Value {
    let mut members = vec![
        (Tag::Context(0), Value::Uint(d.node_id)),
        (
            Tag::Context(1),
            Value::Bytes(d.peer_noc_public_key.to_vec()),
        ),
    ];
    if let Some(rr) = &d.resumption_record {
        members.push((Tag::Context(2), Value::Bytes(rr.clone())));
    }
    if let Some(addr) = &d.last_known_addr {
        members.push((Tag::Context(3), Value::Utf8(addr.clone())));
    }
    Value::Structure(members)
}

/// Deserialize a snapshot blob into [`ControllerState`]. Implemented in Task 6.
///
/// # Errors
///
/// Returns [`Error::Snapshot`] on malformed input.
pub fn deserialize(_bytes: &[u8]) -> Result<ControllerState, Error> {
    Err(Error::Snapshot("deserialize not yet implemented".into()))
}

// Silence unused import until Task 6 wires the reader/cert parse path.
#[allow(unused_imports)]
use MatterCertificate as _SnapshotCertMarker;
