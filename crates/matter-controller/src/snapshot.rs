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

/// Deserialize a snapshot blob into [`ControllerState`].
///
/// # Errors
///
/// Returns [`Error::Snapshot`] if the structure or version is invalid,
/// [`Error::Codec`] on TLV decode failure, or [`Error::Cert`] if an
/// embedded certificate fails to parse.
pub fn deserialize(bytes: &[u8]) -> Result<ControllerState, Error> {
    use matter_codec::TlvReader;

    let mut r = TlvReader::new(bytes);
    let (_tag, value) = r.read_value()?;
    let root = as_struct(&value)?;

    let version = get_uint(root, 0)?;
    if version != u64::from(SNAPSHOT_VERSION) {
        return Err(Error::Snapshot(format!(
            "unsupported snapshot version {version}"
        )));
    }

    let fabrics_val =
        get(root, 1).ok_or_else(|| Error::Snapshot("missing fabrics array".into()))?;
    let mut fabrics = Vec::new();
    for fv in as_array(fabrics_val)? {
        fabrics.push(fabric_from_value(fv)?);
    }
    Ok(ControllerState { fabrics })
}

fn fabric_from_value(v: &Value) -> Result<FabricEntry, Error> {
    let m = as_struct(v)?;
    let commissioner_val =
        get(m, 4).ok_or_else(|| Error::Snapshot("missing commissioner".into()))?;
    let devices_val = get(m, 5).ok_or_else(|| Error::Snapshot("missing devices array".into()))?;
    let mut devices = Vec::new();
    for dv in as_array(devices_val)? {
        devices.push(device_from_value(dv)?);
    }
    Ok(FabricEntry {
        fabric_id: get_uint(m, 0)?,
        ipk: byte_array::<16>(get_bytes(m, 1)?, "ipk")?,
        rcac_cert: MatterCertificate::from_tlv(get_bytes(m, 2)?)?,
        rcac_pkcs8: get_bytes(m, 3)?.to_vec(),
        commissioner: commissioner_from_value(commissioner_val)?,
        devices,
    })
}

fn commissioner_from_value(v: &Value) -> Result<CommissionerIdentity, Error> {
    let m = as_struct(v)?;
    Ok(CommissionerIdentity {
        node_id: get_uint(m, 0)?,
        operational_pkcs8: get_bytes(m, 1)?.to_vec(),
        noc: MatterCertificate::from_tlv(get_bytes(m, 2)?)?,
    })
}

fn device_from_value(v: &Value) -> Result<DeviceEntry, Error> {
    let m = as_struct(v)?;
    let resumption_record = match get(m, 2) {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    };
    let last_known_addr = match get(m, 3) {
        Some(Value::Utf8(s)) => Some(s.clone()),
        _ => None,
    };
    Ok(DeviceEntry {
        node_id: get_uint(m, 0)?,
        peer_noc_public_key: byte_array::<65>(get_bytes(m, 1)?, "peer_noc_public_key")?,
        resumption_record,
        last_known_addr,
    })
}

// --- small TLV-Value accessors ---

fn as_struct(v: &Value) -> Result<&[(Tag, Value)], Error> {
    match v {
        Value::Structure(members) => Ok(members),
        _ => Err(Error::Snapshot("expected structure".into())),
    }
}

fn as_array(v: &Value) -> Result<&[Value], Error> {
    match v {
        Value::Array(items) => Ok(items),
        _ => Err(Error::Snapshot("expected array".into())),
    }
}

fn get(members: &[(Tag, Value)], ctx: u8) -> Option<&Value> {
    members
        .iter()
        .find(|(t, _)| *t == Tag::Context(ctx))
        .map(|(_, v)| v)
}

fn get_uint(members: &[(Tag, Value)], ctx: u8) -> Result<u64, Error> {
    match get(members, ctx) {
        Some(Value::Uint(n)) => Ok(*n),
        _ => Err(Error::Snapshot(format!(
            "missing or non-uint at context {ctx}"
        ))),
    }
}

fn get_bytes(members: &[(Tag, Value)], ctx: u8) -> Result<&[u8], Error> {
    match get(members, ctx) {
        Some(Value::Bytes(b)) => Ok(b),
        _ => Err(Error::Snapshot(format!(
            "missing or non-bytes at context {ctx}"
        ))),
    }
}

fn byte_array<const N: usize>(b: &[u8], field: &str) -> Result<[u8; N], Error> {
    b.try_into()
        .map_err(|_| Error::Snapshot(format!("{field}: expected {N} bytes, got {}", b.len())))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test code: CLAUDE.md allows unwrap/expect with justification.
mod tests {
    use super::*;
    use crate::fabric::{create_fabric, FabricConfig};
    use matter_cert::MatterTime;
    use matter_commissioning::SystemNocRng;

    fn sample_state() -> ControllerState {
        let cfg = FabricConfig {
            fabric_id: 0x1122_3344_5566_7788,
            rcac_id: 1,
            commissioner_node_id: 0x0000_0000_0000_0001,
            validity: (
                MatterTime::from_unix_secs(1_700_000_000),
                MatterTime::NO_EXPIRY,
            ),
        };
        let mut fabric = create_fabric(&cfg, &SystemNocRng).expect("create_fabric");
        fabric.devices.push(DeviceEntry {
            node_id: 0xABCD,
            peer_noc_public_key: [0x04; 65],
            resumption_record: Some(vec![1, 2, 3, 4]),
            last_known_addr: Some("[fe80::1]:5540".to_string()),
        });
        fabric.devices.push(DeviceEntry {
            node_id: 0xBEEF,
            peer_noc_public_key: [0x04; 65],
            resumption_record: None,
            last_known_addr: None,
        });
        ControllerState {
            fabrics: vec![fabric],
        }
    }

    #[test]
    fn round_trips_a_full_state() {
        let state = sample_state();
        let bytes = serialize(&state).expect("serialize");
        let back = deserialize(&bytes).expect("deserialize");

        assert_eq!(back.fabrics.len(), 1);
        let (a, b) = (&state.fabrics[0], &back.fabrics[0]);
        assert_eq!(a.fabric_id, b.fabric_id);
        assert_eq!(a.ipk, b.ipk);
        assert_eq!(a.rcac_pkcs8, b.rcac_pkcs8);
        assert_eq!(a.rcac_cert.to_tlv().unwrap(), b.rcac_cert.to_tlv().unwrap());
        assert_eq!(a.commissioner.node_id, b.commissioner.node_id);
        assert_eq!(
            a.commissioner.operational_pkcs8,
            b.commissioner.operational_pkcs8
        );
        assert_eq!(
            a.commissioner.noc.to_tlv().unwrap(),
            b.commissioner.noc.to_tlv().unwrap()
        );
        assert_eq!(a.devices.len(), b.devices.len());
        assert_eq!(a.devices[0].node_id, b.devices[0].node_id);
        assert_eq!(
            a.devices[0].resumption_record,
            b.devices[0].resumption_record
        );
        assert_eq!(a.devices[0].last_known_addr, b.devices[0].last_known_addr);
        assert_eq!(a.devices[1].resumption_record, None);
        assert_eq!(a.devices[1].last_known_addr, None);
    }

    #[test]
    fn empty_state_round_trips() {
        let bytes = serialize(&ControllerState::default()).expect("serialize");
        assert!(deserialize(&bytes).expect("deserialize").fabrics.is_empty());
    }

    #[test]
    fn rejects_unknown_version() {
        // Hand-build a root with version 99.
        let root = Value::Structure(vec![
            (Tag::Context(0), Value::Uint(99)),
            (Tag::Context(1), Value::Array(vec![])),
        ]);
        let mut out = Vec::new();
        let mut w = TlvWriter::new(&mut out);
        w.write_value(Tag::Anonymous, &root).unwrap();
        let err = deserialize(&out).expect_err("must reject");
        assert!(matches!(err, Error::Snapshot(_)));
    }
}
