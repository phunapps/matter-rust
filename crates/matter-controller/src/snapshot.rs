//! Versioned TLV serialization of [`ControllerState`].
//!
//! Layout (all members context-tagged):
//! ```text
//! root: Structure { C0: version(u8), C1: Array[fabric] }
//! fabric: Structure {
//!   C0: fabric_id(uint), C1: ipk(bytes16), C2: rcac_cert(bytes,TLV),
//!   C3: rcac_pkcs8(bytes), C4: commissioner(struct), C5: Array[device],
//!   C6: Array[group_key_set] (optional — absent in v1 snapshots written
//!       before group-key support; defaults to empty on read),
//!   C7: outbound_group_counter(uint, optional — same default rule)
//! }
//! commissioner: Structure { C0: node_id(uint), C1: op_pkcs8(bytes), C2: noc(bytes,TLV) }
//! device: Structure {
//!   C0: node_id(uint), C1: peer_noc_public_key(bytes65),
//!   C2: resumption_record(bytes, optional), C3: last_known_addr(utf8, optional)
//! }
//! group_key_set: Structure {
//!   C0: key_set_id(uint), C1: epoch_key(bytes16), C2: epoch_start_time(uint)
//! }
//! ```
//!
//! ## Backward compatibility
//!
//! C6 and C7 are optional tags: a v1 snapshot without them (written by an
//! older binary) still deserializes cleanly — `group_keys` defaults to
//! `Vec::new()` and `outbound_group_counter` to `0`.  No version bump is
//! needed because the tag-keyed deserializer simply treats absent tags as
//! defaults.

use matter_cert::MatterCertificate;
use matter_codec::{Tag, TlvWriter, Value};

use crate::error::Error;
use crate::state::{
    CommissionerIdentity, ControllerState, DeviceEntry, FabricEntry, GroupKeySetConfig,
};

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
    let group_keys: Vec<Value> = f.group_keys.iter().map(group_key_to_value).collect();
    Ok(Value::Structure(vec![
        (Tag::Context(0), Value::Uint(f.fabric_id)),
        (Tag::Context(1), Value::Bytes(f.ipk.to_vec())),
        (Tag::Context(2), Value::Bytes(f.rcac_cert.to_tlv()?)),
        (Tag::Context(3), Value::Bytes(f.rcac_pkcs8.clone())),
        (Tag::Context(4), commissioner_to_value(&f.commissioner)?),
        (Tag::Context(5), Value::Array(devices)),
        (Tag::Context(6), Value::Array(group_keys)),
        (
            Tag::Context(7),
            Value::Uint(u64::from(f.outbound_group_counter)),
        ),
    ]))
}

fn group_key_to_value(k: &GroupKeySetConfig) -> Value {
    Value::Structure(vec![
        (Tag::Context(0), Value::Uint(u64::from(k.key_set_id))),
        (Tag::Context(1), Value::Bytes(k.epoch_key.to_vec())),
        (Tag::Context(2), Value::Uint(k.epoch_start_time)),
    ])
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

    // t6 / t7 are optional (absent in v1 snapshots written before group-key
    // support was added).  Default to empty / 0 when missing — this keeps old
    // stores loadable without a version bump.
    let group_keys = match get(m, 6) {
        Some(arr) => {
            let mut keys = Vec::new();
            for kv in as_array(arr)? {
                keys.push(group_key_from_value(kv)?);
            }
            keys
        }
        None => Vec::new(),
    };
    let outbound_group_counter = match get(m, 7) {
        Some(Value::Uint(n)) => u32::try_from(*n)
            .map_err(|_| Error::Snapshot("outbound_group_counter exceeds u32 range".into()))?,
        _ => 0,
    };

    Ok(FabricEntry {
        fabric_id: get_uint(m, 0)?,
        ipk: byte_array::<16>(get_bytes(m, 1)?, "ipk")?,
        rcac_cert: MatterCertificate::from_tlv(get_bytes(m, 2)?)?,
        rcac_pkcs8: get_bytes(m, 3)?.to_vec(),
        commissioner: commissioner_from_value(commissioner_val)?,
        devices,
        group_keys,
        outbound_group_counter,
    })
}

fn group_key_from_value(v: &Value) -> Result<GroupKeySetConfig, Error> {
    let m = as_struct(v)?;
    let key_set_id = u16::try_from(get_uint(m, 0)?)
        .map_err(|_| Error::Snapshot("key_set_id exceeds u16 range".into()))?;
    let epoch_key = byte_array::<16>(get_bytes(m, 1)?, "epoch_key")?;
    let epoch_start_time = get_uint(m, 2)?;
    Ok(GroupKeySetConfig {
        key_set_id,
        epoch_key,
        epoch_start_time,
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

    // --- property-based round-trip (CLAUDE.md: encoders get a proptest) ---

    use proptest::prelude::*;
    use std::sync::OnceLock;

    /// Mint one real fabric and reuse it across all proptest cases — key
    /// generation is expensive, but cloning a `FabricEntry` is cheap.
    fn shared_fabric() -> &'static FabricEntry {
        static FABRIC: OnceLock<FabricEntry> = OnceLock::new();
        FABRIC.get_or_init(|| {
            let cfg = FabricConfig {
                fabric_id: 0x0102_0304_0506_0708,
                rcac_id: 1,
                commissioner_node_id: 0x0000_0000_0000_0001,
                validity: (
                    MatterTime::from_unix_secs(1_700_000_000),
                    MatterTime::NO_EXPIRY,
                ),
            };
            create_fabric(&cfg, &SystemNocRng).expect("mint shared fabric")
        })
    }

    prop_compose! {
        fn arb_device()(
            node_id in any::<u64>(),
            pk in prop::collection::vec(any::<u8>(), 65),
            rr in prop::option::of(prop::collection::vec(any::<u8>(), 0..40)),
            addr in prop::option::of("[ -~]{0,32}"),
        ) -> DeviceEntry {
            let mut peer_noc_public_key = [0u8; 65];
            peer_noc_public_key.copy_from_slice(&pk);
            DeviceEntry { node_id, peer_noc_public_key, resumption_record: rr, last_known_addr: addr }
        }
    }

    proptest! {
        /// `deserialize(serialize(state)) == state` for arbitrary device lists.
        #[test]
        fn snapshot_round_trips(devices in prop::collection::vec(arb_device(), 0..6)) {
            let mut fabric = shared_fabric().clone();
            fabric.devices = devices.clone();
            let state = ControllerState { fabrics: vec![fabric] };

            let bytes = serialize(&state).expect("serialize");
            let back = deserialize(&bytes).expect("deserialize");

            prop_assert_eq!(back.fabrics.len(), 1);
            let dev_back = &back.fabrics[0].devices;
            prop_assert_eq!(dev_back.len(), devices.len());
            for (a, b) in devices.iter().zip(dev_back.iter()) {
                prop_assert_eq!(a.node_id, b.node_id);
                prop_assert_eq!(a.peer_noc_public_key, b.peer_noc_public_key);
                prop_assert_eq!(&a.resumption_record, &b.resumption_record);
                prop_assert_eq!(&a.last_known_addr, &b.last_known_addr);
            }
        }
    }

    // --- group-key persistence tests ---

    #[test]
    fn group_keys_round_trip() {
        // A FabricEntry WITH group_keys and a non-zero counter must survive
        // serialize → deserialize with all group fields preserved.
        let mut fabric = shared_fabric().clone();
        fabric.group_keys = vec![
            GroupKeySetConfig {
                key_set_id: 0x0001,
                epoch_key: [0xAA; 16],
                epoch_start_time: 1_700_000_000,
            },
            GroupKeySetConfig {
                key_set_id: 0x0002,
                epoch_key: [0xBB; 16],
                epoch_start_time: 1_700_100_000,
            },
        ];
        fabric.outbound_group_counter = 42;
        let state = ControllerState {
            fabrics: vec![fabric.clone()],
        };

        let bytes = serialize(&state).expect("serialize");
        let back = deserialize(&bytes).expect("deserialize");

        assert_eq!(back.fabrics.len(), 1);
        let f = &back.fabrics[0];
        assert_eq!(f.outbound_group_counter, 42);
        assert_eq!(f.group_keys.len(), 2);
        assert_eq!(f.group_keys[0].key_set_id, 0x0001);
        assert_eq!(f.group_keys[0].epoch_key, [0xAA; 16]);
        assert_eq!(f.group_keys[0].epoch_start_time, 1_700_000_000);
        assert_eq!(f.group_keys[1].key_set_id, 0x0002);
        assert_eq!(f.group_keys[1].epoch_key, [0xBB; 16]);
        assert_eq!(f.group_keys[1].epoch_start_time, 1_700_100_000);
    }

    #[test]
    fn old_snapshot_without_t6_t7_loads_with_defaults() {
        // Simulate a v1 snapshot written by old code: a fabric value that has
        // only t0..t5 (no t6/t7).  The deserializer must accept it and default
        // group_keys to [] and outbound_group_counter to 0.
        let fabric = shared_fabric().clone();

        // Build the fabric Value manually with only t0..t5 (the old layout).
        let old_fabric_val = Value::Structure(vec![
            (Tag::Context(0), Value::Uint(fabric.fabric_id)),
            (Tag::Context(1), Value::Bytes(fabric.ipk.to_vec())),
            (
                Tag::Context(2),
                Value::Bytes(fabric.rcac_cert.to_tlv().expect("rcac tlv")),
            ),
            (Tag::Context(3), Value::Bytes(fabric.rcac_pkcs8.clone())),
            (
                Tag::Context(4),
                commissioner_to_value(&fabric.commissioner).expect("commissioner"),
            ),
            (Tag::Context(5), Value::Array(vec![])), // no devices
        ]);

        let root = Value::Structure(vec![
            (Tag::Context(0), Value::Uint(u64::from(SNAPSHOT_VERSION))),
            (Tag::Context(1), Value::Array(vec![old_fabric_val])),
        ]);

        let mut out = Vec::new();
        let mut w = TlvWriter::new(&mut out);
        w.write_value(Tag::Anonymous, &root).unwrap();

        let back = deserialize(&out).expect("old snapshot must load without error");
        assert_eq!(back.fabrics.len(), 1);
        let f = &back.fabrics[0];
        assert!(
            f.group_keys.is_empty(),
            "group_keys must default to empty for old snapshot"
        );
        assert_eq!(
            f.outbound_group_counter, 0,
            "outbound_group_counter must default to 0 for old snapshot"
        );
    }
}
