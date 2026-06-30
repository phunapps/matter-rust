// Integration tests are a binary crate; crate-level docs are not required.
// Test-code carve-out for unwrap/expect: see CLAUDE.md.
#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::items_after_statements
)]

use matter_clusters::gen::{electrical_energy_measurement, electrical_power_measurement};
use matter_codec::{Tag, TlvWriter};
use matter_controller::{Node, ReadPath, Value};

fn value_to_tlv(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.write_value(Tag::Anonymous, value)
        .expect("infallible: Vec-backed TlvWriter");
    buf
}

async fn read_attr(node: &Node, ep: u16, cluster: u32, attr: u32) -> Value {
    let r = node
        .read(&[ReadPath::concrete(ep, cluster, attr)])
        .await
        .expect("read attribute");
    r.into_iter()
        .find(|(p, _)| p.attribute == attr)
        .map(|(_, v)| v)
        .expect("attribute present in report")
}

/// ElectricalPowerMeasurement (0x0090) + ElectricalEnergyMeasurement (0x0091) on
/// evse-app ep1: typed-decode the live device bytes. At rest the readings are
/// null/zero (which decode fine), and the EEM `Accuracy` composite struct +
/// EPM `PowerMode` are populated — so this validates the typed decoders,
/// including the composite struct decoder, against real device bytes.
#[tokio::test]
async fn electrical_measurement_typed_decode() {
    let cfg = integration_tests::dut_or_skip!();
    if !cfg.is_app("evse") {
        eprintln!("skipped: Electrical* test needs the evse-app DUT (`just integration-energy`)");
        return;
    }
    let (controller, node_id) = integration_tests::fixture::connect(&cfg)
        .await
        .expect("connect/commission DUT");
    let node = controller.node(node_id);

    // ElectricalPowerMeasurement (0x0090).
    const EPM: u32 = 0x0090;
    let mode = read_attr(&node, 1, EPM, 0x0000).await; // PowerMode
    assert!(
        electrical_power_measurement::decode_power_mode(&value_to_tlv(&mode)).is_ok(),
        "EPM.PowerMode typed-decode failed: {mode:?}"
    );
    let voltage = read_attr(&node, 1, EPM, 0x0004).await; // Voltage
    assert!(
        electrical_power_measurement::decode_voltage(&value_to_tlv(&voltage)).is_ok(),
        "EPM.Voltage typed-decode failed: {voltage:?}"
    );
    let power = read_attr(&node, 1, EPM, 0x0008).await; // ActivePower
    assert!(
        electrical_power_measurement::decode_active_power(&value_to_tlv(&power)).is_ok(),
        "EPM.ActivePower typed-decode failed: {power:?}"
    );

    // ElectricalEnergyMeasurement (0x0091): the composite Accuracy struct + a
    // cumulative-energy reading.
    const EEM: u32 = 0x0091;
    let accuracy = read_attr(&node, 1, EEM, 0x0000).await; // Accuracy (MeasurementAccuracyStruct)
    assert!(
        electrical_energy_measurement::decode_accuracy(&value_to_tlv(&accuracy)).is_ok(),
        "EEM.Accuracy composite typed-decode failed: {accuracy:?}"
    );
    let imported = read_attr(&node, 1, EEM, 0x0001).await; // CumulativeEnergyImported
    assert!(
        electrical_energy_measurement::decode_cumulative_energy_imported(&value_to_tlv(&imported))
            .is_ok(),
        "EEM.CumulativeEnergyImported typed-decode failed: {imported:?}"
    );
}
