//! `xtask capture-commissioning` — drive matter.js through a full
//! simulated commissioning and record every emitted Invoke +
//! `ReadAttribute` payload to
//! `test-vectors/commissioning/e2e/happy-path.json`.
//!
//! M6.4.6. Operator-touch step — re-run whenever matter.js's
//! `@matter/protocol` `CommissioningManager` / `CommissionerNode` API
//! shifts. The fixture this generates feeds the
//! `commissioning_byte_parity.rs` integration test in
//! `matter-commissioning`, which skips cleanly when the fixture is
//! missing/empty so CI stays green during operator wiring (T56).
//!
//! Mirrors the dispatch pattern used by every other `capture-*` arm in
//! `main.rs`: resolve the script directory under
//! `xtask/scripts/capture-commissioning/`, refuse to run without
//! `node_modules` (forces the operator to `npm install` once), spawn
//! `node index.js` with that directory as `cwd`, surface a non-zero
//! exit verbatim.

#![forbid(unsafe_code)]
// xtask is build tooling, not library code; the CLAUDE.md no-unwrap
// rule is for library code only. The existing capture-* modules apply
// the same allow.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

/// Entry point invoked from xtask main.
///
/// # Errors
///
/// Returns a descriptive string if the script directory or its
/// `node_modules` are missing, if `node` fails to spawn, or if the
/// matter.js capture script exits non-zero. The xtask `main` surfaces
/// the message via `eprintln!` and exits non-zero.
pub(crate) fn run() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/capture-commissioning");

    if !script_dir.exists() {
        return Err(format!(
            "capture-commissioning script directory not found: {}",
            script_dir.display()
        ));
    }
    if !script_dir.join("node_modules").exists() {
        return Err(format!(
            "node_modules not found in {}; run `npm install` there first",
            script_dir.display()
        ));
    }

    let status = Command::new("node")
        .arg("index.js")
        .current_dir(&script_dir)
        .status()
        .map_err(|err| format!("failed to spawn node: {err}"))?;

    if !status.success() {
        return Err(format!("node index.js exited with status {status}"));
    }

    post_process(&workspace_root, &script_dir.join("out"))
}

// ---------------------------------------------------------------------------
// Post-processing: trace.jsonl + meta.json → happy-path.json (+ tampered-dac)
// ---------------------------------------------------------------------------

/// One decrypted wire message from the JS capture (its "tx" records only —
/// both in-process peers share the patched codec, so every message appears
/// once as tx from its sender and once as rx at its receiver).
#[derive(serde::Deserialize)]
struct TraceRow {
    dir: String,
    exchange: u16,
    /// 16-bit protocol short id: 0 = `SecureChannel`, 1 = `InteractionModel`.
    protocol: u16,
    opcode: u8,
    payload: String,
}

#[derive(serde::Deserialize)]
struct Meta {
    captured_at_unix: u64,
    pase_attestation_challenge_b64: String,
    cd_signing_spki_pem: String,
}

/// One captured Invoke (request fields + the response payload in the exact
/// shape the Rust driver feeds `Commissioner::on_response`).
struct CapturedInvoke {
    cluster: u32,
    command: u32,
    fields_tlv: Vec<u8>,
    response_payload: Vec<u8>,
}

#[derive(serde::Serialize)]
struct StageOut {
    stage: &'static str,
    action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    attribute_ids: Vec<u32>,
    expected_payload_b64: Option<String>,
    response_payload_b64: Option<String>,
}

#[derive(serde::Serialize)]
struct FixtureOut {
    /// Unix seconds at capture time — the parity test verifies the captured
    /// attestation chain at THIS instant (matter.js mints its dev DAC/PAI
    /// fresh per run, so a fixed historical date would violate their
    /// validity window).
    captured_at_unix: u64,
    fabric_id: String,
    commissioner_node_id: String,
    assigned_node_id: String,
    ipk_epoch_key_b64: String,
    pase_attestation_challenge_b64: String,
    /// matter.js's capture-time nonces: the parity test scripts its
    /// `NocRng` with these so the Rust state machine reproduces the exact
    /// `AttestationRequest` / `CSRRequest` payloads (and accepts the captured
    /// responses' nonce echoes).
    attestation_nonce_b64: String,
    csr_nonce_b64: String,
    /// SPKI PEM of the CD signer matter.js used (chip's official test CMS
    /// signer) — the parity test builds its `CdSigningRoots` from this.
    cd_signing_spki_pem: String,
    stages: Vec<StageOut>,
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Map the captured matter.js commissioning dialogue onto the Rust
/// `Commissioner` stage sequence and write the byte-parity fixtures.
///
/// matter.js's own step order differs from ours (it configures the
/// regulatory domain after the NOC, we do it before attestation), so
/// invokes are matched by `(cluster, command)` — plus the `CertChainRequest`
/// type field — rather than by position. matter.js-only invokes (e.g. its
/// post-CASE `UpdateFabricLabel`) are reported and skipped.
#[allow(clippy::too_many_lines)] // Linear trace→stages mapping; splitting hurts clarity.
fn post_process(root: &std::path::Path, out_dir: &std::path::Path) -> Result<(), String> {
    use matter_interaction::InvokeResponse;

    let trace_path = out_dir.join("trace.jsonl");
    let trace_text = std::fs::read_to_string(&trace_path)
        .map_err(|e| format!("read {}: {e}", trace_path.display()))?;
    let meta: Meta = serde_json::from_str(
        &std::fs::read_to_string(out_dir.join("meta.json"))
            .map_err(|e| format!("read meta.json: {e}"))?,
    )
    .map_err(|e| format!("parse meta.json: {e}"))?;

    let rows: Vec<TraceRow> = trace_text
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("parse trace.jsonl: {e}"))?;

    // Keep tx records only; decode hex payloads once.
    let tx: Vec<(u16, u16, u8, Vec<u8>)> = rows
        .iter()
        .filter(|r| r.dir == "tx")
        .map(|r| {
            hex::decode(&r.payload)
                .map(|p| (r.exchange, r.protocol, r.opcode, p))
                .map_err(|e| format!("hex decode: {e}"))
        })
        .collect::<Result<_, _>>()?;

    // Pair Invokes with their responses by exchange id, in wire order.
    let mut invokes: Vec<CapturedInvoke> = Vec::new();
    let mut reports: Vec<matter_interaction::ReportData> = Vec::new();
    for (i, (exchange, protocol, opcode, payload)) in tx.iter().enumerate() {
        if *protocol != 1 {
            continue; // SecureChannel (PASE/CASE handshakes, acks)
        }
        match opcode {
            0x08 => {
                let req = matter_interaction::parse_invoke_request(payload)
                    .map_err(|e| format!("parse InvokeRequest: {e:?}"))?;
                let cmd = req
                    .commands
                    .first()
                    .ok_or("InvokeRequest with no command")?;
                // The matching InvokeResponse is the next IM message on the
                // same exchange.
                let resp = tx[i + 1..]
                    .iter()
                    .find(|(e, p, o, _)| e == exchange && *p == 1 && *o == 0x09)
                    .ok_or_else(|| format!("no InvokeResponse for exchange {exchange:#06x}"))?;
                let response_payload = match matter_interaction::parse_invoke_response(&resp.3)
                    .map_err(|e| format!("parse InvokeResponse: {e:?}"))?
                {
                    InvokeResponse::Command { fields_tlv, .. } => fields_tlv,
                    // Same mapping as the production driver: Success → [0x00],
                    // Failure(code) → [code].
                    InvokeResponse::Status(matter_interaction::ImStatus::Success) => vec![0x00],
                    InvokeResponse::Status(matter_interaction::ImStatus::Failure(code)) => {
                        vec![code]
                    }
                    InvokeResponse::Status(_) => vec![0x01],
                };
                invokes.push(CapturedInvoke {
                    cluster: cmd.path.cluster,
                    command: cmd.path.command,
                    fields_tlv: cmd.fields_tlv.clone(),
                    response_payload,
                });
            }
            0x05 => {
                reports.push(
                    matter_interaction::parse_report_data(payload)
                        .map_err(|e| format!("parse ReportData: {e:?}"))?,
                );
            }
            _ => {}
        }
    }

    // --- helpers over the captured dialogue --------------------------------
    let find_invoke = |cluster: u32, command: u32, nth: usize| -> Result<&CapturedInvoke, String> {
        invokes
            .iter()
            .filter(|iv| iv.cluster == cluster && iv.command == command)
            .nth(nth)
            .ok_or_else(|| {
                format!("captured dialogue has no invoke #{nth} for cluster {cluster:#06x} command {command:#04x}")
            })
    };
    // CertificateChainRequest carries type 1 = DAC, 2 = PAI (Matter Core
    // §11.18.6, CertificateChainTypeEnum) in context tag 0.
    let cert_chain_by_type = |wanted: u64| -> Result<&CapturedInvoke, String> {
        invokes
            .iter()
            .filter(|iv| iv.cluster == 0x003E && iv.command == 0x02)
            .find(|iv| {
                let mut r = matter_codec::TlvReader::new(&iv.fields_tlv);
                matches!(
                    r.read_value(),
                    Ok((_, matter_codec::Value::Structure(members)))
                        if members.iter().any(|(t, v)| {
                            *t == matter_codec::Tag::Context(0)
                                && *v == matter_codec::Value::Uint(wanted)
                        })
                )
            })
            .ok_or_else(|| format!("no CertificateChainRequest with type {wanted}"))
    };
    // An attribute value from any captured ReportData, re-encoded exactly as
    // the production driver's `extract_read_payload` does (anonymous tag).
    let read_attr_payload = |cluster: u32, attribute: u32| -> Result<Vec<u8>, String> {
        for report in &reports {
            for item in &report.items {
                if item.path.cluster == cluster && item.path.attribute == attribute {
                    let mut buf = Vec::new();
                    let mut w = matter_codec::TlvWriter::new(&mut buf);
                    w.write_value(matter_codec::Tag::Anonymous, &item.value)
                        .map_err(|e| format!("re-encode attr: {e}"))?;
                    return Ok(buf);
                }
            }
        }
        Err(format!(
            "no captured report carries cluster {cluster:#06x} attribute {attribute:#06x}"
        ))
    };
    // A 32-byte nonce from context tag 0 of a request's fields.
    let nonce_of = |iv: &CapturedInvoke| -> Result<Vec<u8>, String> {
        let mut r = matter_codec::TlvReader::new(&iv.fields_tlv);
        if let Ok((_, matter_codec::Value::Structure(members))) = r.read_value() {
            for (t, v) in members {
                if t == matter_codec::Tag::Context(0) {
                    if let matter_codec::Value::Bytes(b) = v {
                        return Ok(b);
                    }
                }
            }
        }
        Err("request fields carry no ctx-0 octet-string nonce".into())
    };

    // --- out-of-wire identity inputs, all from the AddNOC payload ----------
    let add_noc = find_invoke(0x003E, 0x06, 0)?;
    let mut noc_tlv: Option<Vec<u8>> = None;
    let mut ipk: Option<Vec<u8>> = None;
    let mut case_admin_subject: Option<u64> = None;
    {
        let mut r = matter_codec::TlvReader::new(&add_noc.fields_tlv);
        if let Ok((_, matter_codec::Value::Structure(members))) = r.read_value() {
            for (t, v) in members {
                match (t, v) {
                    (matter_codec::Tag::Context(0), matter_codec::Value::Bytes(b)) => {
                        noc_tlv = Some(b);
                    }
                    (matter_codec::Tag::Context(2), matter_codec::Value::Bytes(b)) => {
                        ipk = Some(b);
                    }
                    (matter_codec::Tag::Context(3), matter_codec::Value::Uint(v)) => {
                        case_admin_subject = Some(v);
                    }
                    _ => {}
                }
            }
        }
    }
    let noc_tlv = noc_tlv.ok_or("AddNOC carries no NOCValue (ctx 0)")?;
    let ipk = ipk.ok_or("AddNOC carries no IPKValue (ctx 2)")?;
    let case_admin_subject = case_admin_subject.ok_or("AddNOC carries no CaseAdminSubject")?;
    let noc = matter_cert::MatterCertificate::from_tlv(&noc_tlv)
        .map_err(|e| format!("parse captured NOC: {e}"))?;
    let fabric_id = noc
        .subject()
        .fabric_id()
        .ok_or("captured NOC subject has no FabricId")?;
    let assigned_node_id = noc
        .subject()
        .node_id()
        .ok_or("captured NOC subject has no NodeId")?;

    let attestation_request = find_invoke(0x003E, 0x00, 0)?;
    let csr_request = find_invoke(0x003E, 0x04, 0)?;

    // --- assemble the stage walk in the Rust state machine's order ---------
    let inv_stage = |stage: &'static str, iv: &CapturedInvoke| StageOut {
        stage,
        action: "Invoke",
        cluster: Some(format!("{:#06x}", iv.cluster)),
        command: Some(format!("{:#04x}", iv.command)),
        attribute_ids: Vec::new(),
        expected_payload_b64: Some(b64(&iv.fields_tlv)),
        response_payload_b64: Some(b64(&iv.response_payload)),
    };
    // matter.js sends SetRegulatoryConfig only to devices whose Network
    // Commissioning cluster carries the WI or TH feature (Matter Core §5.5 —
    // regulatory config is for radio devices). Against this ethernet-only
    // virtual device it is legitimately absent from the capture, so the
    // fixture carries NO expected payload for ConfigRegulatory (the parity
    // test asserts only when one is present; regulatory byte-parity was
    // separately validated live by the M6.6 trace-diff run) and a
    // synthesized success response to keep the walk moving.
    let config_regulatory = if let Ok(iv) = find_invoke(0x0030, 0x02, 0) {
        inv_stage("ConfigRegulatory", iv)
    } else {
        eprintln!(
            "capture-commissioning: ethernet-only device — matter.js skipped \
                 SetRegulatoryConfig; synthesizing a success response (no parity assert)"
        );
        let mut buf = Vec::new();
        let mut w = matter_codec::TlvWriter::new(&mut buf);
        w.start_structure(matter_codec::Tag::Anonymous)
                .and_then(|()| w.put_uint(matter_codec::Tag::Context(0), 0)) // ErrorCode: OK
                .and_then(|()| w.put_utf8(matter_codec::Tag::Context(1), "")) // DebugText
                .and_then(|()| w.end_container())
                .map_err(|e| format!("synthesize SetRegulatoryConfigResponse: {e}"))?;
        StageOut {
            stage: "ConfigRegulatory",
            action: "Invoke",
            cluster: Some("0x0030".into()),
            command: Some("0x02".into()),
            attribute_ids: Vec::new(),
            expected_payload_b64: None,
            response_payload_b64: Some(b64(&buf)),
        }
    };

    let stages = vec![
        StageOut {
            stage: "ReadCommissioningInfo",
            action: "ReadAttribute",
            cluster: Some("0x0030".into()),
            command: None,
            attribute_ids: vec![0, 1, 2, 4],
            expected_payload_b64: None,
            response_payload_b64: Some(b64(&read_attr_payload(0x0030, 0x0001)?)),
        },
        inv_stage("ArmFailsafe", find_invoke(0x0030, 0x00, 0)?),
        config_regulatory,
        inv_stage("SendPaiCertRequest", cert_chain_by_type(2)?),
        inv_stage("SendDacCertRequest", cert_chain_by_type(1)?),
        inv_stage("SendAttestationRequest", attestation_request),
        inv_stage("SendOpCertSigningRequest", csr_request),
        inv_stage("SendTrustedRootCert", find_invoke(0x003E, 0x0B, 0)?),
        inv_stage("SendNoc", add_noc),
        StageOut {
            stage: "ReadNetworkCommissioningInfo",
            action: "ReadAttribute",
            cluster: Some("0x0031".into()),
            command: None,
            attribute_ids: vec![0xFFFC],
            expected_payload_b64: None,
            response_payload_b64: Some(b64(&read_attr_payload(0x0031, 0xFFFC)?)),
        },
        StageOut {
            stage: "EstablishCase",
            action: "EstablishCase",
            cluster: None,
            command: None,
            attribute_ids: Vec::new(),
            expected_payload_b64: None,
            response_payload_b64: None,
        },
        inv_stage("SendComplete", find_invoke(0x0030, 0x04, 0)?),
    ];

    // Captured invokes actually consumed = Invoke stages whose expected
    // payload came off the wire (the synthesized ConfigRegulatory has none).
    let consumed: usize = stages
        .iter()
        .filter(|s| s.action == "Invoke" && s.expected_payload_b64.is_some())
        .count();
    let unmapped = invokes.len().saturating_sub(consumed);
    if unmapped > 0 {
        eprintln!(
            "capture-commissioning: {unmapped} captured invoke(s) not part of the Rust stage walk \
             (matter.js extras such as UpdateFabricLabel) — skipped"
        );
    }

    let fixture = FixtureOut {
        captured_at_unix: meta.captured_at_unix,
        fabric_id: format!("{fabric_id:#x}"),
        commissioner_node_id: format!("{case_admin_subject:#x}"),
        assigned_node_id: format!("{assigned_node_id:#x}"),
        ipk_epoch_key_b64: b64(&ipk),
        pase_attestation_challenge_b64: meta.pase_attestation_challenge_b64.clone(),
        attestation_nonce_b64: b64(&nonce_of(attestation_request)?),
        csr_nonce_b64: b64(&nonce_of(csr_request)?),
        cd_signing_spki_pem: meta.cd_signing_spki_pem.clone(),
        stages,
    };

    let e2e_dir = root.join("test-vectors/commissioning/e2e");
    std::fs::create_dir_all(&e2e_dir).map_err(|e| format!("create e2e dir: {e}"))?;
    let happy = serde_json::to_string_pretty(&fixture).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(e2e_dir.join("happy-path.json"), &happy)
        .map_err(|e| format!("write happy-path.json: {e}"))?;

    // Tampered-DAC sibling: identical dialogue except one bit flipped in the
    // DAC certificate byte of the DacCertChainResponse — the state machine
    // must reject it during attestation verification (verdict-only fixture;
    // no byte-parity is asserted on a rejection path).
    let mut tampered: serde_json::Value =
        serde_json::from_str(&happy).map_err(|e| format!("reparse: {e}"))?;
    {
        use base64::Engine;
        let stages = tampered["stages"]
            .as_array_mut()
            .ok_or("stages not an array")?;
        let dac = stages
            .iter_mut()
            .find(|s| s["stage"] == "SendDacCertRequest")
            .ok_or("no SendDacCertRequest stage")?;
        let resp_b64 = dac["response_payload_b64"]
            .as_str()
            .ok_or("DAC stage has no response payload")?;
        let mut resp = base64::engine::general_purpose::STANDARD
            .decode(resp_b64)
            .map_err(|e| format!("decode DAC response: {e}"))?;
        // Flip one bit deep inside the certificate body (past the TLV
        // envelope), leaving the message well-formed but the signature
        // invalid.
        let idx = resp.len() / 2;
        resp[idx] ^= 0x01;
        dac["response_payload_b64"] =
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&resp));
        tampered["verdict_only_reject"] = serde_json::Value::Bool(true);
    }
    std::fs::write(
        e2e_dir.join("tampered-dac.json"),
        serde_json::to_string_pretty(&tampered).map_err(|e| format!("serialize tampered: {e}"))?,
    )
    .map_err(|e| format!("write tampered-dac.json: {e}"))?;

    println!(
        "capture-commissioning: wrote {} + tampered-dac.json ({} stages, fabric {fabric_id:#x}, node {assigned_node_id:#x})",
        e2e_dir.join("happy-path.json").display(),
        fixture.stages.len(),
    );
    Ok(())
}

// Mirrors the resolver in `main.rs` so this module stays self-contained
// (the one in `main.rs` is a free function, not exported).
fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map_err(|_| "CARGO_MANIFEST_DIR not set; run via `cargo xtask`".to_string())?;
    PathBuf::from(manifest_dir)
        .parent()
        .map(PathBuf::from)
        .ok_or_else(|| "could not derive workspace root from CARGO_MANIFEST_DIR".to_string())
}
