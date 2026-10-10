//! Helpers for the per-batch cluster sweeps (M9-A3 spec §6.3): read every
//! attribute of a cluster with one wildcard read and decode each with the
//! generated `matter-clusters` decoder, and invoke a command and decode its
//! response.

use anyhow::{bail, Context, Result};
use matter_clusters::error::ClusterError;
use matter_controller::{CommandPath, ImStatus, InvokeResult, Node, ReadPath};

use crate::events::payload_tlv;

/// Global attribute ids (`AcceptedCommandList`, `AttributeList`, ...,
/// 0xF000..=0xFFFE) are left out of a sweep: `gen/globals.rs` covers them for
/// every cluster.
fn is_global(attribute: u32) -> bool {
    (0xF000..=0xFFFE).contains(&attribute)
}

/// Every non-global attribute of `cluster` on `endpoint`, from one wildcard
/// read, as `(attribute id, value TLV)` sorted by id: the input the generated
/// `decode_<attribute>` functions take.
///
/// # Errors
///
/// A transport or IM error from the read.
pub async fn read_cluster_attributes(
    node: &Node,
    endpoint: u16,
    cluster: u32,
) -> Result<Vec<(u32, Vec<u8>)>> {
    let mut attrs: Vec<(u32, Vec<u8>)> = node
        .read(&[ReadPath::cluster(endpoint, cluster)])
        .await
        .with_context(|| format!("wildcard read of cluster {cluster:#06x} on ep{endpoint}"))?
        .into_iter()
        .filter(|(p, _)| p.cluster == cluster && !is_global(p.attribute))
        .map(|(p, v)| (p.attribute, payload_tlv(&v)))
        .collect();
    attrs.sort_by_key(|(id, _)| *id);
    Ok(attrs)
}

/// Read every non-global attribute of `cluster` on `endpoint` and decode each
/// with `decode(attribute_id, tlv)`. Returns what was read (as
/// [`read_cluster_attributes`]), so the caller can assert the sweep was not
/// vacuous and inspect decoded values without a second read.
///
/// # Panics
///
/// On a read error or the first attribute that fails to decode, naming it.
pub async fn decode_every_attribute(
    node: &Node,
    endpoint: u16,
    cluster: u32,
    decode: impl Fn(u32, &[u8]) -> Result<(), String>,
) -> Vec<(u32, Vec<u8>)> {
    let attrs = read_cluster_attributes(node, endpoint, cluster)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    for (id, tlv) in &attrs {
        decode(*id, tlv).unwrap_or_else(|e| {
            panic!("cluster {cluster:#06x} attribute {id:#06x} failed to decode: {e}; {tlv:02x?}")
        });
    }
    eprintln!(
        "[sweep] ep{endpoint} cluster {cluster:#06x}: decoded attributes {:04x?}",
        attribute_ids(&attrs)
    );
    attrs
}

/// The attribute ids of a sweep's results, in order.
#[must_use]
pub fn attribute_ids(attrs: &[(u32, Vec<u8>)]) -> Vec<u32> {
    attrs.iter().map(|(id, _)| *id).collect()
}

/// The value TLV of attribute `id` in a sweep's results.
///
/// # Panics
///
/// If the wildcard read did not return `id`.
#[must_use]
pub fn attribute_tlv(attrs: &[(u32, Vec<u8>)], id: u32) -> &[u8] {
    &attrs
        .iter()
        .find(|(a, _)| *a == id)
        .unwrap_or_else(|| panic!("attribute {id:#06x} not in the wildcard read"))
        .1
}

/// Map a generated decoder's result to the [`decode_every_attribute`] shape.
///
/// # Errors
///
/// The decoder's error, rendered.
pub fn ok<T>(r: Result<T, ClusterError>) -> Result<(), String> {
    r.map(|_| ()).map_err(|e| e.to_string())
}

/// An attribute id the 1.4 codegen does not know (a 1.5-era chip may serve
/// one): logged and skipped, never a failure. The callers assert the ids they
/// do know were all read.
///
/// # Errors
///
/// Never; the `Result` matches the decode-closure signature.
#[allow(clippy::unnecessary_wraps)]
pub fn newer_than_codegen(cluster: &str, attribute: u32) -> Result<(), String> {
    eprintln!("[sweep] {cluster}: skipping attribute {attribute:#06x} unknown to the 1.4 codegen");
    Ok(())
}

/// Invoke `path` with pre-encoded `fields` and return the response command's
/// payload TLV, for the generated `<Response>::decode`.
///
/// # Errors
///
/// A transport error, a bare status instead of a response, or a response
/// whose command id is not `response_command`.
pub async fn invoke_for_response(
    node: &Node,
    path: CommandPath,
    fields: Vec<u8>,
    response_command: u32,
) -> Result<Vec<u8>> {
    match node.invoke_tlv(path, fields).await.context("invoke")? {
        InvokeResult::Data { path: got, fields } if got.command == response_command => {
            Ok(payload_tlv(&fields))
        }
        other => bail!(
            "command {:#06x}/{:#04x}: expected response {response_command:#04x}, got {other:?}",
            path.cluster,
            path.command
        ),
    }
}

/// Invoke `path` with pre-encoded `fields` and return the bare status the
/// device answered (a command with no response command).
///
/// # Errors
///
/// A transport error, or a response command where a status was expected.
pub async fn invoke_for_status(
    node: &Node,
    path: CommandPath,
    fields: Vec<u8>,
) -> Result<ImStatus> {
    match node.invoke_tlv(path, fields).await.context("invoke")? {
        InvokeResult::Status(s) => Ok(s),
        other => bail!(
            "command {:#06x}/{:#04x}: expected a status, got {other:?}",
            path.cluster,
            path.command
        ),
    }
}

/// Sweep one `ModeBase` derivative (M9-A3 B2) on `$endpoint`: decode every
/// attribute from a wildcard read (asserting `SupportedModes` and
/// `CurrentMode` are among them, and that `CurrentMode` is a supported mode),
/// then invoke `ChangeToMode(CurrentMode)` and decode the response.
///
/// `ChangeToMode(CurrentMode)` is the safe command: chip answers `Success`
/// before it consults the app's delegate and changes nothing
/// (`ModeBaseCluster.cpp` `HandleChangeToMode`), and it never sends
/// `StatusText` (spec §3.1), which the macro asserts. `$m` is the generated
/// module, in scope at the call site (`use matter_clusters::gen::rvc_run_mode;`).
///
/// Panics (it is a test helper) on any failure, naming the cluster.
#[macro_export]
macro_rules! sweep_mode_base {
    ($node:expr, $endpoint:expr, $m:ident) => {{
        use $crate::sweep::{
            attribute_ids, attribute_tlv, decode_every_attribute, invoke_for_response,
            newer_than_codegen, ok,
        };
        use $m::attribute_id::{CURRENT_MODE, SUPPORTED_MODES};
        let name = stringify!($m);
        let attrs = decode_every_attribute($node, $endpoint, $m::CLUSTER_ID, |id, t| match id {
            SUPPORTED_MODES => ok($m::decode_supported_modes(t)),
            CURRENT_MODE => ok($m::decode_current_mode(t)),
            other => newer_than_codegen(name, other),
        })
        .await;
        let ids = attribute_ids(&attrs);
        assert!(
            ids.contains(&SUPPORTED_MODES) && ids.contains(&CURRENT_MODE),
            "{name}: {ids:04x?}"
        );
        let modes = $m::decode_supported_modes(attribute_tlv(&attrs, SUPPORTED_MODES)).unwrap();
        let current = $m::decode_current_mode(attribute_tlv(&attrs, CURRENT_MODE)).unwrap();
        assert!(
            modes.iter().any(|m| m.mode == current),
            "{name}: CurrentMode {current} not in SupportedModes"
        );
        let path = ::matter_controller::CommandPath {
            endpoint: $endpoint,
            cluster: $m::CLUSTER_ID,
            command: $m::command_id::CHANGE_TO_MODE,
        };
        let resp = invoke_for_response(
            $node,
            path,
            $m::encode_change_to_mode(current),
            $m::command_id::CHANGE_TO_MODE_RESPONSE,
        )
        .await
        .unwrap_or_else(|e| panic!("{name}: {e:#}"));
        let r = $m::ChangeToModeResponse::decode(&resp)
            .unwrap_or_else(|e| panic!("{name}: ChangeToModeResponse: {e}"));
        assert_eq!(r.status, $m::ModeChangeStatus::Success, "{name}");
        assert_eq!(r.status_text, None, "{name}: chip sends no StatusText");
    }};
}
