//! `InvokeRequestMessage` / `InvokeResponseMessage` framing — Matter §10.7.

#![forbid(unsafe_code)]

use crate::im::{CommandPath, IM_REVISION};
use matter_codec::{Tag, TlvWriter};

/// Write a `CommandPathIB` (a TLV **list**: 0=endpoint, 1=cluster,
/// 2=command) under `tag`.
#[allow(clippy::expect_used, clippy::missing_panics_doc)] // Vec-backed TlvWriter is infallible.
fn write_command_path(w: &mut TlvWriter<'_>, tag: Tag, path: CommandPath) {
    w.start_list(tag).expect("infallible: vec writer");
    w.put_uint(Tag::Context(0), u64::from(path.endpoint))
        .expect("infallible: vec writer");
    w.put_uint(Tag::Context(1), u64::from(path.cluster))
        .expect("infallible: vec writer");
    w.put_uint(Tag::Context(2), u64::from(path.command))
        .expect("infallible: vec writer");
    w.end_container().expect("infallible: vec writer");
}

/// Build an `InvokeRequestMessage` carrying a single command.
///
/// `command_fields_tlv` is the already-encoded command-fields struct
/// (e.g. the output of `crate::noc::encode_csr_request`); it is embedded
/// verbatim as the `CommandFields` member. `SuppressResponse` and
/// `TimedRequest` are both `false`.
///
/// # Errors
///
/// This function is infallible; `Vec`-backed `TlvWriter` never fails.
/// The `command_fields_tlv` slice must be a valid anonymous-tagged TLV
/// element (panics otherwise — callers pass codec-generated output).
#[must_use]
#[allow(clippy::expect_used, clippy::missing_panics_doc)] // Vec-backed TlvWriter is infallible.
pub fn build_invoke_request(path: CommandPath, command_fields_tlv: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous)
        .expect("infallible: vec writer");
    w.put_bool(Tag::Context(0), false)
        .expect("infallible: vec writer"); // SuppressResponse
    w.put_bool(Tag::Context(1), false)
        .expect("infallible: vec writer"); // TimedRequest
    w.start_array(Tag::Context(2))
        .expect("infallible: vec writer"); // InvokeRequests
    {
        w.start_structure(Tag::Anonymous)
            .expect("infallible: vec writer"); // CommandDataIB
        write_command_path(&mut w, Tag::Context(0), path);
        w.put_preencoded(Tag::Context(1), command_fields_tlv)
            .expect("infallible: caller passes a valid anonymous-tagged struct");
        w.end_container().expect("infallible: vec writer"); // CommandDataIB
    }
    w.end_container().expect("infallible: vec writer"); // InvokeRequests array
    w.put_uint(Tag::Context(0xFF), u64::from(IM_REVISION))
        .expect("infallible: vec writer");
    w.end_container().expect("infallible: vec writer"); // message struct
    buf
}

#[cfg(test)]
mod tests {
    // Test-code carve-out: see CLAUDE.md.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::im::CommandPath;
    use matter_codec::{ContainerKind, Element, Tag, TlvReader, Value};

    #[test]
    fn invoke_request_has_expected_structure() {
        // ArmFailSafe-like: endpoint 0, cluster 0x0030, command 0x00,
        // command fields = an empty anonymous struct (0x15 0x18).
        let fields = vec![0x15, 0x18];
        let bytes = build_invoke_request(
            CommandPath {
                endpoint: 0,
                cluster: 0x0030,
                command: 0x00,
            },
            &fields,
        );

        let mut r = TlvReader::new(&bytes);
        // Top-level InvokeRequestMessage struct (anonymous).
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::Structure
            })
        ));
        // SuppressResponse = false.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(0),
                value: Value::Bool(false)
            })
        ));
        // TimedRequest = false.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(1),
                value: Value::Bool(false)
            })
        ));
        // InvokeRequests array start.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Context(2),
                kind: ContainerKind::Array
            })
        ));
        // CommandDataIB anonymous struct start.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::Structure
            })
        ));
        // CommandPathIB list at context tag 0.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Context(0),
                kind: ContainerKind::List
            })
        ));
        // Endpoint = 0 at context tag 0.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(0),
                value: Value::Uint(0)
            })
        ));
        // Cluster = 0x0030 at context tag 1.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(1),
                value: Value::Uint(0x0030)
            })
        ));
        // Command = 0x00 at context tag 2.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(2),
                value: Value::Uint(0)
            })
        ));
        // End CommandPathIB list.
        assert!(matches!(r.next().unwrap(), Some(Element::ContainerEnd)));
        // CommandFields (empty struct) at context tag 1 — ContainerStart then end.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind: ContainerKind::Structure
            })
        ));
        assert!(matches!(r.next().unwrap(), Some(Element::ContainerEnd)));
        // End CommandDataIB struct.
        assert!(matches!(r.next().unwrap(), Some(Element::ContainerEnd)));
        // End InvokeRequests array.
        assert!(matches!(r.next().unwrap(), Some(Element::ContainerEnd)));
        // InteractionModelRevision = IM_REVISION at context tag 0xFF.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar { tag: Tag::Context(0xFF), value: Value::Uint(v) })
                if v == u64::from(IM_REVISION)
        ));
        // End top-level struct.
        assert!(matches!(r.next().unwrap(), Some(Element::ContainerEnd)));
        // No more elements.
        assert!(r.next().unwrap().is_none());
    }

    #[test]
    fn invoke_request_carries_command_path_and_fields() {
        // `put_preencoded` re-tags the anonymous-struct control byte (0x15)
        // to a context-1 struct (0x35 0x01), then appends the body (0x18).
        // Verify that the re-tagged representation [0x35, 0x01, 0x18] is
        // present in the output (i.e. the fields blob was embedded).
        let fields = vec![0x15u8, 0x18]; // anonymous empty struct
        let bytes = build_invoke_request(
            CommandPath {
                endpoint: 1,
                cluster: 0x0031,
                command: 0x06,
            },
            &fields,
        );
        // Retagged form: context-1 struct start (0x35, 0x01) then body (0x18).
        let retagged = [0x35u8, 0x01, 0x18];
        assert!(
            bytes.windows(retagged.len()).any(|w| w == retagged),
            "command fields not embedded (expected retagged bytes {retagged:02X?} in {bytes:02X?})",
        );
    }
}
