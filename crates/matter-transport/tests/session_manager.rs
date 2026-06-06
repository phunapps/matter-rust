//! `SessionManager` integration tests.
//!
//! Six tests are inherited from M5.1 (registration + counter bump +
//! roundtrip + unknown-session error), updated for the M5.2 signatures
//! that thread the protocol header and MRP state through the manager.
//! Six new tests cover M5.2 behaviour: reliable+piggyback roundtrip,
//! cross-session `poll_timeout`, duplicate-reliable resend, expired-event
//! draining, concurrent-exchange isolation, and the payload-too-large
//! guard with the protocol header included.

#![allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.

use matter_crypto::pase::PaseSessionKeys;
use matter_transport::mrp::MrpFlags;
use matter_transport::session::{PeerHint, SessionKeys, SessionManager, SessionRole};
use matter_transport::{
    encode_secured, MessageCounter, SecuredMessageFlags, SecuredMessageHeader, SecurityFlags,
    SessionId,
};

fn pase_keys() -> PaseSessionKeys {
    PaseSessionKeys {
        ke: [0xAAu8; 16],
        i2r_key: [0x11u8; 16],
        r2i_key: [0x22u8; 16],
        attestation_key: [0x33u8; 16],
    }
}

#[test]
fn register_pase_allocates_session_id() {
    let mut mgr = SessionManager::new();
    let sid = mgr.register_pase(
        pase_keys(),
        SessionRole::Initiator,
        /* peer_session_id */ 0xBEEF,
        PeerHint::default(),
    );
    let s = mgr.get(sid).unwrap();
    assert_eq!(s.peer_id.0, 0xBEEF);
    assert_eq!(s.role, SessionRole::Initiator);
    assert_eq!(s.keys.i2r_key, [0x11u8; 16]);
    assert_eq!(s.keys.r2i_key, [0x22u8; 16]);
}

#[test]
fn allocated_session_ids_are_unique() {
    let mut mgr = SessionManager::new();
    let s1 = mgr.register_pase(pase_keys(), SessionRole::Initiator, 1, PeerHint::default());
    let s2 = mgr.register_pase(pase_keys(), SessionRole::Initiator, 2, PeerHint::default());
    assert_ne!(s1, s2);
}

#[test]
fn remove_drops_the_session() {
    let mut mgr = SessionManager::new();
    let sid = mgr.register_pase(pase_keys(), SessionRole::Initiator, 1, PeerHint::default());
    assert!(mgr.get(sid).is_some());
    assert!(mgr.remove(sid).is_some());
    assert!(mgr.get(sid).is_none());
    assert!(mgr.remove(sid).is_none());
}

#[test]
fn encode_outbound_bumps_counter() {
    let mut mgr = SessionManager::new();
    let sid = mgr.register_pase(
        pase_keys(),
        SessionRole::Initiator,
        0xBEEF,
        PeerHint::default(),
    );
    let initial_counter = mgr.get(sid).unwrap().outbound_counter;

    let _ = mgr
        .encode_outbound(
            sid,
            None,
            0x02,
            matter_transport::protocol_header::ProtocolId::INTERACTION_MODEL,
            b"hello",
            MrpFlags::default(),
            std::time::Instant::now(),
        )
        .unwrap();

    let after = mgr.get(sid).unwrap().outbound_counter;
    assert_eq!(after, initial_counter.wrapping_add(1));
}

#[test]
fn encode_outbound_then_decode_inbound_roundtrip() {
    // Two managers, each side of the same session.
    let mut alice = SessionManager::new();
    let mut bob = SessionManager::new();
    let keys = pase_keys();
    let now = std::time::Instant::now();

    let alice_sid = alice.register_pase(
        keys.clone(),
        SessionRole::Initiator,
        /* peer_session_id (bob's local id, faked here) */ 1,
        PeerHint::default(),
    );
    let bob_sid = bob.register_pase(
        keys,
        SessionRole::Responder,
        /* peer_session_id (alice's local id) */ alice_sid.0,
        PeerHint::default(),
    );

    // encode_outbound sets header.session_id to peer_id from alice's
    // session record. Alice's peer_id == 1 == bob's local id, so bob
    // can demux on receipt.
    let out = alice
        .encode_outbound(
            alice_sid,
            None,
            0x02,
            matter_transport::protocol_header::ProtocolId::INTERACTION_MODEL,
            b"ping",
            MrpFlags::default(),
            now,
        )
        .unwrap();

    let decoded = bob.decode_inbound(&out.wire_bytes, now).unwrap();
    match decoded {
        matter_transport::session::DecodeInboundOutput::AppMessage {
            session_id,
            payload,
            ..
        } => {
            assert_eq!(session_id, bob_sid);
            assert_eq!(payload, b"ping");
        }
        other => panic!("expected AppMessage, got {other:?}"),
    }
}

#[test]
fn decode_inbound_unknown_session_errors() {
    let mut mgr = SessionManager::new();
    // Craft a wire packet with a session ID we never registered.
    let keys = SessionKeys {
        i2r_key: [0x11u8; 16],
        r2i_key: [0x22u8; 16],
        attestation_key: [0x33u8; 16],
    };
    let header = SecuredMessageHeader {
        flags: SecuredMessageFlags::empty(),
        session_id: SessionId(0xDEAD),
        security_flags: SecurityFlags::empty(),
        message_counter: MessageCounter(1),
        source_node_id: None,
        destination_node_id: None,
    };
    let wire = encode_secured(&header, b"x", &keys, SessionRole::Initiator, 0).unwrap();

    let err = mgr
        .decode_inbound(&wire, std::time::Instant::now())
        .unwrap_err();
    assert!(matches!(
        err,
        matter_transport::Error::UnknownSession(0xDEAD)
    ));
}

#[test]
fn encode_outbound_reliable_then_decode_inbound_ack() {
    // Alice (Initiator) sends reliable; Bob (Responder) receives. Bob's
    // process_inbound queues a piggyback. Bob then sends a response in
    // the same exchange; the response carries A=1 + ack_counter back to
    // Alice. Alice's pending_acks clears.
    use matter_transport::protocol_header::ProtocolId;
    use matter_transport::session::DecodeInboundOutput;

    let mut alice = SessionManager::new();
    let mut bob = SessionManager::new();
    let keys = pase_keys();
    let now = std::time::Instant::now();

    let alice_sid =
        alice.register_pase(keys.clone(), SessionRole::Initiator, 1, PeerHint::default());
    let bob_sid = bob.register_pase(
        keys,
        SessionRole::Responder,
        alice_sid.0,
        PeerHint::default(),
    );

    let out1 = alice
        .encode_outbound(
            alice_sid,
            None,
            0x02,
            ProtocolId::INTERACTION_MODEL,
            b"req",
            MrpFlags { reliable: true },
            now,
        )
        .unwrap();
    let exchange_id = out1.exchange_id;
    // Alice has a pending retransmit.
    assert!(alice.get(alice_sid).unwrap().mrp.poll_timeout().is_some());

    let received_at_bob = bob.decode_inbound(&out1.wire_bytes, now).unwrap();
    let (_, _) = match received_at_bob {
        DecodeInboundOutput::AppMessage {
            exchange_id: ex,
            payload,
            ..
        } => (ex, payload),
        other => panic!("expected AppMessage, got {other:?}"),
    };

    // Bob sends a response in the same exchange — piggyback drains.
    let out2 = bob
        .encode_outbound(
            bob_sid,
            Some(exchange_id),
            0x03,
            ProtocolId::INTERACTION_MODEL,
            b"resp",
            MrpFlags::default(),
            now,
        )
        .unwrap();
    assert!(out2.piggyback_acked, "Bob piggybacked Alice's ack");

    // Alice decodes Bob's response — the embedded ack clears her pending.
    let received_at_alice = alice.decode_inbound(&out2.wire_bytes, now).unwrap();
    match received_at_alice {
        DecodeInboundOutput::AppMessage { payload, .. } => {
            assert_eq!(payload, b"resp");
        }
        other => panic!("expected AppMessage at Alice, got {other:?}"),
    }
    assert!(
        alice.get(alice_sid).unwrap().mrp.poll_timeout().is_none(),
        "Alice's pending retransmit cleared by piggyback ack",
    );
}

#[test]
fn poll_timeout_min_across_sessions() {
    use matter_transport::protocol_header::ProtocolId;
    use std::time::Duration;

    let mut mgr = SessionManager::new();
    let s1 = mgr.register_pase(pase_keys(), SessionRole::Initiator, 1, PeerHint::default());
    let s2 = mgr.register_pase(pase_keys(), SessionRole::Initiator, 2, PeerHint::default());

    let now = std::time::Instant::now();
    let _ = mgr
        .encode_outbound(
            s1,
            None,
            0x02,
            ProtocolId::INTERACTION_MODEL,
            b"x",
            MrpFlags { reliable: true },
            now,
        )
        .unwrap();
    let later = now + Duration::from_millis(100);
    let _ = mgr
        .encode_outbound(
            s2,
            None,
            0x02,
            ProtocolId::INTERACTION_MODEL,
            b"y",
            MrpFlags { reliable: true },
            later,
        )
        .unwrap();

    let deadline = mgr.poll_timeout().unwrap();
    assert_eq!(
        deadline,
        now + Duration::from_millis(300),
        "earliest is s1's 300ms deadline",
    );
}

#[test]
fn decode_inbound_duplicate_reliable_emits_resend_packet() {
    use matter_transport::protocol_header::ProtocolId;
    use matter_transport::session::DecodeInboundOutput;

    let mut alice = SessionManager::new();
    let mut bob = SessionManager::new();
    let keys = pase_keys();
    let now = std::time::Instant::now();

    let alice_sid =
        alice.register_pase(keys.clone(), SessionRole::Initiator, 1, PeerHint::default());
    let bob_sid = bob.register_pase(
        keys,
        SessionRole::Responder,
        alice_sid.0,
        PeerHint::default(),
    );

    let out = alice
        .encode_outbound(
            alice_sid,
            None,
            0x02,
            ProtocolId::INTERACTION_MODEL,
            b"req",
            MrpFlags { reliable: true },
            now,
        )
        .unwrap();
    bob.decode_inbound(&out.wire_bytes, now).unwrap();

    // Alice retransmits the same wire bytes (peer's ack was lost).
    let outcome = bob.decode_inbound(&out.wire_bytes, now).unwrap();
    match outcome {
        DecodeInboundOutput::DuplicateReliableAckResent {
            session_id,
            exchange_id,
            ack_packet,
        } => {
            assert_eq!(session_id, bob_sid);
            assert_eq!(exchange_id, out.exchange_id);
            assert!(!ack_packet.is_empty());
        }
        other => panic!("expected DuplicateReliableAckResent, got {other:?}"),
    }
}

#[test]
fn handle_timeout_drains_expired_sessions() {
    use matter_transport::protocol_header::ProtocolId;
    use matter_transport::MrpEvent;
    use std::time::Duration;

    let mut mgr = SessionManager::new();
    let sid = mgr.register_pase(pase_keys(), SessionRole::Initiator, 1, PeerHint::default());
    let now = std::time::Instant::now();

    let _ = mgr
        .encode_outbound(
            sid,
            None,
            0x02,
            ProtocolId::INTERACTION_MODEL,
            b"x",
            MrpFlags { reliable: true },
            now,
        )
        .unwrap();

    // Advance well past all 5 retransmits.
    let mut t = now;
    let mut saw_expired = false;
    for _ in 0..10 {
        t += Duration::from_secs(10);
        let events = mgr.handle_timeout(t);
        if events.iter().any(|e| matches!(e, MrpEvent::Expired { .. })) {
            saw_expired = true;
            break;
        }
    }
    assert!(
        saw_expired,
        "expected at least one Expired event after exhausting retransmits"
    );
}

#[test]
fn concurrent_exchanges_isolated() {
    use matter_transport::protocol_header::ProtocolId;

    let mut mgr = SessionManager::new();
    let sid = mgr.register_pase(pase_keys(), SessionRole::Initiator, 1, PeerHint::default());
    let now = std::time::Instant::now();

    let out1 = mgr
        .encode_outbound(
            sid,
            None,
            0x02,
            ProtocolId::INTERACTION_MODEL,
            b"a",
            MrpFlags { reliable: true },
            now,
        )
        .unwrap();
    let out2 = mgr
        .encode_outbound(
            sid,
            None,
            0x02,
            ProtocolId::INTERACTION_MODEL,
            b"b",
            MrpFlags { reliable: true },
            now,
        )
        .unwrap();

    assert_ne!(out1.exchange_id, out2.exchange_id);
    assert_eq!(out1.message_counter.0 + 1, out2.message_counter.0);
}

#[test]
fn allocate_then_register_pase_under_chosen_local_id() {
    let mut mgr = SessionManager::new();
    let local = mgr.allocate_session_id();
    assert_ne!(local.0, 0, "allocated id must be non-zero");
    let local2 = mgr.allocate_session_id();
    assert_ne!(local, local2);

    let keys = matter_crypto::pase::PaseSessionKeys {
        ke: [0u8; 16],
        i2r_key: [1u8; 16],
        r2i_key: [2u8; 16],
        attestation_key: [3u8; 16],
    };
    mgr.register_pase_with_local_id(
        local,
        keys,
        SessionRole::Initiator,
        0x00BB,
        PeerHint::default(),
    );

    let s = mgr.get(local).unwrap();
    assert_eq!(s.local_id, local);
    assert_eq!(s.peer_id, SessionId(0x00BB));
}

#[test]
fn payload_too_large_with_protocol_header() {
    use matter_transport::protocol_header::ProtocolId;

    let mut mgr = SessionManager::new();
    let sid = mgr.register_pase(pase_keys(), SessionRole::Initiator, 1, PeerHint::default());
    let now = std::time::Instant::now();

    // MAX_PAYLOAD_LEN = 1024 includes the protocol header (~6 bytes).
    // 1025 bytes of app payload pushes the wire payload (header + app)
    // past the cap and the framing layer rejects it.
    let oversized = vec![0u8; 1025];
    let err = mgr
        .encode_outbound(
            sid,
            None,
            0x02,
            ProtocolId::INTERACTION_MODEL,
            &oversized,
            MrpFlags::default(),
            now,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        matter_transport::Error::PayloadTooLarge { .. }
    ));
}
