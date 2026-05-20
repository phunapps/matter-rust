//! `SessionManager` skeleton tests for M5.1.
//!
//! MRP behaviour (`poll_timeout` / `handle_timeout`) is M5.2 territory and
//! has its own dedicated test file.

#![allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.

use matter_crypto::pase::PaseSessionKeys;
use matter_transport::session::{MrpFlags, PeerHint, SessionKeys, SessionManager, SessionRole};
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
        .encode_outbound(sid, b"hello", MrpFlags::default())
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
    let wire = alice
        .encode_outbound(alice_sid, b"ping", MrpFlags::default())
        .unwrap();

    let (sid, payload) = bob.decode_inbound(&wire).unwrap();
    assert_eq!(sid, bob_sid);
    assert_eq!(payload, b"ping");
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
    let wire = encode_secured(&header, b"x", &keys, SessionRole::Initiator).unwrap();

    let err = mgr.decode_inbound(&wire).unwrap_err();
    assert!(matches!(
        err,
        matter_transport::Error::UnknownSession(0xDEAD)
    ));
}
