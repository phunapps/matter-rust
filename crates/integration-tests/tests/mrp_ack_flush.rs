// Integration tests are a binary crate; crate-level docs are not required.
// Test-code carve-out for unwrap/expect: see CLAUDE.md.
#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::doc_markdown
)]

//! MRP on a live chip device: every response is ACKed when its exchange
//! closes, as chip's `ExchangeContext::DoClose` → `FlushAcks` does, so
//! neither commissioning nor a controller dropped the instant a read returns
//! leaves the device anything to retransmit.
//!
//! The device's own log is the witness. chip logs, at Progress level:
//!
//! - `??N [E:<exchange> S:<lsid> M:<counter>] (…) Msg Retransmission to …
//!   scheduled for …ms` on EVERY reliable send
//!   (src/messaging/ReliableMessageMgr.cpp:590 at master 5cd2917a, :581 at
//!   v1.4.2.0);
//! - `<<N [E:… S:<lsid> M:…] (S) Msg Retransmission to …` only when it
//!   actually re-sends (:224), or gives up (`… failure (max retries:4)`,
//!   :193), at both refs.
//!
//! The line prefix differs by backend: chip master prints
//! `[ts] [pid:tid] [EM] <<1 …` on Darwin and Linux, v1.4.2.0 on Linux prints
//! `[ts][pid:tid] CHIP:EM: <<1 …` (src/platform/Linux/Logging.cpp:46), so the
//! matchers look for the markers anywhere in the line. Sessions are named by
//! the LSID chip logs at Detail level when it activates one,
//! `New secure session activated for device <node, fabric>, LSID:<n>
//! PSID:<m>!` (src/protocols/secure_channel/PairingSession.cpp:56 master,
//! :55 v1.4.2.0). Each test also counts `??N` lines on its sessions, so a log
//! format or level change fails loudly instead of passing vacuously.
//!
//! Runs in the all-clusters arm (every binary no other arm lists): locally
//! (`just integration`, chip master) and in the nightly at v1.4.2.0.

use std::time::Duration;

use integration_tests::dut::DutConfig;
use matter_controller::ReadPath;

/// Short-lived controllers in a row. chip's Linux apps at master have 15
/// packet buffers, so 40 unACKed responses would also run one dry.
const CYCLES: usize = 40;

/// How long to watch after the last message. A chip device's first
/// retransmit comes about 330-550 ms after the original (our advertised
/// 300/500 ms active/idle intervals plus chip's margin; app.log's "scheduled
/// for" lines), so 2 s covers at least two retransmit rounds.
const RETRANSMIT_WATCH: Duration = Duration::from_secs(2);

/// The device's log, written by `xtask integration`
/// (`xtask/src/integration.rs`, `log_path = dut_dir.join("app.log")`), fresh
/// for every run.
fn app_log(cfg: &DutConfig) -> std::path::PathBuf {
    cfg.dut_dir.join("app.log")
}

/// Whether `marker` occurs in `line` immediately followed by an ASCII digit.
fn marker_then_digit(line: &str, marker: &str) -> bool {
    line.match_indices(marker)
        .any(|(i, _)| line[i + marker.len()..].starts_with(|c: char| c.is_ascii_digit()))
}

/// chip re-sent (or gave up on) a reliable message: `<<N … Msg Retransmission
/// to …`, without "scheduled for", whatever the line prefix.
fn is_retransmission(line: &str) -> bool {
    line.contains("Msg Retransmission to")
        && !line.contains("scheduled for")
        && marker_then_digit(line, "<<")
}

/// chip sent a reliable message: `??N … Msg Retransmission to … scheduled
/// for …`, logged once per reliable send.
fn is_reliable_send(line: &str) -> bool {
    line.contains("Msg Retransmission to")
        && line.contains("scheduled for")
        && marker_then_digit(line, "??")
}

/// The session (LSID) a chip MRP log line names: the number after ` S:`.
fn lsid_of(line: &str) -> Option<&str> {
    line.split(" S:").nth(1)?.split_whitespace().next()
}

/// `(is the PASE peer, LSID)` of every session activation in `log`, in order.
/// A PASE session's peer is the temporary node id `FFFFFFFB00000000` on
/// fabric index 0.
fn activations(log: &str) -> Vec<(bool, String)> {
    log.lines()
        .filter(|l| l.contains("New secure session activated"))
        .filter_map(|l| {
            let lsid = l.split("LSID:").nth(1)?.split_whitespace().next()?;
            Some((l.contains("<FFFFFFFB00000000, 0>"), lsid.to_string()))
        })
        .collect()
}

/// `(reliable sends, retransmission lines)` on the sessions `lsids`.
fn mrp_lines_on<'a>(log: &'a str, lsids: &[String]) -> (usize, Vec<&'a str>) {
    let on = |l: &&str| lsid_of(l).is_some_and(|s| lsids.iter().any(|x| x == s));
    let sends = log
        .lines()
        .filter(|l| is_reliable_send(l))
        .filter(on)
        .count();
    let retransmitted = log
        .lines()
        .filter(|l| is_retransmission(l))
        .filter(on)
        .collect();
    (sends, retransmitted)
}

/// The run's commissioning: its PASE session (the first activation, for the
/// PASE peer) and the commissioner's own CASE session (the next activation)
/// must have left no retransmission. That CASE session carries only
/// CommissioningComplete, so a `<<N` line on it is that response unACKed;
/// one on the PASE session is a response whose ACK came too late (the Tapo
/// P110M straggler of M6.6.5, on chip). Reads the whole log: the fixture
/// commissions once per run, in whichever test binary runs first.
#[tokio::test]
async fn commissioning_leaves_no_retransmission() {
    let cfg = integration_tests::dut_or_skip!();
    if !cfg.is_app("all-clusters") {
        eprintln!("skipped: the commissioning ACK check runs against all-clusters");
        return;
    }
    // Commission now if no earlier binary did, then give the device time to
    // retransmit anything it is owed an ACK for.
    let (controller, _node_id) = integration_tests::fixture::connect(&cfg)
        .await
        .expect("connect/commission DUT");
    drop(controller);
    tokio::time::sleep(RETRANSMIT_WATCH).await;

    let log = std::fs::read(app_log(&cfg)).expect("app.log");
    let log = String::from_utf8_lossy(&log);
    let all = activations(&log);
    let pase = all
        .iter()
        .position(|(is_pase, _)| *is_pase)
        .expect("app.log shows the PASE session activation");
    let commissioning: Vec<String> = all[pase..]
        .iter()
        .take(2)
        .map(|(_, lsid)| lsid.clone())
        .collect();
    assert_eq!(
        commissioning.len(),
        2,
        "PASE and the commissioner's CASE session: {all:?}"
    );
    let (sends, retransmitted) = mrp_lines_on(&log, &commissioning);
    assert!(
        sends >= 2,
        "positive control: chip's `??N` send lines on {commissioning:?} (found {sends})"
    );
    assert_eq!(
        retransmitted,
        Vec::<&str>::new(),
        "the device retransmitted a commissioning response on {commissioning:?}"
    );
}

#[tokio::test]
async fn controllers_dropped_right_after_a_read_leave_no_retransmission() {
    let cfg = integration_tests::dut_or_skip!();
    if !cfg.is_app("all-clusters") {
        eprintln!("skipped: the drop-after-read check runs against all-clusters");
        return;
    }
    // Commission (if this is the run's first test) and drop: no CASE session
    // is opened until the first exchange.
    let (controller, _node_id) = integration_tests::fixture::connect(&cfg)
        .await
        .expect("connect/commission DUT");
    drop(controller);
    let start = std::fs::metadata(app_log(&cfg)).expect("app.log").len();

    for cycle in 0..CYCLES {
        let (controller, node_id) = integration_tests::fixture::connect(&cfg)
            .await
            .expect("connect DUT");
        let report = controller
            .node(node_id)
            .read(&[ReadPath::concrete(0, 0x0028, 0x0002)]) // BasicInformation.VendorID
            .await
            .unwrap_or_else(|e| panic!("cycle {cycle}: read failed: {e:?}"));
        assert_eq!(report.len(), 1, "cycle {cycle}: VendorID");
        drop(controller); // no pause: the ACK must already be on the wire
    }
    tokio::time::sleep(RETRANSMIT_WATCH).await;

    let log = std::fs::read(app_log(&cfg)).expect("app.log");
    let tail = String::from_utf8_lossy(&log[usize::try_from(start).unwrap()..]);
    let lsids: Vec<String> = activations(&tail).into_iter().map(|(_, l)| l).collect();
    assert_eq!(
        lsids.len(),
        CYCLES,
        "each cycle's controller opens its own CASE session; app.log shows {lsids:?}"
    );
    let (sends, retransmitted) = mrp_lines_on(&tail, &lsids);
    assert!(
        sends >= CYCLES,
        "positive control: one `??N` send line per cycle at least (found {sends})"
    );
    assert_eq!(
        retransmitted,
        Vec::<&str>::new(),
        "the device retransmitted responses on the test's sessions"
    );
}
