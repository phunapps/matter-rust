//! Event helpers for the event integration tests (M9-A3 B1): stimulate an
//! event on the DUT (`GeneralDiagnostics.TestEventTrigger`, or the app's
//! out-of-band `--app-pipe` command FIFO), then read it back from the event
//! path and hand its payload to a generated `matter-clusters` decoder.

use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use matter_clusters::gen::general_diagnostics;
use matter_codec::{Tag, TlvWriter, Value};
use matter_controller::{
    CommandPath, EventPath, EventReport, EventReportItem, ImStatus, InvokeResult, Node,
};

use crate::dut::DutConfig;

/// The `TestEventTrigger` enable key every chip app is launched with by
/// `xtask integration` (`--enable-key 00112233445566778899aabbccddeeff`).
/// chip's default key is all zeros, which disables triggers. Must match
/// `TEST_EVENT_ENABLE_KEY_HEX` in `xtask/src/integration.rs`.
pub const TEST_EVENT_ENABLE_KEY: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

/// How long a stimulated event may take to appear on the event path.
pub const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Encode a report's payload [`Value`] as a standalone anonymous TLV element,
/// the input the generated `<Name>Event::decode` functions take.
///
/// # Panics
///
/// Never in practice: a `Vec`-backed `TlvWriter` cannot fail.
#[must_use]
#[allow(clippy::expect_used)] // Vec-backed TlvWriter is infallible.
pub fn payload_tlv(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.write_value(Tag::Anonymous, value)
        .expect("infallible: Vec-backed TlvWriter");
    buf
}

/// Invoke `GeneralDiagnostics.TestEventTrigger` (endpoint 0) with
/// [`TEST_EVENT_ENABLE_KEY`].
///
/// # Errors
///
/// A transport error, or any response other than a bare `Success` (chip
/// answers `ConstraintError` for a wrong key and `InvalidCommand` for a
/// trigger no handler claims).
pub async fn test_event_trigger(node: &Node, trigger: u64) -> Result<()> {
    let fields =
        general_diagnostics::encode_test_event_trigger(&TEST_EVENT_ENABLE_KEY.to_vec(), trigger);
    let path = CommandPath {
        endpoint: 0,
        cluster: general_diagnostics::CLUSTER_ID,
        command: general_diagnostics::command_id::TEST_EVENT_TRIGGER,
    };
    match node
        .invoke_tlv(path, fields)
        .await
        .context("invoke TestEventTrigger")?
    {
        InvokeResult::Status(ImStatus::Success) => Ok(()),
        other => bail!("TestEventTrigger {trigger:#018x} rejected: {other:?}"),
    }
}

/// How long a write to the app pipe may block before the test fails: opening
/// a FIFO for writing blocks until a reader has it open, so a DUT that never
/// started its pipe must fail the test, not hang it.
const APP_PIPE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Write one JSON command to the DUT's `--app-pipe` FIFO, then give the app
/// half a second to act on it. chip reads the FIFO in chunks and parses each
/// chunk as one JSON document, so commands must not be written back to back.
///
/// # Errors
///
/// If the harness did not launch the DUT with an app pipe
/// (`MATTER_INTEGRATION_APP_PIPE` unset), nothing reads the pipe within
/// 5 s (`APP_PIPE_WRITE_TIMEOUT`), or the write fails.
pub async fn send_app_pipe(cfg: &DutConfig, json: &str) -> Result<()> {
    let path = cfg
        .app_pipe
        .clone()
        .context("MATTER_INTEGRATION_APP_PIPE not set: this DUT has no app pipe")?;
    write_fifo_line(path, json, APP_PIPE_WRITE_TIMEOUT).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(())
}

/// Append `json` plus a newline to the FIFO at `path`, failing if the
/// blocking open/write does not finish within `timeout`.
async fn write_fifo_line(path: PathBuf, json: &str, timeout: Duration) -> Result<()> {
    let line = format!("{json}\n");
    let shown = path.display().to_string();
    let write = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let mut fifo = std::fs::OpenOptions::new().write(true).open(&path)?;
        fifo.write_all(line.as_bytes())
    });
    tokio::time::timeout(timeout, write)
        .await
        .with_context(|| format!("app pipe {shown}: no reader within {timeout:?}"))?
        .context("app pipe writer task panicked")?
        .with_context(|| format!("write app pipe {shown}"))
}

/// Every event currently readable on `path` (data reports only; a per-path
/// status is an error).
///
/// # Errors
///
/// A transport error, or an `EventStatusIB` for the path.
pub async fn read_event_items(node: &Node, path: EventPath) -> Result<Vec<EventReportItem>> {
    let mut items = Vec::new();
    for report in node
        .read_events(&[path], &[])
        .await
        .context("read_events")?
    {
        match report {
            EventReport::Data(item) => items.push(item),
            EventReport::Status { path, status } => {
                bail!("event path {path:?} answered status {status:#04x}")
            }
            other => bail!("unexpected event report {other:?}"),
        }
    }
    Ok(items)
}

/// Poll `(endpoint, cluster, event)` until at least one event is reported or
/// [`EVENT_TIMEOUT`] passes; returns every reported event.
///
/// # Errors
///
/// A read error, or no event before the timeout.
pub async fn wait_for_event(
    node: &Node,
    endpoint: u16,
    cluster: u32,
    event: u32,
) -> Result<Vec<EventReportItem>> {
    let deadline = Instant::now() + EVENT_TIMEOUT;
    loop {
        let items = read_event_items(node, EventPath::concrete(endpoint, cluster, event)).await?;
        if !items.is_empty() {
            return Ok(items);
        }
        if Instant::now() >= deadline {
            bail!("no event {cluster:#06x}/{event:#04x} on endpoint {endpoint} within {EVENT_TIMEOUT:?}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[tokio::test]
    async fn app_pipe_without_a_reader_fails_instead_of_hanging() {
        let dir = std::env::temp_dir().join(format!("matter-rust-pipe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("no-reader");
        let _ = std::fs::remove_file(&fifo);
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo failed");
        let err = write_fifo_line(fifo.clone(), "{}", Duration::from_millis(200))
            .await
            .expect_err("a FIFO nobody reads must time out");
        assert!(err.to_string().contains("no reader"), "{err:#}");
        // Unblock the leaked writer thread so the test process exits cleanly.
        let _reader = std::fs::File::open(&fifo).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
