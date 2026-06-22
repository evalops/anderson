//! Hash-chained audit log (Anderson §3.3).
//!
//! Each entry carries the SHA-256 of `(seq, ts, event, prev_hash)`, so a
//! single-entry edit breaks the chain and [`AuditLog::verify_chain`] rejects
//! it. A whole-chain rewrite by an attacker with file-write access still
//! wins — see the README threat model.
//!
//! The chain covers both monitor decisions *and* the session's terminal
//! state: an [`AuditEvent::Answer`] or [`AuditEvent::Halt`] is recorded at
//! the end of every session. A model that exfiltrates secrets in its final
//! answer text now leaves a hash-linked trace; previously the answer was
//! returned to the caller without ever touching the chain.
//!
//! When a [`JsonlFileSink`] is attached and a `write` or `fsync` fails, the
//! in-memory chain still extends so the session can keep running, but the
//! first error is captured in [`AuditLog::persist_status`] and is also
//! returned from [`AuditLog::verify_chain`]. The on-disk file is broken from
//! that point forward (subsequent entries chain to a `prev_hash` whose
//! source entry never landed on disk), so the operator must be told.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::monitor::Decision;
use crate::tools::ToolCall;

/// One event in the audit chain.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditEvent {
    /// A monitor decision on a model-proposed tool call.
    Tool { call: ToolCall, decision: Decision },
    /// The session ended normally with this answer.
    Answer { text: String },
    /// The session halted (spend exhausted, escalation, etc.).
    Halt { reason: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts_millis: u128,
    pub event: AuditEvent,
    /// Hex SHA-256 of the previous entry's `hash`. Empty for the first entry.
    pub prev_hash: String,
    /// Hex SHA-256 of `(seq, ts_millis, event, prev_hash)` in canonical JSON form.
    pub hash: String,
}

impl AuditEntry {
    /// Convenience accessor for the common "is this a tool decision?" check.
    pub fn as_tool_decision(&self) -> Option<(&ToolCall, &Decision)> {
        match &self.event {
            AuditEvent::Tool { call, decision } => Some((call, decision)),
            _ => None,
        }
    }
}

pub struct AuditLog {
    entries: Vec<AuditEntry>,
    next_seq: u64,
    last_hash: String,
    sink: Option<JsonlFileSink>,
    /// First persist failure observed on the attached sink, if any. The
    /// on-disk JSONL becomes unrecoverable from this point: subsequent
    /// in-memory entries chain to a `prev_hash` whose source entry never
    /// reached disk, so disk-side replay will fail at the next entry.
    persist_error: Option<String>,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_seq: 0,
            last_hash: String::new(),
            sink: None,
            persist_error: None,
        }
    }

    /// Construct a log that also writes every entry to a JSONL file.
    pub fn with_sink(sink: JsonlFileSink) -> Self {
        let mut l = Self::new();
        l.sink = Some(sink);
        l
    }

    pub fn record_decision(&mut self, call: &ToolCall, decision: &Decision) {
        self.record_event(AuditEvent::Tool {
            call: call.clone(),
            decision: decision.clone(),
        });
    }

    pub fn record_answer(&mut self, text: impl Into<String>) {
        self.record_event(AuditEvent::Answer { text: text.into() });
    }

    pub fn record_halt(&mut self, reason: impl Into<String>) {
        self.record_event(AuditEvent::Halt {
            reason: reason.into(),
        });
    }

    fn record_event(&mut self, event: AuditEvent) {
        let seq = self.next_seq;
        self.next_seq += 1;
        let ts_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let prev_hash = self.last_hash.clone();
        let hash = compute_entry_hash(seq, ts_millis, &event, &prev_hash);
        self.last_hash = hash.clone();
        let entry = AuditEntry {
            seq,
            ts_millis,
            event,
            prev_hash,
            hash,
        };
        if let Some(sink) = self.sink.as_mut() {
            if let Err(e) = sink.write(&entry) {
                eprintln!("audit: persist failed for entry {seq}: {e}");
                if self.persist_error.is_none() {
                    self.persist_error = Some(format!("audit persist failed at seq {seq}: {e}"));
                }
            }
        }
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// `Ok(())` if every entry was durably persisted (or if no sink is
    /// attached); `Err` with the first failure's message otherwise. The
    /// in-memory chain is unaffected by sink failures — callers who care
    /// about the on-disk record should check this before trusting it.
    pub fn persist_status(&self) -> Result<(), &str> {
        match &self.persist_error {
            None => Ok(()),
            Some(e) => Err(e.as_str()),
        }
    }

    /// Walk the chain and confirm every link is intact. Returns `Err` on the
    /// first entry whose `seq`, `prev_hash`, or `hash` does not line up, or
    /// the captured persist error if a sink write/fsync ever failed.
    pub fn verify_chain(&self) -> Result<(), String> {
        if let Some(e) = &self.persist_error {
            return Err(e.clone());
        }
        let mut prev = String::new();
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != i as u64 {
                return Err(format!("entry {i}: seq {} (expected {i})", e.seq));
            }
            if e.prev_hash != prev {
                return Err(format!("entry {i}: prev_hash does not chain"));
            }
            let expected = compute_entry_hash(e.seq, e.ts_millis, &e.event, &e.prev_hash);
            if e.hash != expected {
                return Err(format!("entry {i}: hash does not match content"));
            }
            prev = e.hash.clone();
        }
        Ok(())
    }

    /// Test hook: simulate a persist failure that has already happened.
    /// Not exposed in non-test builds.
    #[cfg(test)]
    pub(crate) fn force_persist_error_for_test(&mut self, msg: impl Into<String>) {
        if self.persist_error.is_none() {
            self.persist_error = Some(msg.into());
        }
    }

    /// One JSON object per line — the conventional shape for a log a separate
    /// process can tail and forward.
    pub fn to_jsonl(&self) -> String {
        self.entries
            .iter()
            .map(|e| serde_json::to_string(e).expect("AuditEntry is serialisable"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn compute_entry_hash(seq: u64, ts_millis: u128, event: &AuditEvent, prev_hash: &str) -> String {
    let canonical = serde_json::to_string(&(seq, ts_millis, event, prev_hash))
        .expect("canonical form serialisable");
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    hex_encode(&h.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

/// File-backed audit sink. Each `write` appends one JSON line and calls
/// `sync_data` so the entry is durable before the call returns.
pub struct JsonlFileSink {
    file: std::fs::File,
}

impl JsonlFileSink {
    pub fn new(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self { file })
    }
}

impl JsonlFileSink {
    fn write(&mut self, entry: &AuditEntry) -> std::io::Result<()> {
        use std::io::Write;
        let line = serde_json::to_string(entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        writeln!(self.file, "{line}")?;
        self.file.sync_data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::Action;

    fn sample_call() -> ToolCall {
        ToolCall {
            action: Action::FsRead {
                path: "/etc/hosts".into(),
            },
            justification_chunks: vec![0],
        }
    }

    #[test]
    fn chain_verifies_for_empty_and_growing_log() {
        let mut log = AuditLog::new();
        assert!(log.verify_chain().is_ok());
        log.record_decision(&sample_call(), &Decision::Allow);
        log.record_decision(&sample_call(), &Decision::Deny { reason: "x".into() });
        log.record_answer("done");
        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn chain_detects_tampered_entry() {
        let mut log = AuditLog::new();
        log.record_decision(&sample_call(), &Decision::Allow);
        log.record_decision(&sample_call(), &Decision::Allow);
        log.entries[0].event = AuditEvent::Tool {
            call: sample_call(),
            decision: Decision::Deny {
                reason: "fake".into(),
            },
        };
        assert!(log.verify_chain().is_err());
    }

    #[test]
    fn chain_detects_tampered_answer() {
        // A model that exfiltrates secrets in its final answer should not be
        // able to rewrite the answer text without invalidating the chain.
        let mut log = AuditLog::new();
        log.record_decision(&sample_call(), &Decision::Allow);
        log.record_answer("real answer");
        log.entries[1].event = AuditEvent::Answer {
            text: "innocuous answer".into(),
        };
        assert!(log.verify_chain().is_err());
    }

    #[test]
    fn persist_failure_surfaces_via_verify_chain() {
        // The in-memory chain still verifies internally, but a sink failure
        // means the on-disk record is no longer reliable. verify_chain must
        // surface that — silent partial-write failures used to break the
        // on-disk audit chain with no signal to the operator.
        let mut log = AuditLog::new();
        log.record_decision(&sample_call(), &Decision::Allow);
        assert!(log.verify_chain().is_ok());
        assert!(log.persist_status().is_ok());
        log.force_persist_error_for_test("simulated disk failure");
        assert!(log.persist_status().is_err());
        match log.verify_chain() {
            Err(e) => assert!(e.contains("simulated disk failure"), "got: {e}"),
            Ok(()) => panic!("expected verify_chain to surface persist error"),
        }
    }

    #[test]
    fn jsonl_sink_persists_each_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path).expect("open sink");
        let mut log = AuditLog::with_sink(sink);
        log.record_decision(&sample_call(), &Decision::Allow);
        log.record_decision(&sample_call(), &Decision::Deny { reason: "x".into() });
        log.record_halt("budget exhausted");
        let contents = std::fs::read_to_string(&path).expect("read sink");
        assert_eq!(contents.lines().count(), 3);
        for line in contents.lines() {
            let _: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
        }
    }
}
