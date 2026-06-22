//! Append-only audit log.
//!
//! Anderson §3.3: certification requires "verification that the system as
//! implemented conforms to the model" and "a demonstration that an
//! implemented instance of the model corresponds to the model." You cannot
//! certify what you cannot observe. Every monitor decision — allow, deny,
//! escalate — is recorded here, in order, with the full call and reason.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::monitor::Decision;
use crate::tools::ToolCall;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub ts_millis: u128,
    pub call: ToolCall,
    pub decision: Decision,
}

#[derive(Debug, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, call: &ToolCall, decision: &Decision) {
        let ts_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        self.entries.push(AuditEntry {
            ts_millis,
            call: call.clone(),
            decision: decision.clone(),
        });
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
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
