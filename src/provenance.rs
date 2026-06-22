//! Provenance tags for every byte of context the model sees.
//!
//! Anderson §3.7 lists "positive identification (authentication) of all users
//! at all times" as a precondition the reference monitor depends on but does
//! not itself provide. For LLM agents the analogous question is not "which
//! human" but "which *source of intent* is asking" — the operator, a tool's
//! own output, a fetched webpage, or a file on disk. Without that distinction
//! the model cannot tell an instruction the user gave from an instruction a
//! hostile webpage inserted into its context, and the monitor cannot enforce
//! any rule that depends on the difference.

use serde::{Deserialize, Serialize};

/// The source of a piece of context shown to the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provenance {
    /// A direct instruction from the human operator running the session.
    User,
    /// The harness's own system prompt, set by the trusted operator.
    System,
    /// A notification emitted by the orchestrator or monitor (e.g. a denial
    /// reason). Informational only — *not* a source of intent. Citing one of
    /// these as justification for a high-impact action will be rejected,
    /// which is what closes the authority-laundering loop: a model that has
    /// just had an action denied cannot turn the denial message into the
    /// authority required to retry it.
    Monitor,
    /// Output returned by a tool the agent invoked.
    Tool { name: String, call_id: u64 },
    /// Content fetched from the network.
    Web { url: String },
    /// Content read from the filesystem.
    File { path: String },
}

impl Provenance {
    /// True iff this provenance is treated as carrying operator authority.
    ///
    /// Only `User` and `System` qualify. `Monitor` notifications, tool output,
    /// web content, and file content are all *untrusted as sources of intent*
    /// — they may inform the model's reasoning, but they cannot, on their own,
    /// authorize an action the operator did not request.
    pub fn carries_user_authority(&self) -> bool {
        matches!(self, Provenance::User | Provenance::System)
    }

    /// Short label used in audit log entries and human-readable output.
    pub fn label(&self) -> String {
        match self {
            Provenance::User => "USER".into(),
            Provenance::System => "SYSTEM".into(),
            Provenance::Monitor => "MONITOR".into(),
            Provenance::Tool { name, call_id } => format!("TOOL({name}#{call_id})"),
            Provenance::Web { url } => format!("WEB({url})"),
            Provenance::File { path } => format!("FILE({path})"),
        }
    }
}

/// A piece of context shown to the model, with its provenance attached.
///
/// `id` is the handle the model uses when it cites a chunk as justification
/// for a tool call (see [`crate::tools::ToolCall::justification_chunks`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    pub id: u64,
    pub provenance: Provenance,
    pub content: String,
}
