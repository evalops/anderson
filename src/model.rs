//! The model interface.
//!
//! A real integration plugs OpenAI, Anthropic, etc. behind this trait. The
//! POC ships both:
//!
//!   * [`ScriptedModel`] — deterministic playback of pre-canned steps, used by
//!     the injection demo and the integration test so the security claim is
//!     reproducible without an API key.
//!   * [`crate::openai::OpenAiModel`] — a real model wired in via
//!     `async-openai` using OpenAI's native tool-calling protocol.
//!
//! The trait deliberately includes notification hooks. Stateless models like
//! `ScriptedModel` ignore them; stateful models like `OpenAiModel` use them to
//! keep their internal conversation history in sync without re-deriving it
//! from the context list every turn.

use async_trait::async_trait;

use crate::provenance::Chunk;
use crate::tools::ToolCall;

#[derive(Debug, Clone)]
pub enum ModelStep {
    Call(ToolCall),
    Stop { answer: String },
}

#[async_trait]
pub trait Model: Send {
    /// Propose the next step given the current context.
    async fn next_step(&mut self, context: &[Chunk]) -> ModelStep;

    /// Notify the model that a chunk has been added to context. Default impl
    /// is a no-op; stateful models override to keep their own history fresh.
    async fn notify_chunk(&mut self, _chunk: &Chunk) {}

    /// Notify the model that its most recently proposed call was denied or
    /// escalated by the monitor. The model is expected to revise its plan on
    /// the next `next_step`.
    async fn notify_denial(&mut self, _call: &ToolCall, _reason: &str) {}
}

/// A model that follows a hard-coded script of steps.
pub struct ScriptedModel {
    steps: std::collections::VecDeque<ModelStep>,
}

impl ScriptedModel {
    pub fn new(steps: Vec<ModelStep>) -> Self {
        Self {
            steps: steps.into(),
        }
    }
}

#[async_trait]
impl Model for ScriptedModel {
    async fn next_step(&mut self, _context: &[Chunk]) -> ModelStep {
        self.steps.pop_front().unwrap_or(ModelStep::Stop {
            answer: "(script exhausted)".into(),
        })
    }
}
