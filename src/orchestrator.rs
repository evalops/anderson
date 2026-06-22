//! The orchestrator — the session loop that drives model → monitor → executor.
//!
//! This file is *not* the security kernel; it is the scaffolding that ensures
//! the kernel is invoked. Contracts it upholds:
//!
//!   * Every model-proposed action passes through [`Monitor::decide`] before
//!     the executor sees it (Anderson's "always invoked").
//!   * Every chunk added to context is tagged with provenance.
//!   * On denial, the model is told (`notify_denial` + a system chunk) and
//!     the loop continues, so the agent can recover by proposing a different
//!     action. The session only halts on a model `Stop`, exhaustion of any
//!     spend dimension, or an escalation that requires a human.
//!   * Wall-clock, step count, allowed tool calls, and consecutive denials
//!     are all independently bounded.

use std::time::{Duration, Instant};

use crate::audit::AuditLog;
use crate::capability::Capabilities;
use crate::model::{Model, ModelStep};
use crate::monitor::{Monitor, Verdict};
use crate::provenance::{Chunk, Provenance};
use crate::tools::ToolExecutor;

#[derive(Debug)]
pub enum SessionEnd {
    Answer(String),
    Halted { reason: String },
}

pub struct Session<M: Model, E: ToolExecutor> {
    model: M,
    executor: E,
    caps: Capabilities,
    audit: AuditLog,
    context: Vec<Chunk>,
    next_chunk_id: u64,
    next_call_id: u64,
    calls_made: u32,
}

impl<M: Model, E: ToolExecutor> Session<M, E> {
    pub fn new(model: M, executor: E, caps: Capabilities) -> Self {
        Self::with_audit(model, executor, caps, AuditLog::new())
    }

    pub fn with_audit(model: M, executor: E, caps: Capabilities, audit: AuditLog) -> Self {
        Self {
            model,
            executor,
            caps,
            audit,
            context: Vec::new(),
            next_chunk_id: 0,
            next_call_id: 0,
            calls_made: 0,
        }
    }

    pub async fn add_user_input(&mut self, content: impl Into<String>) -> u64 {
        self.push_chunk(Provenance::User, content.into()).await
    }

    pub async fn add_system_prompt(&mut self, content: impl Into<String>) -> u64 {
        self.push_chunk(Provenance::System, content.into()).await
    }

    pub fn context(&self) -> &[Chunk] {
        &self.context
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    pub async fn run(&mut self) -> SessionEnd {
        let started = Instant::now();
        let wall = Duration::from_secs(self.caps.spend.max_wall_seconds);
        let mut steps: u32 = 0;
        let mut consecutive_denials: u32 = 0;

        loop {
            if started.elapsed() > wall {
                return SessionEnd::Halted {
                    reason: format!(
                        "wall-clock budget exhausted ({}s)",
                        self.caps.spend.max_wall_seconds
                    ),
                };
            }
            if steps >= self.caps.spend.max_steps {
                return SessionEnd::Halted {
                    reason: format!(
                        "step budget exhausted ({} steps)",
                        self.caps.spend.max_steps
                    ),
                };
            }
            steps += 1;

            let step = self.model.next_step(&self.context).await;
            match step {
                ModelStep::Stop { answer } => return SessionEnd::Answer(answer),
                ModelStep::Call(call) => {
                    let verdict = {
                        let mut monitor =
                            Monitor::new(&self.caps, &mut self.audit, &mut self.calls_made);
                        monitor.decide(&call, &self.context)
                    };
                    match verdict {
                        Verdict::Allow(allowed) => {
                            consecutive_denials = 0;
                            let call_id = self.next_call_id;
                            self.next_call_id += 1;
                            let output = self.executor.execute(&allowed).await;
                            let provenance =
                                output.provenance_hint.unwrap_or_else(|| Provenance::Tool {
                                    name: format!("{:?}", call.action_class()),
                                    call_id,
                                });
                            self.push_chunk(provenance, output.content).await;
                        }
                        Verdict::Deny { reason } => {
                            consecutive_denials += 1;
                            self.model.notify_denial(&call, &reason).await;
                            self.push_chunk(
                                Provenance::System,
                                format!("[monitor denied last call: {reason}]"),
                            )
                            .await;
                            if consecutive_denials >= self.caps.spend.max_consecutive_denials {
                                return SessionEnd::Halted {
                                    reason: format!(
                                        "{} consecutive denials reached; last reason: {reason}",
                                        consecutive_denials
                                    ),
                                };
                            }
                        }
                        Verdict::Escalate { reason } => {
                            // POC halts on escalation. A real harness would
                            // pause for human input on the specific call.
                            return SessionEnd::Halted {
                                reason: format!("escalation required: {reason}"),
                            };
                        }
                    }
                }
            }
        }
    }

    async fn push_chunk(&mut self, provenance: Provenance, content: String) -> u64 {
        let id = self.next_chunk_id;
        self.next_chunk_id += 1;
        let chunk = Chunk {
            id,
            provenance,
            content,
        };
        self.model.notify_chunk(&chunk).await;
        self.context.push(chunk);
        id
    }
}
