//! Anderson — an LLM-agent harness built on reference-monitor principles.
//!
//! See the project README for the principle → code mapping. In brief:
//!
//!   * [`monitor`] is the reference validation mechanism — small, deterministic,
//!     always invoked, with no model-influenceable configuration.
//!   * [`capability`] defines the finite, declarative grants of authority
//!     the monitor enforces.
//!   * [`provenance`] tags every byte of model context with its source, so
//!     the monitor can refuse to act on intent from untrusted sources.
//!   * [`tools`] separates *what* a tool does from *how* it runs, leaving room
//!     for subprocess isolation in production.
//!   * [`orchestrator`] is the session loop; its only security responsibility
//!     is to ensure the monitor is called before the executor.
//!   * [`audit`] is the append-only record of every decision.
//!   * [`model`] is the model interface; the POC supplies a scripted mock.

pub mod audit;
pub mod capability;
pub mod model;
pub mod monitor;
pub mod openai;
pub mod orchestrator;
pub mod provenance;
pub mod tools;
