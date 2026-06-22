//! Live OpenAI session. Requires `OPENAI_API_KEY`.
//!
//! Run with: `cargo run --example openai_chat -- "your prompt here"`
//!
//! The session is granted only `fs_read` on `/etc/hosts` — try asking the
//! model what's in that file, or what's in `/etc/passwd` (which it will be
//! refused) and see how it handles the denial.

use anderson::capability::{ActionClass, Capabilities, Spend};
use anderson::openai::OpenAiModel;
use anderson::orchestrator::{Session, SessionEnd};
use anderson::tools::{ExecutorLimits, SandboxedExecutor};

#[tokio::main]
async fn main() {
    let prompt: String = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    let prompt = if prompt.is_empty() {
        "Read /etc/hosts and tell me what it contains.".to_string()
    } else {
        prompt
    };

    if std::env::var("OPENAI_API_KEY").is_err() {
        eprintln!("OPENAI_API_KEY is not set. Refusing to call the API.");
        std::process::exit(2);
    }

    let model_name = std::env::var("ANDERSON_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string());

    let caps = Capabilities {
        fs_read: vec!["/etc/hosts".into()],
        fs_write: vec![],
        net_get: vec![],
        exec: vec![],
        spend: Spend::restrictive(),
        require_confirm: vec![],
        require_user_intent: vec![ActionClass::Exec, ActionClass::FsWrite, ActionClass::NetGet],
    };
    let executor = SandboxedExecutor::new(
        caps.fs_read.clone(),
        caps.fs_write.clone(),
        ExecutorLimits::default(),
    );
    let model = OpenAiModel::new(model_name);
    let mut session = Session::new(model, executor, caps);
    session.add_user_input(&prompt).await;

    match session.run().await {
        SessionEnd::Answer(a) => println!("\nANSWER:\n{a}"),
        SessionEnd::Halted { reason } => println!("\nHALTED:\n{reason}"),
    }

    println!("\nAUDIT LOG:");
    for entry in session.audit().entries() {
        println!("  {}", serde_json::to_string(entry).unwrap_or_default());
    }
}
