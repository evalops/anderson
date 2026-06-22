//! Benign session: agent reads /etc/hosts and reports its contents.
//! Run with: `cargo run --example benign`

use anderson::capability::{ActionClass, Capabilities, Spend};
use anderson::model::{ModelStep, ScriptedModel};
use anderson::orchestrator::{Session, SessionEnd};
use anderson::tools::{Action, ExecutorLimits, SandboxedExecutor, ToolCall};

#[tokio::main]
async fn main() {
    let model = ScriptedModel::new(vec![
        ModelStep::Call(ToolCall {
            action: Action::FsRead {
                path: "/etc/hosts".into(),
            },
            justification_chunks: vec![0],
        }),
        ModelStep::Stop {
            answer: "/etc/hosts has been read into context.".into(),
        },
    ]);

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

    let mut session = Session::new(model, executor, caps);
    session.add_user_input("What's in /etc/hosts?").await;
    let outcome = session.run().await;

    match outcome {
        SessionEnd::Answer(a) => println!("ANSWER: {a}"),
        SessionEnd::Halted { reason } => println!("HALTED: {reason}"),
    }
    println!("\nFinal context:");
    for c in session.context() {
        println!(
            "  [#{} {}] {}",
            c.id,
            c.provenance.label(),
            c.content.lines().next().unwrap_or("")
        );
    }
}
