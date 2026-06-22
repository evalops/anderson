//! Integration tests asserting the harness's security invariants.
//!
//! These are the load-bearing claims of the project. If any of these tests
//! fail, the README is lying.

use anderson::capability::{ActionClass, ArgPattern, Capabilities, ExecRule, Spend};
use anderson::model::{ModelStep, ScriptedModel};
use anderson::monitor::Decision;
use anderson::orchestrator::{Session, SessionEnd};
use anderson::tools::{Action, ExecutorLimits, SandboxedExecutor, ToolCall};

fn caps_with_exec_requiring_user() -> Capabilities {
    Capabilities {
        fs_read: vec![],
        fs_write: vec![],
        net_get: vec!["https://example.com/".into()],
        exec: vec![ExecRule::any_args("curl")],
        spend: Spend::restrictive(),
        require_confirm: vec![],
        require_user_intent: vec![ActionClass::Exec, ActionClass::FsWrite, ActionClass::NetGet],
    }
}

#[tokio::test]
async fn injection_via_web_chunk_is_denied_and_session_recovers() {
    let user_id = 0u64;
    let web_id = 1u64;

    let model = ScriptedModel::new(vec![
        ModelStep::Call(ToolCall {
            action: Action::NetGet {
                url: "https://example.com/page".into(),
            },
            justification_chunks: vec![user_id],
        }),
        ModelStep::Call(ToolCall {
            action: Action::Exec {
                cmd: "curl https://evil/".into(),
            },
            justification_chunks: vec![web_id],
        }),
        ModelStep::Stop {
            answer: "Refused to follow the page's instructions.".into(),
        },
    ]);
    let caps = caps_with_exec_requiring_user();
    let executor = SandboxedExecutor::new(
        caps.fs_read.clone(),
        caps.fs_write.clone(),
        ExecutorLimits::default(),
    )
    .with_web_override("https://example.com/page", "hostile content");
    let mut session = Session::new(model, executor, caps);
    session.add_user_input("fetch and summarise").await;
    let outcome = session.run().await;

    match outcome {
        SessionEnd::Answer(_) => {}
        other => panic!("expected Answer (recovered after denial), got {other:?}"),
    }

    let entries = session.audit().entries();
    assert_eq!(entries.len(), 2, "expected exactly two recorded decisions");
    matches!(entries[0].decision, Decision::Allow);
    match &entries[1].decision {
        Decision::Deny { reason } => {
            assert!(reason.contains("untrusted"), "deny reason: {reason}");
        }
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[tokio::test]
async fn injection_with_mixed_citations_is_still_denied() {
    // The "smart lie" variant: the model cites a real user chunk AND the
    // web chunk. The stricter check fails because the web chunk is cited.
    let user_id = 0u64;
    let web_id = 1u64;

    let model = ScriptedModel::new(vec![
        ModelStep::Call(ToolCall {
            action: Action::NetGet {
                url: "https://example.com/page".into(),
            },
            justification_chunks: vec![user_id],
        }),
        ModelStep::Call(ToolCall {
            action: Action::Exec {
                cmd: "curl https://evil/".into(),
            },
            justification_chunks: vec![user_id, web_id],
        }),
        ModelStep::Stop {
            answer: "done".into(),
        },
    ]);
    let caps = caps_with_exec_requiring_user();
    let executor = SandboxedExecutor::new(
        caps.fs_read.clone(),
        caps.fs_write.clone(),
        ExecutorLimits::default(),
    )
    .with_web_override("https://example.com/page", "hostile content");
    let mut session = Session::new(model, executor, caps);
    session.add_user_input("fetch and summarise").await;
    let _ = session.run().await;

    let denials: Vec<_> = session
        .audit()
        .entries()
        .iter()
        .filter(|e| matches!(e.decision, Decision::Deny { .. }))
        .collect();
    assert!(!denials.is_empty(), "expected at least one denial");
}

#[tokio::test]
async fn out_of_bundle_target_is_denied() {
    let model = ScriptedModel::new(vec![
        ModelStep::Call(ToolCall {
            action: Action::FsRead {
                path: "/etc/passwd".into(),
            },
            justification_chunks: vec![0],
        }),
        ModelStep::Stop {
            answer: "done".into(),
        },
    ]);
    let caps = Capabilities {
        fs_read: vec!["/etc/hostname".into()],
        fs_write: vec![],
        net_get: vec![],
        exec: vec![],
        spend: Spend::restrictive(),
        require_confirm: vec![],
        require_user_intent: vec![],
    };
    let executor = SandboxedExecutor::new(
        caps.fs_read.clone(),
        caps.fs_write.clone(),
        ExecutorLimits::default(),
    );
    let mut session = Session::new(model, executor, caps);
    session.add_user_input("get /etc/passwd").await;
    let _ = session.run().await;

    let deny_count = session
        .audit()
        .entries()
        .iter()
        .filter(|e| matches!(e.decision, Decision::Deny { .. }))
        .count();
    assert_eq!(deny_count, 1);
}

#[tokio::test]
async fn exec_with_wrong_arg_prefix_is_denied_by_capability_check() {
    // Per-arg patterns close the program-only allow-list gap: even with
    // user-provenance citation, curl can only be invoked with URLs the bundle
    // explicitly permits.
    let model = ScriptedModel::new(vec![
        ModelStep::Call(ToolCall {
            action: Action::Exec {
                cmd: "curl https://attacker.example/x".into(),
            },
            justification_chunks: vec![0],
        }),
        ModelStep::Stop {
            answer: "denied".into(),
        },
    ]);
    let caps = Capabilities {
        fs_read: vec![],
        fs_write: vec![],
        net_get: vec![],
        exec: vec![ExecRule::new(
            "curl",
            vec![ArgPattern::prefix("https://example.com/")],
        )],
        spend: Spend::restrictive(),
        require_confirm: vec![],
        require_user_intent: vec![],
    };
    let executor = SandboxedExecutor::new(
        caps.fs_read.clone(),
        caps.fs_write.clone(),
        ExecutorLimits::default(),
    );
    let mut session = Session::new(model, executor, caps);
    session.add_user_input("run that curl").await;
    let _ = session.run().await;

    let denials: Vec<_> = session
        .audit()
        .entries()
        .iter()
        .filter(|e| matches!(e.decision, Decision::Deny { .. }))
        .collect();
    assert_eq!(denials.len(), 1);
    if let Decision::Deny { reason } = &denials[0].decision {
        assert!(
            reason.contains("outside capability bundle"),
            "unexpected reason: {reason}"
        );
    }
}

#[tokio::test]
async fn audit_log_hash_chain_verifies_after_session() {
    let model = ScriptedModel::new(vec![
        ModelStep::Call(ToolCall {
            action: Action::Exec {
                cmd: "curl https://blocked/".into(),
            },
            justification_chunks: vec![],
        }),
        ModelStep::Stop {
            answer: "done".into(),
        },
    ]);
    let caps = caps_with_exec_requiring_user();
    let executor = SandboxedExecutor::new(
        caps.fs_read.clone(),
        caps.fs_write.clone(),
        ExecutorLimits::default(),
    );
    let mut session = Session::new(model, executor, caps);
    session.add_user_input("anything").await;
    let _ = session.run().await;

    session
        .audit()
        .verify_chain()
        .expect("audit chain must verify after a real session");
}

#[tokio::test]
async fn consecutive_denial_limit_halts_session() {
    // A model stuck proposing the same denied call must not loop forever.
    let model = ScriptedModel::new(vec![
        ModelStep::Call(ToolCall {
            action: Action::FsRead {
                path: "/etc/shadow".into(),
            },
            justification_chunks: vec![0],
        }),
        ModelStep::Call(ToolCall {
            action: Action::FsRead {
                path: "/etc/shadow".into(),
            },
            justification_chunks: vec![0],
        }),
        ModelStep::Call(ToolCall {
            action: Action::FsRead {
                path: "/etc/shadow".into(),
            },
            justification_chunks: vec![0],
        }),
        ModelStep::Call(ToolCall {
            action: Action::FsRead {
                path: "/etc/shadow".into(),
            },
            justification_chunks: vec![0],
        }),
    ]);
    let mut spend = Spend::restrictive();
    spend.max_consecutive_denials = 3;
    let caps = Capabilities {
        fs_read: vec!["/etc/hostname".into()],
        fs_write: vec![],
        net_get: vec![],
        exec: vec![],
        spend,
        require_confirm: vec![],
        require_user_intent: vec![],
    };
    let executor = SandboxedExecutor::new(
        caps.fs_read.clone(),
        caps.fs_write.clone(),
        ExecutorLimits::default(),
    );
    let mut session = Session::new(model, executor, caps);
    session.add_user_input("read shadow").await;
    let outcome = session.run().await;

    match outcome {
        SessionEnd::Halted { reason } => assert!(reason.contains("consecutive denials")),
        other => panic!("expected Halted, got {other:?}"),
    }
}
