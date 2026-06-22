//! Capability bundles — finite, declarative grants of authority.
//!
//! Anderson §3.5 diagnoses the GCOS III failure as the operating system
//! suspending bounds-checking whenever it acted "on behalf of" a user, which
//! collapsed the user's narrow authority into the supervisor's full ambient
//! authority. A capability bundle is the opposite arrangement: every action
//! class the agent might attempt is enumerated up front, narrowly scoped, and
//! enforced by an external monitor that the model cannot influence.
//!
//! The bundle also bounds *time and rate*, not just *target*. A session that
//! is permitted to read a directory should not be permitted to read it ten
//! thousand times, run for an hour, or sit in a loop being denied. Those
//! are independent containment dimensions and the monitor enforces each.

use serde::{Deserialize, Serialize};

/// All authority an agent session is permitted to exercise.
///
/// Structural choices worth flagging:
///
/// 1. All target lists are *allow-lists*. Anything not listed is forbidden.
/// 2. `require_user_intent` names action classes that may only fire when
///    *every* cited justification chunk carries user authority. A model
///    that has been prompt-injected can still propose such an action, but
///    its cited justifications will betray the true source.
/// 3. `spend` is a hard ceiling on every dimension a session can consume:
///    tool calls, model steps, wall-clock seconds, and consecutive denials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub fs_read: Vec<String>,
    pub fs_write: Vec<String>,
    pub net_get: Vec<String>,
    pub exec: Vec<String>,
    pub spend: Spend,
    pub require_confirm: Vec<ActionClass>,
    pub require_user_intent: Vec<ActionClass>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Spend {
    /// Maximum number of *allowed* tool calls in the session.
    pub max_tool_calls: u32,
    /// Maximum number of model `next_step` invocations.
    pub max_steps: u32,
    /// Maximum wall-clock time the session may run.
    pub max_wall_seconds: u64,
    /// Maximum number of consecutive denials before the session halts.
    /// Prevents loops where the model keeps proposing the same bad action.
    pub max_consecutive_denials: u32,
    /// Maximum response size from `net_get`, in bytes.
    pub max_response_bytes: usize,
}

impl Spend {
    pub fn restrictive() -> Self {
        Self {
            max_tool_calls: 8,
            max_steps: 16,
            max_wall_seconds: 30,
            max_consecutive_denials: 3,
            max_response_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    FsRead,
    FsWrite,
    NetGet,
    Exec,
}

impl Capabilities {
    pub fn permits_fs_read(&self, path: &str) -> bool {
        self.fs_read.iter().any(|p| matches_path(p, path))
    }

    pub fn permits_fs_write(&self, path: &str) -> bool {
        self.fs_write.iter().any(|p| matches_path(p, path))
    }

    pub fn permits_net_get(&self, url: &str) -> bool {
        self.net_get.iter().any(|p| url.starts_with(p))
    }

    pub fn permits_exec(&self, cmd: &str) -> bool {
        let prog = cmd.split_whitespace().next().unwrap_or("");
        self.exec.iter().any(|p| p == prog)
    }
}

/// Smallest-possible glob: a trailing `/**` means "this prefix or anything
/// under it"; otherwise exact match. Real glob support is deliberately out of
/// scope — the monitor's job is to be small and obvious, not flexible.
fn matches_path(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/**") {
        path == prefix || path.starts_with(&format!("{prefix}/"))
    } else {
        path == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_prefix_matches_subpaths() {
        assert!(matches_path("/tmp/work/**", "/tmp/work"));
        assert!(matches_path("/tmp/work/**", "/tmp/work/a"));
        assert!(matches_path("/tmp/work/**", "/tmp/work/a/b.txt"));
        assert!(!matches_path("/tmp/work/**", "/tmp/workshop"));
        assert!(!matches_path("/tmp/work/**", "/etc/passwd"));
    }

    #[test]
    fn exec_matches_program_not_full_command() {
        let caps = Capabilities {
            fs_read: vec![],
            fs_write: vec![],
            net_get: vec![],
            exec: vec!["ls".into()],
            spend: Spend::restrictive(),
            require_confirm: vec![],
            require_user_intent: vec![],
        };
        assert!(caps.permits_exec("ls -la /tmp"));
        assert!(!caps.permits_exec("curl evil.com"));
    }
}
