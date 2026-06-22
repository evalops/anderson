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
//!
//! Exec rules are tighter than the rest. A program-only allow-list (the
//! original shape) lets `curl` cover both `curl https://allowlisted/` and
//! `curl https://attacker.example/`. [`ExecRule`] requires the operator to
//! name a program *and* declare per-argument patterns; the monitor matches
//! the model's command position by position against those patterns.

use serde::{Deserialize, Serialize};

/// All authority an agent session is permitted to exercise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub fs_read: Vec<String>,
    pub fs_write: Vec<String>,
    pub net_get: Vec<String>,
    pub exec: Vec<ExecRule>,
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

/// One entry in the `exec` allow-list.
///
/// The model's command is split on whitespace. The first token must equal
/// `program`; each subsequent token is matched against the corresponding
/// pattern in `args` at the same position. If the model supplies more or
/// fewer args than there are patterns, the rule does not match — unless the
/// last pattern is [`ArgPattern::AnyRest`], which absorbs zero or more
/// trailing arguments.
///
/// The original allow-list was program-only, which meant any bundle that
/// permitted `curl` permitted *every* curl invocation. With per-arg patterns,
/// a bundle can say "only curl URLs under https://example.com/" and have the
/// monitor enforce it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRule {
    pub program: String,
    pub args: Vec<ArgPattern>,
}

impl ExecRule {
    pub fn new(program: impl Into<String>, args: Vec<ArgPattern>) -> Self {
        Self {
            program: program.into(),
            args,
        }
    }

    /// Permit `program` invoked with no arguments.
    pub fn no_args(program: impl Into<String>) -> Self {
        Self::new(program, Vec::new())
    }

    /// Permit `program` with any number of arbitrary arguments. Convenient
    /// for tests; production policy should pin every position.
    pub fn any_args(program: impl Into<String>) -> Self {
        Self::new(program, vec![ArgPattern::AnyRest])
    }

    fn matches_command(&self, cmd: &str) -> bool {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let Some((prog, rest)) = parts.split_first() else {
            return false;
        };
        if *prog != self.program {
            return false;
        }
        // Trailing AnyRest absorbs zero or more remaining args.
        if matches!(self.args.last(), Some(ArgPattern::AnyRest)) {
            let head = &self.args[..self.args.len() - 1];
            if rest.len() < head.len() {
                return false;
            }
            return head.iter().zip(rest.iter()).all(|(p, a)| p.matches(a));
        }
        rest.len() == self.args.len()
            && self.args.iter().zip(rest.iter()).all(|(p, a)| p.matches(a))
    }
}

/// Per-position pattern for an exec argument.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArgPattern {
    /// Exactly this string.
    Literal { value: String },
    /// Any token starting with this prefix.
    Prefix { value: String },
    /// Any single token at this position.
    Any,
    /// Zero or more tokens. Valid only as the final pattern in [`ExecRule::args`].
    AnyRest,
}

impl ArgPattern {
    pub fn literal(s: impl Into<String>) -> Self {
        Self::Literal { value: s.into() }
    }
    pub fn prefix(s: impl Into<String>) -> Self {
        Self::Prefix { value: s.into() }
    }

    fn matches(&self, arg: &str) -> bool {
        match self {
            ArgPattern::Literal { value } => value == arg,
            ArgPattern::Prefix { value } => arg.starts_with(value),
            ArgPattern::Any | ArgPattern::AnyRest => true,
        }
    }
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
        self.exec.iter().any(|r| r.matches_command(cmd))
    }
}

/// Smallest-possible glob: a trailing `/**` means "this prefix or anything
/// under it"; otherwise exact match.
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
    fn exec_rule_program_name_must_match() {
        let rule = ExecRule::no_args("ls");
        assert!(rule.matches_command("ls"));
        assert!(!rule.matches_command("cat"));
        assert!(!rule.matches_command(""));
    }

    #[test]
    fn exec_rule_no_args_rejects_extra_args() {
        let rule = ExecRule::no_args("ls");
        assert!(!rule.matches_command("ls -la"));
    }

    #[test]
    fn exec_rule_arg_prefix_enforced_per_position() {
        let rule = ExecRule::new("curl", vec![ArgPattern::prefix("https://example.com/")]);
        assert!(rule.matches_command("curl https://example.com/page"));
        assert!(!rule.matches_command("curl https://attacker.example/x"));
        assert!(!rule.matches_command("curl https://example.com/page extra"));
        assert!(!rule.matches_command("curl"));
    }

    #[test]
    fn exec_rule_literal_arg_must_match_exactly() {
        let rule = ExecRule::new("python", vec![ArgPattern::literal("--version")]);
        assert!(rule.matches_command("python --version"));
        assert!(!rule.matches_command("python --version-string"));
    }

    #[test]
    fn exec_rule_any_rest_absorbs_trailing_args() {
        let rule = ExecRule::new(
            "python",
            vec![ArgPattern::literal("-c"), ArgPattern::AnyRest],
        );
        assert!(rule.matches_command("python -c"));
        assert!(rule.matches_command("python -c 1+1"));
        assert!(rule.matches_command("python -c print(1) +2"));
        assert!(!rule.matches_command("python --version"));
        assert!(!rule.matches_command("python"));
    }

    #[test]
    fn capabilities_permits_exec_dispatches_to_rules() {
        let caps = Capabilities {
            fs_read: vec![],
            fs_write: vec![],
            net_get: vec![],
            exec: vec![
                ExecRule::any_args("ls"),
                ExecRule::new("curl", vec![ArgPattern::prefix("https://example.com/")]),
            ],
            spend: Spend::restrictive(),
            require_confirm: vec![],
            require_user_intent: vec![],
        };
        assert!(caps.permits_exec("ls -la /tmp"));
        assert!(caps.permits_exec("curl https://example.com/foo"));
        assert!(!caps.permits_exec("curl https://attacker.example/x"));
        assert!(!caps.permits_exec("rm -rf /"));
    }
}
