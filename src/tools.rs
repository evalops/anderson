//! Tools and tool execution.
//!
//! Anderson §3.5 argues that security-relevant code paths must run in their
//! own protection domain — the GCOS III failure was the supervisor running
//! in-process with the user's authority. The production analog for agents is:
//! each tool runs in its own sandbox so a compromise of one tool cannot read
//! the harness's memory or another tool's credentials.
//!
//! This module ships [`SandboxedExecutor`], which:
//!
//!   * runs `exec` actions inside the platform sandbox (`sandbox-exec` on
//!     macOS, `bwrap` on Linux), with a cleared environment, a wall-clock
//!     timeout, and a stdout byte cap;
//!   * fetches `net_get` via `reqwest` with a connect/read timeout and a hard
//!     byte cap on the response;
//!   * canonicalises file paths before opening them, then re-checks that the
//!     canonical path still falls inside the capability bundle (defence
//!     against TOCTOU via symlink replacement);
//!   * fails closed when its sandbox prerequisites are missing.
//!
//! It refuses to fall back to unsandboxed execution. A harness whose sandbox
//! fails open is a harness whose sandbox does not exist.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};

use crate::capability::ActionClass;
use crate::provenance::Provenance;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    FsRead { path: String },
    FsWrite { path: String, content: String },
    NetGet { url: String },
    Exec { cmd: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub action: Action,
    pub justification_chunks: Vec<u64>,
}

impl ToolCall {
    pub fn action_class(&self) -> ActionClass {
        match &self.action {
            Action::FsRead { .. } => ActionClass::FsRead,
            Action::FsWrite { .. } => ActionClass::FsWrite,
            Action::NetGet { .. } => ActionClass::NetGet,
            Action::Exec { .. } => ActionClass::Exec,
        }
    }
}

/// The result of executing an allowed action. `provenance_hint`, when present,
/// tells the orchestrator how to tag the resulting chunk — `FsRead` produces
/// `File` provenance, `NetGet` produces `Web`, and so on. This is what lets
/// the monitor distinguish "the user said run this command" from "a web page
/// said run this command" downstream.
#[derive(Debug, Clone)]
pub struct Output {
    pub content: String,
    pub provenance_hint: Option<Provenance>,
}

#[async_trait]
pub trait ToolExecutor: Send {
    async fn execute(&mut self, action: &Action) -> Output;
}

/// Configuration knobs for [`SandboxedExecutor`]. Bounded everything; no
/// "unlimited" mode.
#[derive(Debug, Clone, Copy)]
pub struct ExecutorLimits {
    pub exec_timeout: Duration,
    pub exec_stdout_max_bytes: usize,
    pub http_timeout: Duration,
    pub http_max_bytes: usize,
    pub fs_max_read_bytes: usize,
}

impl Default for ExecutorLimits {
    fn default() -> Self {
        Self {
            exec_timeout: Duration::from_secs(15),
            exec_stdout_max_bytes: 64 * 1024,
            http_timeout: Duration::from_secs(10),
            http_max_bytes: 256 * 1024,
            fs_max_read_bytes: 256 * 1024,
        }
    }
}

pub struct SandboxedExecutor {
    limits: ExecutorLimits,
    http: reqwest::Client,
    fs_read_allow_prefixes: Vec<PathBuf>,
    fs_write_allow_prefixes: Vec<PathBuf>,
    web_overrides: Vec<(String, String)>,
}

impl SandboxedExecutor {
    /// Build an executor that mirrors the capability bundle's FS allow-list
    /// for its own post-canonicalisation re-check. Always pass the same paths
    /// you put in `Capabilities::fs_read` / `fs_write`.
    ///
    /// Each allow-list prefix is canonicalised at construction time when
    /// possible, so that operator-friendly paths like `/etc/hosts` correctly
    /// match the canonical `/private/etc/hosts` on macOS. Prefixes that don't
    /// exist yet (typical for write targets) are kept as-is.
    pub fn new(fs_read: Vec<String>, fs_write: Vec<String>, limits: ExecutorLimits) -> Self {
        let http = reqwest::Client::builder()
            .timeout(limits.http_timeout)
            .connect_timeout(limits.http_timeout)
            .build()
            .expect("reqwest client");
        Self {
            limits,
            http,
            fs_read_allow_prefixes: canonical_prefixes(fs_read),
            fs_write_allow_prefixes: canonical_prefixes(fs_write),
            web_overrides: Vec::new(),
        }
    }

    /// Install a pre-canned response for a specific URL. Used by the injection
    /// demo to reproduce "the agent fetched a hostile page" deterministically
    /// without making a real network call.
    pub fn with_web_override(mut self, url: impl Into<String>, body: impl Into<String>) -> Self {
        self.web_overrides.push((url.into(), body.into()));
        self
    }

    fn within(prefixes: &[PathBuf], path: &std::path::Path) -> bool {
        prefixes.iter().any(|p| path == p || path.starts_with(p))
    }

    async fn do_fs_read(&self, raw_path: &str) -> Output {
        let canon = match tokio::fs::canonicalize(raw_path).await {
            Ok(p) => p,
            Err(e) => return err(format!("canonicalize {raw_path}: {e}")),
        };
        if !Self::within(&self.fs_read_allow_prefixes, &canon) {
            return err(format!(
                "fs_read denied: canonical path {} escapes the bundle",
                canon.display()
            ));
        }
        match tokio::fs::read(&canon).await {
            Ok(bytes) => {
                let truncated = bytes.len() > self.limits.fs_max_read_bytes;
                let mut s = String::from_utf8_lossy(
                    &bytes[..bytes.len().min(self.limits.fs_max_read_bytes)],
                )
                .into_owned();
                if truncated {
                    s.push_str(&format!("\n... [truncated, {} bytes total]", bytes.len()));
                }
                Output {
                    content: s,
                    provenance_hint: Some(Provenance::File {
                        path: canon.display().to_string(),
                    }),
                }
            }
            Err(e) => err(format!("fs_read {}: {e}", canon.display())),
        }
    }

    async fn do_fs_write(&self, raw_path: &str, content: &str) -> Output {
        // For write the parent must canonicalise; the file itself may not exist yet.
        let path = PathBuf::from(raw_path);
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let canon_parent = match tokio::fs::canonicalize(&parent).await {
            Ok(p) => p,
            Err(e) => return err(format!("canonicalize parent {}: {e}", parent.display())),
        };
        let canon = canon_parent.join(match path.file_name() {
            Some(n) => n,
            None => return err("fs_write: empty file name".into()),
        });
        if !Self::within(&self.fs_write_allow_prefixes, &canon) {
            return err(format!(
                "fs_write denied: canonical path {} escapes the bundle",
                canon.display()
            ));
        }
        match tokio::fs::write(&canon, content).await {
            Ok(()) => Output {
                content: format!("wrote {} bytes to {}", content.len(), canon.display()),
                provenance_hint: None,
            },
            Err(e) => err(format!("fs_write {}: {e}", canon.display())),
        }
    }

    async fn do_net_get(&self, url: &str) -> Output {
        if let Some((_, body)) = self.web_overrides.iter().find(|(u, _)| u == url) {
            return Output {
                content: body.clone(),
                provenance_hint: Some(Provenance::Web {
                    url: url.to_string(),
                }),
            };
        }
        let req = self.http.get(url).send();
        let resp = match tokio::time::timeout(self.limits.http_timeout, req).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return err(format!("net_get {url}: {e}")),
            Err(_) => return err(format!("net_get {url}: timed out")),
        };
        let status = resp.status();
        let mut stream = resp.bytes_stream();
        let mut buf = Vec::with_capacity(8 * 1024);
        let cap = self.limits.http_max_bytes;
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => return err(format!("net_get {url} stream: {e}")),
            };
            let remaining = cap.saturating_sub(buf.len());
            if remaining == 0 {
                buf.extend_from_slice(b"\n... [response truncated at byte cap]");
                break;
            }
            let take = chunk.len().min(remaining);
            buf.extend_from_slice(&chunk[..take]);
        }
        let mut body = String::from_utf8_lossy(&buf).into_owned();
        body.insert_str(0, &format!("HTTP {status}\n\n"));
        Output {
            content: body,
            provenance_hint: Some(Provenance::Web {
                url: url.to_string(),
            }),
        }
    }

    async fn do_exec(&self, raw_cmd: &str) -> Output {
        let parts: Vec<&str> = raw_cmd.split_whitespace().collect();
        if parts.is_empty() {
            return err("exec: empty command".into());
        }
        let sandboxed = match build_sandboxed_command(&parts) {
            Ok(c) => c,
            Err(e) => return err(format!("exec sandbox unavailable: {e}")),
        };
        let mut cmd = sandboxed;
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return err(format!("exec spawn: {e}")),
        };
        let waited = tokio::time::timeout(self.limits.exec_timeout, child.wait_with_output()).await;
        match waited {
            Ok(Ok(out)) => {
                let mut s = String::from_utf8_lossy(
                    &out.stdout[..out.stdout.len().min(self.limits.exec_stdout_max_bytes)],
                )
                .into_owned();
                if out.stdout.len() > self.limits.exec_stdout_max_bytes {
                    s.push_str(&format!(
                        "\n... [stdout truncated, {} bytes total]",
                        out.stdout.len()
                    ));
                }
                if !out.status.success() {
                    s.push_str(&format!("\n[exit status: {}]", out.status));
                }
                Output {
                    content: s,
                    provenance_hint: None,
                }
            }
            Ok(Err(e)) => err(format!("exec wait: {e}")),
            Err(_) => err("exec: timed out".into()),
        }
    }
}

fn err(content: String) -> Output {
    Output {
        content: format!("error: {content}"),
        provenance_hint: None,
    }
}

fn canonical_prefixes(raw: Vec<String>) -> Vec<PathBuf> {
    raw.into_iter()
        .map(|p| {
            let trimmed = p.trim_end_matches("/**").to_string();
            std::fs::canonicalize(&trimmed).unwrap_or_else(|_| PathBuf::from(trimmed))
        })
        .collect()
}

#[async_trait]
impl ToolExecutor for SandboxedExecutor {
    async fn execute(&mut self, action: &Action) -> Output {
        match action {
            Action::FsRead { path } => self.do_fs_read(path).await,
            Action::FsWrite { path, content } => self.do_fs_write(path, content).await,
            Action::NetGet { url } => self.do_net_get(url).await,
            Action::Exec { cmd } => self.do_exec(cmd).await,
        }
    }
}

/// Construct a platform-appropriate sandboxed [`tokio::process::Command`].
///
/// macOS: `sandbox-exec -p <profile>` (deprecated by Apple but still
/// functional and present on every Mac). Profile denies network, restricts
/// writes to /tmp and /private/tmp, allows reads of typical system paths so
/// dynamic linking works.
///
/// Linux: `bwrap` with `--unshare-net --unshare-user --die-with-parent` and a
/// minimal read-only bind mount of `/usr`, `/lib`, `/lib64`, plus a tmpfs at
/// `/tmp`.
///
/// Everything else: fail closed.
#[allow(clippy::needless_return)] // platform cfg-blocks make a uniform return style clearer
fn build_sandboxed_command(parts: &[&str]) -> Result<tokio::process::Command, String> {
    #[cfg(target_os = "macos")]
    {
        let profile = r#"(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow signal (target self))
(allow file-read*)
(allow sysctl-read)
(allow file-write* (subpath "/tmp") (subpath "/private/tmp") (subpath "/private/var/tmp"))
(allow mach-lookup)
(allow ipc-posix-shm)
"#;
        let mut c = tokio::process::Command::new("/usr/bin/sandbox-exec");
        c.arg("-p").arg(profile).arg("--");
        c.args(parts);
        return Ok(c);
    }
    #[cfg(target_os = "linux")]
    {
        if !std::path::Path::new("/usr/bin/bwrap").exists() {
            return Err("bwrap not found at /usr/bin/bwrap".into());
        }
        let mut c = tokio::process::Command::new("/usr/bin/bwrap");
        c.args([
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--ro-bind",
            "/etc/resolv.conf",
            "/etc/resolv.conf",
            "--tmpfs",
            "/tmp",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--unshare-net",
            "--unshare-user",
            "--die-with-parent",
            "--",
        ]);
        c.args(parts);
        return Ok(c);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = parts;
        Err("no sandbox implementation for this platform".into())
    }
}
