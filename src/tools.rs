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
//!   * opens files first and then verifies the canonical path of the *open
//!     file descriptor*, closing the TOCTOU window that canonicalize-then-open
//!     leaves open;
//!   * writes with `O_NOFOLLOW` so a symlink installed at the target leaf
//!     between policy check and write cannot redirect the data;
//!   * fails closed when its sandbox prerequisites are missing.
//!
//! The executor takes [`AllowedAction`] rather than [`Action`]. The only way
//! to obtain an `AllowedAction` is from [`crate::monitor::Monitor::decide`]
//! returning [`crate::monitor::Verdict::Allow`]. There is no public
//! constructor and no `Deserialize` derive. "Always invoked" therefore is a
//! compile-time property of this crate, not a code-review one.
//!
//! **macOS note.** `sandbox-exec` is Apple-deprecated since 10.7, but still
//! present and functional on every Mac. The profile we ship is intentionally
//! tighter than the original: reads are restricted to dynamic-linker
//! bootstrap paths (`/usr/lib`, `/System`, `/usr/bin`, etc.) instead of being
//! allowed everywhere; writes are confined to scratch directories. A
//! production harness should layer a microvm executor (Firecracker, gVisor)
//! on top.

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

/// An action that has passed every check in
/// [`crate::monitor::Monitor::decide`].
///
/// The executor accepts only `&AllowedAction`. This struct has no public
/// constructor, no `Clone` derive, and no `Deserialize` derive — so
/// downstream code cannot forge one, duplicate one, or deserialize one from
/// untrusted input. The only path from [`ToolCall`] to execution is through
/// the monitor.
///
/// This is the type-level embodiment of Anderson §3.2.2(b) "the reference
/// validation mechanism must always be invoked." A future contributor who
/// tries to add a fast path bypassing the monitor will get a compile error,
/// not a code-review nit.
#[derive(Debug)]
pub struct AllowedAction {
    action: Action,
}

impl AllowedAction {
    /// Construct an `AllowedAction`. Intentionally crate-private: only the
    /// monitor calls this, and only after every check passes.
    pub(crate) fn new(action: Action) -> Self {
        Self { action }
    }

    pub fn action(&self) -> &Action {
        &self.action
    }
}

/// The result of executing an allowed action. `provenance_hint`, when present,
/// tells the orchestrator how to tag the resulting chunk.
#[derive(Debug, Clone)]
pub struct Output {
    pub content: String,
    pub provenance_hint: Option<Provenance>,
}

#[async_trait]
pub trait ToolExecutor: Send {
    async fn execute(&mut self, allowed: &AllowedAction) -> Output;
}

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
    /// for its own post-open path re-check. Always pass the same paths you
    /// put in `Capabilities::fs_read` / `fs_write`.
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
    /// demo to reproduce "the agent fetched a hostile page" deterministically.
    pub fn with_web_override(mut self, url: impl Into<String>, body: impl Into<String>) -> Self {
        self.web_overrides.push((url.into(), body.into()));
        self
    }

    fn within(prefixes: &[PathBuf], path: &std::path::Path) -> bool {
        prefixes.iter().any(|p| path == p || path.starts_with(p))
    }

    async fn do_fs_read(&self, raw_path: &str) -> Output {
        // TOCTOU defence: open the file first, then resolve the path of the
        // open fd. A symlink swap *after* `open` cannot redirect the bytes we
        // already have a descriptor for. A symlink swap *before* `open` is
        // caught by the post-open check, because we verify the canonical path
        // of what we actually opened, not the path we were asked to open.
        use std::os::unix::io::AsRawFd;
        let file = match tokio::fs::File::open(raw_path).await {
            Ok(f) => f,
            Err(e) => return err(format!("open {raw_path}: {e}")),
        };
        let canonical = match canonical_path_of_fd(file.as_raw_fd()) {
            Ok(p) => p,
            Err(e) => return err(format!("resolve open fd path: {e}")),
        };
        if !Self::within(&self.fs_read_allow_prefixes, &canonical) {
            return err(format!(
                "fs_read denied: canonical path {} escapes the bundle",
                canonical.display()
            ));
        }
        use tokio::io::AsyncReadExt;
        let cap = self.limits.fs_max_read_bytes as u64;
        let mut reader = tokio::io::BufReader::new(file).take(cap + 1);
        let mut buf = Vec::with_capacity(8 * 1024);
        if let Err(e) = reader.read_to_end(&mut buf).await {
            return err(format!("read {}: {e}", canonical.display()));
        }
        let truncated = buf.len() > self.limits.fs_max_read_bytes;
        let take = buf.len().min(self.limits.fs_max_read_bytes);
        let mut s = String::from_utf8_lossy(&buf[..take]).into_owned();
        if truncated {
            s.push_str("\n... [truncated at byte cap]");
        }
        Output {
            content: s,
            provenance_hint: Some(Provenance::File {
                path: canonical.display().to_string(),
            }),
        }
    }

    async fn do_fs_write(&self, raw_path: &str, content: &str) -> Output {
        // Resolve the parent (must exist), join the basename, and re-check
        // that the result falls inside the write allow-list. The actual write
        // uses O_NOFOLLOW on the leaf to refuse symlinked targets.
        let path = PathBuf::from(raw_path);
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let canon_parent = match tokio::fs::canonicalize(&parent).await {
            Ok(p) => p,
            Err(e) => return err(format!("canonicalize parent {}: {e}", parent.display())),
        };
        let basename = match path.file_name() {
            Some(n) => n.to_owned(),
            None => return err("fs_write: empty file name".into()),
        };
        let canon = canon_parent.join(&basename);
        if !Self::within(&self.fs_write_allow_prefixes, &canon) {
            return err(format!(
                "fs_write denied: canonical path {} escapes the bundle",
                canon.display()
            ));
        }
        if let Err(e) = open_write_no_follow(&canon, content.as_bytes()).await {
            return err(format!("fs_write {}: {e}", canon.display()));
        }
        Output {
            content: format!("wrote {} bytes to {}", content.len(), canon.display()),
            provenance_hint: None,
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

/// Resolve the canonical filesystem path of an already-open file descriptor.
///
/// macOS: `fcntl(fd, F_GETPATH, buf)`.
/// Linux: `readlink("/proc/self/fd/N")`.
///
/// Both return the resolved path of the inode the descriptor points to. This
/// is the post-open verification that closes the canonicalize-then-open
/// TOCTOU window in [`SandboxedExecutor::do_fs_read`].
fn canonical_path_of_fd(fd: i32) -> std::io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        const PATH_MAX: usize = 1024;
        let mut buf = vec![0u8; PATH_MAX];
        let ret =
            unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr() as *mut libc::c_char) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let s = std::str::from_utf8(&buf[..nul]).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "non-utf8 fd path")
        })?;
        Ok(PathBuf::from(s))
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/self/fd/{fd}"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = fd;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "fd-path resolution unavailable on this platform",
        ))
    }
}

/// Write `content` to `path` with `O_NOFOLLOW` on the leaf. If the target is
/// a symlink the open fails with `ELOOP` and no data is written.
async fn open_write_no_follow(path: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = path.to_path_buf();
    let content = content.to_vec();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW);
        let mut f = opts.open(&path)?;
        use std::io::Write;
        f.write_all(&content)?;
        f.sync_data()?;
        Ok(())
    })
    .await
    .map_err(std::io::Error::other)?
}

#[async_trait]
impl ToolExecutor for SandboxedExecutor {
    async fn execute(&mut self, allowed: &AllowedAction) -> Output {
        match allowed.action() {
            Action::FsRead { path } => self.do_fs_read(path).await,
            Action::FsWrite { path, content } => self.do_fs_write(path, content).await,
            Action::NetGet { url } => self.do_net_get(url).await,
            Action::Exec { cmd } => self.do_exec(cmd).await,
        }
    }
}

/// Construct a platform-appropriate sandboxed [`tokio::process::Command`].
///
/// macOS: `sandbox-exec -p <profile>`. The profile is tighter than the
/// original draft: reads are restricted to dynamic-linker bootstrap paths
/// (`/usr/lib`, `/System`, `/usr/bin`, etc.) instead of `(allow file-read*)`
/// everywhere, so an exec'd child cannot exfiltrate `/etc/passwd` or the
/// user's home directory. Writes are confined to scratch dirs. No network.
///
/// Linux: `bwrap` with `--unshare-net --unshare-user --unshare-ipc
/// --unshare-pid --die-with-parent` and ro-bind mounts of the system dirs.
/// The bwrap binary is located by probing common paths and PATH; the previous
/// hardcoded `/usr/bin/bwrap` failed closed on distros that put it elsewhere.
///
/// Everything else: fail closed.
#[allow(clippy::needless_return)]
fn build_sandboxed_command(parts: &[&str]) -> Result<tokio::process::Command, String> {
    #[cfg(target_os = "macos")]
    {
        let profile = r#"(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow signal (target self))
(allow mach-lookup)
(allow ipc-posix-shm)
(allow sysctl-read)
; dyld + system libraries (required for any binary to load).
(allow file-read* (subpath "/usr/lib"))
(allow file-read* (subpath "/usr/share"))
(allow file-read* (subpath "/System"))
; Binaries (kernel must read these to exec them).
(allow file-read* (subpath "/usr/bin"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/sbin"))
; Minimal /etc entries libc reads at startup.
(allow file-read* (literal "/private/etc/services"))
(allow file-read* (literal "/private/etc/protocols"))
(allow file-read* (literal "/private/etc/localtime"))
(allow file-read* (literal "/private/etc/nsswitch.conf"))
; Writes only to scratch directories.
(allow file-write* (subpath "/tmp"))
(allow file-write* (subpath "/private/tmp"))
(allow file-write* (subpath "/private/var/tmp"))
"#;
        let mut c = tokio::process::Command::new("/usr/bin/sandbox-exec");
        c.arg("-p").arg(profile).arg("--");
        c.args(parts);
        return Ok(c);
    }
    #[cfg(target_os = "linux")]
    {
        let bwrap = find_bwrap()
            .ok_or_else(|| "bwrap not found on PATH or in usual locations".to_string())?;
        let mut c = tokio::process::Command::new(bwrap);
        // --ro-bind-try silently skips missing binds, accommodating distros
        // that don't have /lib64 or have merged /bin into /usr/bin.
        c.args([
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind-try",
            "/lib",
            "/lib",
            "--ro-bind-try",
            "/lib64",
            "/lib64",
            "--ro-bind-try",
            "/bin",
            "/bin",
            "--ro-bind-try",
            "/sbin",
            "/sbin",
            "--tmpfs",
            "/tmp",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--unshare-net",
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
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

#[cfg(target_os = "linux")]
fn find_bwrap() -> Option<PathBuf> {
    for p in [
        "/usr/bin/bwrap",
        "/bin/bwrap",
        "/usr/local/bin/bwrap",
        "/run/current-system/sw/bin/bwrap",
    ] {
        if std::path::Path::new(p).is_file() {
            return Some(PathBuf::from(p));
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let p = std::path::Path::new(dir).join("bwrap");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fs_read_canonical_check_rejects_symlink_escape() {
        // Create a directory whose canonical path is the "bundle". Inside it,
        // place a symlink pointing OUT of the bundle to a real file. The
        // bundle allow-list contains only the bundle's canonical path, so a
        // post-open check must reject the symlink's target.
        let bundle = tempfile::tempdir().expect("bundle tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        let outside_file = outside.path().join("secret");
        std::fs::write(&outside_file, b"escape").expect("write outside");
        let symlink = bundle.path().join("trapdoor");
        std::os::unix::fs::symlink(&outside_file, &symlink).expect("symlink");

        let executor = SandboxedExecutor::new(
            vec![bundle.path().display().to_string() + "/**"],
            vec![],
            ExecutorLimits::default(),
        );
        let out = executor.do_fs_read(&symlink.display().to_string()).await;
        assert!(
            out.content.contains("escapes the bundle"),
            "expected escape error, got: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn fs_read_allows_in_bundle_path() {
        let bundle = tempfile::tempdir().expect("bundle tempdir");
        let file = bundle.path().join("note.txt");
        std::fs::write(&file, b"hello").expect("write file");

        let executor = SandboxedExecutor::new(
            vec![bundle.path().display().to_string() + "/**"],
            vec![],
            ExecutorLimits::default(),
        );
        let out = executor.do_fs_read(&file.display().to_string()).await;
        assert!(out.content.contains("hello"), "got: {}", out.content);
        assert!(matches!(out.provenance_hint, Some(Provenance::File { .. })));
    }

    #[tokio::test]
    async fn fs_write_refuses_symlinked_leaf() {
        let bundle = tempfile::tempdir().expect("bundle tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        let target = outside.path().join("victim");
        std::fs::write(&target, b"original").expect("write victim");
        // Plant a symlink at the leaf the model will ask us to write.
        let leaf = bundle.path().join("output.txt");
        std::os::unix::fs::symlink(&target, &leaf).expect("symlink");

        let executor = SandboxedExecutor::new(
            vec![],
            vec![bundle.path().display().to_string() + "/**"],
            ExecutorLimits::default(),
        );
        let out = executor
            .do_fs_write(&leaf.display().to_string(), "hostile")
            .await;
        assert!(
            out.content.contains("error"),
            "expected error, got: {}",
            out.content
        );
        // The victim file outside the bundle must not have been overwritten.
        let after = std::fs::read(&target).expect("read victim");
        assert_eq!(after, b"original");
    }
}
