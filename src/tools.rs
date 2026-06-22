//! Tools and tool execution (Anderson §3.5: tools in their own protection
//! domain).
//!
//! [`SandboxedExecutor`] runs `exec` inside `sandbox-exec` (macOS) or `bwrap`
//! (Linux) with a cleared env, wall-clock timeout, and stdout byte cap; opens
//! both `fs_read` and `fs_write` by walking from the bundle-root directory fd
//! one component at a time with `openat(O_NOFOLLOW)`, so a symlink at any
//! depth fails open with `ELOOP` and `..` is rejected outright. Fails closed
//! where the platform sandbox is unavailable. The executor accepts only
//! [`AllowedAction`] — see [`crate::monitor`] for why.

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

// `AllowedAction` lives in [`crate::monitor`] inside a private submodule so
// that only `monitor.rs` can construct one. See its docs there.
pub use crate::monitor::AllowedAction;

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
        // No redirects. The capability check only inspects the URL the model
        // proposed; if reqwest were allowed to follow a 3xx, an allow-listed
        // origin could redirect the agent to anywhere (internal RFC1918
        // hosts, cloud-metadata endpoints, exfil targets) and the resulting
        // bytes would land in context tagged with the *original* URL's
        // provenance — spoofing the source. The model can re-issue `net_get`
        // with the redirect target and that fresh URL will go through
        // `permits_net_get` like any other call.
        let http = reqwest::Client::builder()
            .timeout(limits.http_timeout)
            .connect_timeout(limits.http_timeout)
            .redirect(reqwest::redirect::Policy::none())
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

    async fn do_fs_read(&self, raw_path: &str) -> Output {
        // Symmetric with do_fs_write:
        //
        //   1. Canonicalise the parent (path resolution only — no open against
        //      the target). Combined with the bundle-prefix check below this
        //      rejects out-of-bundle targets *before* any read-syscall fires.
        //   2. Walk from the bundle-root dir fd with `openat(O_NOFOLLOW)` per
        //      component, opening the leaf `O_RDONLY|O_NOFOLLOW`. A symlink
        //      at any depth fails `ELOOP`; `..` and other non-normal
        //      components are rejected outright.
        //
        // Error messages do *not* echo the resolved canonical path: that
        // would turn out-of-bundle denials into an existence/path oracle for
        // the surrounding filesystem.
        let path = PathBuf::from(raw_path);
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let canon_parent = match tokio::fs::canonicalize(&parent).await {
            Ok(p) => p,
            Err(_) => return err("fs_read denied: target outside the bundle".into()),
        };
        let basename = match path.file_name() {
            Some(n) => n.to_owned(),
            None => return err("fs_read: empty file name".into()),
        };
        let canon = canon_parent.join(&basename);
        let Some(bundle_root) = self
            .fs_read_allow_prefixes
            .iter()
            .find(|p| canon.starts_with(p))
            .cloned()
        else {
            return err("fs_read denied: target outside the bundle".into());
        };
        let relative = match canon.strip_prefix(&bundle_root) {
            Ok(r) => r.to_path_buf(),
            Err(_) => return err("fs_read: internal path-resolution error".into()),
        };
        let file = match open_read_walked(&bundle_root, &relative).await {
            Ok(f) => f,
            Err(_) => return err("fs_read denied: open failed".into()),
        };
        use tokio::io::AsyncReadExt;
        let cap = self.limits.fs_max_read_bytes as u64;
        let mut reader = tokio::io::BufReader::new(file).take(cap + 1);
        let mut buf = Vec::with_capacity(8 * 1024);
        if reader.read_to_end(&mut buf).await.is_err() {
            return err("fs_read: read failed".into());
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
                path: canon.display().to_string(),
            }),
        }
    }

    async fn do_fs_write(&self, raw_path: &str, content: &str) -> Output {
        // Resolve which bundle prefix the target falls under, then open every
        // component of the relative remainder with `O_NOFOLLOW`. A single
        // `O_NOFOLLOW` on the leaf is *not* enough — an attacker who can
        // write under any intermediate directory could swap it for a symlink
        // between the canonicalize-parent step and the open, redirecting the
        // write outside the bundle. Walking per-component refuses the swap.
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
        let Some(bundle_root) = self
            .fs_write_allow_prefixes
            .iter()
            .find(|p| canon.starts_with(p))
            .cloned()
        else {
            return err(format!(
                "fs_write denied: canonical path {} escapes the bundle",
                canon.display()
            ));
        };
        let relative = match canon.strip_prefix(&bundle_root) {
            Ok(r) => r.to_path_buf(),
            Err(_) => return err("fs_write: internal path-resolution error".into()),
        };
        if let Err(e) = open_write_walked(&bundle_root, &relative, content.as_bytes()).await {
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
        let body = String::from_utf8_lossy(&buf);
        Output {
            content: format!("HTTP {status}\n\n{body}"),
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

/// Walk from `bundle_root` to the directory holding the leaf, returning the
/// dir fd and the leaf's basename as a `CString`. Used by both
/// [`open_read_walked`] and [`open_write_walked`] so the symlink-refusal
/// invariant lives in one place.
///
/// The bundle root itself is opened `O_NOFOLLOW` (a swap of the root for a
/// symlink is refused). Every intermediate `openat` uses
/// `O_RDONLY|O_DIRECTORY|O_NOFOLLOW`. `..` and other non-normal components
/// are rejected outright.
fn walk_to_leaf_dir(
    bundle_root: &std::path::Path,
    relative: &std::path::Path,
) -> std::io::Result<(std::os::unix::io::OwnedFd, std::ffi::CString)> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

    let mut components: Vec<std::ffi::OsString> = Vec::new();
    for comp in relative.components() {
        match comp {
            std::path::Component::Normal(n) => components.push(n.to_os_string()),
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("disallowed path component {other:?}"),
                ));
            }
        }
    }
    if components.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "relative path resolves to bundle root",
        ));
    }

    let c_root = std::ffi::CString::new(bundle_root.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let root_fd = unsafe {
        libc::open(
            c_root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut current: OwnedFd = unsafe { OwnedFd::from_raw_fd(root_fd) };

    let last = components.len() - 1;
    for (i, comp) in components.iter().enumerate() {
        let c_name = std::ffi::CString::new(comp.as_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        if i == last {
            return Ok((current, c_name));
        }
        let next_fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        current = unsafe { OwnedFd::from_raw_fd(next_fd) };
    }
    unreachable!("walk_to_leaf_dir loop returns on the last component")
}

/// Open `bundle_root/relative` for reading via `openat(O_RDONLY|O_NOFOLLOW)`
/// from the bundle-root dir fd. Symlinks at any depth fail `ELOOP`.
async fn open_read_walked(
    bundle_root: &std::path::Path,
    relative: &std::path::Path,
) -> std::io::Result<tokio::fs::File> {
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

    let bundle_root = bundle_root.to_path_buf();
    let relative = relative.to_path_buf();
    tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
        let (dir_fd, leaf) = walk_to_leaf_dir(&bundle_root, &relative)?;
        let leaf_fd = unsafe {
            libc::openat(
                dir_fd.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if leaf_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(leaf_fd) }.into())
    })
    .await
    .map_err(std::io::Error::other)?
    .map(tokio::fs::File::from_std)
}

/// Open `bundle_root/relative` for writing via
/// `openat(O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW)` from the bundle-root dir fd,
/// then write `content` and `sync_data`. Symlinks at any depth fail `ELOOP`.
async fn open_write_walked(
    bundle_root: &std::path::Path,
    relative: &std::path::Path,
    content: &[u8],
) -> std::io::Result<()> {
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

    let bundle_root = bundle_root.to_path_buf();
    let relative = relative.to_path_buf();
    let content = content.to_vec();

    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let (dir_fd, leaf) = walk_to_leaf_dir(&bundle_root, &relative)?;
        let leaf_fd = unsafe {
            libc::openat(
                dir_fd.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if leaf_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut leaf_file: std::fs::File = unsafe { OwnedFd::from_raw_fd(leaf_fd) }.into();
        use std::io::Write;
        leaf_file.write_all(&content)?;
        leaf_file.sync_data()?;
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
        // `(deny default)` covers any path not explicitly allowed below —
        // including /Users, /private/var (except scratch dirs), and the
        // harness's own binary location. `mach-lookup` is allowed to a
        // filtered set of bootstrap services rather than blanket-allowed,
        // so an exec'd child cannot reach `tccd`, `securityd`, or the
        // keychain agent via Mach IPC. Network is denied because no
        // `(allow network*)` rule exists.
        let profile = r#"(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow signal (target self))
(allow ipc-posix-shm)
(allow sysctl-read)
; Bootstrap Mach services a Rust binary needs at startup. Deliberately
; narrow: tccd / securityd / keychain agent / pasteboard are NOT here.
(allow mach-lookup
    (global-name "com.apple.system.notification_center")
    (global-name "com.apple.system.opendirectoryd.libinfo")
    (global-name "com.apple.system.opendirectoryd.api"))
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
    async fn fs_read_rejects_symlink_at_leaf() {
        // A symlink at the requested path: `openat(O_NOFOLLOW)` on the leaf
        // walk fails with ELOOP before any data is read.
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
        assert!(out.content.starts_with("error:"), "got: {}", out.content);
        assert!(
            !out.content.contains("escape"),
            "symlink target leaked into output: {}",
            out.content
        );
        // The resolved out-of-bundle path must not be echoed back: that turns
        // denials into a path/existence oracle for the surrounding fs.
        assert!(
            !out.content.contains(outside.path().to_str().unwrap()),
            "denial leaked the resolved out-of-bundle path: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn fs_read_refuses_intermediate_symlink() {
        // A symlink at an *intermediate* directory between the bundle root and
        // the leaf used to let the `open` syscall hit the resolved out-of-
        // bundle target (with the post-open canonical check only refusing the
        // *bytes*). The bundle-root openat-walk refuses the symlink itself.
        let bundle = tempfile::tempdir().expect("bundle");
        let outside = tempfile::tempdir().expect("outside");
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, b"OUT-OF-BUNDLE SECRET").expect("write secret");
        let symdir = bundle.path().join("doorway");
        std::os::unix::fs::symlink(outside.path(), &symdir).expect("symlink");

        let executor = SandboxedExecutor::new(
            vec![bundle.path().display().to_string() + "/**"],
            vec![],
            ExecutorLimits::default(),
        );
        let target = symdir.join("secret.txt");
        let out = executor.do_fs_read(&target.display().to_string()).await;
        assert!(out.content.starts_with("error:"), "got: {}", out.content);
        assert!(
            !out.content.contains("OUT-OF-BUNDLE SECRET"),
            "intermediate-symlink escape leaked content: {}",
            out.content
        );
        assert!(
            !out.content.contains(outside.path().to_str().unwrap()),
            "denial leaked the resolved out-of-bundle path: {}",
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
