# Cybernova Mentor Workbench

## Roles

- **ChatGPT** — senior engineer, reviewer and mentor. Uses the existing,
  explicitly connected Sign in with ChatGPT account. In collaborative mode
  it forms a testable task, evaluates DeepSeek's reports and issues a follow-up.
- **DeepSeek** — active researcher model; uses the existing MCP safety gateway,
  research scope, Google web research and scanner adapters.
- **Operator** — starts/stops a run, selects the authorized scope and approves
  any action outside the reviewed read-only tool policy.

This is not an LLM masquerading as a second agent: each turn is sent to the
corresponding model inference backend and persisted with its actual actor in
the communications SQLite database.

## Collaboration flow

Start from the **Совместно** tab. Select a ChatGPT model from the
actually-connected SIWC account, enter a goal and choose 1–3 research cycles.

A two-cycle run uses:

1. ChatGPT (initial hypotheses and first assignment)
2. DeepSeek (evidence and technical analysis)
3. ChatGPT (review, challenge and next assignment)
4. DeepSeek (retest or continuation)
5. ChatGPT (final report)

The browser invokes `/api/collab/step` one step at a time, displays each
completed response, and persists the sequence to the same private database as
the existing communication queue. This is *turn-by-turn*, not word-by-word
token streaming. Each model request can take time. The operator can stop the
run; an in-flight API call may finish, but its reply does not trigger new turns.

After browser refresh, the saved session can be reopened; resuming
requires a new explicit click. No unlimited self-triggering background loop,
invisible retries or unbounded ChatGPT API cost.

An unavailable model or rejected tool causes a visible blocked state.
DeepSeek cannot silently approve an active scanner: the existing policy and
individual approval requirements remain in force.

## Shared daily tools

Both modes can use the following restricted and actually implemented tools:

- `google_search`: external public technical search (best-effort Google HTML)
- `research_source_open`: protected public HTTPS page read
- `safe_terminal`: **fixed** read-only diagnostics only: `pwd`, `list`,
  `python --version`, `git status`, `git log`

The researcher receives these as ordinary MCP tool descriptors. ChatGPT uses
the same safe adapters through a bounded controller preflight when the user's
question clearly requests lookup, a source page or one terminal diagnostic.
The server attaches the *actual result* as untrusted context and returns a
tool receipt in the reply. It does not advertise general shell access or
pretend that ChatGPT directly invoked unrestricted MCP tool calls.

The **Инструменты** panel exposes these three operations in both modes.
No shell syntax, flags, generic commands, arbitrary file reads, write
operations or production scanner invocation are permitted via this shared
endpoint. The advanced developer tooling remains under the existing worktree,
scope and approval policy.

## Data boundaries

- The profile is separate for each model; common user context is shared only
  when the relevant owner-controlled checkbox is enabled.
- The collaboration goal, mentor instructions and evidence summaries are sent
  to the two selected cloud/local model providers. Do **not** include access
  tokens, customer records, raw proprietary logs or sensitive identifiers.
- Google queries are privacy-filtered before leaving the local system.
- External web pages and terminal results remain *untrusted data*, never
  instructions that can broaden scope.
- Records live beside the Cybernova communications database, not in Git.

## API (behind localhost or authenticated port 18795)

- POST `/api/collab/start` — creates bounded run.
- POST `/api/collab/step` — one real model inference response.
- POST `/api/collab/stop` — prevent subsequent steps.
- GET `/api/collab/runs` — persisted conversation index.
- GET `/api/collab/run?task_id=...` — persisted role-attributed timeline.
- POST `/api/tools/run` — strict allowlist for three safe shared tools.

The localhost port 18794 is a backend and bypasses the 18795 Basic Auth
gateway when accessed directly. Keep both bound to loopback.
