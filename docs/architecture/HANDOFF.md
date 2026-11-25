# Architecture handoff

> **Historical correction — 2026-11-25:** the statement below that the GitHub
> repository was empty is no longer current. Source code is present in
> `4oker12/cybernoc`; the 2026-11-16 status is retained as history, not as
> the current blocker.

## Current verified state — 2026-11-25

- GitHub repository: `4oker12/cybernoc`.
- Main working branch baseline: `feature/full-shell-computer-discovery`,
  HEAD `2ab19ba97387f9d04199645ed11a74a89232532f`.
- Current review branch: `agent/agent-cycle-routing-consistency`.
- Draft PR: [#38 — Align agent tool routing across providers](https://github.com/4oker12/cybernoc/pull/38).
- Review head: `0d76a157243aa01c74ca66a319b91705071cd1f8`.
- GitHub Actions Quality Gate: success; 476 unit tests passed, compile,
  JavaScript parsing, portable deployment validation, registry checks and
  default-closed scope checks passed.
- The PR changes shared tool guidance, DeepSeek JSON-fallback catalog/context,
  explicit catalog overflow handling and approval-client scope propagation.
- High-impact actions without direct user intent remain blocked. Existing tests
  intentionally reject unsolicited approval prompts for those actions.
- Local Windows worktree, service processes, ports, live Account GPT calls,
  live DeepSeek calls and local end-to-end behavior have not been verified.
- GitHub `main` is 107 commits ahead of the working feature branch. No merge,
  reset or branch switch was performed; the PR targets the instructed feature
  branch only.

### Next step

Review PR #38 and decide whether to merge it into
`feature/full-shell-computer-discovery`. After that, continue the provider/tool
catalog parity audit and perform the read-only Windows preflight before any
local update or service operation.

---

## Historical snapshot — 2026-11-16

Updated: 2026-11-16 (Europe/Kiev)

## Verified state

Phase A is complete. The private GitHub repository `4oker12/cybernoc` is accessible with push permission, but GitHub's contents API reports: **"This repository is empty."** Repository metadata also reports size 0. There are no repository files to inspect.

The previously discussed Vast installation at `/workspace/cybersec-doctor` is **not** evidence of what is currently in GitHub. No current-state code audit, working-component claim, migration mapping, or test result has been made in this architecture task.

## Blocker

Phase B (technical audit) requires the source snapshot and integration configuration described in [SOURCE_IMPORT.md](SOURCE_IMPORT.md). Do not infer implementation from the user's design brief or earlier chat.

## Next session

1. Verify the imported tree, branch, commit and secret scan.
2. Trace the real Qwen/Ollama tool-call path, executor policy, browser capture, evidence store and Open WebUI integration from code.
3. Run existing tests or minimal reproducible smoke checks; label unavailable runtime checks explicitly.
4. Produce the 14 requested architecture documents in `docs/architecture/`, with observed facts separated from target design.
5. Commit after each completed phase; publish a reviewable branch or PR. Do not commit cases, credentials, HAR, subscriber data or environment files.

## Status

- A — repository access: **complete**
- B — current-state audit: **blocked by absent source**
- C–F — design, taxonomy, review and migration: **pending source audit**

No measured Codex quota percentage is available; do not invent one.
