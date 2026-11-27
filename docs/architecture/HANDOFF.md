# Architecture handoff

> **Historical correction — 2026-11-25:** the statement below that the GitHub
> repository was empty is no longer current. Source code is present in
> `4oker12/cybernoc`; the 2026-11-16 status is retained as history, not as
> the current blocker.

## Current verified state — 2026-11-27

- GitHub repository: `4oker12/cybernoc`.
- Primary working branch: `feature/full-shell-computer-discovery`.
- Latest tested code commit: `716112c9750584d5bd67c60be766d18cc375aa8e`.
- Integration merge commit: `e587c80bd81c97928c30906312dcaa08093a59d9`; its parents are the previous full-shell branch head `ae3c262d1441793435f40e9ec3e20aea52d3660a` and `main` head `dac7c4b1771dfe963b3cfef5e61c03d385d8f3e7`. The `main` ref was not rewritten.
- The integrated tree retains the full-shell/computer-discovery and work-item collaboration changes, plus main's account mission, vault, protected owner-input, and related UI/runtime work.
- Research Platform Quality Gate [run 46006211723](https://github.com/4oker12/cybernoc/actions/runs/46006211723): **success**. 585 unit tests passed; source compilation, JavaScript parsing, repository secret/data guard, portable deployment, tool registry, and default-closed scope checks passed.
- Windows Readonly Integration Smoke [run 46006211781](https://github.com/4oker12/cybernoc/actions/runs/46006211781): **success** on an ephemeral GitHub Windows runner. CMD, Windows PowerShell, pwsh, read-only system/computer inventory, Chromium navigation, semantic page snapshot, text search, network metadata, public search/source opening, and shared DeepSeek tool dispatch passed. The only warning was that the test page had no suitable link for `browser_follow_link`; no hard failures remained.
- Browser snapshots now expose a page type and bounded content statistics in addition to headings, landmarks, controls, tables, and visible text. Browser page/table reading and targeted control discovery are available through separate bounded tools.
- Local Windows worktree, installed version, processes, ports, live model/provider calls, authenticated UI and local end-to-end behavior remain unverified. No local files, services, ports, or runtime data were changed in this integration.
 
### Next step

Perform the read-only Windows preflight for repository root, branch, worktree, origin, local/remote HEAD, ancestry, and owners of ports 18792, 18794, 18795 and 18796. If the worktree and ownership checks are safe, update the laptop with a fast-forward only. Then verify local startup, authentication, MCP, the selected model/provider, browser actions, and a real multi-agent task separately from GitHub CI.

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
