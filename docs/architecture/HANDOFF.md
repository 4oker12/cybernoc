# Architecture handoff

> **Historical correction — 2026-11-25:** the statement below that the GitHub
> repository was empty is no longer current. Source code is present in
> `4oker12/cybernoc`; the 2026-11-16 status is retained as history, not as
> the current blocker.

## Current verified state — 2026-11-27

- GitHub repository: `4oker12/cybernoc`.
- Primary working branch: `feature/full-shell-computer-discovery`.
- Latest tested code commit: `ab1f5ca6702cd83e8b957749b96d1c753f928284`.
- Integration merge commit: `e587c80bd81c97928c30906312dcaa08093a59d9`; its parents are the previous full-shell branch head `ae3c262d1441793435f40e9ec3e20aea52d3660a` and `main` head `dac7c4b1771dfe963b3cfef5e61c03d385d8f3e7`. The `main` ref was not rewritten.
- The integrated tree retains the full-shell/computer-discovery and work-item collaboration changes, plus main's account mission, vault, protected owner-input, and related UI/runtime work.
- Research Platform Quality Gate [run 46010900519](https://github.com/4oker12/cybernoc/actions/runs/46010900519): **success**. 585 unit tests passed; source compilation, JavaScript parsing, repository secret/data guard, portable deployment, tool registry and default-closed scope checks passed.
- Windows Readonly Integration Smoke [run 46010900593](https://github.com/4oker12/cybernoc/actions/runs/46010900593): **success** on an ephemeral Windows runner. CMD, Windows PowerShell, pwsh, read-only system/computer inventory, Chromium navigation, semantic snapshots, text search, exact-URL link following, tabs/history, public source opening and shared DeepSeek tool dispatch passed. Final summary: zero hard failures and zero warnings.
- Browser navigation supports exact visible link names and an exact safe-URL selector (`url:<URL>`) for cases where labels are ambiguous. Existing session isolation, private-host authorization, sensitive-field redaction and protected-submit controls remain in place.
- Search fallback pagination is explicitly **unverified** when Google returns a JavaScript shell and Bing HTML/RSS is used. The smoke test reports this as `UNVERIFIED`, not as a pass or a hard failure; it does not bypass CAPTCHA, consent or anti-bot challenges.
- A manual live-provider test was added at `cybernova/research-platform/tests/browser_agent_e2e.py`. It starts a loopback-only fixture page and asks the configured DeepSeek model to navigate links, read a long page/table, fill a harmless field, click a local test button and report the resulting state. It is compiled by CI but has **not** been run against the user's local provider/runtime.
- Related PRs #42 and #43 were not merged: their CI runs failed because `dialog_action` was present in browser tool definitions but absent from the GPT/MCP adapter schemas. PR #46 remains an audit-only conflicting snapshot and must not be merged.
- Last observed local Windows copy (2026-11-27 10:07): `C:\Users\Andrei\Cybernova-browser-agent-continuation`, branch `feature/full-shell-computer-discovery`, HEAD `cdca3210122eeabc45affcc51ea696bbe75df360`, clean worktree, origin `https://github.com/4oker12/cybernoc.git`. GitHub has since advanced to `ab1f5ca6702cd83e8b957749b96d1c753f928284`; the laptop has not been updated or rechecked in this session.
- No local files, services, ports, SQLite data, venv, secrets or runtime data were changed.

### Next step

Run a read-only local preflight for the recorded repository, branch, worktree, origin, remote HEAD and owners of ports 18792, 18794, 18795 and 18796. If the branch/worktree/origin and process ownership are safe, update with the repository's fast-forward-only updater. Then run `tests/browser_agent_e2e.py` against the local configured DeepSeek provider and verify the authenticated UI/MCP/model separately from GitHub CI.

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
