# Session Control installation review — 18 November 2026

Reviewed PR #6 baseline: `0c7b03d9d8f72108f6ce65e7d923a2efdbb5762f`, branch `feature/cybernova-session-control`.

## Findings and fixes

1. **Rollback of an upgrade was incomplete.** The old installer moved the previous addon away but restored only the historic before-addon profile on a health failure. If the current profile already pointed to an addon, restoring a profile alone could leave the failed new code selected. A fresh private activation snapshot now preserves the exact previous code/profile pair and verifies its checksums before restoration; failed code and previous snapshots remain available.
2. **Failures outside the final health check lacked recovery.** A recovery handler now covers errors/signals after the first deployment mutation, including worker/cron failures. Prerequisites are checked before mutation. Tunnel recovery is bounded and never intentionally starts a second tunnel while one remains alive.
3. **Session dependencies were not preflighted.** Check mode now imports the wrapper and verifies handler APIs, the pinned MCP SDK capability, lab modules and storage access as `cybernova`. The lab interpreter and MCP interpreter stay separate; no production package installation occurs automatically.
4. **Partial evidence could be counted as a passed validation.** Session evidence verification now rejects explicitly incomplete captures, symlink run directories and oversized artifacts, in addition to checking original hashes and lengths.
5. **Installer lifecycle.** Explicit activation, rejection of extra arguments, an installation lock and closing that lock in background children prevent accidental activation or a permanently inherited installation lock.

## Verified

- Bash syntax check passed.
- All 28 original tests pass in isolated MCP SDK 2.3.0; six rollback tests and two evidence regressions bring the suite to **36 passed**.
- The initial run under local MCP SDK 1.x failed the v2 `DiscoverResult` protocol test as expected; installing the stated dependency in a separate virtual environment resolves it. This is not evidence of the currently installed Vast SDK version.
- The existing Vast bridge health read responds `ready` (bridge 0.5). Its monitored terminal is readable; its command execution still requires the original local single-use approval. No session-start tool is exposed in the current connected tool catalog.

## Not yet performed on Vast

Browser initialization reports that the originating browser context is unavailable, so the already-open Jupyter tab cannot be read or operated. No alternate channel was used to self-approve commands. Consequently **Vast `install.sh --check`, `--activate`, tunnel reconnection/tool rescan, `cybernova_session_start` and actual session evidence review have not been performed in this review**. The active Agent, tunnel profile and autodeploy branch were not changed.

After browser connectivity returns: obtain the reviewed feature-branch HEAD in a separate checkout; record current addon/profile/Agent hashes without printing secrets; run check; activate only after successful checks and required administrative approval; verify bridge recovery and tool registration; start the fixed local preset; poll status/report; inspect exact action evidence and hashes. Do not merge into the watched autodeploy branch as an installation shortcut.
