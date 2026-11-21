# Cybernova / CyberNoc — operational master context

**Updated:** 2026-11-21  
**Repository:** https://github.com/4oker12/cybernoc  
**Scope:** local Windows development and operation. This document is an operational handoff, not proof that the laptop is currently running the application.

## 1. Mission and responsibilities

Cybernova is a local-first engineering and cybersecurity research platform. The intended result is a system that can investigate architecture, form and test hypotheses, operate development tools, inspect browser/network behavior, write and test code, preserve evidence, and produce reproducible reports. Merely installing scanners or exposing shell commands is not the goal.

- **ChatGPT:** principal architect, coordinator and reviewer. Understand the outcome, inspect current implementation, plan changes, set acceptance criteria, review evidence and report the real result.
- **DeepSeek/Qwen:** local research and execution agent. Inspect files and system state, use authorized tools, implement assigned work, run tests and return logs/evidence.
- **Runtime/MCP:** execution layer. Provides actual capabilities; tool availability must be inspected rather than assumed.
- **User:** defines goals and authorizes actions that affect their machine, accounts, data or external targets.

An optional Account GPT session inside Cybernova is not automatically the same session as the user's main ChatGPT conversation. Do not assume shared history, permissions or tools.

## 2. Current repository and branch discipline

Repository: `4oker12/cybernoc`.

The active branch for the current full-shell work is:

`feature/full-shell-computer-discovery`

A separate branch, `feature/account-gpt-local-tools`, exists and must not be confused or merged into the current work without an explicit reason.

**Last observed local state from the user's terminal (2026-11-21):**
- branch: `feature/full-shell-computer-discovery`;
- local HEAD: `28e4a35`;
- worktree output showed the branch name and commit, with no visible dirty-file entries.

**Last observed GitHub state before the documentation commits in this update:**
- remote branch HEAD: `ab5d68259a908fe7cf3a8cc897a8bff7bc498c3b);
- local `28e4a35` was an ancestor of that remote HEAD;
- CI runs observed for the relevant branch were successful.

This repository has since received documentation-only commits in this task:
- `ba0fa8a` — update `AGENTS.md` for PowerShell 5.1 and project workflow;
- `625ff7e` — add `docs/CHATGPT_PROJECT_INSTRUCTIONS.md`.

Re-fetch the branch HEAD before any further update. The user's laptop has **not** been confirmed to have pulled these commits.

Never switch branches just to make the update easier. Before Git operations, inspect repository root, branch, status, origin, local and remote HEAD, ancestry and relevant port owners. Update only with a verified fast-forward. Do not use `reset --hard`, `git clean -fd`, force push or blind overwrite. Stop if the worktree is dirty, branch unexpected, origin wrong or history diverged.

The repository already has a root `AGENTS.md`. It is guidance for agents that actually load it; its presence alone does not inject it into every model prompt. Verify the local agent's instruction-loading path.

## 3. Local Windows installation — last known details

Expected repository path:

`%USERPROFILE%\Cybernova-DeepSeek`

Persistent data directory:

`%LOCALAPPDATA%\CyberNova\data`

Python virtual environment:

`%LOCALAPPDATA%\CyberNova\data\venv\Scripts\python.exe`

Native launcher:

`cybernova\research-platform\portable\native.py`

The user last reported these local items existed:
- project directory;
- data directory;
- Python venv;
- `runtime.env`;
- SQLite communications database;
- `web_access.txt`.

The last local diagnostic showed no listeners on the watched ports and the API at `127.0.0.1:18794/api/status` was unavailable. This indicates the services were not running at that moment; it does **not** indicate that source or user data should be deleted or reinstalled. Recheck before acting.

### Standard start command

From Windows PowerShell:

```powershell
Set-Location "$HOME\Cybernova-DeepSeek"; & "$env:LOCALAPPDATA\CyberNova\data\venv\Scripts\python.exe" "$HOME\Cybernova-DeepSeek\cybernova\research-platform\portable\native.py" --data-dir "$env:LOCALAPPDATA\CyberNova\data" run
```

This is the normal native launcher invocation. Do not start individual internal Python modules manually unless source inspection establishes a specific reason. Keep the launcher console open while the services are needed.

## 4. Components and known ports

The last observed native startup identified these components:

| Port | Component / purpose |
|---|---|
| 18792 | `console.portable_tool_gateway` |
| 18794 | `console.server` / API |
| 18795 | `console.tunnel_access` / local access gateway and Web UI entry point |
| 18796 | `console.communication_mcp` |
| 18883 | historical standalone Quick Send bridge |
| 18884 | previously tested alternate bridge port |
| 9588, 18732 | possible auxiliary ports; inspect current configuration |

Expected local Web UI URL:

`http://127.0.0.1:18795/`

Do not assume a component is listening just because it appears in configuration or a startup message. Check the actual listener, PID, process name, executable path and command line.

### Mandatory port/process preflight

Before any project operation that updates code, installs components, starts/stops/restarts services or opens a listener:
1. Inspect all relevant listening TCP ports.
2. Resolve each listener to its PID.
3. Inspect process name, executable path and command line.
4. Determine whether the process belongs to Cybernova.
5. If ownership is unclear, stop and investigate.

Never kill processes solely by port number. Do not bulk-kill Python, Chrome, AutoHotkey or arbitrary PIDs. Prefer Ctrl+C in the correct launcher console or an identified graceful shutdown.

## 5. PowerShell 5.1 command contract

The user uses both CMD and legacy Windows PowerShell 5.1. Identify the active shell from the prompt. Never mix CMD and PowerShell syntax.

PowerShell 5.1 has a confirmed multiline-paste issue: multiline text may be reversed or corrupted. Therefore:
- never provide multiline PowerShell blocks for direct paste;
- simple commands must be one physical line;
- multiple simple commands may be separated by semicolons;
- complex scripts containing `try/catch`, loops, functions or nested blocks must be delivered as one `powershell.exe -NoProfile -EncodedCommand BASE64` line;
- generate Base64 from the complete script using UTF-16LE, decode it back and validate syntax before sharing;
- never fabricate, truncate or use a placeholder Base64 value;
- explain what a command changes before asking the user to run it.

For CMD, use valid CMD syntax and `&&` for dependent steps. Prefer one complete block with 4–5 labelled stages. Stop at the first blocking error and preserve the exact output.

## 6. Safe updater

The repository contains:
- `tools/windows/Update_Cybernova_Safe.cmd`
- `tools/windows/Update_Cybernova_Safe.ps1`

The CMD wrapper launches the PowerShell 5.1 updater. The inspected updater performs repository/branch/remote checks, port-owner checks, clean-worktree validation, fetch and fast-forward-only update, and final revision verification. It does not stop or start services, install dependencies or alter firewall settings.

Before relying on it, inspect the current branch version of both files. The updater's existence in GitHub does not mean it has been downloaded or executed on the laptop.

## 7. Definition of a successful start

A successful start requires more than `CYBERNOVA_STARTED` messages. Verify each layer:

1. Expected processes exist.
2. Ports 18792, 18794, 18795 and 18796 listen on the expected local addresses.
3. PID, executable and command line match the intended Cybernova components.
4. The actual health/status endpoint, confirmed from the current source, responds.
5. Web UI opens at `http://127.0.0.1:18795/` and authentication works.
6. MCP `ListTools` succeeds and at least one safe tool call executes.
7. The configured model/provider returns a real response and tool calling works.
8. Browser integration is tested separately when it is part of the task.

HTTP 200, MCP ListTools, model response and end-to-end tool execution are separate checks. Report each independently.

## 8. Chrome extension / Quick Send

Known extension package previously discussed:

`C:\Users\Andrei\Downloads\Cybernova_QuickSend_v3_0_5\Cybernova_QuickSend_v3_0_5\extension`

An older Background/NumpadEnter v2.x package also exists in Downloads. Do not mix package versions or assume the old bridge is part of the current extension.

Previously observed error:

`clipboard_read_denied: NotAllowedError`

It occurred in the extension service worker during clipboard access. To validate a fix, inspect the loaded unpacked extension path, manifest, host permissions, service worker console, offscreen document, content script, page origin and actual DOM send flow. Do not claim it works because the extension is merely enabled in Chrome.

Desired user workflow: copy terminal output, focus the ChatGPT message field, right-click once, insert clipboard text and send. Any implementation must preserve normal right-click behavior outside the target message field and must not read the clipboard in the background without a user gesture.

## 9. Local-only deployment boundary

Current operational target is the user's Windows laptop. Do not rely on Vast.ai, remote Vast tunnels or old hosted instances. Historical source names such as `tunnel_access` do not prove that a Vast server is involved.

Keep source code separate from runtime data. Never commit:
- API keys, tokens, passwords, cookies or browser sessions;
- `.env` or `runtime.env`;
- SQLite databases or subscriber data;
- HAR/PCAP with sensitive contents;
- screenshots or logs containing secrets;
- virtual environments or model weights.

The local `web_access.txt` contains access credentials. Do not paste its contents into chat, Git or shared logs.

## 10. Development and security workflow

For every code task:
1. Restate the requested outcome and acceptance criteria briefly.
2. Inspect the current implementation and relevant tests.
3. Identify the smallest responsible layer to change.
4. Check branch, worktree, dependencies and port/process impact.
5. Make a minimal reversible change.
6. Run syntax checks and focused unit tests.
7. Run integration tests and a real component-level smoke test.
8. Inspect the diff and scan for secrets.
9. Commit to the intended branch only after checks.
10. Report changed files, commit, tests, limitations and rollback path.

Cybersecurity research must stay within explicit authorization and scope. The model may reason about adversarial techniques, but execution must pass the policy/scope controls and must not silently target third parties.

## 11. Architecture priorities

The following are priorities, not claims that they are already implemented:

- reliable supervisor with readiness, health checks, graceful shutdown and recovery;
- single source of truth for services, ports, PIDs and process ownership;
- verified loading of `AGENTS.md` and trusted system instructions into every agent entry point;
- consistent tool registry and permission model for ChatGPT and local agents;
- isolated execution runtime for powerful shell and filesystem operations;
- browser contexts isolated by task, with clear permissions and traceable actions;
- structured logs and end-to-end `run_id` / `task_id` correlation;
- complete backup/restore of configuration, database and runtime state;
- dependency lockfiles, SBOM and secret/dependency scanning;
- versioned skills with practical competency tests;
- end-to-end tests for installation, update, startup, extension and recovery.

## 12. ChatGPT Project settings are a separate layer

The file `docs/CHATGPT_PROJECT_INSTRUCTIONS.md` contains the concise text intended for the ChatGPT Project's **Project Instructions** field. A GitHub commit does not modify that ChatGPT setting. Paste the file contents into the CyberNoc Project settings manually, then keep it synchronized with `AGENTS.md`.

The detailed repository rules are in `AGENTS.md`. The historical architecture notes under `docs/architecture/` should be read with their dates and stated scope; do not treat a dated statement about an earlier empty repository or a target-only design as the current runtime status.
