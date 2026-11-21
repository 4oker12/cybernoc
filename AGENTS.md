# AGENTS.md — Cybernova / CyberNoc agent operating contract

This file applies to the entire repository. All coding agents, local assistants,
ChatGPT coordinators, DeepSeek researchers and reviewers **that are given this
repository** must read this file before making changes or proposing operator commands.
Treat these as project operating rules, not as a substitute for runtime permissions
or the user's explicit approval. If the active environment cannot read this file,
report the limitation; do not claim compliance.

## 1. Mission and roles

- Cybernova is a local-first cybersecurity research laboratory. Success means
  understanding architectures, testing hypotheses within authorization, recording
  evidence, and reporting reproducible findings — not merely running tools.
- ChatGPT is the coordinator/reviewer. DeepSeek (and configured alternative models)
  may be researchers/executors. Share the same inspected tool runtime wherever
  configured; do not silently assume each model has identical access.
- Prefer verified observations to assumptions. Clearly distinguish repository
  state, GitHub CI, installed local state, process status, HTTP responsiveness,
  tool availability and **end-to-end functional success**. They are not equivalent.
- Stay inside the user's authorized scope. Never silently conduct active external
  scanning, intrusive tests or destructive operations.

## 2. Current deployment context — important

- Active development environment is **local Windows laptop**, repository
  `%USERPROFILE%\Cybernova-DeepSeek`, data in
  `%LOCALAPPDATA%\CyberNova\data`. These are defaults to verify, not assumptions.
- **Do not rely on Vast.ai, legacy Vast tunnels or remote MCP instances.**
  Some historical source files and names still include `Vast` or `tunnel_access`;
  their presence does NOT prove that a remote Vast machine is running.
  Use remote infrastructure only after a new, explicit request.
- Default operator terminal is **Windows CMD**, not Git Bash or PowerShell.
  All directly pasteable commands must use valid CMD syntax. If PowerShell is
  needed, wrap it in `powershell.exe -NoProfile -Command "..."`, or provide an
  audited local `.cmd` launcher for a versioned PowerShell script.
- Do not put multiple CMD commands together without `&&`, `&` or correct
  line breaks. Prefer a single pasteable block with labelled stages, e.g.
  `[1/5] PORTS`, `[2/5] PROCESSES`, `[3/5] GIT`, `[4/5] UPDATE`,
  `[5/5] VERIFY`. Fail at the first blocking error.

## 3. Mandatory preflight BEFORE ANY update, install, restart or new listener

1. Confirm the intended **machine, OS, shell, repository path and active branch**.
   Use `git rev-parse --show-toplevel`, `git branch --show-current`,
   `git status --porcelain`, and `git remote -v` as appropriate.
2. Inspect relevant listening ports and **owners of the PID** before launching,
   restarting or changing versions. Inspect the executable/module and avoid
   printing credentials embedded in command lines. Do not infer port freedom
   from a single log line. Include IPv4 and IPv6/wildcard listeners.
3. Known local Cybernova ports to check where relevant:
   - `18792`: portable tool gateway;
   - `18794`: console server / UI backend;
   - `18795`: local access gateway;
   - `18796`: communication MCP;
   - `9588`, `18732`: possible auxiliary components, when configured;
   - `18883`, `18884`: **legacy** Quick Send bridge ports; modern extension
     versions should not require either port.
   These are known defaults; inspect source/config before treating as exhaustive.
4. If a conflicting listener exists, **STOP and identify it**. Never bulk-kill
   Python, AutoHotkey, browser processes or arbitrary PIDs. Never assume a
   listener is Cybernova merely because it uses a familiar port. Prefer stopping
   the known runtime via `Ctrl+C` in its own console, or a specific approved
   graceful shutdown. An explicit, identified PID may be stopped only when
   the user has authorized that action and the impact is understood.
5. Refuse to update an unexpectedly dirty worktree, detached HEAD, unknown
   remote, mismatched branch, or non-fast-forward history. Preserve all local
   changes and backups. Never use `git reset --hard`, `git clean -fd`,
   `git push --force` or deletion as an automatic remedy.
6. For portable local app updates, keep runtime data, secrets, virtualenv and
   source distinct; do not assume Git pull updates running processes. Verify
   exact revision, dependency changes and compatibility before restarting.

## 4. Standard Windows local update procedure

Use the repository's `tools/windows/Update_Cybernova_Safe.cmd` launcher.
It performs a staged **preflight → clean tree check → fast-forward update →
verification** and stops on conflicts. It does not stop services, start services,
install dependencies, alter firewall rules or change system settings.
On the first installation of this script, manually preflight before fetching it.
Never promise port-conflict resolution by silently killing listeners.

When ready to start after an update, repeat the port-owner check first and use
the versioned `portable/native.py --data-dir ... run` command only if safe.
Verify all expected ports listening and HTTP application readiness, not merely
`CYBERNOVA_STARTED` log messages.

## 5. Changes, testing, security and evidence

- Reproduce the issue, isolate the responsible layer, prefer the smallest change,
  keep rollback paths, then test at the layer that failed.
- Test command syntax for **the actual requested shell**. Do not mix Git Bash,
  PowerShell and CMD as if interchangeable.
- For browser extensions, check the loaded unpacked extension path, `manifest.json`,
  service worker errors, permissions, content scripts, page origin, and actual DOM
  selectors. Passing static JS tests is not proof of working Chrome UI automation.
- Do not leak or commit API keys, tokens, passwords, cookies, clipboard contents,
  private IP inventories, or diagnostic output containing credentials.
- Do not overwrite user data, delete backups, disable security protections,
  or install software without clear user authorization.
- Preserve timestamps, failure messages, exit codes, command sequence and
  source revision for investigations; redact secrets in reports.
- Maintain a rollback path, report any limitations, and do not claim a change
  is deployed locally merely because GitHub has a commit or green CI.

## 6. Response/command contract for the user

When the user asks for an operational fix or update:

1. First state **what is confirmed**, the likely cause, and what will change.
2. Give **one CMD-ready block** (or one committed `.cmd` launcher) instead
   of repeated fragments. Mark each stage and **stop on error**, recording
   which stage failed. Favor reversible read-only checks before changes.
3. Explain clearly what is **checked**, **changed**, **not changed**, and
   what constitutes success.
4. Add the exact next commands for any claimed verification, unless the check
   is already executed. Do not leave the user with “check this” and no command.
5. For logs, interpret the path of execution: process → listener → protocol →
   response → actual task; identify the failing layer and competing hypotheses.
6. Prefer one targeted troubleshooting question only when facts are genuinely
   missing. Do not repeat facts the user already provided.
7. Never fabricate a PID, port, command output, commit, CI result or test outcome.
   Distinguish “updated in GitHub”, “pulled to Windows”, “started” and “works”.

## 7. Runtime integration caveat

A repository `AGENTS.md` is **not automatically a system prompt** for every
ChatGPT browser session or for a DeepSeek model invoked through an API.
Every agent entry point must explicitly load/reference these rules in its own
trusted instruction path, and this should be tested. Do not claim that writing
this file alone activates the instructions in all agents.
