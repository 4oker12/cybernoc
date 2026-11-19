# Cybernova — operator handoff convention

This repo contains a Windows-laptop native installation used by the operator. The operator expects a complete path from action to verification.

## Mandatory response format for any operational change

When proposing or implementing an update, configuration change, deployment or test:

1. State what changed, what has *actually been verified*, and what has not yet been deployed.
2. Provide the **immediate next executable commands in the same response**; do not leave the operator to ask "what command now?".
3. Default to **Windows PowerShell**, with individually copy-pasteable *single-line commands* or one self-contained, syntactically verified code block. Never use bash-only syntax (`&&` on old PowerShell, `sudo`, `export`, `cd ... && ...`, Unix continuation slashes) for Windows.
4. Use a numbered order: inspect current state → safeguard data → update → start → verify. Each step must say **which terminal/system** runs it.
5. Explicitly distinguish the notebook installation from Vast.ai and from Docker/WSL. Do not assume the service address `127.0.0.1:18795` reveals where code is running.
6. Preserve user data, SQLite history, profiles and secrets. Stop before overwriting dirty Git worktrees; never propose destructive resets or `git clean -fd`, and never print keys/tokens.
7. Provide exact paths when verified; do not invent local locations. The previously documented Windows native setup used:
   - checkout: `$HOME\Cybernova-DeepSeek`
   - portable management: `$HOME\Cybernova-DeepSeek\cybernova\research-platform\portable`
   - external data: `$env:LOCALAPPDATA\CyberNova\data`
   - native Python: `$env:LOCALAPPDATA\CyberNova\data\venv\Scripts\python.exe`
   - internal API: `http://127.0.0.1:18794`; browser gateway `http://127.0.0.1:18795`
   These are historical setup details; validate them when executing or after migration.
8. If there are multiple possible install variants, show one decisive diagnostic command first and then branch the instructions by its output. Do not dump irrelevant alternatives.
9. The GitHub branch may contain new code that has passed CI but has **not** been deployed locally. Never conflate CI with live verification.
10. Conclude with an observable success condition: exact command/URL/UI element and expected output.

Prefer two or three short, syntactically correct commands over a long speculative script. The operator wants precise execution, not hand-wavy next steps.
