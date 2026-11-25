# feature/grok-audit

Base: `fix/patchright-tool-routing`.

Adds `resolve_tool_groups` / `infer_relevant_tool_groups` so empty UI tool_groups
infer a focused catalog (browser/web/computer/...) instead of the full list.

## Pull

```powershell
Set-Location "$HOME\Cybernova-DeepSeek"; git fetch origin; git checkout feature/grok-audit; git pull --ff-only origin feature/grok-audit; git log -3 --oneline
```

## Start

```powershell
Set-Location "$HOME\Cybernova-DeepSeek"; & "$env:LOCALAPPDATA\CyberNova\data\venv\Scripts\python.exe" "$HOME\Cybernova-DeepSeek\cybernova\research-platform\portable\native.py" --data-dir "$env:LOCALAPPDATA\CyberNova\data" run
```

UI: http://127.0.0.1:18794/
