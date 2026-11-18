# Cybernova security researcher — WebUI deployment

## Architecture
Browser (SSH tunnel or authenticated private reverse proxy) -> Open WebUI (127.0.0.1:18791) -> local Ollama (127.0.0.1:11434) -> custom model `cybernova-security:30b` -> base `brianmatzelle/qwen3-coder-heretic:30b`.

The existing Cybernova event-ring/control panel and updater are separate components. This deployment does not replace or modify them.

## Files
- `SYSTEM_PROMPT.md`: versioned security-researcher specification.
- `Modelfile`: same role applied persistently as Ollama system prompt; temperature 0.25, top_p 0.85, context 8192.
- `bootstrap.sh`: checks preinstalled model/Ollama, creates specialized model, installs Open WebUI in Docker if available, otherwise in isolated Python venv; starts localhost-only.
- `compose.yml` and `start-python.sh`: deployment backends.

## Run on Vast (after repository is made available locally)
```bash
cd /path/to/cybernova/qwen-webui
bash bootstrap.sh
```

Never commit the WebUI secret, auth database, SSH private keys, or Ollama API access externally. Runtime data stays under `/workspace/cybernova-qwen-webui-runtime` for Python mode and named volume `cybernova_webui_data` for Docker mode.

Open via *private* SSH forwarding: remote 127.0.0.1:18791 -> local 127.0.0.1:18791, then visit http://127.0.0.1:18791 on your laptop. The first account becomes admin; turn off new signup immediately if it is still enabled. Select `cybernova-security:30b` in the model picker.

## Acceptance
1. `ollama list` includes both the base model and `cybernova-security:30b`.
2. `curl http://127.0.0.1:18791/` returns UI HTML, not an API error.
3. Authenticated Open WebUI user sees `cybernova-security:30b` and receives a reply to a benign test prompt.
4. The model treats a supplied sample code review as an authorized offline audit, reports hypotheses separately from validated findings, and does not pretend to invoke tools.
5. The pre-existing Cybernova control panel and MCP bridge remain available.

## Important
The system prompt defines reasoning and workflow; it does not create tools, long-term memory, autonomous permission, or external browser/terminal access. Separate guarded tool adapters and an artifact/evidence store are needed for execution.
