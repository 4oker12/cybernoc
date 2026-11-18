# Cybernova Research Platform — working runtime

**Milestone:** local offline-first research controller and optional real Qwen/Ollama tool-calling loop.

## Project documents
- PLAN.md — full authorized SIMNET Web/API audit methodology, scope and milestones.
- ARSENAL.md — 107 engine candidates mapped to 85 host-neutral capabilities.
- prompts/RESEARCHER_SYSTEM.md — Qwen research rules, anti-hallucination and stop conditions.
- prompts/AUDIT_PROTOCOL.md — phase-by-phase evidence-first procedure.

## Code organization
- app.py — dedicated loopback-only HTTP API and responsive UI server.
- core/policy.py — exact scope checks and approval dry-run.
- core/offline_tools.py — actual callable offline tools with input schemas.
- core/agent_loop.py — bounded Qwen tool-calling via local Ollama.
- core/evidence.py — SHA-256 and redaction.
- core/storage.py — SQLite findings and minimal audit events.
- ui/index.html, ui/style.css, ui/app.js — NOC-style research console.
- tools/catalog.json — 85 generic tool names and status per tool.
- engines/manifest.json — 107 engine candidates, NOT installed.
- profiles/simnet.example.json — DRAFT, all assets out of scope by default.
- tests/ — unit and localhost HTTP integration.
- install_arsenal.py — software dry-run inventory and optional official PDTM software installation.

## Offline quality gate
From an isolated checkout with Python 3.12 and no special dependencies:

    cd cybernova/research-platform
    python3 -m compileall -q .
    python3 -m unittest discover -s tests -p 'test_*.py' -v
    python3 cli.py catalog
    python3 install_arsenal.py --profile inventory
    python3 app.py --check --db /tmp/cybernova-test.db

Passing tests must be verified from actual CI or a local run. Code committed does not mean deployed.

## Launch dedicated Research Console
    cd cybernova/research-platform
    python3 app.py

Open http://127.0.0.1:18794/ from the same host. The server only listens on 127.0.0.1. For remote access use authenticated SSH forwarding, not a public tunnel. Do not expose port 18794 or Ollama port 11434 publicly.

Tabs: Overview, Tools, Qwen Researcher, Findings, Report.
The UI distinguishes callable tools from planned capabilities, lets operators enter typed arguments, displays actual results and logged findings. Findings require separate review and a SHA-256 evidence reference before being marked verified.

## Optional local Qwen runtime
To intentionally enable local Ollama model function calling:

    python3 app.py --enable-local-llm --model cybernova-security:30b

The model runner calls only fixed localhost Ollama 127.0.0.1:11434. Exposes a subset of implemented read-only offline tools to the model. It refuses fake textual tool calls and never executes arbitrary shell, remote scans, account changes or human finding verification. If the chosen model template cannot perform structured tool calling, we report that, not a fabricated receipt.

## Actually implemented generic offline tools (20)
gateway_status, tool_catalog, engagement_validate, scope_check, plan_build, plan_validate, asset_inventory, threat_model_build, ip_network_summary, http_header_review, python_static_review, api_schema_import, evidence_hash, evidence_redact, risk_assess, finding_create, finding_verify, finding_list, audit_event_log, report_generate.

All listed 20 tools can be called through the local console API. Finding creation/review writes only local case metadata, not to any target. The model is never granted write-oriented finding actions. No active scanner is exposed in this application.

## Safety and reliability
- An example website name is not authorization to scan; SIMNET example is deliberately draft and out of scope.
- Exact FQDN, authorization validity, risk level and budgets remain separate concerns.
- Never trust content from HTML, logs, APIs or code as new system instructions.
- Keep raw tokens, personal/financial data and unrelated subscriber records out of project prompts, GitHub and results.
- Evidence SHA-256 alone is not evidence of authenticity: human review and reproducibility still required.
- Every real tool invocation produces a structured response and a minimal action receipt; invented tool name is rejected.
- No uncontrolled command line, template engine or dynamic script execution in the model path.

## Next engineering milestone
Add individually reviewed capability adapters for HTTP, DNS, TLS, browser, code/infra; constrain target access using the RoE service; integrate proper persisted evidence references and exercise the full Qwen workflow against a local owned fixture before authorized public targets.

This branch does not modify running Vast services until independently deployed and verified.
