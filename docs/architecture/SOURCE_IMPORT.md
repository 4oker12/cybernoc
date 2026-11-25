# Import the current implementation before architecture audit

The GitHub repository contained no source files when checked on 2026-11-16. Import a **reviewed source snapshot**, then resume Phase B. The Vast filesystem and the Open WebUI database may contain different parts of the implementation.

## Required source set

Place these in the repository when present:

- The CyberSec Doctor Python package or scripts, dependency manifests and version pins.
- The bounded executor: command allowlist, target/scope validation, time/resource limits and privilege dropping.
- Browser Network Investigator and HAR redaction code.
- Planner, prompts, Qwen/Ollama adapter, tool-call loop and state persistence.
- Evidence/report schemas, retention and sanitization code.
- Open WebUI tool/function source and model-profile configuration, **without** tokens or user sessions.
- Vast startup/supervisor scripts as redacted templates.
- Lab fixtures and meaningful tests.
- Existing README, ADRs and deployment instructions.

Known candidate paths from the earlier setup discussion are `/workspace/cybersec-doctor/cybersec_doctor.py`, `/workspace/cybersec-doctor/doctor_lab.py`, and an Open WebUI `cybersec_doctor` tool. **Verify their current contents and presence**; these are pointers, not an audited inventory.

## Safe import procedure

1. On a machine with authorized SSH access, list source files on Vast **without copying the cases directory**:

   ```powershell
   ssh -o ClearAllForwardings=yes vast-qwen 'find /workspace/cybersec-doctor -maxdepth 4 -type f -not -path "*/cases/*" -not -path "*/run/*" -not -path "*/home/*"'
   ```

2. Copy only reviewed source/config/test files into a local clone of `https://github.com/4oker12/cybernoc`. For example, adjust the destination to your clone:

   ```powershell
   scp -i C:\Users\Andrei\.ssh\id_ed25519 -P 40282 root@59.9.140.81:/workspace/cybersec-doctor/cybersec_doctor.py .\src\cybersec_doctor.py
   ```

   If that host/port has changed, use the current SSH command shown by Vast. Export the Open WebUI tool's **source code**, not its SQLite database or authentication token. Redact host-specific credentials from service scripts.

3. Before each commit, inspect `git status --short`, `git diff --cached` and run a secret scan. Confirm no subscriber names, session URLs, cookies or HAR request bodies appear. Commit source and tests first; commit sanitized deployment templates separately.

4. Push to a review branch and open a PR. Share the PR or commit SHA in this chat. The architecture audit should use that exact commit as its evidence baseline.

## Never import

`cases/`, `run/`, `home/`, `*.har`, screenshots, PCAPs, raw HTTP logs, `.env`, SSH keys, API tokens, Open WebUI database, Ollama model blobs, virtual environments, browser caches, subscriber data or session-bearing URLs.

## Acceptance gate for Phase B

A reviewer can identify the planner entry point, the Qwen/Ollama request path, the tool registry, executor policy, browser capture, evidence writer, report builder, runtime configuration and at least one reproducible test from the committed tree. Missing components are listed as gaps rather than imagined.
