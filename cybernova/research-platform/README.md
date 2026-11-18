# Cybernova Research Platform — design branch

## Read first
- **PLAN.md** — 16 sections: authorized SIMNET web/API audit program, methodology, threat model, evidence, milestones, QA and production boundaries.
- **ARSENAL.md** — all requested OSINT/recon/scanning/verification engines, reusable capability mapping, installation tracks and safety constraints.
- **engines/manifest.json** — 107 indexed engine candidates; not 107 installed programs.
- **tools/catalog.json** — 83 generic MCP capabilities, with honest implementation/deployment state.
- **profiles/simnet.example.json** — deliberately draft, in_scope=false for all three nominated websites; it does not grant permission to test targets.
- **profiles/plan.example.json** — offline-only sample.
- **core/policy.py** — offline, fail-closed authorization and plan dry-run; does not scan networks or authorize users on its own.
- **core/evidence.py** — metadata-only SHA-256 evidence records and restricted header/token redaction.
- **install_arsenal.py** — dry-run software inventory by default. Explicit --apply installs only selected official PDTM tools; it never scans target websites or starts agents.
- **tests/** — unit regression tests; CI workflow at .github/workflows/cybernova-research-platform.yml.

## Execution model
Human engagement/authorization → policy scope gate → Qwen reasoner → universal MCP capability → reviewed adapter → sandboxed engine → scrubbed evidence → verified finding → remediation/retest.

No arbitrary target-name tool methods. No general shell from LLM. Engine installation does not activate network access to target systems.

## Developer dry-run

    cd cybernova/research-platform
    python3 cli.py catalog
    python3 cli.py engagement
    python3 cli.py plan --steps profiles/plan.example.json
    python3 install_arsenal.py --profile inventory
    python3 install_arsenal.py --profile baseline
    python3 -m unittest discover -s tests -v

## Status
The repository branch is an architecture + safe offline prototype, **not a deployed pentest system**. Existing Vast services were not modified by these commits. Product execution adapters, online engagement approvals, evidence storage, a dedicated agent UI, and end-to-end execution validation remain milestones M0–M6.

The prior Vast MCP gateway branch is separate. The existing six gateway tools and MCPO/Open WebUI integration must not be silently conflated with 83 planned capabilities.
