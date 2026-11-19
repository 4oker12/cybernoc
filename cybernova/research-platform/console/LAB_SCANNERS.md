# Cybernova Lab Scanner Arsenal

Eight implemented, fixed-profile scanner adapters plus one real inventory function.

| Cybernova tool | Engine | Bounded profile |
|---|---|---|
| lab_nmap | Nmap | TCP Connect, service/version light, single declared lab port, max 90 seconds, no NSE |
| lab_nuclei | ProjectDiscovery Nuclei | Operator-reviewed local templates, <=3 requests/s, concurrency 1, no OOB or raw request records |
| lab_zap_baseline | OWASP ZAP Baseline | Passive checks and 1-minute crawler, JSON output, not ZAP full active scanner |
| lab_nikto | Nikto | Config checks, 90 seconds, JSON report |
| lab_testssl | testssl.sh | HTTPS-only TLS review, fast profile |
| lab_ffuf | ffuf | Fixed small lab-only wordlist, 3 requests/s, 2 workers, 60-second limit |
| lab_semgrep | Semgrep | Local rules and source SAST without telemetry |
| lab_trivy | Trivy | Offline filesystem dependency and IaC review using local DB |
| lab_scanner_inventory | Engine presence/target IDs | No scan or network requests |

All eight scanner wrappers build fixed argv lists, call the executable without
a shell, enforce a wall-clock timeout, and return only structured findings and
a SHA-256 fingerprint. Qwen chooses the scanner. Active scans are never
auto-approved; each requires one-time user approval for exact parameters.

## First initialize the lab

In the repository directory cybernova/research-platform, run:

    python -m console.lab_setup --init

This creates the lab root at /workspace/cybernova-lab, a projects directory,
reviewed Nuclei and Semgrep sample rules, a five-line ffuf wordlist, and an
empty, disabled lab_scope.json policy.

Next establish a genuinely isolated network. The scanner worker itself must
have no route to the internet, provider equipment, production networks, real
subscribers or production billing. Running a container connected to a Docker
network marked internal can form part of the isolation, but it does NOT isolate
a scanner process that still runs in the host network namespace.

Populate the lab policy deliberately. Example content (do NOT use this
address unless the address actually belongs to your isolated test lab):

    {
      "version": 1,
      "enabled": true,
      "targets": {
        "juice-lab": {"url": "http://172.30.48.10:3000/"}
      },
      "projects": {
        "sample-code": "sample-code"
      },
      "nuclei_templates": "rules/nuclei-reviewed",
      "semgrep_rules": "rules/semgrep-reviewed",
      "ffuf_wordlist": "wordlists/lab-small.txt"
    }

Only explicitly listed IP-literal targets are eligible. Valid ranges:
RFC1918 (10/8, 172.16/12, 192.168/16), loopback or IPv6 ULA.
Public internet IPs, CGNAT 100.64/10, and documentation IP ranges are rejected
even if an operator mistakenly lists them. No URL credentials or query strings.

Launch the scanner worker after external isolation is established:

    export CYBERNOVA_LAB_ROOT=/workspace/cybernova-lab
    export CYBERNOVA_LAB_SCOPE=/workspace/cybernova-lab/lab_scope.json
    export CYBERNOVA_LAB_ISOLATED=1
    python -m console.server

The environment flag is operator attestation, NOT a firewall. The real egress
barrier must exist independently. The default shipped policy is disabled.

## Install the actual engine executables

This GitHub change contains operational adapters, not downloaded binaries.
The runtime checks PATH and reports which engines are genuinely present.
Install vetted, pinned versions of official engines in the isolated lab
environment and keep their version metadata for research reproducibility.

Official sources:
- Nmap: https://nmap.org/download.html
- Nuclei: https://github.com/projectdiscovery/nuclei
- OWASP ZAP baseline: https://www.zaproxy.org/docs/docker/baseline-scan/
- Nikto: https://github.com/sullo/nikto
- testssl.sh: https://github.com/testssl/testssl.sh
- ffuf: https://github.com/ffuf/ffuf
- Semgrep: https://semgrep.dev/docs/getting-started/
- Trivy: https://trivy.dev/docs/latest/getting-started/installation/

Some systems have Nmap, Nikto and testssl.sh in apt. Nuclei and ffuf offer
official Go/release installations, Semgrep a Python installation, and Trivy
official packages. The current ZAP adapter expects the upstream
zap-baseline.py executable to be available in PATH inside the isolated lab
or a trusted operator-maintained wrapper with that name.

To inspect readiness without initiating scans:

    python -m console.lab_setup --check

The Cybernova chat also has lab_scanner_inventory. It lists engine
availability, configured lab target IDs and project IDs. No invented output.
Source code projects live under /workspace/cybernova-lab/projects.
Rule files and wordlists are operator-controlled and never downloaded on demand
during Qwen inference.

## How Qwen uses these tools

1. Understand the question, gather observations, determine whether a lab scan is
   needed and inspect inventory.
2. Choose a corresponding lab tool and an exact configured lab target ID.
3. Cybernova creates a one-time approval card showing tool, purpose and target.
4. After approval, the scanner executes in the lab with fixed resource limits.
5. Raw scanner output is discarded. Qwen receives limited structured findings,
   categorizes confidence and decides whether other evidence is required.

Scanners cannot accept custom model-supplied shell commands, flags, arbitrary
template paths, usernames, credentials or target lists.

An error message is returned if the scanner binary is not installed, lab scope
is absent, the network isolation flag is missing or a target falls outside the
lab scope.

## Verification

    python -m unittest discover -s tests -p 'test_*.py' -v
    node --check console/static/app.js
    python -m compileall -q console

Ask Qwen to list its engines using lab_scanner_inventory. Then request a
bounded scan of a synthetic container in your isolated network and check that
it asks for approval instead of launching the scan automatically. Compare
observations with independent operator diagnostics before declaring a finding.

No active scanner tests against simnet.ua or real subscriber/ISP assets are
authorized by this runbook. Installing a scanner is not authorization to target
any system. No production target has been scanned as part of this change.
