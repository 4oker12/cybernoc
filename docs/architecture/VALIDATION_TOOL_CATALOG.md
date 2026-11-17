# Cybernova — Vulnerability Validation and Controlled Impact Toolbox

**Status:** proposed tool adapters and evidence rules. Neither installation nor active operation is implied.  
Companion: [Full-stack controls, 191 checks](FULL_STACK_TEST_CATALOG.md).  
Case: [exact-origin simnet.ua scope](../cases/SIMNET_UA_SCOPE.md).

## 1. What "confirmation" means
Validation is a decision over an observed *security boundary*, not merely a successful scanner return code.

- **E0 — Informational:** CVE match, fingerprint, default configuration indicator.
- **E1 — Technical reproduction:** minimal non-destructive response or local-code evidence with negative control.
- **E2 — Security-boundary validation:** controlled, authorized synthetic account/data/asset demonstrates impact.
- **E3 — Laboratory exploit-impact:** isolated disposable environment proves a chain, with rollback and captured logs.
- **E4 — Operational finding:** authorized owner confirms production applicability and remediation; E3 alone never proves E4.

Status is \`candidate\`, \`confirmed\`, \`inconclusive\`, \`false_positive\` or \`not_tested\`. A CVE banner match remains a candidate. The tool's name does not change approval requirements.

## 2. Recommended tool family inventory

| Validation class | Candidate tools | Preferred proof and alternatives | Control tier |
|---|---|---|---|
| CVE identification and prerequisites | SearchSploit, CVE/NVD/OSV lookup, Vulners, vendor advisories | Advisory prerequisites + affected build + actual vulnerable behavior | D0 |
| CVE check module | Metasploit \`search\` / \`info\` / carefully reviewed \`check\`, selected Nuclei template | Confirm condition with bounded probes; \`check\` may be unsupported/unsafe | D0 inspect, D2/D3 reviewed check |
| Framework exploit impact | Metasploit exploit modules, disposable lab VMs | Lab-only proof; side effects and payload path reviewed, no production automation | D4 isolated lab |
| Web scanners/independent check | OWASP ZAP, Nuclei, Burp Suite scanner (licensed) | Reproduction with minimal scoped request and false-positive triage | D2, selected tests D3 |
| SQL/NoSQL injection | Burp Repeater, ZAP manual, sqlmap detection with strict controls, source analysis | Harmless differential observation, no DB dump, no destructive statements | D2/D3 |
| XSS/reflection | Dalfox, XSStrike, ZAP, browser devtools | Inert controlled sentinel in proper context; no stolen sessions | D2 reflected, D3 stored |
| SSRF/blind injection | Controlled self-hosted Interactsh, Burp Collaborator | One approved external callback and correlation token; no internal/metadata endpoints | D3 |
| Broken access control / IDOR / BOLA | Autorize, AuthMatrix, test-role harness, Postman | Two synthetic principals and a controlled object access decision | D3 |
| Authentication and session flaws | Burp Suite, ZAP, jwt_tool offline, synthetic browser identities | Session rotation, logout, scope and token checks | D0/D3 |
| OAuth/OIDC/SAML | OIDC configuration review, SAML-tracer, test IdP/SP clients | Issuer/audience/nonce/state/PKCE trust evidence | D0/D3 |
| XML/XXE | Source analysis, XML parser fixtures, ZAP controlled tests | Verify parser policy without external data reads | D0/D3 |
| Path traversal and LFI | Burp Repeater, reviewed Nuclei check | Owned fixture resource and normalization proof, no protected-file collection | D2/D3 |
| Upload / content serving | ZAP, Burp, inert synthetic file harness | Content-type, storage and rendering evidence; no web shells | D3 |
| Template, command and code execution | Semgrep/CodeQL, reviewed test fixture, Commix/SSTImap in disposable lab | Source reachability + isolated execution-boundary demonstration | D0/D4 lab |
| Deserialization and unsafe gadget path | CodeQL/SAST, SBOM and isolated fixture | Prove unsafe code path locally; no live deserialization payload | D0/D4 lab |
| HTTP smuggling/parser discrepancies | Reverse-proxy configuration, isolated dual-parser fixture | Mismatch observed only in independent lab | D0/D4 lab |
| Business logic and race | Threat-model workflow, Burp Repeater, Turbo Intruder in isolated fixture | Synthetic state invariant breached, deterministic event log | D3/D4 lab |
| REST/GraphQL APIs | Postman/Newman, Schemathesis, ZAP importer, GraphQL testing client | Schema and permissions validated with bounded test objects | D2/D3 |
| Network service and exposed daemon | Nmap NSE *curated safe scripts*, ssh-audit, vendor-specific read-only checks | Version+configuration+safe response, no broad port sweep outside scope | D2 |
| TLS/PKI and crypto policy | testssl.sh, SSLyze, OpenSSL | Handshake and configuration evidence | D2 |
| OS privilege or security baseline | Lynis, OpenSCAP, osquery, CIS-CAT, local offline policy audit | Read-only config discrepancy and lab reproduction | D0/D2, exploit D4 lab |
| Active Directory and privilege graph | BloodHound CE, PingCastle, authorized directory queries | Permission/path graph without lateral actions or credential abuse | D0/D3 distinct scope |
| Cloud IAM and infrastructure | Prowler, ScoutSuite, Checkov, native cloud policy analyzers | Role/resource trust and exposure from approved credentials | D0/D2 distinct scope |
| Kubernetes and container security | Kubescape, kube-bench, kubeaudit, Trivy, Grype | RBAC/pod policy/image findings with prerequisite checks | D0/D2 distinct scope |
| Firmware/CPE | binwalk, Ghidra, Firmware Analysis Toolkit in isolated firmware lab | Offline binary/config surface and synthetic reproduction | D0/D4 lab |
| ISP/PON/BNG | Vendor read-only OLT/BNG APIs/CLI, SNMPv3, sanitized provisioning logs | Authentication, subscriber separation and policy evidence | D0/D2 distinct scope |
| Detection/purple-team impact | Atomic Red Team, MITRE Caldera on disposable lab agents, SIEM canaries | Specific authorized alert/control behavior, no persistence | D4 lab |
| Supply chain | Gitleaks, Semgrep, CodeQL, Trivy, Syft, cosign | Dependency path, source flaw and artifact provenance | D0 on owned files |

**Optional, not blanket grants:** Every wrapper requires a signed scope and per-tool capability policy. Integration/licensing must be verified before claiming availability (for example Burp Pro modules and some CIS tooling).

## 3. Metasploit capability design — expanded
Metasploit can be useful, but it must be split into capabilities with different permissions:

| Capability name (proposed) | Allowed function | Default safety |
|---|---|---|
| \`msf.module_search\` | Search installed module index for CVE/service/platform | D0, no target traffic |
| \`msf.module_inspect\` | Describe options, preconditions, references, check/exploit support | D0 |
| \`msf.module_risk_review\` | Review module source and risk/side effects before check | D0 |
| \`msf.module_check\` | Single approved module/target, only if vetted low impact | Disabled until D2/D3 specific approval |
| \`msf.auxiliary_readonly\` | Only allowlisted safe auxiliary checks | Disabled until D2 permission |
| \`msf.module_exploit_lab\` | Reproduce effect in disposable fixture; no real target | D4 lab-only, specific approval |
| \`msf.evidence_import\` | Parse and sanitize results from authorized runs | D0 |
| \`msf.report_mapping\` | Map module evidence to CWE/CVE/affected component | D0 |

Do not give Qwen generic \`msfconsole\`, remote command shells, unbounded payload execution or unrestricted target changes. Inspect each \`check\` implementation: some check methods can modify state. Do not automatically escalate from \`check\` to \`exploit\`.

## 4. Tool-selection decision
For each finding, Qwen evaluates:

1. **Technology fit:** actual protocol, authenticated role, version and input point.
2. **Hypothesis strength:** evidence, conflicting observations and known false positives.
3. **Least impact:** offline/static check first, then approved bounded dynamic test.
4. **Evidence gain:** will this check distinguish a false positive from a real boundary violation?
5. **Availability:** installed, healthy, licensed, versioned and adapter-tested.
6. **Policy:** exact origin + asset/credential allowlist + D-tier.
7. **Reproducibility:** deterministic control/negative-control and reportable artifacts.

Expected output: \`proposed_tool_ids\`, \`selected_capability\`, \`evidence_needed\`, \`approval_tier\`, \`limits\`, \`stop_conditions\`, \`false_positive_checks\`.

## 5. Required proof record
\`\`\`json
{
  "finding_id": "F-0001",
  "control_id": "EXP-01",
  "asset_id": "case-scoped-asset",
  "hypothesis": "candidate weakness",
  "tool_capability": "registered-versioned-id",
  "authorization": "approved-case-specific-policy",
  "execution_mode": "D0",
  "evidence": [
    {"evidence_id": "E-0001", "type": "redacted-observation", "sha256": "content-hash"}
  ],
  "positive_control": "expected observed change",
  "negative_control": "expected unaffected case",
  "preconditions_confirmed": [],
  "result": "candidate",
  "impact": "not_established",
  "remediation": "required review / mitigation",
  "retest_status": "pending"
}
\`\`\`

## 6. Per-tool adapter acceptance tests
- Block out-of-scope origin, redirect, port, resolved IP, and rebinding before network I/O.
- Reject unsupported/uninstalled tool and unsafe modes without improvising shell commands.
- Hard limits: time, requests, concurrency, retries, output size, CPU/memory and file write paths.
- Disallow changing target system state unless D3/D4 approval explicitly matches capability and fixture.
- Link evidence with tool version, source, timestamp, sanitized output and hash; censor credentials and personal data.
- Validate negative control and false-positive handling; scanner label alone must never set \`confirmed\`.
- Enforce an absolute stop switch, bounded repeated-action counter and safe checkpoint resume.

## 7. Implementation priorities
1. P0: registry + policy gate + proof schema + safe HTTP/TLS + unit tests.
2. P1: browser/ZAP/Nuclei safe adapters, synthetic-role API tests, detailed finding pipeline.
3. P2: specialist detection plugins and Metasploit module *search/inspect*; vetted \`check\` only where allowed.
4. P3: lab-only impact, host/network/ISP and purple-team adapters on separately scoped environments.

**Current exact-origin simnet.ua case remains PLAN_ONLY.** This file does not install software, give blanket approval, authorize intrusive tests or claim a vulnerability exists.
