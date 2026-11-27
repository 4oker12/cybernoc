# Cybernova — Full-Stack Security Assessment Catalog

**Version:** 1.0 · **Status:** design specification / not installed / not executed  
**Case context:** [simnet-ua-web-001](../cases/SIMNET_UA_SCOPE.md)  
**Companions:** [Pentest workflow](PENTEST_WORKFLOW_PLAN.md) · [Qwen agent contract](QWEN_PENTEST_AGENT_PROMPT.md)

## 0. Purpose, bounds and interpretation

This catalog is a **menu of controls** for a security assessment, not an authorization to run them. It covers OSI L1–L7 plus identity, data, hosts, CI/CD, cloud, software supply chain, monitoring, ISP/PON and AI-agent security. Qwen chooses controls based on a bounded, approved case. Cybernova enforces scope, rate, credentials, output limits and approvals **outside the model**.

**The only currently declared target:** exact HTTPS origin \`https://simnet.ua:443\`. Any subdomain, DNS server, BNG, OLT, ONU, VLAN, upstream IP, connected API origin, billing portal or infrastructure device requires a **separate target record and authorization**. A certificate SAN, reverse DNS result, redirect, shared address or discovered link does not expand scope.

**Modes** (authorization gates rather than tool names):
- **D0** — Offline planning / source review / fixture analysis; no target request.
- **D1** — Passive public-source research; no direct active target scan.
- **D2** — Bounded, read-only direct checks; requires approved case, target allowlist, limits and window.
- **D3** — Stateful/authenticated checks using dedicated synthetic accounts or disposable objects; separate approval.
- **D4** — Intrusive or exploit-impact validation; explicit per-technique authorization; isolated lab by default.

**Case applicability labels:**
- **WEB** — conceptually relevant to this HTTPS origin; may only execute when corresponding D2/D3/D4 gate opens.
- **LATER** — requires a distinct authorized asset/environment; not part of the current \`simnet.ua\` case.
- **OFFLINE** — can be planned/triaged without sending target traffic.

No tool is assumed installed merely because it appears below.

## 1. Cross-cutting assessment controls

| ID | Check | Methods / tool families | Evidence and pass/fail question | Gate | Case |
|---|---|---|---|---|---|
| GOV-01 | Exact asset and origin ownership | ROE, CMDB, contract | Authorized FQDN, port, owner, exceptions recorded? | D0 | WEB |
| GOV-02 | Rules of engagement and stop-switch | Case policy, risk matrix | Times/rates/contact/rollback recorded? | D0 | WEB |
| GOV-03 | Scope validation through redirect/DNS | Policy resolver, URL canonicalizer | Cross-origin hop denied before request? | D0 fixture | WEB |
| GOV-04 | Request/response redaction | Evidence pipeline tests | Credentials and personal data excluded? | D0 | WEB |
| GOV-05 | Resource guardrails | Timeout, rate limiter, job budgets | Maximum requests/duration/concurrency enforced? | D0 | WEB |
| GOV-06 | Evidence and false-positive quality | SHA-256, timestamp, provenance, reviewer | Can another analyst reproduce the finding safely? | D0 | WEB |
| GOV-07 | Test account/fixture lifecycle | Case API, inventory | Synthetic objects created and cleaned up? | D0/D3 | WEB |
| GOV-08 | Change and incident communications | ROE approvals, incident channel | Authorized parties receive tests/incidents notices? | D0 | WEB |
| GOV-09 | Coverage accounting | OWASP WSTG/ASVS, NIST 800-115 | Tested / skipped / not applicable explicitly marked? | D0 | WEB |
| GOV-10 | Human approval before higher impact | Policy engine | D3/D4 cannot self-authorize via prompt? | D0 fixture | WEB |

## 2. Layer L1: physical medium, power, facilities (separate infrastructure scope)

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| L1-01 | Physical access to racks, rooms and patch panels | Access logs, inventory, site inspection | Access control and visitor records | D0/D3 | LATER |
| L1-02 | Fiber optical budget and abnormal attenuation | OLT/ONU DOM, optical power meters, OTDR (approved maintenance) | Rx/Tx, loss, threshold and link health | D2/D3 | LATER |
| L1-03 | Optical splitters, patching and labeling | PON inventory, diagrams, visual inspection | Physical path matches documented route | D0/D3 | LATER |
| L1-04 | Ethernet cabling pairs and PoE budget | Cable tester, LLDP power, PoE counters | Power negotiation and safe cable margin | D2/D3 | LATER |
| L1-05 | UPS, redundant power and environmental alarms | UPS/NMS, sensor telemetry | Availability under planned maintenance | D2/D3 | LATER |
| L1-06 | Out-of-band management physical isolation | OOB inventory / ACL review | Separate control-path topology | D0/D2 | LATER |
| L1-07 | Unauthorized hardware/taps or exposed ports | Controlled site inspection | Asset and tamper-control findings | D3 | LATER |
| L1-08 | Fiber PON ONU identity and inventory match | OLT config, ONU serial/MAC/LOID records | Claimed subscriber attachment matches provisioning | D2 | LATER |

## 3. Layer L2: Ethernet, switching, access and provider bridging

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| L2-01 | VLAN segmentation / QinQ boundary | Switch configs, VLAN maps, passive capture | Tags, trunks and permitted forwarding domains | D0/D2 | LATER |
| L2-02 | Access versus trunk port hardening | Running config, port state | Untagged/default VLAN rules align with design | D0/D2 | LATER |
| L2-03 | MAC learning, flapping and port security | MAC tables, syslog, SNMP/telemetry | MAC movement history and protections | D2 | LATER |
| L2-04 | STP/RSTP/MSTP controls (BPDU Guard, Root Guard) | Switch configs, topology snapshots | Unauthorized topology changes would be blocked | D0/D2 | LATER |
| L2-05 | DHCP Snooping + Option 82 trust | Switch/OLT policy and logs | Unauthorized DHCP server cannot reach clients | D0/D2; lab D4 | LATER |
| L2-06 | Dynamic ARP Inspection / IP source guard | Switch configs, DHCP binding tables | Forged bindings are rejected in lab | D0/D2; lab D4 | LATER |
| L2-07 | 802.1X, MAB and fallback behavior | NAC policies, controlled test identities | Authentication fails closed? | D2/D3 | LATER |
| L2-08 | LLDP/CDP disclosure and management exposure | Switch policy and filtered read-only discovery | Unneeded topology data restricted? | D2 | LATER |
| L2-09 | IGMP snooping/querier and multicast isolation | Configs, counters, packet capture | Membership and querier domains correct? | D2 | LATER |
| L2-10 | EPON/GPON ONU isolation and service profiles | OLT ONU profiles, bridge maps, GEM/T-CONT policy | Subscriber separation and profile alignment | D0/D2 | LATER |

## 4. Layer L3: addressing, routing, segmentation, NAT and IPv6

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| L3-01 | Public and private addressing boundaries | Route/ACL/CMDB analysis | Unexpected routes or reachable segments? | D0/D2 | LATER |
| L3-02 | Router ACL and firewall policy shadowing | Policy diff, vendor analyzers, Batfish | Allow/deny behavior against intended trust zones | D0/D2 | LATER |
| L3-03 | IPv4/IPv6 parity and accidental exposure | AAAA/DNS metadata, approved dual-stack check | Equivalent restrictions on both families? | D1/D2 | WEB for HTTPS; rest LATER |
| L3-04 | ICMP errors, PMTUD and fragmentation behavior | Packet captures, MTU diagnostics, ping/traceroute lab | Path MTU and ICMP handling understood | D2 | LATER |
| L3-05 | Route leaks and BGP origin controls | BGPView, RPKI validators, routing policy review | ROA validity, prefix filter and origin hygiene | D1/D2 | LATER |
| L3-06 | Recursive DNS/route or gateway misconfiguration | Router policy, inventory | No unauthorized routing path to management? | D0/D2 | LATER |
| L3-07 | NAT/CGNAT mapping isolation | NAT/BNG logs, synthetic lab flows | Subscriber session and port mappings isolated? | D2/D3 | LATER |
| L3-08 | uRPF and source-spoofing protections | Router configs / lab traffic | Spoofed sources blocked under agreed scenarios | D0; lab D4 | LATER |
| L3-09 | VPN route/policy-based routing split tunneling | VPN configs, route diff, packet traces | Intended destinations and DNS use VPN? | D2/D3 | LATER |
| L3-10 | IPv6 RA/DHCPv6 safety | Router/host configs, lab validation | Unauthorized router or prefix advertisement prevented? | D0; lab D4 | LATER |

## 5. Layer L4: transport, session state and availability

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| L4-01 | TCP reachability and state handling | curl, OpenSSL, Nmap selected safe service probes | TCP negotiation and timeouts | D2 | WEB for 443 |
| L4-02 | UDP exposed services | Nmap UDP selected ports, service docs | Minimal response/candidate service | D2 | LATER |
| L4-03 | QUIC / HTTP/3 policy and transport fallback | curl HTTP/3 capable build, browser devtools | Negotiated version and downgrade behavior | D2 | WEB if same origin |
| L4-04 | TCP MSS/MTU/fragmentation anomalies | pcap, packet counters, controlled path tests | Consistent retransmit/failure signature | D2 | LATER |
| L4-05 | Connection and request limits | Reverse proxy config, metrics, staging-only load checks | Connection timeouts/limits configured safely | D0/D2; stress lab D4 | WEB config only |
| L4-06 | Stateful firewall/NAT timeout policies | Session tables, config reviews | Idle state boundaries and retention | D0/D2 | LATER |
| L4-07 | Protocol-specific amplification/reflection exposure | Safe config audit, lab test harness | Unsafe service settings eliminated | D0; lab D4 | LATER |
| L4-08 | Rate limiting / retry and backoff behavior | Bounded sequential sample, traffic logs | Rate controls present without disruption | D2/D3 | WEB |

## 6. Layer L5/L6: TLS, PKI, session and content representation

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| TLS-01 | TLS versions and cipher suites | SSLyze, testssl.sh, OpenSSL s_client | Deprecated versions/ciphers disabled? | D2 | WEB |
| TLS-02 | Certificate chain, hostname and validity | OpenSSL, certlint, CT logs | Valid chain, SAN and expiry | D1/D2 | WEB |
| TLS-03 | HSTS and downgrade protections | curl, ZAP headers scanner | HSTS effective for intended host? | D2 | WEB |
| TLS-04 | TLS renegotiation, compression and resumption | SSLyze/testssl reviewed checks | Safe protocol feature configuration | D2 | WEB |
| TLS-05 | Client-cert/mTLS enforcement (if deployed) | OpenSSL test client, server config | Auth enforced at appropriate trust boundary | D2/D3 | WEB if applicable |
| TLS-06 | Cookie transport flags and domain/path isolation | Browser devtools, ZAP, Burp Repeater | Secure, HttpOnly, SameSite and scope correct? | D2/D3 | WEB |
| TLS-07 | Content encoding and parser consistency | curl, browser/devtools, proxy fixture | Encodings and caches do not alter trust boundaries | D2; parser attacks lab D4 | WEB |
| TLS-08 | Certificate lifecycle and secrets | CA/PKI config audit, cert expiry monitors | Automated renewals, key controls and alerts | D0/D2 | LATER |

## 7. DNS, mail and domain perimeter

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| DNS-01 | DNS records and TTL consistency | dig, dnsx, passive DNS | Resolutions, CNAME and TTL recorded | D1/D2 | WEB DNS metadata only |
| DNS-02 | Dangling DNS / takeover candidate | dnsx, passive inventory, provider records | Ownership of abandoned aliases verified | D1; active ownership checks D3 | LATER except origin resolution |
| DNS-03 | DNSSEC and delegation | delv, dig, DNSViz | DS/DNSKEY chain validity | D1/D2 | LATER |
| DNS-04 | Resolver open recursion/misconfiguration | Resolver config audit, safe lab query | Restrict recursion to expected clients? | D0/D2 | LATER |
| DNS-05 | Certificate transparency visibility | crt.sh, CT datasets | Discovery of public names; not new scope | D1 | OFFLINE |
| DNS-06 | SPF, DKIM, DMARC and mail alignment | dig, mail policy auditor | Domain spoofing defenses | D1 | LATER |
| DNS-07 | MX, SMTP TLS and relay configuration | SMTP test tools, mail server config | Email transport/security policy | D2/D3 | LATER |
| DNS-08 | Subdomain ownership / origin mappings | Amass/Subfinder (passive), inventory | Candidate asset inventory only | D1 | OFFLINE |

## 8. Edge infrastructure: CDN, WAF, load balancers, HTTP servers

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| EDGE-01 | Server and framework version indicators | curl, httpx, WhatWeb, Wappalyzer | Fingerprint with confidence not vulnerability claim | D2 | WEB |
| EDGE-02 | Proxy trust of Forwarded/X-Forwarded-* | Config review, synthetic staging requests | Spoofed client identity cannot change trust | D0/D3 | WEB |
| EDGE-03 | HTTP security headers | curl, ZAP passive, Mozilla Observatory | CSP, framing, MIME, referrer and HSTS settings | D2 | WEB |
| EDGE-04 | Cache key and private response separation | curl, Burp Repeater, staging fixtures | Private/auth responses not shared across users | D2/D3 | WEB |
| EDGE-05 | CORS allowlist and credentials | curl, ZAP, Burp Repeater | Origin policy correctly restricts credentialed reads | D2/D3 | WEB |
| EDGE-06 | Exposed default config/status endpoints | Authenticated config review, safe curated checks | Public management/config resources closed | D2 | WEB |
| EDGE-07 | Redirect and canonical origin handling | Browser, curl, safe redirect tracing | External redirect targets not auto-followed beyond scope | D2 | WEB |
| EDGE-08 | WAF/IDS logging and policy visibility | WAF rules review, SIEM correlation | Test requests logged/blocked per ROE | D0/D2 | WEB |
| EDGE-09 | HTTP request smuggling/desync | Isolated proxy/backend fixture, parser analyzers | Parser mismatch validated in lab only | D4 | LATER |
| EDGE-10 | CDN origin exposure and management plane | Architecture/ACL review, approved controlled checks | Edge protections not bypassed via unlisted origin | D0/D3 | LATER |
| EDGE-11 | Robots/sitemap/security.txt discovery | curl, browser | Enumerated paths not automatically treated vulnerable | D2 | WEB |

## 9. Layer L7: web application and business logic

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| WEB-01 | Route and technology inventory | Browser network panel, ZAP spider constrained, httpx | Paths, methods, dependencies and assets | D2 | WEB |
| WEB-02 | Reflected XSS | Burp Repeater, ZAP, Dalfox limited mode | Harmless marker demonstrated in intended context | D2 | WEB |
| WEB-03 | Stored/DOM XSS | Browser test profiles, ZAP, Dalfox / devtools | Synthetic stored marker or DOM sink proof | D3 | WEB |
| WEB-04 | SQL/NoSQL query injection | Manual controlled differential tests, sqlmap detector | Repeatable parser/query boundary effect without dump | D2/D3 | WEB |
| WEB-05 | Server-side template injection | Manual source/template review, SSTImap lab fixture | Parser boundary in isolated fixture | D0; D4 lab | WEB plan only |
| WEB-06 | OS command injection | Source review, Commix lab fixture | Command boundary proven in lab, no production RCE | D0; D4 lab | WEB plan only |
| WEB-07 | Path traversal/LFI | Burp Repeater, reviewed ZAP tests | Normalization failure using safe test fixture | D2/D3 | WEB |
| WEB-08 | SSRF | Source review, self-hosted Interactsh/Collaborator and synthetic target | Unique approved callback correlation, no internal probing | D3 | WEB |
| WEB-09 | XXE / XML parser behavior | Source review, controlled XML test fixture | External entity processing disabled? | D0/D3 | WEB |
| WEB-10 | File upload type and retrieval rules | ZAP/Burp, inert synthetic files | File acceptance/storage/retrieval policy | D3 | WEB |
| WEB-11 | Authorization and IDOR | Autorize, AuthMatrix, synthetic two-role harness | Different roles correctly denied on test objects? | D3 | WEB |
| WEB-12 | CSRF and state-changing requests | Browser devtools, ZAP, two-session harness | Anti-CSRF binding and SameSite behavior | D3 | WEB |
| WEB-13 | Open redirect and URL handling | Manual query review, ZAP passive | Safe redirect target control | D2 | WEB |
| WEB-14 | Session fixation/rotation/expiry | Burp/ZAP, synthetic login flows | Session rotates on privilege change? | D3 | WEB |
| WEB-15 | Password recovery/account enumeration | Dedicated synthetic accounts, manual browser | Same security/privacy behavior for valid/invalid account | D3 | WEB |
| WEB-16 | Business workflow and pricing/privilege boundaries | Threat model, synthetic object workflows | Unauthorized transitions rejected? | D3 | WEB |
| WEB-17 | Error handling and verbose diagnostics | curl, ZAP, code review | Stack traces/secrets not leaked | D2 | WEB |
| WEB-18 | Dependency and JS source risks | Retire.js, SCA, SBOM, developer tools | Vulnerable dependency reachable? Confirm preconditions | D0/D2 | WEB |
| WEB-19 | WebSocket/SSE authorization | Browser devtools, Burp, synthetic tokens | Channel access respects roles/session expiry | D3 | WEB |
| WEB-20 | Deserialization hazards | SAST, dependency/code audit, lab fixture | Dangerous deserialization path evidenced safely | D0; D4 lab | WEB plan only |
| WEB-21 | Race/state transition safety | Replay harness, Burp Turbo Intruder lab | Atomicity of synthetic transaction | D4 lab | WEB plan only |
| WEB-22 | Clickjacking and iframe permissions | Header review, sandbox browser | Frame controls reflect policy | D2 | WEB |

## 10. API: REST, GraphQL, gRPC, SOAP

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| API-01 | API schema and endpoint inventory | OpenAPI importer, ZAP, Postman/Newman | Methods/routes/roles listed | D0/D2 | WEB if same origin |
| API-02 | BOLA / IDOR object authorization | Synthetic two-role harness, Autorize | Object-level denial by identity | D3 | WEB if same origin |
| API-03 | BFLA / function-level permissions | Postman/Newman, AuthMatrix | Privileged functions denied for weaker role | D3 | WEB if same origin |
| API-04 | Schema validation and content types | Schemathesis bounded, Newman | Invalid payloads rejected safely | D2/D3 | WEB if same origin |
| API-05 | GraphQL introspection exposure and access | GraphQL client, ZAP | Introspection policy and field authorization | D2/D3 | WEB if same origin |
| API-06 | Pagination, filtering and overfetch | Manual response diff, synthetic records | No excessive personal field disclosure | D3 | WEB if same origin |
| API-07 | Rate limits, idempotency, retries | Bounded controlled sequential requests | Limits and duplicate-action handling | D2/D3 | WEB if same origin |
| API-08 | Token scope and replay protection | jwt_tool offline, Postman/Newman | Token audience/expiry/scopes correct | D0/D3 | WEB if same origin |
| API-09 | gRPC metadata/mTLS and method authorization | grpcurl in staging; protobuf descriptor review | Method-level security and channel settings | D2/D3 | LATER if separate port |
| API-10 | Webhooks and callback authenticity | Synthetic webhook fixture, config review | Signed event verification and anti-replay | D0/D3 | WEB if same origin |
| API-11 | SOAP/XML security rules | XML source/parser review, lab fixture | Secure entity/schema handling | D0/D3 | WEB if same origin |

## 11. Identity, access control, sessions and secrets

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| IAM-01 | Role/permission graph and least privilege | RBAC matrix, IAM policy analyzer | Excess privileges mapped to principals | D0/D3 | WEB for test roles |
| IAM-02 | MFA enforcement and recovery paths | Synthetic identity flows, config audit | MFA applies to relevant actions | D3 | WEB if implemented |
| IAM-03 | OAuth/OIDC redirect, state, nonce, PKCE | Config, test OAuth client, Burp | Trust and session binding across sign-in | D0/D3 | WEB if implemented |
| IAM-04 | SAML assertions and audience handling | IdP/SP config, SAML-tracer | Signature, audience, expiry | D0/D3 | LATER if separate IdP |
| IAM-05 | JWT validation, algorithm and key lifecycle | jwt_tool offline, source review, test tokens | Signature, issuer, audience, expiry validation | D0/D3 | WEB if applicable |
| IAM-06 | Session revocation and rotation | Two-browser test identity, app logs | Logout/privilege changes invalidate session? | D3 | WEB if applicable |
| IAM-07 | Password reset / account lifecycle | Disposable test identities | Reset token TTL/single-use and alerts | D3 | WEB if applicable |
| IAM-08 | Credential stuffing and brute-force defense | Rate-policy and telemetry review, synthetic rate test | Controls documented without live guessing | D0/D3 | WEB if applicable |
| IAM-09 | Secret scanning in owned code | Gitleaks, TruffleHog offline, GitHub secret scanning | Exposed test secrets and remediation | D0 | LATER unless source supplied |
| IAM-10 | Privileged access and break-glass procedures | PAM/IAM review | Elevated rights are approved, logged and time-limited | D0 | LATER |

## 12. Host, operating system, database and storage

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| HOST-01 | Patch/version and package exposure | Nessus/Greenbone credentialed, osquery, package SBOM | Installed version and reachable flaw condition | D2/D3 | LATER |
| HOST-02 | Secure baseline / CIS configuration | Lynis, OpenSCAP, CIS-CAT (licensed) | Deviations and mitigation | D0/D2 | LATER |
| HOST-03 | Services, listening sockets and firewalls | ss/netstat, nftables/iptables config, Windows firewall | Unexpected listeners/routes | D0/D2 | LATER |
| HOST-04 | SSH/RDP/SMB management access | Config, ssh-audit, Nmap selected scripts | Auth/transport and source restrictions | D2 | LATER |
| HOST-05 | Privilege and service account boundaries | sudoers, PAM, Windows GPO review | Excess privilege or service token risks | D0/D3 | LATER |
| HOST-06 | Scheduled jobs, persistence detection | osquery, endpoint baseline, EDR | Unauthorized startup mechanisms detected | D0/D2 | LATER |
| HOST-07 | Database roles, grants and encryption | DB audit client with read-only account, config | Over-broad grants / encryption setting | D2/D3 | LATER |
| HOST-08 | Backup access, encryption and restore | Backup config/restore test in lab | Recovery point and access controls | D0/D3 | LATER |
| HOST-09 | Object-storage bucket/container ACL | Cloud IAM check, Prowler/ScoutSuite | Public/private access matches intended policy | D0/D2 | LATER |
| HOST-10 | Sensitive data retention, audit and masking | Schema review, DLP policy, synthetic test | Data minimization/privacy evidence | D0/D3 | LATER |

## 13. Cloud, containers, Kubernetes and DevSecOps

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| CLOUD-01 | Cloud IAM roles, trust and credentials | Prowler, ScoutSuite, native analyzers | Misconfigured trust/path to privileges | D0/D2 | LATER |
| CLOUD-02 | Public assets, buckets, ingress and security groups | CSPM, Terraform graph, policy tests | Unintended Internet reachability | D0/D2 | LATER |
| CLOUD-03 | Image and dependency vulnerabilities | Trivy, Grype, Syft SBOM | Vulnerable library with reachability caveats | D0 | LATER |
| CLOUD-04 | Container hardening and privileges | Dockle, Docker Bench, Trivy config | Root/capabilities/mounts/socket risks | D0/D2 | LATER |
| CLOUD-05 | Kubernetes RBAC/service accounts | kube-bench, Kubescape, kubeaudit | Over-broad permissions and pod trust boundaries | D0/D2 | LATER |
| CLOUD-06 | Kubernetes NetworkPolicy and ingress | Policy diff, Cilium/Hubble telemetry | Workload isolation and allowed communications | D0/D2 | LATER |
| CLOUD-07 | Secret storage and key rotation | Vault/KMS/IAM audits | No static secrets in configs/logs/images | D0 | LATER |
| CLOUD-08 | CI/CD workflow and build permissions | GitHub Actions audit, Semgrep, OPA/Conftest | Least privilege for pipelines and artifacts | D0 | LATER |
| CLOUD-09 | SAST and infrastructure-as-code | Semgrep, Checkov, tfsec, CodeQL | Developer-fixable issues and false positives | D0 | LATER |
| CLOUD-10 | Supply chain attestations and artifact signatures | cosign, SLSA provenance, SBOM | Build provenance and verified releases | D0 | LATER |
| CLOUD-11 | IaC drift and baseline regression | Terraform plan (read-only), policy CI | Unexpected config drift logged | D0 | LATER |
| CLOUD-12 | Container runtime / escape impact | Offline advisory correlation; disposable lab fixture | Known preconditions without production exploitation | D0; D4 lab | LATER |

## 14. Client devices, Wi-Fi, desktop and mobile

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| CLIENT-01 | Browser storage and token exposure | Browser devtools, synthetic account | Sensitive tokens not needlessly persisted | D3 | WEB |
| CLIENT-02 | Service worker/cache and offline secrets | Browser devtools, code review | Cached private resources scoped appropriately | D2/D3 | WEB |
| CLIENT-03 | Frontend dependency and CSP interaction | Retire.js, SCA, CSP reports | Component risk with compensating defenses | D0/D2 | WEB |
| CLIENT-04 | Mobile app static analysis | MobSF, jadx, apktool | Manifest, crypto, network-security settings | D0 | LATER |
| CLIENT-05 | Mobile runtime traffic and storage | Emulator/simulator, Frida in own app, proxy | Test credentials and secure storage | D3/D4 lab | LATER |
| CLIENT-06 | Endpoint hardening and EDR | osquery, Defender/EDR console, CIS baseline | Local host posture and alerting | D0/D2 | LATER |
| CLIENT-07 | WLAN authentication and guest separation | AP controller config, passive spectrum, lab clients | WPA3/802.1X/client isolation | D0/D3 | LATER |
| CLIENT-08 | Router/CPE management and TR-069/TR-369 | Config/firmware review, local lab emulation | Secure remote management and update policy | D0/D3 | LATER |

## 15. ISP/telecom: PON, subscriber provisioning, BNG/BRAS, OSS/BSS

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| ISP-01 | OLT/ONU registration, profiles and isolation | OLT read-only commands, EMS exports | Correct serial/LOID/MAC and isolation | D2 | LATER |
| ISP-02 | IPoE/DHCP relay and Option 82 trust | BNG/relay configs, DHCP logs, lab relay | Provisioning binds intended subscriber | D0/D2; D4 lab | LATER |
| ISP-03 | PPPoE discovery/session and RADIUS AAA | BRAS logs, RADIUS accounting, lab CPE | Auth/session/accounting integrity | D0/D2/D3 | LATER |
| ISP-04 | BNG session limits, policy QoS and ACL | Juniper/BNG profiles, session counters | Per-subscriber policy and traffic separation | D0/D2 | LATER |
| ISP-05 | CGNAT port allocation and logging | NAT logs, synthetic traffic, event correlation | Cross-subscriber mapping integrity | D2/D3 | LATER |
| ISP-06 | VLAN/QinQ service stitching OLT to BNG | Switch/OLT maps, config diffs | Customer VLAN mapped only to intended domain | D0/D2 | LATER |
| ISP-07 | Subscriber IPv6-PD and RA protection | DHCPv6-PD logs, lab CPE | Delegations unique and constrained | D0/D3 | LATER |
| ISP-08 | Multicast IPTV IGMP and access segmentation | IGMP reports, switch configs, STB lab | Membership/querier and stream boundaries | D0/D3 | LATER |
| ISP-09 | NMS, SNMP and telemetry credentials | SNMPv3 config, monitor audit | Secure read/write access and allowed sources | D0/D2 | LATER |
| ISP-10 | OSS/BSS permissions and payment audit trails | RBAC review, synthetic billing fixtures | Action attribution, separation of duties, reversals | D0/D3 lab | LATER |
| ISP-11 | Subscriber privacy in CRM/Billing logs | Access reviews, sanitized log samples | PII redaction and authorization | D0 | LATER |
| ISP-12 | CPE firmware and remote-update chain | Firmware hash/signature, offline binwalk, test router | Signed upgrade and default-secure config | D0/D3 lab | LATER |

## 16. Detection, incident response, resilience and recovery

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| DET-01 | Audit log completeness and time sync | SIEM, NTP/PTP configs, sample log correlation | All key actions attributable and timestamped | D0/D2 | LATER |
| DET-02 | WAF and reverse-proxy request correlation | Access logs, WAF dashboards | Approved requests visible with unique case ID | D2 | WEB with owner access |
| DET-03 | EDR/IDS coverage and response playbooks | Detection engineering review, SIEM rule tests | Priority actions detected/triaged | D0/D3 | LATER |
| DET-04 | Synthetic adversary emulation | Atomic Red Team, MITRE Caldera in isolated lab | Expected alert for preapproved lab technique | D4 lab | LATER |
| DET-05 | Backup integrity and restore objective | Test restore, backup audit | RPO/RTO measured, backups protected | D0/D3 | LATER |
| DET-06 | Incident handling/escalation readiness | Tabletop scenarios, runbook review | Contact/escalation/containment steps verified | D0 | LATER |
| DET-07 | Secret leak and token revocation playbook | Gitleaks/TruffleHog on owned artifacts, tabletop | Detection, rotation and revoke workflow | D0 | LATER |
| DET-08 | Regression tracking and retest | Finding lifecycle, repeatable fixture tests | Fix verified against original evidence | D0/D2/D3 | WEB |

## 17. Controlled exploitation, post-exploitation impact and adversary simulations

**This is not a default automated stage**. Each control is off until signed test scope, technique approval, evidence, rollback and a stop switch exist. Use synthetic data and isolated fixtures. The goal is to verify *security boundaries*, not maximize access.

| ID | Hypothesis | Tool family | Minimal admissible outcome | Gate | Case |
|---|---|---|---|---|---|
| EXP-01 | Known CVE affects the detected service | SearchSploit offline, Nuclei safe reviewed template, Metasploit module inspect/check where safe | Version plus actual prerequisites; \`check\` alone not always proof | D0/D2; exploit D4 lab | WEB if in scope |
| EXP-02 | Authorization crossing | Autorize/AuthMatrix, two-test-account harness | Synthetic object blocked/allowed by correct role | D3 | WEB |
| EXP-03 | SQL injection alters query semantics | Burp/ZAP manual differential, sqlmap limited safe detection | Non-destructive reproducible change, no data dump | D2/D3 | WEB |
| EXP-04 | XSS executes in browser security context | ZAP/Burp, Dalfox/XSStrike, isolated browser | Harmless owned marker, no session theft | D2/D3 | WEB |
| EXP-05 | SSRF triggers unintended outbound request | Self-hosted Interactsh/controlled callback | Single matching harmless OAST token | D3 | WEB |
| EXP-06 | Upload policy enables untrusted content | Synthetic inert upload test | File type/routing/permissions verified, no shell | D3 | WEB |
| EXP-07 | RCE-like unsafe interpreter path exists | SAST/patch review, isolated Commix/SSTImap fixture | Lab demonstration only; no production command execution | D0/D4 lab | WEB planning only |
| EXP-08 | Session/identity escalation | Synthetic accounts and role matrix | Explicit privilege boundary outcome | D3 | WEB |
| EXP-09 | Race state corruption possible | Deterministic disposable app fixture, Turbo Intruder lab | Synthetic consistency assertion | D4 lab | LATER |
| EXP-10 | Proxy/parser desynchronization possible | Isolated front/back proxy fixture | Parser mismatch observed without shared edge impact | D4 lab | LATER |
| EXP-11 | Host privilege escalation risk | Local package/patch audit, lab CVE fixture | Reachability + effect in isolated disposable host | D0/D4 lab | LATER |
| EXP-12 | Lateral movement could cross a trust zone | Network path model, synthetic credentials, lab-only BloodHound/Caldera | Graph of feasible route; no real host hopping | D0/D4 lab | LATER |
| EXP-13 | Monitoring does not catch test impact | Atomic Red Team lab and SIEM correlation | Missing/working alert, with no stealth/persistence | D4 lab | LATER |
| EXP-14 | Data boundary allows unintended access | Pre-seeded synthetic canary objects, read-only harness | Evidence of boundary violation without real data extraction | D3/D4 lab | WEB |
| EXP-15 | Credential boundary or token handling risk | jwt_tool offline, session harness | Synthetic token accepted/rejected per policy | D0/D3 | WEB |

**Metasploit adapter design:** separate \`msf.module_search\`, \`msf.module_inspect\`, reviewed \`msf.module_check\` and \`msf.module_exploit_lab\`. Never hand Qwen unrestricted \`msfconsole\`. Not all modules support a harmless \`check\`. Module execution requires independent policy enforcement.

## 18. AI/LLM agents and model-connected tooling

| ID | Check | Tools / sources | Evidence | Gate | Case |
|---|---|---|---|---|---|
| AI-01 | Prompt injection from tool output / websites | Adversarial fixture corpus, mocked browser response | Untrusted data cannot change agent policy | D0 | OFFLINE |
| AI-02 | Agent tool allowlist and arguments | Capability registry, policy unit tests | Unknown tool/args rejected | D0 | OFFLINE |
| AI-03 | Cross-origin, redirect and DNS rebinding protection | Deterministic resolver and redirect fixture | Block occurs before any network call | D0 | OFFLINE |
| AI-04 | Approval token scope and anti-replay | Policy tests, signed case token | Cannot expand scope or reuse an approval | D0 | OFFLINE |
| AI-05 | Duplicate calls, loop detection, checkpoint/resume | Agent fixture, idempotency ledger | Stable completion/error without repeated actions | D0 | OFFLINE |
| AI-06 | Hallucinated findings and false positives | Golden evidence fixtures, counterevidence | No \`confirmed\` without evidence ID | D0 | OFFLINE |
| AI-07 | Exfiltration through prompts, logs or tool args | DLP/secret redaction tests | Sensitive fixtures removed from model-visible records | D0 | OFFLINE |
| AI-08 | Model/provider replacement | Mock adapter/Ollama adapter contract tests | Policy remains unchanged across model | D0 | OFFLINE |
| AI-09 | Unbounded tool impact / resource exhaustion | Negative test suite, per-tool budgets | Hard budgets stop execution | D0 | OFFLINE |
| AI-10 | Versioned prompt and policy provenance | Git SHA, release manifest | Which policy produced an action is auditable | D0 | OFFLINE |

## 19. Qwen capability selection logic

1. **Normalize target:** derive exact origin or explicit asset identifier from the trusted case; never from discovered links. Resolve aliases/redirects defensively.
2. **Determine coverage:** select only test IDs relevant to declared asset type, protocol, application and roles. Mark the rest \`out_of_scope\`/\`not_applicable\`.
3. **Choose weakness candidate:** source observation, alternative hypothesis, expected control, safety classification.
4. **Compare tools:** choose minimal-impact capability with best evidence quality, supported protocol, installed version and stable adapter.
5. **Policy gate:** \`ALLOW\`/\`DENY\`/\`NEEDS_APPROVAL\`; denial is not a model-recoverable error.
6. **Execute and record:** bounded request, exact timestamp, tool/version/options, output hash, unique evidence ID; redact sensitive payloads before LLM context.
7. **Triangulate:** if source fingerprint is the only evidence, mark \`candidate\`, not \`confirmed\`. Second independent method preferred for high-severity findings.
8. **Stop or replan:** no repeated identical actions without new data, no automatic scope expansion, no D4 escalation based on finding severity alone.
9. **Report:** what was tested, what was not, confirmed risks, counterevidence, remediation and retest plan.

### Proposed shared control schema (not implemented yet)

\`\`\`json
{
  "control_id": "WEB-11",
  "case_id": "simnet-ua-web-001",
  "asset_id": "https://simnet.ua:443",
  "hypothesis": "object authorization inconsistent across synthetic roles",
  "proposed_capability_id": "web.authz.synthetic_role_compare",
  "proposed_gate": "D3",
  "approval_status": "not_approved",
  "active": false,
  "expected_evidence": [
    "test object and roles",
    "redacted request and response fingerprints",
    "authorization decision comparison"
  ],
  "preconditions": [
    "test accounts supplied",
    "owned synthetic objects",
    "case and technique approved"
  ],
  "result_status": "not_tested",
  "evidence_ids": [],
  "severity": null,
  "confidence": null
}
\`\`\`

## 20. Tool registry families and delivery order

The tool registry must map *registered capability* -> exact backend adapter (not directly user-supplied CLI), platform/version/license, supported IDs, allowed target types, gate, risk, timeout, request budget, output schema and health check.

| Family | Candidate tools | Initial implementation |
|---|---|---|
| HTTP/TLS and browser evidence | curl, OpenSSL, SSLyze or testssl.sh, browser devtools, ZAP passive | **P0** |
| Web/API controlled analysis | ZAP, Burp manual integration, Nuclei safe reviewed templates, Postman/Newman, Schemathesis | **P1** |
| Fingerprinting / service enumeration | dig, dnsx, WhatWeb, httpx, Nmap curated read-only | **P1**, scope-specific |
| Identity and authorization | Two-role synthetic harness, AuthMatrix, Autorize, jwt_tool offline | **P1** |
| Source, dependency and CI/CD | Semgrep, CodeQL, Gitleaks, Trivy, Syft, Checkov | **P1/P2**, owned source |
| Web specialist | Dalfox, XSStrike, sqlmap limited detector, controlled Interactsh | **P2**, per technique |
| CVE validation and exploit frameworks | SearchSploit, Metasploit module search/inspect/check, lab-only exploit | **P2/P3**, strict gates |
| Host/network/ISP | Greenbone/OpenVAS, osquery, Lynis, ssh-audit, SNMP/OLT/BNG read-only adapters | **P3**, distinct scope |
| Cloud, K8s and supply chain | Prowler, ScoutSuite, Kubescape, kube-bench, Grype, cosign | **P3**, distinct scope |
| Purple-team/adversary lab | Atomic Red Team, MITRE Caldera, synthetic canary fixtures | **P3**, isolated lab |
| Agent reliability | Mocked capabilities, policy rejection suite, duplicate-call detector, checkpoint/evidence store | **P0**, before live operation |

P0/P1/P2/P3 indicate **development priority**, not approval tier D0–D4.

## 21. Required acceptance tests for every adapter

- An out-of-scope FQDN/IP/port/redirect is denied **before** network activity, including DNS rebinding and cross-origin redirects.
- Unknown tools, disallowed methods and excessive parameters are denied, regardless of model suggestions.
- No unapproved D3/D4 action executes; approvals expire and bind case, capability and target.
- Tool missing/unlicensed/health check failure is reported truthfully, never silently ignored.
- Execution has deterministic limits for requests, concurrency, time, memory, output size, file access and retries.
- Evidence has source/provenance, timestamp, stable hash and redaction status.
- No confirmed finding is produced from a banner/CVE version guess alone.
- Redaction is tested with synthetic credentials/PII; no tokens in model context, GitHub or reports.
- The same action cannot loop indefinitely; checkpoint resume is idempotent.
- Production-like negative tests have safe rollback and a demonstrated global kill switch.

## 22. Scope interpretation for simnet.ua

**Permitted planning now:** all IDs may be considered, but only WEB/OFFLINE categories are candidates for the case. \`PLAN_ONLY\` / D0 actions do not contact the website.

**Candidate future low-impact actions, after G0 approval:** \`WEB-01\`, \`EDGE-01\`, \`EDGE-03\`, \`EDGE-07\`, \`EDGE-11\`, \`TLS-01\`, \`TLS-02\`, \`TLS-03\`, \`L4-01\`, \`DNS-01\` metadata for the exact name, and limited passive application tests.

**Separate authorization:** account/session tests D3, intrusive D4 proofs, subdomains, external redirects, infrastructure services, BNG/BRAS, routing, GPON/EPON OLT/ONU, internal services, OSS/BSS, admin/billing portals and privileged customer data.

**No live test was run to create this catalog.** In the current GitHub branch, this is documentation; deployment of the policy gate, installer, test harness and adapters is a later implementation task.

## References

- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP API Security Top 10: https://owasp.org/API-Security/
- PTES: http://www.pentest-standard.org/
- NIST SP 800-115: https://csrc.nist.gov/pubs/sp/800/115/final
- MITRE ATT&CK: https://attack.mitre.org/
- CVSS: https://www.first.org/cvss/
