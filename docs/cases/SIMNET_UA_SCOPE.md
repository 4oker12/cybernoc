# Case brief: SIMNET public website (initial scope)

Case ID: `simnet-ua-web-001`
Created: 2026-11-17 (Europe/Kyiv)
Status: `PLAN_ONLY` — no automated external requests executed
Requested by: operator in ChatGPT conversation
Authorization claim: user explicitly identified `https://simnet.ua/` as an authorized target. Preserve the statement as a scope claim; do not infer authorization over other domains or networks.

## Scope
- **Included:** Public HTTPS website at `https://simnet.ua/` (the exact origin `https://simnet.ua:443`).
- **Excluded until independently included:** `*.simnet.ua` subdomains (including `www` if distinct), `my.simnet.kiev.ua`, `admin.simnet.kiev.ua`, other portals, mail, public IP/CIDRs, related infrastructure, API hosts on other origins, clients and third-party services.
- In-scope public paths hosted on the exact origin are candidates for site inventory. Cross-origin redirects are **not** permission to probe the target of the redirect.
- DNS, certificates, passive public information may be considered for planning and may identify out-of-scope services; identification is not permission to test.

## Known values
```json
{
  "case_id": "simnet-ua-web-001",
  "target_url": "https://simnet.ua/",
  "allowed_origins": ["https://simnet.ua:443"],
  "mode": "PLAN_ONLY",
  "scope_type": "exact-origin",
  "authorization_status": "user_asserted",
  "stage": "P0",
  "active_requests_allowed": false,
  "max_actions": 0,
  "exclude_cross_origin": true,
  "excluded_categories": [
    "customer portals",
    "billing/admin portals",
    "subdomains",
    "third-party services",
    "other ports",
    "neighboring IP assets",
    "other provider infrastructure"
  ]
}
```

## Missing before active tests
- Named authorization/engagement record and approval for individual test techniques.
- Test window, maximum request rate/concurrency, timeout, stop contact.
- Handling of user accounts, personal data and test data.
- Whether redirects and CDNs may be included.
- Whether authenticated roles and internal service access are in scope.
- Backups/rollback plan and separate approval for intrusive validation / post-exploitation.

## Phase-specific plan
1. P0: finalize rules of engagement and limitations.
2. P1: model website boundaries: visitor -> DNS/TLS -> HTTP frontend -> application endpoints -> dependent services; mark observations versus assumptions.
3. P2: passive OSINT: domain registry, certificate transparency, public DNS metadata, publicly documented technologies and archived resources. Do not treat related domains as in scope.
4. P3: after gate, low-impact baseline: response status/redirect chain, security headers, TLS settings, robots/sitemap and endpoint inventory subject to rate limit.
5. P4: after gate, vulnerability analysis against specifically approved paths and methods: configuration, access control, sessions, input handling, OWASP WSTG coverage; optional scanners only if installed, configured and approved.
6. P5: manual non-destructive validation with redacted evidence and false-positive triage.
7. P6/P7: **separate explicit approval** for proof and post-exploitation impact study; use lab/staging and synthetic markers whenever possible.
8. P8/P9: evidence-linked report and remedial retest.

## Agent deliverable in current mode
Return only a site-specific plan, assumptions, missing authorization parameters, proposed low-impact checks and evidence expectations. Do not claim that a scan or live check has run. Do not attempt vulnerability exploitation.

See [Pentest Workflow Plan](../architecture/PENTEST_WORKFLOW_PLAN.md) and [Qwen Agent Contract](../architecture/QWEN_PENTEST_AGENT_PROMPT.md).

## Catalog selection for this case
Use [full-stack control IDs](../architecture/FULL_STACK_TEST_CATALOG.md), [machine-readable disabled control seed](../architecture/catalog/full_stack_controls.json), and [validation toolbox](../architecture/VALIDATION_TOOL_CATALOG.md). Only exact-origin WEB controls are candidates; all other sections are educational/planning or require separate assets and approvals. This does not change `PLAN_ONLY` or authorize a scan.
