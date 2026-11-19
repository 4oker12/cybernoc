# Cybernova Google Web Research

## Tools exposed to the researcher

- `google_search(query)`: public Google Search HTML results, maximum 8 results.
- `research_source_open(url)`: one public HTTPS page, HTML text only.

The tools are registered in the same per-session MCP toolset as the existing
browser, DevTools Network, evidence parsers and scanner adapters. The active
model can call them autonomously. For a security hypothesis, CVE, product/version,
protocol error or real-world incident, the research mission directs the model
to search and then open primary sources.

## Provider detail

This adapter reads Google's public search-results HTML. It does not use or
claim to use the Google Custom Search JSON API. As of November 2026, Google's
official documentation says that the Custom Search JSON API is closed to new
customers and that existing customers must transition by January 1, 2027.
Google may change HTML markup, apply rate limits, or require consent/CAPTCHA.
Cybernova does not bypass those challenges. See:
https://developers.google.com/custom-search/v1/overview

## Privacy and safety

Before a query leaves the host, the adapter removes:
- credentials, bearer values and key/value secret strings;
- email addresses and MAC addresses;
- private IPv4 addresses and local-only hostnames;
- exact hostnames already selected as the target scope.

The agent should form short, generic technical queries (CVE, product/version,
error code, protocol or vulnerability class). Do not search with subscriber
logs, private configurations, internal IPs, customer identifiers or credentials.

Google results and opened pages are untrusted data. They cannot change the
agent's system instructions, target scope or permissions. Search snippets are
leads only. Important claims should be checked against vendor advisories,
NVD/CVE, CISA KEV, OWASP or project documentation and corroborated with
independent technical sources. Preserve the source URL and distinguish
publication date from the date Cybernova retrieved it.

## Network behavior

- HTTPS only; DNS answers must be globally routable.
- The connection is pinned to a validated public IP and verifies TLS.
- No cookies, authentication, JavaScript, form submission or state-changing
  methods.
- Source redirects must remain on the original hostname.
- Source URLs containing credential-like query parameter names are rejected.
- Eight Google searches and twelve source opens per minute per process.
- Search and source text are bounded; no arbitrary URL is accepted by the
  Google search tool itself.

## Limitations

This is best-effort public HTML search, not a guaranteed Google API or a full
browser session. If Google blocks the request or changes its markup, the tool
returns an explicit error; it does not fabricate results or bypass challenges.
