# Cybernova Lab — GitHub delivery

This private branch is reserved for the Cybernova agent delivery pipeline. It does **not** change `main`.

## Proposed delivery flow

1. ChatGPT commits source files to this GitHub branch.
2. A read-only GitHub deploy key or fine-grained read token lets the Vast host fetch this **private** branch.
3. A small on-host updater polls for new commits (or receives a queue signal).
4. It checks the commit, allowed file paths, hashes and syntax in staging.
5. It backs up the previously installed agent, deploys only `/workspace/cybernova-agent` source files, and runs a smoke test.
6. If the test fails, it rolls back and reports status to the existing MCP observability channel.

## Boundaries

- No GitHub credentials or secrets are committed.
- Updates to the MCP server, credentials or operating system are **not** auto-applied.
- The agent updater should run under a dedicated unprivileged Linux account.
- The first enrollment of Vast requires local configuration of read-only repo access and an updater service.
- Subsequent ordinary agent-code releases should not need a ZIP download or per-command `APPROVE`.
- Publishing a commit does not itself mean it is installed on Vast; deployment requires the on-host updater.

## Current status

Dedicated private branch created. Source publication, credential enrollment and updater installation are distinct steps; deployment is not active yet.
