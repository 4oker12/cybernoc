# Cybernova — Qwen as co-developer and simplified operations

## Implemented in GitHub (deployment is separate)

Qwen remains a security researcher and becomes a coding agent for the Cybernova
codebase. Its CommunicationToolClient exposes eleven developer tools alongside
existing MCP/security tools. Every workspace is bound to a durable task.

| Tool | Capability | Invocation |
|---|---|---|
| dev_workspace | Separate Git branch and worktree per task | Automatic |
| dev_list / dev_read / dev_search | Inspect repository source | Automatic |
| dev_edit | Create code or replace exactly one text occurrence | Automatic |
| dev_delete / dev_move | Delete or rename task-branch source files | Automatic |\n| dev_diff | Git diff and status | Automatic |
| dev_test | Execute unittest without root privileges | Automatic |
| dev_commit | Commit only the task worktree changes | Automatic |
| dev_command | Run custom argv without shell or root | Requires owner approval |
| dev_push | Push Qwen task branch to origin | Approval and Git write key |
| dev_open_pr | Create PR through GitHub CLI | Approval and Git write token |

**Implementation is not proof of a working deployment.** First live trial must
show workspace creation, read/edit, diff, test and commit receipts by the Qwen
model. Publication requires separate write credentials and owner approval.
The live console checkout must never be edited by these tools.

Source path: /workspace/cybernova-chat-communication.
Qwen worktree root: /workspace/cybernova-dev-workspaces.
Configuration: CYBERNOVA_DEV_SOURCE and CYBERNOVA_DEV_WORKSPACES.

GitHub publication is **not enabled by default**: Vast currently has a fetch-only
deploy key. For push configure CYBERNOVA_DEV_WRITE_KEY (private SSH key path).
For PR creation configure CYBERNOVA_DEV_GITHUB_TOKEN (private GitHub token).
Never put keys, passwords, task DBs, weights or tokens inside worktrees.

## Simplification target: one stable private entrypoint

Existing infrastructure separately manages Web UI, Basic-Auth bridge,
Cloudflare Quick Tunnel, SSH forwarding, MCP, Ollama GPU and GitHub updater.
These are different responsibilities, not seven different reasoning agents.

Proposed deployment:

    User desktop / phone
             |
    One private authenticated URL
             |
    Cybernova controller + Web UI
        /          |         \
    Tasks DB     MCP tools    GitHub PR + CI
             |
    Provider-neutral LLM adapter
          /                \
     Local Ollama      Hosted HTTPS inference
      (GGUF)          (own GPU endpoint)

The controller and model runtime do not have to run on the same machine.
Use one named Cloudflare Tunnel with Access to reach a stable private hostname,
or Tailscale for private-only access. Keep raw Ollama, MCP, GitHub credentials,
and admin ports behind the gateway. One permanent domain is preferable to
rotating trycloudflare links. Keep the existing bridge in place until new
access, OAuth callback and tool calls pass end-to-end tests.

GitHub remains the source of truth; only private SQLite/configuration needs
persistent backup. One portable CLI for up/status/backup/restore is a NEXT
migration step, not an already implemented feature.

## Model provider options (already implemented)

Local:
- CYBERNOVA_LLM_PROVIDER=ollama
- CYBERNOVA_MODEL=cybernova-security:30b

Remote HTTPS OpenAI-compatible Chat Completions:
- CYBERNOVA_LLM_PROVIDER=openai_compatible
- CYBERNOVA_LLM_BASE_URL=https://OWN-ENDPOINT/v1
- CYBERNOVA_MODEL=provider-model-id
- CYBERNOVA_LLM_API_KEY_FILE=/PRIVATE/PATH/key

Remote model receives user messages and tool evidence. Use a private,
approved provider for sensitive materials. Provider switch requires controlled
service restart. Generic Qwen API does not imply the exact Heretic weights.
For exact weights run the chosen GGUF on your own GPU endpoint and verify its
artifact digest.

## Deployment stages

A. Test Qwen developer workflow locally in isolated task worktree.
B. Explicitly configure separate scoped write credentials and PR review.
C. Move model inference off Vast behind the existing provider adapter.
D. Replace temporary access links with one stable authenticated URL only
   after browser access, OAuth, and MCP function end-to-end.
