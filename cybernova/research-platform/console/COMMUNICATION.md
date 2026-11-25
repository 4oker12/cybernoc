# Cybernova Communication Gateway

## Architecture

Human ↔ Web UI ↔ Cybernova Controller ↔ local Qwen.
ChatGPT ↔ Communication MCP ↔ same durable SQLite task/message queue.
Qwen tools ↔ dedicated Tool MCP and integrated local analyzers.

This requires no paid OpenAI API or Open WebUI. ChatGPT sees messages via
connected MCP functions; **MCP does not wake an idle ChatGPT chat**.

The Console uses FastAPI at 127.0.0.1:18794 and calls local Ollama.
The separate Communication MCP uses Streamable HTTP at
127.0.0.1:18796/mcp, with optional local stdio transport.
The existing Tool MCP at port 18792 is unchanged.

## MCP functions exposed for ChatGPT

- cybernova_create_task(title, instruction)
- cybernova_list_tasks(status="", limit=20)
- cybernova_task_status(task_id)
- cybernova_read_dialog(task_id, after_seq=0, limit=30)
- cybernova_pending_reviews(after_seq=0, limit=30)
- cybernova_new_events(after_seq=0, limit=30)
- cybernova_send_feedback(task_id, message, event_key="")
- cybernova_evidence_index(task_id)
- cybernova_get_evidence(task_id, evidence_id)
- cybernova_tool_receipts(task_id, limit=50)

Qwen receives four session-bound tools:
comm_request_review(question,evidence_refs), comm_post_progress(summary),
comm_record_evidence(kind,observation,method,source_ref,source_sha256),
comm_read_dialog(). The model cannot impersonate ChatGPT.

Controller generates SHA256-only tool receipts separately from Qwen model claims.
Qwen reports remain explicitly unverified; no scanner output or secrets are stored
in the evidence journal. The review packet aggregates context, claims and receipts.

## Message lifecycle

1. A human or ChatGPT creates a task.
2. Qwen investigates using its normal agent and research tools.
3. If she needs independent validation, comm_request_review appends a
   request_review message and marks the task needs_review.
4. ChatGPT, when active or invoked by a supported scheduled check, reads
   pending reviews and the corresponding task dialog.
5. ChatGPT sends feedback through the communication MCP.
6. The task becomes queued. A single Console worker claims it and calls Qwen
   with the previous research history plus ChatGPT's new feedback.
7. Qwen writes another result into the same task, optionally requesting a
   new review. The Web UI displays new messages automatically.

There are no remote notifications from MCP to idle ChatGPT. Periodic
inbox checking requires a separate ChatGPT automation after the new MCP
functions have been connected.

## Durable state

SQLite stores tasks, text messages, statuses, timestamps, evidence reference
IDs, monotonically increasing event sequence numbers and optional idempotency
keys. Clients call read_dialog or new_events with after_seq to get deltas.

Default location:
~/.local/share/cybernova/communications.sqlite3

To set an explicit shared location, both processes use the same environment:

    export CYBERNOVA_COMM_DB=/workspace/cybernova-comm/communications.sqlite3

The database contains conversation text but not original HAR/PCAP payloads.
The evidence index returns reference IDs, not the actual artifact bytes.

## Start on Vast

From cybernova/research-platform, after installing console/requirements.txt:

    python -m console.server

In a second local process with the SAME CYBERNOVA_COMM_DB path:

    python -m console.communication_mcp

The Console starts one communication worker by default.
Disable it only for maintenance with CYBERNOVA_COMM_WORKER=0.
The MCP server is bound to loopback and must not be exposed publicly
without a separate authenticated connector.

## ChatGPT connector requirement

The existing CyberSec_Vast plugin has a fixed tool schema. Merely
implementing this service does NOT make its eight MCP functions available
inside ordinary ChatGPT. An authenticated connector mapping or custom
plugin must be connected explicitly by the user. Until then ChatGPT cannot
read the new SQLite inbox directly in this chat.

A supported ChatGPT automation can periodically query pending reviews
once the connector is installed; currently supported cadence may not be
faster than one hour. No paid model API is needed for task storage or Qwen
inference.

## Acceptance tests

    python -m unittest discover -s tests -p 'test_*.py' -v
    node --check console/static/app.js
    python -m compileall -q console

Then perform a real local MCP handshake (initialize, tools/list, tools/call)
and test on a harmless lab task:

1. Qwen calls comm_request_review.
2. ChatGPT reads the event and sends feedback.
3. The worker resumes Qwen exactly once.
4. The answer appears under the same task in the Web UI.
5. Both messages persist across a restart.
6. Repeated event keys do not repeat the action.

Unit tests with fake Qwen/MCP do not establish live deployment. Deployment
must use the exact feature branch commit, not a previous Vast updater release.

## Personal ChatGPT plan fallback

The current full writable custom MCP integration is not generally available on
personal ChatGPT plans. In the Cybernova Web UI, open Instruments / ChatGPT Review:
copy the **Review Packet**, paste it into this ordinary ChatGPT conversation,
and paste the response into **Reviewer feedback**. The user-relayed message
is recorded as a human handoff, never fraudulently as authenticated ChatGPT.
The Qwen worker picks it up and continues the same task; no paid API is used.

The public Cloudflare tunnel exposes only the allowlisted review endpoints via
the existing HTTPS + HTTP Basic bridge. It does not expose Communication MCP
or Ollama. For true unattended ChatGPT ↔ Qwen review, a supported authenticated
connector or GitHub-mediated relay remains to be integrated and validated.
