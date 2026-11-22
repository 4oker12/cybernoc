# Cybernova — Stage 2 work-item orchestration

This is the implementation contract for PR #29. It extends the existing two-model dialogue and does not replace it. GitHub CI, a local Windows installation, a healthy listener, MCP reachability and working model/tool calls remain separate acceptance levels.

## UI and routes

Only http://127.0.0.1:18795/ is user-facing; port 18794 remains the internal API, exposed through the existing authenticated access gateway. The existing API defaults to mode=dialog, while the new UI offers mode=parallel by default.

The user explicitly creates a task, requests a plan, then clicks to launch the bounded batch. A plan does not execute tools.

- POST /api/collab/start — optional mode=parallel or mode=dialog.
- POST /api/collab/items/plan — ChatGPT produces and validates 2–6 tasks with dependency indices.
- GET /api/collab/items?task_id=... — states, dependencies, results, reviews, measured usage.
- POST /api/collab/items/step — atomic research or review claim and one model call.
- POST /api/collab/items/retry — manually retry a blocked item.
- POST /api/collab/items/recover — manually recover a blocked parent without replay.
- POST /api/collab/stop, /resume, /finish — reuse the existing lifecycle.

## Data model and concurrency

SQLite gains the collaboration_runs.mode column (default dialog, preserving legacy rows) and a collaboration_work_items table. Work items have IDs, task foreign keys, positions, descriptions, dependency IDs, state, attempt count, result, review, blocked phase, error and timestamps. Usage data is optional and migration-safe.

All claims are serialized through SQLite BEGIN IMMEDIATE, not a process-wide model lock. Only accepted dependencies unblock downstream work. At most two work items in the same task are running/reviewing concurrently. The plan has at most six items; each research item gets at most three explicitly requested attempts. Rejected reviews return actionable feedback to the next research attempt.

## Failure / recovery

On startup, uncertain in-flight items are blocked and never replayed. Operator recovery moves a blocked parent into paused state only if no work item is still active. Retry of a blocked review resumes review without repeating DeepSeek tools. A pause stops new scheduling while existing calls can finish and persist results; finish cancels unstarted work and closes idle browser sessions without killing an ongoing tool call. This is cooperative cancellation, not process termination.

## Authorization boundary

ChatGPT planning runs without tools. Model-generated descriptions and imported content are not user authorization. The DeepSeek runtime receives an explicit trusted_user_messages list comprising the human's goal and subsequent human clarifications. Internal-host access and computer approvals derive only from that trusted context. Browser sessions use distinct opaque per-item identifiers and isolated profiles. Existing approval gates remain active.

## Observability

The existing authenticated UI shows compact status cards, dependencies, detailed expandable reports, reviewer feedback and a live activity feed polled every 1.2 seconds while a bounded batch runs. Token counts appear only when a provider reports actual measured usage. No hidden chain-of-thought is displayed.

## Acceptance boundaries

The GitHub tests cover dependency gates, concurrency overlap with mocked model calls, duplicate-claim rejection, review and rework, recovery, scope isolation, and browser-control wiring. This does not prove a successful Windows deployment or real ChatGPT/DeepSeek model inference. A local acceptance test must separately check Git/port/PID ownership preflight, the 18795 login, internal health, MCP ListTools, real model responses and actual task-browser separation. Do not merge or deploy solely because CI passes.

## Known limitations

The coordinator is browser-driven rather than a persistent daemon. Closing the browser ends new scheduling. No forced cancellation of already executing shell commands, automatic exponential retry, cross-provider readiness probe or streaming SSE is included here. Rich artifact publications and a larger resource-aware scheduler remain separate extensions.
