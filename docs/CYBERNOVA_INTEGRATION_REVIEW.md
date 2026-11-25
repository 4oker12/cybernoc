# Integrated UI/runtime review (2026-11-25)

PR #33 failed three assertions for the clipboard hint. This integrated change preserves the hint and native paste path, adopts the approved palette, and preserves the status/error line and configurable sidebar width. The actual token counter remains in Inspector. Do not merge PR #33 separately after this change.

Other corrections:
- Authorised gateway accepts the existing GET usage-progress endpoint (no unauthenticated access added).
- The background DeepSeek worker uses its own runtime instead of the GPT runtime.
- Foreground research and approved actions persist continuation state against the actual model client used; background results also preserve private provider continuation state.
- Running tasks cannot be requeued through feedback in the ordinary running state; duplicate event keys remain idempotent.
- Input budget checked after JSON tool-selection fallback, before any subsequent tool dispatch.
- A worker that did not stop within the join timeout is not silently forgotten/restarted.

Remaining limitations: a task's review-request status can change before its active execution finishes; full durable execution leases across review/approval/collaboration still need testing and design. Instrumented work across modes can contend for the same Windows desktop, terminal files and provider limits. Text-only workers are independent and use no tools; do not treat this as arbitrary parallel desktop automation. Context budget is soft; no provider usage means no enforcement. No live laptop or external-site checks here.
