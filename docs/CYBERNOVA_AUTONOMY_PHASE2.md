# Autonomous runtime phase 2

- Existing SQLite task history is restored from the latest 100 messages, not the first 100.
- Owner-edited cross-session notes are stored in the existing profile outside Git; up to four relevant notes (2,000 characters) are selected by word overlap, subject to researcher profile sharing. No automatic ingestion of raw chat or credentials.
- One-shot scheduled text tasks have persistent UTC due times, a bounded queue and two background worker lanes. They never use tools and do not grant permissions. The normal instrumented worker remains separate. A running job cannot be replayed on restart; pending jobs run when the application is up. Cancel only affects pending scheduled jobs.
- Users can browse independent scheduled tasks while they run; foreground dispatch refuses a queued/running task. This is not arbitrary parallel execution of desktop actions or preemptive cancellation.
- Configurable soft cumulative input-token budget; stop initiating tools when reported usage crosses it, then finalize. A provider call may overshoot; missing usage cannot enforce a limit. The budget applies to main research turn and default background worker, not account GPT or collaboration. Optional follow-up inference skipped after budget. Token totals moved to Inspector.
- Existing profile values and SQLite records preserved. No new service, listener, dependency or Vast connection.
