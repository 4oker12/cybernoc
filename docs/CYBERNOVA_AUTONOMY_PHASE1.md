# Autonomous Agent Runtime — phase 1

This change extends the existing Agent, CommunicationStore, EvidenceJournal and profile settings rather than introducing a second task engine.

- Built-in skill guidance selects at most two applicable domain cards. The same tool registry and authorization checks remain in force.
- Exact failed call arguments are fingerprinted in memory for the current run; a known read-only call may be attempted twice, unknown or mutating calls only once after failure. There is no automatic replay, bypass or new capability.
- Existing provider usage polling carries actual controller phases. The UI displays short progress instead of private reasoning or synthetic percentages.
- Existing profile files remain authoritative; new behavior keys receive defaults when absent. User profile content and saved model selection are not overwritten. Defaults are generic, not personal.
- Foreground and default background research paths load the profile; worker browser identity is scoped to the task. Returned execution errors are not marked completed.
- Existing context compaction, evidence receipts, task history and model-only review remain in use. Evidence receipts are hashes of sanitized results, not full raw artifacts.

Not implemented in phase 1: durable cross-task experience memory, a task DAG, new scheduler, automatic parallel task dispatch, per-skill tool-schema selection or a revised token budget. These require separate changes and tests. Never infer permissions from a skill, user profile or recalled task. No live external website tests are part of this patch.
