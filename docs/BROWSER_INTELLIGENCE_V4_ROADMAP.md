# Browser Intelligence V4 — architecture roadmap

Baseline: v3 `a90701926f0ef790cdfeee43ddc75bc216823def`, PR #52. Target: v4 -> v3; never merge automatically.
Owner: GPT-6.2. No GPT-6.0 delegation interface in this session; independent reads can be parallelized. No deployment or remote machine changes.

## Data flow
Browser DOM/frame/open shadow + available accessibility/visual evidence -> sanitized observations and scoped refs -> semantic context -> tool discovery/routing -> guarded execution -> state delta/verification -> strategy and goal checkpoint -> session observation memory -> next model decision. Page data is untrusted. Existing authorization, write approvals, sensitive input handling and session isolation remain authoritative.

| Stage | A: inspected baseline / gap | B and architectural nodes | Completion criterion |
|---|---|---|---|
| P0.1 semantic | browser_control collector has roles, labels, radio context, flat groups; headings/tables separate | enrich existing collector with nearest semantic containers, heading and relationships; expose on snapshot and search | identical names distinguishable by context; bounded, sanitized output; tests |
| P0.2 hybrid | frame/shadow traversal, screenshot separate, bounds mostly search-only | associate frame-local spatial evidence with stable refs; add coverage and occlusion; evaluate AX availability, screenshot provenance, vision support | model can correlate evidence, unknown not guessed; no hidden values |
| P0.3 interaction | existing typed action dispatcher and ref resolver | extend guarded execution for hover/focus/double click where risk classification and approval remain equivalent; avoid arbitrary JS | one target, verified fresh ref, guard and outcome tests |
| P0.4 execution | v3 catalog and dynamic schema delivery in agent.py | audit registry, exposure and failure paths; preserve manual group restrictions and distinguish discovery from authorization | discovered allowed tool callable with actual schema; unavailable/block reported accurately |
| P0.5 state | page_digest, snapshot_delta, compact results, verify, Network lifecycle | extend digest with semantic/spatial state where relevant; isolate baselines by page; differentiate partial observations and actual outcomes | no false success or cross-tab delta; explicit verification |
| P0.6 adaptation | StrategyTracker and recovery_for | classify no-effect and repeated failure; use observed state and safe alternative strategies | bounded retries and changed strategy; no bypass of controls |
| P0.7 goal | Agent.run and PROGRESS_STORE already set goal and track progress | inspect and extend goal checkpoints and final verification without forcing site scripts | partial and verified completion distinguishable |
| P0.8 memory | refs, digest, strategy and progress already retained | bounded per-session observation records, provenance, stale invalidation, facts versus hypotheses | no credential retention or cross-session confusion |

## Implementation order and record
All stages owned by GPT-6.2 unless a real delegation facility is available. Start P0.1, then integrate P0.2/3 and P0.5/6, audit P0.4 and P0.7/8; update provider-neutral profile without overriding custom profiles. Record per-stage commits, focused checks, limitations. Live DeepSeek/Chromium acceptance remains local. Initial status: all stages pending.

### P0.1 implementation record
Existing collector now reports bounded nearest semantic ancestry, native form association, ARIA description, controls/owns and popup evidence. Search includes group context before the existing collector cap. No new tool or authorization route. Direct heading/explicit labels only; generic unmarked cards, closed shadow roots and full accessibility tree remain outside this stage. Focused sanitizer/collector tests added; execution pending CI or local checkout.

### P0.2 partial implementation record
Frame-local bounds, focus and center-point hit evidence now accompany refs in all snapshot modes; screenshot results declare top viewport coordinate space and non-atomic correlation. No new coordinate action or visibility override. Center hit does not prove interactability or absence of overlay, particularly across frames. Native full AX tree, visual object recognition and screenshot-to-iframe transformation remain pending; explicit correlation coverage is returned. Focused structural tests added; runtime execution pending.
