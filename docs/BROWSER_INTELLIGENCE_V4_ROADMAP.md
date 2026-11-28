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

### P0.3 partial implementation record
Existing browser_click_button dispatch accepts explicit hover/focus/double_click prefixes with a verified ref, preserving the old schema and click path. Double click is limited to ordinary non-form buttons and rejects recognized high-impact/account/payment targets; no forced click or write preauthorization. Existing network policy stays active. Tests added for ref-only gestures and rejecting double click on a form. Arbitrary custom text widgets and richer gestures are not yet covered. Execution pending CI/local checkout.

### P0.4 implementation record
Explicit schema discovery and a rejected-but-registered tool now receive bounded recent priority over group expansion, with the same manual group and deny rules. Candidate exposure is checked after reserving internal meta-tool slots. Browser hover/focus language routes existing interaction tools; no dispatch or authorization bypass. Targeted routing tests added. Execution pending CI/local checkout.

### P0.5 implementation record
Digest/delta now includes tab, frame count, focus/hit and observed control state; cross-tab comparisons yield no baseline. Partial observation cannot prove no change, and additions/removals are explicitly scoped to observed slices. Action completion is not goal verification. Targeted tests cover focus/frame transitions, incomplete observations and tab switching. Runtime execution pending CI/local checkout.

### P0.6 implementation record
StrategyTracker now records repeated no-effect actions on the same observed state separately from exceptions. Observed change resets attempts; incomplete coverage is not treated as proven failure. Advice requests verification or changed authorized strategy. Full response mode retains observations while exposing effect; no automatic alternate actions or bypass. Focused tracker tests added; runtime execution pending.

### P0.7 implementation record
ResearchProgress preserves the open root goal and latest user request separately; completed goals may advance to a fresh generation. Model-declared completion, remaining items and latest explicit browser verification remain distinct, with check invalidation on later browser actions. Agent gives one bounded continuation prompt when a model declares active open work yet returns no call; no forced action and no retry on owner approval or blocked phase. Tests added for goal transitions and verification invalidation. Runtime execution pending.

### P0.8 implementation record
BrowserSession now keeps bounded per-session structural observation memory: observation sequence, generation, state fingerprint, reobserved refs and changed control structures, with navigation/tab invalidation. Only structural properties and refs are retained, not raw text, values, URLs or screenshots. Historical facts never authorize actions and are explicitly marked stale until refreshed. Tests added for memory bounds, changes and invalidation. Runtime execution pending.
