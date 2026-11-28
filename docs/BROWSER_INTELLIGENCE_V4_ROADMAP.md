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

#### P0.4 follow-up: declared contracts

Catalog normalization currently synthesizes an empty-argument contract for missing or non-object input schemas. Omit those entries at the shared registry boundary and reject non-finite argument values before dispatch. The same registry supplies model exposure and approval revalidation. A malformed tool must stay unavailable while a valid zero-argument tool from the same catalog still works. Independent review identified the issue. The coordinator owns implementation and verification.

Implemented. The three focused tool-policy, chat-agent and runtime modules passed all 120 tests. Python compilation and the repository artifact guard passed. Parameter validation retains its existing supported schema subset.

### P0.5 implementation record
Digest/delta now includes tab, frame count, focus/hit and observed control state; cross-tab comparisons yield no baseline. Partial observation cannot prove no change, and additions/removals are explicitly scoped to observed slices. Action completion is not goal verification. Targeted tests cover focus/frame transitions, incomplete observations and tab switching. Runtime execution pending CI/local checkout.

### P0.5 follow-up: verification coverage

Control pagination, partial collections and reused tab indices can distort state comparisons. Carry coverage from the collector into verification and the delta, compare action baselines only for the same page, and validate typed control identifiers. The regression checks must distinguish a changed slice from a confirmed change and reject empty identifiers. Independent source review informed the design. The coordinator owns implementation and verification.

Implemented and checked in Cloud Linux. Of 78 focused tests, 75 passed and three Chromium integration tests were skipped. Python compilation and the repository artifact guard passed. A delta reports evidence of a page change within the collected scope. Goal completion requires a separate check.

### P0.6 implementation record
StrategyTracker now records repeated no-effect actions on the same observed state separately from exceptions. Observed change resets attempts; incomplete coverage is not treated as proven failure. Advice requests verification or changed authorized strategy. Full response mode retains observations while exposing effect; no automatic alternate actions or bypass. Focused tracker tests added; runtime execution pending.

### P0.7 implementation record
ResearchProgress preserves the open root goal and latest user request separately; completed goals may advance to a fresh generation. Model-declared completion, remaining items and latest explicit browser verification remain distinct, with check invalidation on later browser actions. Agent gives one bounded continuation prompt when a model declares active open work yet returns no call; no forced action and no retry on owner approval or blocked phase. Tests added for goal transitions and verification invalidation. Runtime execution pending.

### P0.8 implementation record
BrowserSession now keeps bounded per-session structural observation memory: observation sequence, generation, state fingerprint, reobserved refs and changed control structures, with navigation/tab invalidation. Only structural properties and refs are retained, not raw text, values, URLs or screenshots. Historical facts never authorize actions and are explicitly marked stale until refreshed. Tests added for memory bounds, changes and invalidation. Runtime execution pending.

### Provider-neutral model profile
The active local tool profile is expanded with semantics, spatial evidence, ref gestures, schema discovery, effect verification, goal and observation memory. Agent.run injects the shared AGENT_PROFILE with LOCAL_TOOLS_PROFILE when tools are enabled, and appends existing user profile_instructions separately. No user settings overwritten. No new training or provider capability claimed. Full AX/vision and practical DeepSeek acceptance remain outstanding.

#### Profile follow-up: evidence interpretation

The shared defaults still describe native AX as main-document only and omit the new visual hints. Update the built-in instructions against the current collector output. Describe the sampled coverage, geometry and inferred relationships, and preserve additive user profiles. The coordinator owns the profile update. The existing provider-neutral prompt and custom-profile tests must pass.

Implemented. All 66 chat agent and Account GPT tool-loop tests passed. Four live tests on Cloud Linux with system Chromium passed on `93e930a`. They covered native AX and geometry for a nested frame and an open shadow root, inferred card context and a visual hint, state delta and verification, and service worker routing. The operating system, browser distribution and DeepSeek provider in the intended Windows deployment still require hands-on validation.

### P0.2 refinement: native AX evidence
Targeted control search and screenshot observations now request up to six native Chromium AX nodes for verified main-document DOM refs, correlate via backendDOMNodeId and expose only role, ignored and allowlisted boolean/enumerated states. No AX names, values, descriptions or raw nodes returned. Coverage explicitly partial; iframe/shadow mapping and full visual recognition remain outstanding. Tests mock CDP node correlation and redaction; live backend verification remains required.

### CI baseline correction
The v3 HEAD quality gate (run 46128600459) already failed test_large_catalog_routes_exact_tool_without_exceeding_provider_budget: expected 158 omitted vs actual 159. Production correctly excludes both internal meta-tools from discovered/omitted external counts. The test now excludes both rather than changing routing or weakening its assertions. V4 run 46136671085: Python compilation and repo guard passed; 661 tests run, one inherited assertion failure, three skipped. New HEAD must be checked independently.

### V4 continuation — P0.1 inferred repeated content containers
A bounded structural heuristic recognizes repeated sibling div containers with similar immediate-child shapes, a local visible control and a visible title/media signal. Returned `card_candidate` groups are explicitly inferred, include ordinal and evidence, and participate in the existing targeted search. No new actionable refs or website-specific selectors. One-off or differently shaped cards may remain unclassified. Sanitizer unit test and local Chromium fixture added.

### V4 continuation — P0.2 cross-frame and open-shadow AX correlation
Replaced main-document-only selector lookup with bounded CDP search, backend node resolution and collector WeakMap identity verification. Sample prioritizes distinct frame/shadow scopes; uses frame CDP targets where available and page target for same-process frames. Maps verified ref bounding boxes into top viewport through Playwright, and includes sampled nested controls in screenshot metadata when their box intersects the viewport. Coverage remains partial; intersection is not proof of visibility or atomic capture. Mock and local Chromium fixtures added; no raw AX values or names exposed.

### V4 continuation — P0.2 visual object evidence
The collector reports bounded DOM hints for rendered images, SVGs, canvas/video and small icons owned by controls, including rendered aria-hidden decorative icons. It exposes label provenance, geometry and owner_ref only when the owner was observed, never source URLs or new action targets. Targeted search can find hints by owner/card context; screenshot includes main-viewport hints alongside the masked image. Text-only models receive DOM evidence, not fabricated pixel recognition. Native pixel interpretation depends on model vision support. Unit and Chromium fixture added.

### V4 continuation — P0.3 targeted complex widget interactions
The collector recognizes explicit tree/menu/listbox/grid/toolbar roles and untyped keyboard-focusable text candidates. It reports allowlisted ARIA pressed/current/active-descendant state. Existing click tool accepts ref-scoped non-activating navigation keys, verifies actual focus and records before/after widget state; `activate:ref` is limited to explicit supported widget roles outside forms/nested controls and shares high-impact and network guards. No arbitrary JS, force click, raw keyboard sequences or activation of untyped candidates. Added unit and local Chromium fixtures.
