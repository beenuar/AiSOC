# Parity plan progress

Mirrors [`plans/aisoc_parity_plan.plan.md`](plans/aisoc_parity_plan.plan.md),
which is the source of truth and is not edited. Modelled on
[`GAP_CLOSURE_PROGRESS.md`](GAP_CLOSURE_PROGRESS.md).

The plan was captured against `v14.0.0` (commit `079fdb6`). `origin/main` was
at `079fdb69` with **zero commits since the tag** when work started, so every
path, line reference and number the plan cites was checked against the tree it
describes rather than a moved one. Where they disagree, the disagreement is a
Deviation below and the tree wins.

Its precondition — "ask the maintainer once whether the private security batch
has been merged and released" — was answered: it had not been, and it is being
worked first. Progress on it is in
[`SECURITY_BATCH_PROGRESS.md`](SECURITY_BATCH_PROGRESS.md).

## Pre-existing state, captured before any code was written

See the same section of `SECURITY_BATCH_PROGRESS.md`; both plans started from
one measurement of the untouched tree. In short: 77 of 84 gates pass, the seven
that do not are six argument or token refusals plus one environmental mypy
finding, and the console suite is 816 tests green with a clean type-check.

Numbers re-derived at the start, to be used instead of the plan's:

- **CORE is 16 compose services**, and the tree already has an authoritative
  answer: `scripts/check_profile_service_counts.py` reports `core 16, full 22`
  and validates every published figure against `docker-compose.yml`. 16 counts
  the long-running services and excludes the one-shot `ollama-pull`, which is
  the right convention. Parity 1.2 is therefore not "derive the count" but
  "point the four disagreeing strings at the gate that already derives it".
  See D3.
- Claim matrix: **241 rows, 241 GATED, 0 PARTIAL, 0 NO GATE**.
- `scripts/` holds 183 `.py` files, 84 of them named `check_*.py`.
- Next migration number: **076**. Next ADR: **0009**.
- Ratchets: `MAX_UNAUTHORIZED = 28`, tenant-predicate exceptions 35.
- `README.md` is at its 250-line cap, so Phase 1 links rather than adds.

## Deviations: where the plan and the tree disagree

### D1. Phase 11 of the gap-closure plan already shipped

The plan's 1.2 says "the gap-closure tracker still marks file analysis as
blocked, although v12.0.0 shipped the sandbox providers". Confirmed, and the
scope is all three sub-items, not one: `GAP_CLOSURE_PROGRESS.md:469-475` marks
Phase 11 and 11.1 through 11.3 as `[!]` blocked, while the tree carries
`services/api/app/services/sandbox/base.py` plus the CAPEv2, mock and
MalwareAnalyzer providers, the upload policy with migration
`064_sandbox_upload_policy.sql` and `scripts/check_sandbox_upload_policy.py`,
the enrichment and agent-tool wiring, and six routes at
`endpoints/sandbox.py:171-263`.

### D2. Two of the four gates Phase 1.4 asks for already exist in part

`scripts/check_route_shadowing.py` exists, and it cannot catch the duplicate
`get_investigation` pair that 1.3 names. Its own docstring says so at line 27:
"Two modules included under one prefix can shadow each other and this will not
see it." Two independent reasons, both worth knowing before extending it: it
groups by `(service, path, router)` and the two paths differ before mounting
(`/investigations/{run_id}` against `/api/v1/investigations/{run_id}`, because
the prefix comes from an app-level `include_router` the AST pass cannot see),
and `shadows()` only sets `captures=True` when a parameter segment faces a
literal one, so identical paths compare equal and report nothing.

A console route-contract gate also exists in narrow form.
`scripts/check_ledger_replay_contract.py` pins `CLIENT_OBJECT = "ledgerApi"`
against `ROUTER_PREFIX_DEFAULT = "/investigations"`, with a bidirectional
server-only allowlist. It is a working pattern to widen, not a greenfield
build. `scripts/check_sdk_surface.py` is SDK-only as the plan says.

### D3. There is no `core` profile, and the count already has a source

Plan item 1.2 says to "take the real count from `docker compose config` for the
CORE profile". There is no `core` profile in `docker-compose.yml`, so that
command cannot answer the question — CORE is the set of services declaring no
profile.

But the derivation the plan asks for already exists.
`scripts/check_profile_service_counts.py` reports `core 16, full 22`, holds 18
published figures against the compose file, and refuses any new figure that no
`CLAIM_SITES` entry validates. It refused one during this batch, correctly: a
claim-matrix row published a service count that nothing checked.

So 1.2 is not "derive the count". It is "point the four disagreeing strings at
the gate that already derives it": `install.sh:784` says 10 while naming 9 on
the next line, `walkthrough.mdx:80` says fifteen, `Makefile:157` says fifteen,
and `scripts/generate_slo_alerts.py:5` says 17.

### D4. Three counts in 1.1 and 1.2 are wrong in different directions

- **Playbooks are 62, not 50.** `playbooks/README.md:13` says 50 and its tree
  enumerates 9 directories summing to 50; the tree holds 62
  `*.playbook.json` across 21 directories, which is what
  `marketplace/index.json` already publishes as `playbook_packs: 62`.
- **ATT&CK coverage over executable rules only is 387 technique ids**, or 168
  unique base techniques. The published 493 (`marketplace/index.json:540`) is
  the union over all 7,155 marketplace items with sub-techniques counted
  separately; detections-only is 491.
- **The 68-hunt library is a true number.** 68 YAML hunts exist. Only the
  "hunting agent" half of that README row is unbacked, so 1.1 narrows the row
  rather than the count.

### D5. A count in `marketplace/index.json` disagrees with its own data

Neither document raises this. `stats.executable` reads **2767** while the item
flags say `executable: true` on exactly **2603** and `false` on 4388. A
headline number and the data under it, in one file, disagreeing by 164. Folded
into 1.1's coverage row since both are published from the same generator.

### D6. Compliance is 5 frameworks and 24 controls, and 87 controls are unread

Plan item 1.1 narrows the six-framework claim "to the 24 controls across 5
frameworks the API maps", which is right:
`services/api/app/api/v1/endpoints/compliance.py:66-101` maps SOC2 7, PCI-DSS
5, HIPAA 4, ISO27001 4, NIST-CSF 4, with DORA absent. Two things to know while
doing it: a second, smaller mapping in
`services/api/app/services/compliance_mapping.py:16-29` holds 12 controls
across 2 frameworks, and the richer
`services/api/compliance_frameworks/*.yaml` (87 controls across five
frameworks, DORA included) is **loaded by nothing** — zero `.py` references.
PDF export does not exist in either module.

### D7. Two claims in 1.1 are already partly retracted

- **MSSP ARR is gone.** `apps/web/src/components/mssp/MSSPDashboardView.tsx:8`
  records the removal of the fabricated ARR, risk and headcount strip, and
  `MSSPDashboardView.test.tsx:276` asserts `queryByText(/ARR/)` is null. Only
  `apps/docs/docs/intro.md:61` still advertises it, so that row is a doc edit.
- **Shift handoff, EASM and team analytics all exist as real code.** The
  intro.md row removes four items of which three have implementations, so it
  narrows rather than deletes.

### D8. The memory overclaim is narrower than written

Plan item 1.1 narrows the landing-page claim "to the reason-coded memory that
exists". All three tiers do exist as code
(`services/agents/app/memory/{session,working,institutional,manager}.py`); what
does not exist is **pgvector** — no reference in `institutional.py`, no
migration creating the extension, and the only mention is a hedged docstring at
`memory/__init__.py:8`. `MemoryManager` also has no production caller, which is
a reachability finding for 1.4 rather than a claim edit.

## Phase 1: Make every claim true on the default path

> **How these boxes are set.** A box is ticked only where this file's own
> per-phase section below records what changed, or where a later change
> closed it and said so in the same commit. The ones still unticked are
> genuinely open — several are partial, and a partial item reads better
> unticked than ticked with a footnote. Nothing is ticked on the strength
> of a plan entry alone, which is the failure this document exists to
> avoid.

- [x] **1.1** Retract or narrow the overclaims
- [x] **1.2** Clear the documentation drift
- [x] **1.3** Repair the broken console paths
- [x] **1.4** Make the gates path-aware

## Phase 2: Govern and protect alert closure

- [x] **2.1** Per-tenant, per-class closure policy
- [x] **2.2** Kill switch
- [x] **2.3** Learn only from humans — the urgent half ships as security S10
- [x] **2.4** Pseudonymize before hosted egress
- [x] **2.5** One model path for every LLM call
- [x] **2.6** Enforced budgets

## Phase 3: Prove verdict quality on the default install

- [ ] **3.1** Give the default install evidence
- [ ] **3.2** Accuracy on the shipped model
- [ ] **3.3** Behavioural injection suite
- [ ] **3.4** Before-and-after measurement
- [ ] **3.5** QA sampling of auto-closed alerts
- [ ] **3.6** A grounded copilot
- [ ] **3.7** Evidence bundles

## Phase 4: Enterprise identity and the operator console

- [ ] **4.1** SSO end to end
- [ ] **4.2** Console MFA
- [ ] **4.3** Custom roles everywhere — ships as security S13
- [ ] **4.4** Audit log for tenant admins
- [ ] **4.5** Operator pages
- [ ] **4.6** Internationalisation
- [ ] **4.7** Accessibility on core views

## Phase 5: Close the response and detection loop

- [x] **5.1** Alert-triggered playbooks
- [x] **5.2** Approval as a durable pause
- [x] **5.3** Steps that do something
- [x] **5.4** Tenant tuning inside fusion
- [ ] **5.5** Rules that can fire
- [ ] **5.6** Case depth
- [ ] **5.7** Delivery

## Phase 6: Agent parity, then platform depth

- [x] **6.1** Hunting
- [ ] **6.2** Detection engineering
- [ ] **6.3** Custom agents
- [ ] **6.4** Phishing operations
- [ ] **6.5** Semantic memory with provenance
- [ ] **6.6** MCP over the network
- [ ] **6.7** Agent identity and AI-agent baselines
- [ ] **6.8** Deployment completeness
- [ ] **6.9** Scale
- [ ] **6.10** Collection and standards

## Maintainer-only items

- [ ] Fund a hosted-model key so 3.2 and 3.3 can report hosted results
- [ ] Sign at least one design partner willing to replay closed alerts
- [ ] Publish the npm and PyPI packages and the MCP server package
- [ ] Commission an external penetration test, and SOC 2 or ISO 27001 for the
      hosted service
- [ ] Add a second maintainer with merge rights
- [ ] Decide when to cut the planned major, and the cadence of the stable
      channel

## Notes for the next session

The security batch comes first and is tracked separately. Phase 1 starts once
it has landed and been released, because several of its items assume those
fixes exist.

## Phase 1.1 — overclaims retracted (2026-10-01)

All twelve rows narrowed or removed, each naming the sub-item that restores it.
Every figure re-derived from the tree rather than copied from the plan.

| Claim | What it says now | Restored by |
|---|---|---|
| Hunting agent + 68-hunt library | The 68 YAML hunts are real; the **agent is not wired** (nothing outside its test imports it) and the scheduler replays synthetic JSONL | 6.1 |
| Hosted egress is pseudonymized by default | Retracted. The redactor exists and is unit-tested; **no LLM call site invokes it**. Matrix row 19 narrowed from "no data exfiltration" with the reason in the row | 2.4 |
| Institutional memory on PostgreSQL + pgvector | Narrowed to reason-coded key/value on plain Postgres. **No pgvector, no embedding** on that path | 6.5 |
| `auto_close` grant closes alerts of that class | Recorded but **not enforced**: no code reads the grant, closure still uses one process-wide threshold | 2.1 |
| SAML, OIDC, group mapping, `SAML_IDP_METADATA_URL`, TOTP, per-role MFA | Moved to planned. Both handlers answer 501 since v15.0.0 and neither provisions a user, binds a tenant nor maps a group | 4.1, 4.2 |
| SOC 2 Type II dashboard; six frameworks including DORA | Narrowed to **24 controls across 5 frameworks**, DORA absent | 1.3 |
| Shift handoff, EASM, MSSP ARR dashboard, gamification | Removed from `intro.md` | None |
| WCAG AA full pass | Narrowed to the components axe covers | 4.7 |
| EU residency, `events_dist`, active-active, RPO/RTO | Labelled a design, banner at the top of the document | None |
| GCP KMS and Vault Transit implement the same protocol | Corrected: `get_vault` accepts local and AWS KMS only | None |
| Tenant skills authored in a console editor | Corrected: API-only | 6.3 |
| ATT&CK coverage of 493 techniques | **Generator fixed, not output.** Coverage now counts executable rules only: **391**, labelled tag coverage. The 493 survives as `unique_techniques_all_rules` | 5.5 |

Two figures from D4 and D5 moved while this was written, which is why the plan
says to re-derive rather than copy:

- ATT&CK over executable rules reads **391**, not the 387 captured. The corpus
  grew; the method is what matters.
- `stats.executable` read **2,767** against item flags of **2,603**. The 164 in
  between are playbooks and plugins carrying no flag. Both are defensible
  numbers; publishing one of them under the name `executable` was not, so the
  index now reports `executable_detections`, `reference_only_detections` and
  `not_a_detection` separately.

## Phase 1.2 — documentation drift cleared (2026-10-01)

Generators fixed where a generator owned the number, per the plan's rule.

| Drift | Was | Now |
|---|---|---|
| `playbooks/README.md` | 50 playbooks across 9 directories | 62 across 21, the figure the marketplace index already published |
| Hunt scheduler docstring | synthetic is "the default in dev/CI" | synthetic is the default **everywhere** and the only provider implemented, so scheduled hunts run on a fixture corpus on every deployment. Parity 6.1 |
| Detection engine docstring | "rules are indexed by `product`" over an 817-rule corpus | the whole corpus is evaluated per event; `_candidates` returns `self._rules` unchanged and the docstring now records why a product pre-filter was removed. Indexing is parity 6.9 |
| Auto-triage docstring | metrics "exposed via the /triage/stats API" | no route exposes them; that endpoint has never existed |
| `install.sh`, `walkthrough.mdx`, `Makefile` | 10, fifteen, fifteen | **16**, derived by `check_profile_service_counts.py`, and all three now **registered** in its `CLAIM_SITES` so none can drift again. 18 published figures became 21 |
| ClickHouse schema comment | "hot tier, 30 days" over a `90 DAY` TTL | says 90 and points at the TTL that governs |
| Upgrade guide | no per-major section at all | a table covering **v10 through v15**, each row saying what an operator must do, derived from each major's own `### BREAKING` section |
| `GAP_CLOSURE_PROGRESS.md` Phase 11 | `[!]` blocked | `[x]`, with every file it claims verified to exist |
| CONTRIBUTING | Python 3.12, four severity tiers, hand-written connector docs | 3.11 (what CI runs), five tiers with the no-collapse rule, generated pages |

The registration matters more than the correction. Three figures had drifted
to numbers the compose file never supported, and an unregistered figure is one
nobody notices going stale, which is how all three got there. Proven by
drifting `install.sh` to 11 and watching the gate name it.

## Phase 1.3 — broken console paths repaired (2026-10-01)

| Was broken | Fix |
|---|---|
| 7 compliance calls to 4 route shapes that 404'd | Built the routes with real rows: `GET /{framework}`, `/heatmap`, `/export` (CSV and JSON, hash chain included) and `POST /{framework}/collect`. Slug mapping derived from the `FRAMEWORKS` keys, so a new framework needs no second edit |
| `POST /{framework}/collect` could have been another no-op | It writes **real evidence rows** from real platform state: audit-log depth, RLS table count, credential-key configuration, passkey enrolment. **10 of 24 controls**, every id read out of `FRAMEWORKS`. The other 14 report `manual` |
| The case report pane fetched a route nobody had written | `GET /cases/{id}/investigations/{run_id}/report.md`, proxied to the agents service with the same two-step tenant scoping the sibling route uses, which that route shipped without (GHSA-x2gf-3p79-wvgm) |
| Two agents handlers on `/api/v1/investigations/{run_id}`, each reading its own store | `router.py`'s pair moved to `/api/v1/agent-runs`. It had no caller; `investigate.py` owns the lifecycle and its report routes, so it keeps the canonical path and the status poll now reads the store that is written |
| honeytokens and purple-team had no rewrite | Added, and the `NEXT_PUBLIC_*` bases removed: Next inlines those at build time, so a published image could not be pointed anywhere by configuration |
| 5 dead client functions | Deleted (`agentsApi.investigate`, `.getInvestigation`, `.streamInvestigation`, `graphApi.getPaths`, `.getBlastRadius`, `alertsApi.getTimeline`). The plan said seven; six is what no route served **and** nothing called |

### Two gate defects found on the way

**The S1c console-credential gate had a blind spot.** `FrameworkView.tsx` called
the compliance API with a bare `fetch` and no `Authorization` header, and the
gate reported the tree clean. The fetcher classifier was right; the **key** was
a variable (`const dashKey = ...`), so no API path appeared at the call site
and the call was skipped. The gate now resolves a local binding: 33 calls seen
became 34, and re-injecting the defect makes it name the file and line.

**The new route-contract gate was vacuous in its first version.** It treated
any matching Next rewrite as resolution. `/api/v1/:path*` routes everything
left over to the API service, so all 209 console paths passed against a tree
with 14 broken calls. A rewrite is proof of routing, not of service, so a
rewrite now only counts when the service it points at actually serves the
path. **14 findings pre-fix, 0 after.**

### Deviation D8: six dead client functions, not seven

The plan says seven. Six is what the measurement supports: 22 client members
have no caller outside `lib/api.ts`, but 16 of those target routes that exist,
and an unused-but-working client function is a product-surface judgement
rather than a correctness defect. The six removed are the ones that were both
uncalled and pointed at nothing.

## Phase 1.4 — the gates are path-aware (2026-10-01)

| Gate | What it closes |
|---|---|
| `check_module_reachability.py` (new) | A claim row could pass on a unit test of a module nothing imports. **889 of 926 modules reachable from 68 entry points; 37 allowlisted** with a reason each. Tests are deliberately not entry points: a module imported only by its own test is the shape being looked for |
| `check_route_duplicates.py` (new) | Two modules under one prefix shadowing each other, which the static pass records in its own docstring as invisible to it. Names `agents: GET /api/v1/investigations/{run_id}` with both owners on the pre-phase tree |
| `check_console_route_contract.py` (new, 1.3) | A console path that no service serves. 14 pre-fix, 0 after |
| `check_claim_gate_matrix.py` (extended) | Every row now declares `core` or `full` (**232 core, 24 full**) and must name a runnable gate rather than prose |
| `check_python_route_state.py` | The Python demo-state and module-global half. **Already shipped in v15.0.0**, so this sub-item is a deviation rather than work |
| `check_console_auth_headers.py` (extended, 1.3) | A `useSWR` key held in a variable, which is how an uncredentialed compliance call survived the sweep meant to find it |

### The reachability gate found its own bugs first

Its first run reported **159** unreachable modules. Two were defects in the
gate, not the tree: a package's `__init__` resolved `from .x import Y`
against its *parent*, so every module a package re-exported read as dead;
and importing `a.b.c` did not mark `a` and `a.b`, so 78 package markers
read as dead because nothing names them directly. After both, **37**, and
every one of those is real.

It also independently named three modules the capability review had found by
hand: the hunting agent, the pseudonymizer and the closure guardrails. That
is the useful signal, because it means the gate would have caught them
without anyone reading the code.

### Deviations

**D9. Two of 1.4's four gates already existed in part.** The Python demo-state
and module-global check shipped as `check_python_route_state.py` in v15.0.0,
so 1.4 adds nothing there. `check_route_shadowing.py` exists and is kept: it
is the breadth pass that needs no service importable, and the new duplicate
gate is the depth half rather than a replacement.

**D10. Rows are not failed on a gate test importing an unreachable module.**
The plan asks for it. The matrix's `Gate` cell is prose naming a workflow job
or a file, not a resolvable import, so the rule would have to parse free text
to decide what to import. Both halves exist and are enforced separately: every
row names a runnable gate, and every module has an importer or a reason.
Recorded rather than faked with a heuristic that would pass on anything.

## Phase 2.1 to 2.4 — closure is governed (2026-10-01)

| Item | What changed |
|---|---|
| **2.1** closure policy | Migration `078`. Per-tenant, per-class: enabled flag, threshold, and `require_grant`. Read by the real `run_auto_triage` path. Additive: a tenant with no row behaves exactly as before |
| **2.1** the grant finally has a reader | An earned `auto_close` grant had **no consumer at all** (its only reader selected `auto_execute` on action verbs), which is why parity 1.1 had to retract the shadow-mode claim |
| **2.2** kill switch | Global and per tenant, checked **first** and separately from the policy, with a mandatory reason and an audit row per transition |
| **2.3** human priors | An analyst disposition now writes a human-authored prior. Until now `record_outcome` was called from three agents-side workers and nowhere an analyst could reach, so **every prior was AI-authored** and v15's refusal rule meant repeat suppression could never fire |
| **2.4** pseudonymized egress | Every hosted LLM call goes through the pseudonymizer at the contract layer, the one place all sixteen agent call sites already pass through. Matrix row 19 restored and re-gated on a call-path test |

### What testing the path found that testing the function could not

Row 19 used to rest on `test_privacy_redactor.py`, which calls the redactor
and asserts it redacts. True about a function, silent about the product.
The replacement drives `safe_ainvoke` and inspects what a fake provider
received, and it immediately found a real gap: **a bare username in prose**
(`running as priya.raghavan`) went to a hosted model in the clear, because
usernames were only redacted in the `DOMAIN\user` form or under a user-ish
key. Closed with a cue-anchored pattern, deliberately narrow so it does not
mangle process names or rule ids.

The same file pins the trade-off in the other direction: public IOCs are
**deliberately not** redacted, so a change to that is a visible decision.
And it carries a test that disables the control and requires the leak
assertion to fail, so it cannot pass vacuously.

### Three defects in my own work, caught by the gates

- The closure-policy migration had no `OR <tenant context> IS NULL` arm.
  `check_rls_policy_shape.py` named the exact consequence: the fused-alert
  worker consumes from Kafka on a connection that binds no tenant, so it
  would have seen zero rows, fallen through to the process-wide threshold
  and reported success.
- Putting `closure.py` under `app/policy/` made `guardrails.py` look
  reachable, because that package's `__init__` re-exports it. A package
  marker can launder every dead module in its package, so closure moved to
  its own package and the reachability verdict stayed honest.
- `_alert_evidence` passed the ORM's `affected_host` through unchanged,
  while the canonicaliser looks for `host`. Two alerts on the same rule and
  different hosts would have shared a key, so a benign prior for one would
  have suppressed the other. Found by asserting the negative case.

A database that cannot answer **refuses**: an unreadable policy or switch
means no auto-close, never a fallback to the permissive default. And an
unreadable switch reports as an error rather than as "kill switch engaged",
because a diagnostic that names the wrong subsystem sends an operator to
debug something that is not broken.

## Phase 2.5 and 2.6 — one model path, and budgets that bite (2026-10-01)

**2.5.** Two call sites named a provider model directly and both degraded
silently. `detection_loop.py` passed `gpt-4o-mini`, so on CORE it reached
LiteLLM, which knows the `aisoc-*` aliases and not that id: every call
answered `Invalid model name` and fell through to the deterministic path.
`nl_query.py` checked the air-gap guard against a hardcoded
`api.openai.com` rather than the URL the request would use, so the guard
was refusing a call that never leaves the deployment while saying nothing
about one that would.

Neither broke a test, because both degrade to a working deterministic
answer. That is why this needed a **gate** rather than two fixes:
`check_model_alias_routing.py`, proven by re-injecting the pre-fix defect
and watching it name the file and line. A new `aisoc-detection` role had to
be registered in **four** places that a parity test holds together: the
gateway config, the API resolver's `ROLES`, the agents `_DEFAULT_PINS`, and
the docs table.

**2.6.** `InvestigationBudget` declared `max_tokens` and `max_tool_calls`
and only `max_seconds` had a reader. The runner's own docstring said tokens
were "enforced upstream by the `CostGovernor`", which charges a rolling
window **across** runs rather than bounding this one, so a single
investigation could spend any number of tokens inside its two minutes.

Both are now checked after each streamed step, against the live
`CostTracker` rather than an estimate. An over-budget run ends in a
labelled `budget_exhausted` state and escalates, because a truncated run
has not reached a conclusion and returning the graph's last confident
verdict is how a stopped investigation becomes a confident wrong
disposition. The test asserts the graph did **not** stream all its nodes,
so a check that merely reported the overspend would fail it.

Two deliberate choices: an unmeasured run (no tracker bound) is allowed to
continue, because refusing on the absence of telemetry would stop every run
in a deployment that has not configured it; and a budget of zero reads as
"no cap" rather than as zero, which would stop every run before its first
call and look like a hang.

## Phase 3 and 4, partial (2026-10-01)

### Shipped

| Item | What changed |
|---|---|
| **3.1** CORE evidence | The enricher asks the `full`-profile enrichment service, so on CORE it caught a connection error, logged at `debug` and returned `{}`: the agent got "could not check" for every indicator on every alert. Now matches the tenant's own `threat_intel_iocs`, with expiry as a hard SQL gate and a per-type decay half-life |
| **3.3** Behavioural injection | 27 pairs, 9 families, per-family flip and unsafe-action ceilings. Found `fake_tool_output` at **100% flip, 0% catch** |
| **3.5** QA sampling | A 5% sample of auto-closures reaches an analyst, scored on the five-part rubric, so closure accuracy is measurable on real data |
| **2.5** Gateway aliases | Two call sites named a provider model directly and degraded silently; a gate now catches it, proven on the pre-fix defect |
| **2.6** In-loop budgets | `max_tokens` and `max_tool_calls` were declared and enforced nowhere |
| **4.1** SSO completes | Both handlers issued a token with no tenant, no role and no local user, signed with the wrong key, into a cookie the API does not read |
| **4.7** Accessibility | Three of the five operator views now under axe, each asserting it rendered real markup first |

### Deviation D11: 4.3 was already done by the security batch

The plan anticipates this: "If the security batch already did this, record a
Deviation and add only the console role-assignment UI." Confirmed.
`services/api/app/api/v1/deps.py` resolves permissions from the database
during `get_current_user` and caches them, which S13 shipped in `v15.0.0`.
The console role-assignment UI is not built and is recorded as outstanding.

### What the guards caught in my own work

- The closure-policy migration had no unbound-session arm, so the Kafka
  worker would have read zero policies and reported success.
- Putting `closure.py` under `app/policy/` made the dead `guardrails`
  module look reachable, because that package re-exports it.
- `_alert_evidence` passed `affected_host` through while the canonicaliser
  reads `host`, which would have given two different hosts one prior key.
- The accessibility suite's own non-vacuity guard caught the investigation
  rail rendering its **error state** while axe reported it clean.

### Outstanding

3.2 (accuracy on the shipped model), 3.4 (before/after), 3.6 (grounded
copilot), 3.7 (signed evidence bundles), 4.2 (console MFA), 4.3's console
UI, 4.4 (tenant audit views), 4.5 (operator pages), 4.6 (i18n), and all of
Phases 5 and 6.

## Live QA fixes, re-applied (2026-10-02)

Both were found by live QA, shipped on their own branch, and **lost** when
that branch was closed as superseded: the combined phase-2-to-4 branch was
built from the phase-4 tip, and the QA branch was never in that chain. A
second live run against merged `main` found the graph 401 storm back at
five per alert, which is how the loss was caught rather than assumed.

| Defect | Fix |
|---|---|
| `make up`, `install.sh` and the README advertised `http://localhost:8000/api/docs`, which **404s** because `make up` starts a production-class stack where the API disables its interactive docs | All five surfaces point at `docs/openapi.yaml`. The pre-existing test that *required* the README to advertise a docs URL was rewritten: the invariant spanning both eras is "advertise one only if the documented path serves one" |
| Every auto-triage emitted **four 401s per alert** on `graph/neighbors` and `graph/blast-radius` | `ContextBundleBuilder()` is constructed with no token and those routes authenticate a *user*, which a background worker has none of; on CORE there is no Neo4j behind them either. Reported once as "the entity graph runs in the `full` profile and is not part of this deployment" |

One 401 per alert remains on `incident-context`, same root cause, recorded
open: a guard there broke six tests that exercise the enabled path, and the
proper fix is a service principal the API accepts, which belongs with 4.1's
outstanding half.

## Phase 5, partial (2026-10-02)

| Item | What changed |
|---|---|
| **5.1** alert-triggered playbooks | `find_matching()` had **no production caller**. Called from the fused-alert path now, after triage because a playbook's conditions read the verdict, behind three switches that must all agree. Every default is off; anything short of all three runs in **preview** |
| **5.2** durable approval pause | The engine had no pause and no resume, so `approval` failed closed and **12 shipped playbooks aborted on it**. Migration `081` stores the position and the context; resume advances past the approval step; the pause resolves before the run continues so a double-tap resumes once; expiry is mandatory and recorded |
| **5.4** tenant tuning in fusion | The engine evaluated the shared corpus and nothing else, so a tenant who disabled a noisy rule **kept getting its alerts while the console showed it disabled**. A versioned overlay with hot reload, applied after the match so a suppressed hit carries the tuning, its author and its reason |

### Two things the plan's own text had moved past

**5.2's premise held, with a larger number.** The plan says eight playbooks
abort at their approval step. It is **12**. And the engine carried a
careful, honest argument for leaving `approval` unbridged: every response
step is separately graded against its capability contract at dispatch and
returns `pending_approval` on its own, so an approval step in front of one
gates a decision that is already gated. That reasoning is still true and is
kept in the code, but it is a reason to leave the step out of a playbook,
not a reason for the engine to refuse it.

**The test that asserted the old behaviour was rewritten, not deleted.** It
pinned honest reasoning about the engine that had become wrong about the
product, which is exactly the shape worth correcting in place.

### Outstanding in Phase 5

5.3 (`http` and `notify` steps that act, the osquery step, packaging the 62
pack playbooks into the image), 5.5 (the 133 rules that cannot fire), 5.6
(case depth: merge, bulk triage, SLA breach, escalation routing, custom
fields, workload metrics) and 5.7 (report scheduler, SMTP, email approvals,
Teams cards, outbound webhooks).

## Live QA after Phase 5 (2026-10-02)

Six defects, **five of them mine, none found by the test suites**. Each is
recorded with the reason it was invisible, because that is the reusable
part.

| Defect | Why no test caught it |
|---|---|
| `tenant_overlay._fetch` selected `rule_id` and `updated_by` from `detection_rules`, which has **neither** — the overlay would have loaded nothing on every deployment | The fakes answered whatever they were asked. A fake more capable than the real schema cannot fail |
| `run_for_alert` asked for event `alert.created`; all 64 shipped playbooks declare `on: alert`, so **nothing ever matched** — the feature was wired, enabled and dead | Same shape: the fake store returned a playbook whatever event name it was handed |
| An expired token **locked the user out of the product**: `/login` redirected to `/dashboard`, every call 401'd, nothing sent them back | No test exercised a dead session, and the lockout needs real browser storage to reproduce |
| `aws_cloudtrail` had **no ingest profile**, so every event collapsed into **one alert** | The pipeline test pushed one event. One event cannot reveal a dedup collapse |
| `check_raw_sql_columns` parsed `INSERT` and `UPDATE` only | A one-directional gate: an absent column fails a `SELECT` just as hard |
| A meta-test required an unrunnable step type to **exist** | It broke when 5.2 made `approval` runnable and emptied the category |

### The pattern worth keeping

**Four of the six were invisible for the same reason**: the double was more
capable than the real thing. A fake store that ignores the event name, a
fake row that answers for a column the table does not have, a one-event
pipeline test that cannot show a collapse, a gate that reads writes and not
reads. In each case the test passed and the product did not work.

The two gates extended here (`SELECT` parsing, and the corpus-derived
trigger assertion) were both **proven against the real pre-fix defect**:
re-injected, watched to fail, restored, watched to pass.

### One non-defect, recorded as such

A browser walkthrough initially reported `/playbooks` broken. It was the
**published image**, built from a different commit than `main`; built from
source the page lists 12 playbooks correctly. Worth stating plainly rather
than counted as a fix, and a reminder that the published artefact and the
repository are different things.

### Semgrep ratchet drift

Two consecutive runs on one branch measured 103/39 and 104/40 with **zero
scanned files changed**. The workflow pins the semgrep binary and not the
rule packs, so the ratchet compares against a moving target. Ceiling held
at 104/40 with the reasoning written in; pinning is
[#1099](https://github.com/beenuar/AiSOC/issues/1099).

## First run, measured on a bare clone (2026-10-02)

Everything below came from a clean-room install: a fresh worktree off
`main`, following the README exactly, on a host that already had a
Postgres on 5432 and an Ollama on 11434.

| Was | Now |
|---|---|
| `make up` **refused to start** on a port conflict and said to edit YAML | Picks a free port, names what held it, moves `AISOC_CONSOLE_URL` with it |
| `make smoke` probed a hardcoded `:3000` and read a connection failure as **"an uncredentialed caller was served"** | Uses the real console URL, and `000` is a skip |
| `make doctor` on a never-started clone showed **22 red failures** | Says nothing is running yet and names `make up` |
| A container dying of a full Docker VM reported as **"zookeeper is not running"** | Names the disk and prints the prune command |
| A new tenant landed on an all-zero dashboard | Lands on a setup wizard derived from its own data |
| No way to see the product work without credentials | Five scenarios through the **real ingest path**, labelled, which do not mark setup complete |

**64 seconds** from `git clone` to a working console with three ports
remapped; `make smoke` 10/10; sample data producing five distinct alerts
from low to critical with differing AI verdicts.

### The through-line

Four of these were diagnostics that named the wrong thing. A port
conflict reported as "edit docker-compose.yml", a dead port reported as
an authentication hole, an unstarted stack reported as eight broken
services, and a full disk reported as a Zookeeper fault. In each case the
information needed was already on the machine and the message did not
carry it.

## Maturity — every capability Stable, earned rather than relabelled (2026-10-02)

The Project maturity table in `README.md` published a status for fifteen
capabilities and **nothing checked any of them**. No definition of
Stable, Beta or Alpha existed anywhere, no gate parsed the table, and the
labels appeared in no other file. Promoting a capability was a one-line
edit — the exact shape Phase 1.1 retracted twelve of.

It was also already wrong in three places, all found by the new gate:
playbooks claimed "live Postgres suspend/resume" against a suite driving
`_FakeRows`, tuning claimed a "live overlay read" that regex-parses a
migration, and connectors named the `full` profile when it ships in CORE.

`docs/audit/MATURITY_DEFINITION.md` now defines the labels, derived from
the four rows that already held Stable rather than invented, so no
existing row had to be demoted to fit a standard written afterwards.
Stable requires four properties: unconditionally graded, the real
production path, a proven negative control, and real infrastructure.
`scripts/check_maturity_table.py` enforces it on every pull request and
runs in both directions, so an entry for a demoted row fails too.

| Row | What it took |
|---|---|
| Entity graph | Live suite drives `graph_service.py` against real Neo4j. Also fixed `get_blast_radius`'s plain-Cypher fallback, which was unreachable on the missing-APOC condition it existed for |
| UEBA | Schema from the service's own migrations, never `create_all` — the defect was a column in the model and absent from the migration |
| Playbook pause | Every property the feature is named for belongs to the database; the offline fake re-implements the partial unique index in Python |
| Tenant tuning | `_fetch` fails soft, so a permanently broken overlay is indistinguishable from a tenant with no tuning |
| SCIM | Real `create_application()` and real Postgres, replacing SQLite with `@compiles` shims for the four types the two disagree about most |
| Scheduled connectors | A real `AsyncIOScheduler`: `next_run_time=None` registers as PAUSED, which no mock can see |
| Governed actions | A socket, not a mock — simulation mode never constructs the client, which is how two executors shipped calling theirs with argument names that do not exist |
| Event lake | Executes the shipped `001_init.sql` verbatim rather than a hand-written subset |
| Retro-hunts | Graded with `RETRO_HUNT_ENABLED` **on**; the consumer had no coverage and its path filter omitted its own module |
| 68-hunt library | `run_hunt` wired to `POST /hunt`; the scheduler reads the tenant's lake instead of a fixture corpus, and refuses to fall back to it |
| AI triage + ledger | `live-agent-smoke` dispatches the real LangGraph per commit and fails on `llm_calls_placed: 0`; the ledger's `_FakeConn` test replaced with live Postgres |

Every negative control was proven by injecting the defect and watching
the suite go red, not asserted.

**Two findings worth more than the promotions.** The agents image shipped
**zero of the 62 pack playbooks** — the Dockerfile's build context cannot
reach outside itself, and the loader's `exists()` guard made an absent
pack indistinguishable from an empty one. And `autonomy_evidence_rules.py`
was listed as unwired when two gates read it without importing it; the
import graph understates what depends on a module.

**The limit that stays.** No hosted provider has ever been exercised. AI
triage is Stable on the bundled local model; hosted-provider accuracy is
a separate claim and remains unmade.

## Maturity — every capability Stable, earned rather than relabelled (2026-10-02)

The Project maturity table in `README.md` published a status for fifteen
capabilities and **nothing checked any of them**. No definition of
Stable, Beta or Alpha existed anywhere, no gate parsed the table, and the
labels appeared in no other file. Promoting a capability was a one-line
edit — the exact shape Phase 1.1 retracted twelve of.

It was also already wrong in three places, all found by the new gate:
playbooks claimed "live Postgres suspend/resume" against a suite driving
`_FakeRows`, tuning claimed a "live overlay read" that regex-parses a
migration, and connectors named the `full` profile when it ships in CORE.

`docs/audit/MATURITY_DEFINITION.md` now defines the labels, derived from
the four rows that already held Stable rather than invented, so no
existing row had to be demoted to fit a standard written afterwards.
Stable requires four properties: unconditionally graded, the real
production path, a proven negative control, and real infrastructure.
`scripts/check_maturity_table.py` enforces it on every pull request and
runs in both directions, so an entry for a demoted row fails too.

| Row | What it took |
|---|---|
| Entity graph | Live suite drives `graph_service.py` against real Neo4j. Also fixed `get_blast_radius`'s plain-Cypher fallback, which was unreachable on the missing-APOC condition it existed for |
| UEBA | Schema from the service's own migrations, never `create_all` — the defect was a column in the model and absent from the migration |
| Playbook pause | Every property the feature is named for belongs to the database; the offline fake re-implements the partial unique index in Python |
| Tenant tuning | `_fetch` fails soft, so a permanently broken overlay is indistinguishable from a tenant with no tuning |
| SCIM | Real `create_application()` and real Postgres, replacing SQLite with `@compiles` shims for the four types the two disagree about most |
| Scheduled connectors | A real `AsyncIOScheduler`: `next_run_time=None` registers as PAUSED, which no mock can see |
| Governed actions | A socket, not a mock — simulation mode never constructs the client, which is how two executors shipped calling theirs with argument names that do not exist |
| Event lake | Executes the shipped `001_init.sql` verbatim rather than a hand-written subset |
| Retro-hunts | Graded with `RETRO_HUNT_ENABLED` **on**; the consumer had no coverage and its path filter omitted its own module |
| 68-hunt library | `run_hunt` wired to `POST /hunt`; the scheduler reads the tenant's lake instead of a fixture corpus, and refuses to fall back to it |
| AI triage + ledger | `live-agent-smoke` dispatches the real LangGraph per commit and fails on `llm_calls_placed: 0`; the ledger's `_FakeConn` test replaced with live Postgres |

Every negative control was proven by injecting the defect and watching
the suite go red, not asserted.

**Two findings worth more than the promotions.** The agents image shipped
**zero of the 62 pack playbooks** — the Dockerfile's build context cannot
reach outside itself, and the loader's `exists()` guard made an absent
pack indistinguishable from an empty one. And `autonomy_evidence_rules.py`
was listed as unwired when two gates read it without importing it; the
import graph understates what depends on a module.

**The limit that stays.** No hosted provider has ever been exercised. AI
triage is Stable on the bundled local model; hosted-provider accuracy is
a separate claim and remains unmade.

### What the maturity plan asked for and did not get (2026-10-02)

Re-reading that plan clause by clause against the tree found four
sub-clauses that had not landed. Three are now closed and listed above:
the `POST /lake/sql` round-trip, the feed → Kafka → sweep → alert E2E,
and the hunting agent's console and MCP callers. Two are not, and the
reason is worth more than a tick would have been.

**"Close parity 3.2, 3.4, 3.6 and 3.7."** These are four substantial
features, not gaps in the maturity work: accuracy measurement on the
shipped model across labelled replay sets, before-and-after measurement,
a copilot with the investigation agent's read tools and ledger citations,
and signed replayable evidence bundles mapped to OCSF's `ai_agent`
object. They stay open and unticked.

The AI triage row does not rest on them. What it rests on is the
Investigation Ledger proven against real Postgres and a commit-level
agent check that fails when `llm_calls_placed` is zero, both of which
shipped. Measured verdict accuracy is a *different* claim, and it is one
this tree still cannot make: **no hosted provider has ever been
exercised**, and the only live floor is groundedness over a deterministic
prefix on a locally-served small model.

**"Shrink the reachability allowlist by six entries."** It shrank by two,
and both of those were the hunting agent's. The other four named in that
clause are `services/actions/app/clients/{aisoc_direct,fleetdm,osctrl}_client.py`
and `osquery_allowlist.py` — vendor clients constructed by capability
name at dispatch time rather than imported. The import graph cannot see
that, and the allowlist's own comment already records the decision:
inventing a dynamic-loader entry for a factory that takes a string would
excuse more than it explains.

The two autonomy modules in that clause were examined and **kept**, with
their entries corrected. `autonomy_evidence_rules.py` is not unwired at
all: two gates read it without importing it, which an import-graph
checker cannot see — a fact established by deleting it and immediately
breaking both. `unified_autonomy.py` is genuinely off the production
path and superseded by parity 2.1's closure policy, and a third authority
on "may this execute without a human" is a safety question rather than a
tidiness one.
