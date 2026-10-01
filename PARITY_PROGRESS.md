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

- [ ] **1.1** Retract or narrow the overclaims
- [ ] **1.2** Clear the documentation drift
- [ ] **1.3** Repair the broken console paths
- [ ] **1.4** Make the gates path-aware

## Phase 2: Govern and protect alert closure

- [ ] **2.1** Per-tenant, per-class closure policy
- [ ] **2.2** Kill switch
- [ ] **2.3** Learn only from humans — the urgent half ships as security S10
- [ ] **2.4** Pseudonymize before hosted egress
- [ ] **2.5** One model path for every LLM call
- [ ] **2.6** Enforced budgets

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

- [ ] **5.1** Alert-triggered playbooks
- [ ] **5.2** Approval as a durable pause
- [ ] **5.3** Steps that do something
- [ ] **5.4** Tenant tuning inside fusion
- [ ] **5.5** Rules that can fire
- [ ] **5.6** Case depth
- [ ] **5.7** Delivery

## Phase 6: Agent parity, then platform depth

- [ ] **6.1** Hunting
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
