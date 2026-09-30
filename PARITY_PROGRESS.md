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

- **CORE is 17 compose services**, being those with no `profiles:` key, which
  is what `make up` starts. 16 if one-shot `ollama-pull` is excluded. See D3.
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

### D3. There is no `core` profile, so the CORE count has no single source

Plan item 1.2 says to "take the real count from `docker compose config` for the
CORE profile". There is no `core` profile in `docker-compose.yml`, so that
command cannot answer the question. CORE is the set of services declaring no
profile, which is 17 of the 32 declared: actions, agents, api, connectors,
fusion, ingest-worker, kafka, litellm, ollama, ollama-pull, postgres, qdrant,
realtime, redis, threatintel, web, zookeeper.

Four places in the tree disagree with each other about it: `install.sh:784`
says 10 while naming 9 on the next line, `walkthrough.mdx:80` says fifteen,
`Makefile:157` says fifteen, and `scripts/generate_slo_alerts.py:5` says 17. So
1.2 needs one derivation the others read from, not four string edits.

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
