# Walkthrough — `lateral-movement`

> **Impossible-travel Okta sign-in.** Alice signs in successfully from
> New York at 09:30 UTC, then again from Saint Petersburg eight
> minutes later. The geographical pivot is physically impossible
> inside that window.

- **Fixture:** [`examples/alerts/lateral-movement.json`](./alerts/lateral-movement.json)
- **MITRE techniques:** T1078, T1078.004
- **Severity at intake:** `high`
- **What the sandbox computes:** `geo_velocity` — Saint Petersburg 0.13 h after New York, 6,888.5 km apart: an implied 53,115.6 km/h, above the 1,000 km/h threshold, so the travel really is impossible; `source_diversity` — 2 source addresses across 2 countries

> **The step-by-step below describes the full stack.** The offline
> `aisoc-sandbox` run shows the same ledger *shape* but computes only what
> arithmetic over these events can give it — there is no model, no graph, no
> Qdrant and no lake in the wheel, and it emits no confidence score, no
> automation tier and no verdict. Values it cannot compute say so, with the
> reason attached. What it does compute for this scenario is listed above.

## Run it

```bash
# Offline simulator (< 5 s, no Docker):
aisoc-sandbox demo --scenario lateral-movement

# Real stack (after `make up`, with `pip install -e packages/aisoc-cli`):
aisoc submit examples/alerts/lateral-movement.json
```

## What the agent does, step by step

### Step 0 · DetectAgent · detect

Matches the two Okta `user.session.start` events against the executable
detection corpus (2,529 rules as of this writing — `docs/detections/truth-table.md`
carries the generated count). The `okta-impossible-travel` rule fires on the
geographical delta + the sub-10-minute time window, and Fusion lifts
the per-alert confidence by another notch because both sessions
authenticated through the same `FACTOR_PROVIDER`.

> would-call `rules.match({"technique_set": ["T1078", "T1078.004"]})`
>
> would-call `fusion.score({"window_minutes": 15})`

**Decision:** open alert at `severity=high`.

### Step 1 · TriageAgent · triage

Cross-references the user against Qdrant for prior cases involving
`alice@example.com` and walks the Neo4j graph two hops out from the
user node to surface devices and groups the user owns.

Offline, none of that is available, so the sandbox says only what it
worked out: `alice@example.com appears at Saint Petersburg, RU 0.13 h
after New York, US — 6,888.5 km apart, implied speed 53,115.6 km/h,
above the 1,000 km/h threshold.` The related-case count and the entity
risk score read `not computed in the sandbox`, each naming the store it
would have come from.

> would-call `qdrant.semantic_search({"k": 5, "collection": "cases"})`
>
> would-call `graph.neighbours({"depth": 2})`

**Decision (sandbox):** 3 of 4 signals computed from the events, 2 fired. No confidence score: the sandbox runs no model, so it has nothing to calibrate one from.

### Step 2 · HuntAgent · hunt

Translates the hypothesis "any activity by `alice@example.com` in last
24 h" into an ES|QL query and sweeps the warm tier.

Offline there is no warm tier to sweep, so the sandbox runs no query
and reports no result: `matches_found` reads `not computed`, and so
does `additional_compromised_entities` — *unknown* rather than zero,
because a search that never ran did not find nothing, it looked
nowhere.

> would-call `nl_to_query.translate({"hypothesis": "any activity by alice@example.com in last 24h"})`
>
> would-call `lake.query({"language": "ES|QL", "row_cap": 1000})`

**Decision (sandbox):** Pivot not performed; the entities the live
HuntAgent would sweep on are listed, and nothing is claimed about them.

### Step 3 · RespondAgent · respond

Proposes the graduated containment: revoke every active session,
require password reset, create the case, page the SOC on-call. Each
verb is graded against its capability contract and the approval matrix
of confidence against blast radius, and a session revocation at this
confidence lands in **`human_approval_required`**; nothing executes
without analyst confirmation.

> would-call `user.session.revoke_all({"user": "alice@example.com"})`
>
> would-call `user.require_password_reset({"user": "alice@example.com"})`
>
> would-call `case.create({"title": "Lateral movement — impossible-travel Okta sign-in", "severity": "high"})`
>
> would-call `case.notify({"channel": "slack", "audience": "soc-on-call"})`

**Decision (live stack):** 4 actions proposed; awaiting analyst approval before execution.

**Decision (sandbox):** the same actions are listed as call *shapes*, each marked `executed: false`. The automation tier and the approval posture read `not computed` — the live stack resolves both from the capability contract and the approval matrix, and neither is a thing a severity label can select.

## What the analyst would do next

1. Approve `user.session.revoke_all` (the only single-user-blast-radius
   action) immediately via the responder PWA.
2. Pivot on the second IP (203.0.113.50) in the console's **Threat
   Intelligence** tab (`/threat-intel`) to see if it has appeared in
   other tenants' OTX feeds.
3. Page Alice's manager from the case to confirm whether she travelled.
4. If credential reuse is suspected: rotate every API key in Alice's
   1Password vault from the [credential vault rotation runbook](../apps/docs/docs/operations/credentials.md).
