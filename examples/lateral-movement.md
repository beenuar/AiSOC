# Walkthrough — `lateral-movement`

> **Impossible-travel Okta sign-in.** Alice signs in successfully from
> New York at 09:30 UTC, then again from Saint Petersburg eight
> minutes later. The geographical pivot is physically impossible
> inside that window.

- **Fixture:** [`examples/alerts/lateral-movement.json`](./alerts/lateral-movement.json)
- **MITRE techniques:** T1078, T1078.004
- **Severity at intake:** `high`
- **Confidence band (sandbox):** 83/100, `high`

## Run it

```bash
# Offline simulator (< 5 s, no Docker):
aisoc-sandbox demo --scenario lateral-movement

# Real stack (after `pnpm aisoc:demo`):
pnpm aisoc:submit examples/alerts/lateral-movement.json
```

## What the agent does, step by step

### Step 0 · DetectAgent · detect

Matches the two Okta `user.session.start` events against the 800+
native Sigma ruleset. The `okta-impossible-travel` rule fires on the
geographical delta + the sub-10-minute time window, and Fusion lifts
the per-alert confidence by another notch because both sessions
authenticated through the same `FACTOR_PROVIDER`.

> would-call `rules.match({"rule_count": "800+", "technique_set": ["T1078", "T1078.004"]})`
>
> would-call `fusion.score({"window_minutes": 15})`

**Decision:** open alert at `severity=high`.

### Step 1 · TriageAgent · triage

Cross-references the user against Qdrant for prior cases involving
`alice@example.com` and walks the Neo4j graph two hops out from the
user node to surface devices and groups the user owns. The decision
copy ("authenticated session signals look legitimate at the protocol
layer, but the geo pivot between sequential events is physically
impossible — classic credential takeover") mirrors what an analyst
would write at handoff.

> would-call `qdrant.semantic_search({"k": 5, "collection": "cases"})`
>
> would-call `graph.neighbours({"depth": 2})`

**Decision:** Confidence `high` (83/100).

### Step 2 · HuntAgent · hunt

Translates the hypothesis "any activity by `alice@example.com` in last
24 h" into an ES|QL query and sweeps the warm tier. The pivot reveals
nothing else compromised beyond the alert payload — a clean,
contained incident.

> would-call `nl_to_query.translate({"hypothesis": "any activity by alice@example.com in last 24h"})`
>
> would-call `lake.query({"language": "ES|QL", "row_cap": 1000})`

**Decision:** Pivot complete; no additional compromised entities.

### Step 3 · RespondAgent · respond

Proposes the graduated containment: revoke every active session,
require password reset, create the case, page the SOC on-call. The
**blast radius is human_approval_required** because the severity is
`high`; nothing executes without analyst confirmation.

> would-call `user.session.revoke_all({"user": "alice@example.com"})`
>
> would-call `user.require_password_reset({"user": "alice@example.com"})`
>
> would-call `case.create({"title": "Lateral movement — impossible-travel Okta sign-in", "severity": "high"})`
>
> would-call `case.notify({"channel": "slack", "audience": "soc-on-call"})`

**Decision:** 4 actions proposed; awaiting analyst approval before execution.

## What the analyst would do next

1. Approve `user.session.revoke_all` (the only single-user-blast-radius
   action) immediately via the responder PWA.
2. Pivot on the second IP (203.0.113.50) in the [Threat Intel](https://docs.tryaisoc.com/console/threat-intel) tab to see if it has appeared in
   other tenants' OTX feeds.
3. Page Alice's manager from the case to confirm whether she travelled.
4. If credential reuse is suspected: rotate every API key in Alice's
   1Password vault from the [credential vault rotation runbook](../apps/docs/docs/operations/credentials.md).
