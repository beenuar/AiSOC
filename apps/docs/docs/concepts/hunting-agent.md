---
title: Hunting agent
sidebar_position: 8
---

# Hunting agent

A hunt library answers the hypotheses somebody already wrote down. The hunting
agent answers the one you have right now: you describe what you suspect, and it
searches the event lake for evidence.

It does this without ever writing a query.

## The model fills a plan, it does not compose SQL

The obvious design is to let the model emit a query and sanitise what comes
back. That makes the safety of the whole feature a property of a filter, and a
filter is only as good as the payloads whoever wrote it thought of.

Instead the model is handed a schema whose fields and operators are **closed
enumerations** — 17 fields and 8 operators, both drawn from the columns the
event lake actually has — and it fills in a plan:

```json
{
  "clauses": [
    {"field": "user_name", "operator": "eq", "value": "svc_deploy"},
    {"field": "process_name", "operator": "eq", "value": "powershell.exe"}
  ],
  "hours": 168
}
```

`compile_plan` turns that into SQL. Every value the model supplied travels as a
**bound parameter**, never as statement text. There is no string the model can
produce that becomes SQL, so injection here is not filtered — it is not
expressible in the first place.

A value that looks exactly like SQL is therefore uninteresting: the compiled
statement is byte-identical whether the value is `svc_deploy`, `'; DROP TABLE
aisoc.raw_events; --`, or the compiler's own placeholder `%(tenant_id)s`. Only
the parameter map differs. That is the property the tests assert.

## The tenant comes from the credential

The plan has no tenant field, and a tenant supplied in the request body is
ignored. The predicate is bound from the authenticated caller, so a plan cannot
be pointed at somebody else's history regardless of what the model was
persuaded to emit.

## Three outcomes, kept apart

A hunt that finds nothing and a hunt that could not run look identical if both
return an empty list, and the difference matters more than the result: one says
the estate is clean, the other says nobody looked.

| Outcome | Shape |
| --- | --- |
| Findings | `available: true`, `rows: [...]`, `row_count > 0` |
| No findings | `available: true`, `rows: []`, `row_count: 0` |
| Could not check | `available: false`, `reason: "..."`, **no `rows` key at all** |

The third case omits `rows` deliberately. A caller that reads `rows` without
checking `available` raises a `KeyError` instead of receiving an empty list it
would go on to report as a clean estate. Three causes land here — no lake
configured, the time budget exceeded, and the lake refusing or failing the
query — and each names itself in the reason.

## Authorisation

The route requires the `lake:query` permission, which already exists and is
already granted to the roles that may read the event lake. A hunt-specific
permission would have read more naturally and would have been a silent 403 on
every deployment, since nothing grants a permission that no role declares.

## What the gate proves, and what it does not

`scripts/check_hunt_agent_boundary.py` reads three things together — the field
and operator enumerations, the SQL compiler, and the ClickHouse DDL — and fails
when any drifts from the other two. A field added to the enumeration but absent
from the table would match nothing forever, which is a wrong answer that looks
like a working hunt rather than an error anybody would notice.

The gate reads structure, not intent. It can say the model was unable to
express anything outside the vocabulary. It cannot say the plan the model chose
is a sensible hunt for the hypothesis it was given.
