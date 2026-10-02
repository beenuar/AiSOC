# What Stable means

The Project maturity table in [`README.md`](../../README.md) publishes a status
for every capability this product ships. Until now those labels were
**ungated prose**: no definition existed anywhere in the repository, nothing
parsed the table, and the words appeared in no other file. Promoting a
capability was a one-line edit.

That is the shape this project spends most of its effort refusing. Phase 1.1
of the parity plan retracted twelve published claims that nothing checked, and
the lesson recorded from it is that a figure nobody compares to anything
drifts, and nobody finds out. The maturity table was the last large claim
surface with no gate behind it.

This page defines the labels, and
[`scripts/check_maturity_table.py`](../../scripts/check_maturity_table.py)
enforces them on every pull request.

## The definition was read off the tree, not invented

Four rows already held **Stable** before this page existed: ingest to alert,
the detection engine, alert correlation, and the REST API with the console.
Rather than invent criteria and discover the existing rows failed them, the
definition is what those four actually have in common.

`golden-pipeline.yml` is the reference implementation of all four properties
at once: no path filter, the real `make up` stack, eleven independently
reported stages, and a step that stops fusion and fails if the test still
passes.

### Stable

A capability is Stable when **all four** of these hold:

1. **Unconditionally graded.** A pull-request check exercises it with no
   `paths:` filter and no `if:` guard that could skip it. A required check
   that never reports is weaker than no check at all: it looks green on every
   commit it never read.

2. **Exercised along the real production path.** The test drives the code a
   deployment runs — not a re-implementation, not a copy, and not a double
   more capable than the real thing. Six defects found in one live-QA pass
   shared that single cause, and four of them passed every test they had.

3. **Proven able to fail.** A negative control exists: something that breaks
   the capability and makes the check go red. A gate asserted to work is not a
   gate. This is the property that separates "we tested it" from "we know the
   test would notice".

4. **Run against real infrastructure.** Real containers, real Postgres, real
   ClickHouse. Not in-memory SQLite with type shims, not a hand-written fake
   that answers whatever it is asked.

### Beta

Implemented, wired to production, and tested — but missing at least one of
the four. The row's `Tested` column must say which coverage genuinely exists,
and must not describe coverage that does not.

### Alpha

Something load-bearing is not finished. A component with no production
importer, a scheduler reading a fixture instead of tenant data, or a
documented gap in the parity plan. The row must name the gap.

## What Stable does *not* mean

Two distinctions matter, because conflating them would either overclaim or
hold a finished capability at Beta forever.

**Stable is independent of the compose profile.** ClickHouse, Neo4j and UEBA
ship in the `full` profile, and that is a deployment choice about memory and
disk, not a statement about maturity. The table carries a separate
`Production ready` column which is where `full` profile belongs. A capability
that is proven on all four properties is Stable whether or not a default
`make up` starts it.

**Stable is independent of autonomy.** Response actions require a human
approver by design, and AI triage ships in copilot mode. Neither is
immaturity. What Stable asserts for a governed capability is that the
governance machinery is proven — *including that it correctly refuses*.

## What the gate checks

`check_maturity_table.py` parses the table out of `README.md` and, for every
row marked Stable, requires a matching entry in its evidence registry. The
registry names the artefacts; the gate verifies they exist and hold:

| Property | How it is checked |
|---|---|
| Unconditionally graded | The named workflow has no `paths:` / `paths-ignore:` filter on `pull_request`, and the named job carries no `if:` referencing a changes filter |
| Real production path | The named test imports a real driver (`asyncpg`, `clickhouse_driver`, `neo4j`, `httpx` against a container) and does not define a fake standing in for the system under test |
| Proven able to fail | A named negative control exists — a `--prove-gate` or `--self-test` invocation, a CI step that breaks the system and expects red, or a test whose body removes the mechanism and asserts the failure |
| Real infrastructure | The workflow declares `services:` containers, or the test is collected by a job that does |

A registry of exact sites rather than a search over prose, for the reason
`check_profile_service_counts.py` records about its own list: a gate that
guesses which words are claims will either miss the one that matters or flag
prose forever.

The gate also runs in the **reverse direction**. An evidence entry naming a
capability that is no longer Stable, or a test file that has been deleted or
renamed, fails the build — so the registry shrinks when a row is demoted
rather than accumulating stale entries that imply coverage.

## Promotion procedure

1. Build the missing property. Do not edit the table first.
2. Add the evidence entry.
3. Prove the negative control genuinely fails by breaking the thing and
   watching the check go red, then restoring it.
4. Change the row to Stable in the same change, so the claim and its proof
   land together and a reviewer sees both.

A capability that cannot honestly reach Stable stays Beta with the reason
written in its row. Closing the list is not the objective; the table being
true is.
