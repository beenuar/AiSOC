# Contributing strategies and actions

Two libraries in this repository are designed to grow: investigation
strategies and response actions. Both are the same shape as things that have
already gone wrong here, and the rules below exist because of those specific
failures rather than as general good practice.

## Why there are rules at all

The detection corpus reached roughly 6,000 rules of which 833 executed. The
gap was not laziness: rules were added faster than anything checked whether
they could fire, and by the time anyone counted, the number nobody could
defend had been published for months. The connector catalogue went the same
way — 35 of 84 had no documentation, and the sidebar listed 34 pages against
96 files, so most of what existed could not be found.

The detection figure is 2,603 now, and how it moved is the part worth keeping.
It was not closed by writing rules. Someone asked why the existing ones could
not fire and found a single cause — Windows events nest their payload one
level below the namespace the matcher reads, so the two most-used fields in
the corpus resolved to `None` — and then made "executable" mean *observed to
fire through the real connector and the real engine*, with a gate that reverts
the fix and requires those rules to go silent. A count that is gated on
evidence can be raised honestly; a count that is gated on a flag can only be
edited.

Both recovered by making the artifact derived and the count gated. A
strategy library aiming at a hundred entries, and an action registry aiming
at dozens per vendor, will reach the same state within a year without the
same discipline.

The rule is therefore one sentence: **a contribution that cannot fail a test
is not a contribution.**

## Adding an investigation strategy

A strategy lives in `services/agents/app/investigator/strategies.py` and is a
dataclass, not prose. Five things are required and `scripts/check_investigation_depth.py`
enforces each:

| Field | Requirement | Why |
|-------|-------------|-----|
| `rationale` | Non-empty | A strategy whose reasoning nobody wrote down cannot be reviewed or retired |
| `expected_pivots` | Every entry names a real tool | Guidance the model cannot follow is worse than none — it will improvise |
| `min_pivots` | At least 2, at most `len(expected_pivots)` | One tool call is enrichment; a floor above the pivot count can never pass |
| `techniques` / `keywords` | Enough to select on | A strategy nothing routes to is dead weight the model pays context for |
| Selection test | A case in `check_selection` | Otherwise nobody notices when a new strategy steals another's alerts |

The gate also fails when a tool is offered to the model that no strategy
names. That caught `process_tree` being registered with nothing telling the
model when to reach for it.

### What makes a strategy good

Specificity about the *chain*, not the phrasing. Compare:

> Investigate the alert thoroughly and check all relevant sources.

with

> Take the binary's hash and find every other host that has run it —
> first-seen timestamps clustered in one morning mean something different
> from a binary present for a year.

The second tells the model what the answer is *for*. The first is a longer
way of saying nothing, and it will produce a longer report that says nothing.

Write the plan as an approach, not a numbered imperative. A model handed
steps one to five will execute step three even when step two returned
nothing, and a tool call with no input is a tool call that wastes budget and
pads the trace.

## Adding a response action

An action is governed before it runs, so its contract is mandatory.
`scripts/check_action_contract.py` enforces every field, and the defaults are
deliberately unsafe — an executor that declares nothing is treated as
irreversible and prohibited, so an omission fails closed and is named.

Required:

- **`impact`** — what this does to the estate if the finding is wrong. Not
  how likely it is to be wrong; that is confidence, and conflating the two is
  how "we were 99% sure" becomes justification for an irreversible action.
- **`approval`** — the baseline. The tenant's tier and the confidence matrix
  can raise it, never lower it.
- **`required_permission`** — what the dispatcher authorises against.
- **`reversal`** — one of platform, self-healing, manual-only, none. Not a
  boolean: a killed process cannot be un-killed, but the effect does not
  persist, and collapsing that into "irreversible" alongside "isolated a
  production host" loses the distinction an approver needs.
- **`has_verification_probe`**, or a **`verification_gap`** saying why not.
  An absent probe is an acceptable answer. Silence is not — an omission and
  a deliberate decision look identical six months later.

Two rules follow from those and are enforced:

**Unverifiable means not autonomous.** An action that can execute without a
human and has no read-back certifies itself, so it cannot be `AUTOMATIC` at
moderate impact or above. Three actions were demoted to analyst approval on
exactly this ground.

**The contract is per capability, not per vendor.** Isolating a host is
equally disruptive on every EDR. Adding a vendor for an existing verb
inherits the classification; if twenty vendors each declared it, the one that
drifts low is the one that auto-executes.

### Signature tests are mandatory

Simulation mode never constructs the vendor client, so a signature mismatch
between an executor and its client is invisible until a real credential
appears. `SearchSIEMExecutor` passed `max_results=` to a client taking
`max_count`, and every live call raised `TypeError` while every test passed.
Use `autospec=True`.

## Adding a connector

Documentation is generated from `schema()` by
`scripts/generate_connector_docs.py`, so there is nothing to write by hand
and nothing to keep in sync. Add the class to `_CONNECTOR_CLASSES`, run the
generator, and put vendor-specific setup notes between the `HUMAN NOTES`
markers — that section survives regeneration.

The gate fails when a connector has no page, when a generated page has
drifted from its schema, or when a hand-written page omits a required or
secret field.

## Adding a detection

Positive **and** negative fixtures, and the negative one is the one that
matters: a rule with only a positive fixture passes by matching everything.

Write fixtures from a real event shape. Roughly 600 of 825 fixtures were
synthesized from the rule they test, which makes replay tautological — it
can never catch a rule matching a field nothing produces, which is how 663
of 825 loaded rules came to match on fields that were not visible.

## What gets rejected

Not as a matter of taste:

- A strategy with no selection test. It will silently never be chosen, or
  silently steal another's alerts.
- An action with no impact classification. It defaults to prohibited and the
  gate names it, so this is caught, but it means the contribution is not
  finished.
- A detection with only a positive fixture.
- A capability whose declared reverse is not in the vocabulary. The rollback
  path would resolve to nothing while believing it has a route back — four
  verbs were in exactly that state.
- Anything that raises the count of a published figure without raising what
  the figure measures.
