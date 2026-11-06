# ADR-0012: How fusion scales — required-field indexing and entity partitioning

- **Status:** accepted
- **Date:** 2026-10-11
- **Context:** depth plan 4.4 / parity plan 6.9

## Context

Parity 6.9 asks for three things: detection rules indexed by log source so
fusion stops running every rule against every event, consumers partitioned
with ordering kept per entity, and lag-based autoscaling hints.

Two of those have an obvious implementation that is wrong, and this ADR
exists to record why the shipped ones differ from the plan's wording.

## Decision 1: index rules by required field, not by log source

`services/fusion/app/services/detection_engine.py` evaluated every rule
against every event. Its own docstring already recorded why a log-source
index could not be the fix:

> Connector product names don't line up 1:1 with spec products
> (`aws_cloudtrail` vs `aws`, `crowdstrike_falcon` vs `edr`), so any
> product-based pre-filter risks silently dropping a real match.

A product-based pre-filter had been tried and reverted for exactly that.
Reinstating it with a mapping table would leave every new connector one
missing table entry away from a detection that stops firing, with nothing
failing and no error anywhere — the worst available failure mode for a
detection platform.

**We index on the fields a rule requires instead.** `match_when` is an AND
at the top level, so a rule that requires a field the event does not carry
cannot match it, whatever either side's product names say. That is
strictly more selective than log source *and* it is provably lossless,
which log source is not.

"Required" is decided by **running the real matcher against an empty
event**, once per clause at load time, rather than by reading operator
names:

```python
_check(field, op, expected, {}) is False  # => the field is required
```

Writing the test for that proved the point. `neq` reads like a negation
and would be on anyone's hand-written list of absence-tolerant operators.
This matcher's `neq` returns `False` for a missing field *on purpose* —
its own comment says a rule using it must not fire on absence of data — so
the field is required. A hand-maintained list would have been wrong in the
direction that drops detections.

### Measured

| | |
|---|---|
| Rules loaded | 2,511 |
| Rules with at least one required field | 1,751 (69.74%) |
| Rules in every candidate list | 760 |
| Candidates for a routine cloud event | 797 of 2,511 (**68.3% fewer**) |
| Evaluation time, full pass | 2.760 ms/event |
| Evaluation time, indexed | 1.066 ms/event (**2.6x**) |

Measured over 2,000 iterations in process on an 18-core Apple-silicon
host. Not a cloud-hardware figure; see the performance page.

The corpus was **2,511 executable rules** when this was measured, and the
figures above are left at what was actually run rather than restated against
a corpus that has since grown to 2,966. What carries forward is the ratio —
the index narrows a routine cloud event to roughly a third of the corpus,
whatever its size — not the absolute counts. Re-measure before quoting an
absolute number here.

### What keeps it safe

`services/fusion/tests/test_rule_index_is_lossless.py` replays every
committed fixture through both paths and requires identical hits in the
same order, plus 200 random non-matching events and the empty event. The
indexed fraction is pinned just below the measured 0.6974 so it can only
ratchet up and a change that lowers it has to say so in the same commit.

## Decision 2: partition by entity, keyed the way fusion correlates

`services/ingest` keyed every Kafka message `tenant:event_id`, which is
unique per event. Every event therefore hashed to an arbitrary partition
and **nothing about one entity's events was ordered relative to another's**
— while fusion correlates on `{tenant}:{entity}:{tactic}` and the windowed
engine stitches sequences by event time. Two events about one host
arriving on two partitions, consumed by two replicas, is the case where a
sequence is stitched out of order or one incident is split in two.

The key is now `tenant:entity`, with entity resolved in **the same
precedence `RawAlert.correlation_key()` uses** — source IP, then hostname,
then username, then domain. Partitions are ordered, so one entity's events
are ordered relative to each other; different entities still spread across
the cluster, so this is ordering without serialising the topic.

A partition key that disagreed with the correlation key would route an
entity's events to a partition and then correlate them under a different
name, which spreads one incident across replicas while looking correct
from either end. The two orders are held together by a test.

An event with no resolvable entity falls back to its own id. Falling back
to the tenant id would put every anonymous event in a tenant onto one
partition — a hot partition, and the least useful one to serialise.

## Decision 3: lag hints are published, not acted on

`services/fusion` publishes a consumer-lag gauge and a derived
`aisoc_fusion_scale_hint` so an operator's autoscaler can read it. AiSOC
does **not** scale itself.

Deliberate. An autoscaler is the cluster's, not the application's: a
platform that scaled its own deployments would need write access to the
orchestrator, would fight whatever HPA or KEDA scaler the operator already
runs, and would be unable to honour the quota and cost policies that live
outside it. Publishing the signal is the whole of our job; the
`ScaledObject` in `apps/docs/docs/operations/performance.md` shows how to
consume it.

## Consequences

- A rule whose clauses are all absence-tolerant is in every candidate
  list. That is correct and is 760 rules today; a corpus that drifted
  towards such rules would quietly lose the index's benefit, which is why
  the fraction is pinned.
- Partitioning by entity means a single very noisy entity is a hot
  partition. That is the trade for per-entity ordering and is the
  conventional one; the alternative loses the ordering fusion depends on.
- The 5,000 events/s target in the depth plan is **not met and not
  measured** on cloud hardware. No cloud instance has been provisioned for
  this project. The performance page states that rather than implying a
  figure.
