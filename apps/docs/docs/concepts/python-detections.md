---
title: Writing detections in Python
description: When a rule needs logic a YAML condition cannot express.
---

# Writing detections in Python

Most detection content is declarative, and should be: a YAML condition is
reviewable by someone who does not write Python, diffable, and safe to
accept from a contributor. Some rules are not expressible that way — a
comparison between two fields, a computation over a list, a check that
depends on the relationship between values rather than any one of them.

`packages/aisoc-detections` is for those.

```python
from aisoc_detections import rule

@rule(
    id="ssh-key-added-outside-change-window",
    severity="high",
    techniques=["T1098.004"],
)
def detect(event: dict) -> bool:
    """Authorised-keys modified outside the declared change window.

    Not expressible declaratively: it compares the event's own timestamp
    against a per-tenant window, which is a relationship between two values
    rather than a property of one.
    """
    if event.get("file_path") != "/root/.ssh/authorized_keys":
        return False
    hour = int(event.get("event_time_hour", -1))
    return not (2 <= hour <= 4)
```

## The fixture gate

A Python rule ships with a positive and a negative fixture, and CI runs both.
The negative one is the one that matters: a rule with only a positive fixture
passes its test by returning `True` unconditionally, and the test proves
nothing.

This is the same non-circular discipline the YAML corpus uses, and it exists
because of a specific failure in this repo's history — roughly 600 of 825
fixtures were *synthesized from the rule they test*, so fixture replay was
tautological and could never catch a rule matching a field nothing produces.
A fixture written from the rule tests that the rule is itself.

Write fixtures from a real event shape. If you do not have one, say so in the
rule's docstring rather than inventing a plausible payload.

## What a rule may and may not do

A rule is a pure function of one normalised event. It may not:

- perform I/O, including network calls and file reads
- import anything outside the standard library and `aisoc_detections`
- hold state between invocations

These are enforced, not advisory. A rule runs on the hot path for every
ingested event, and a rule that makes a network call turns the detection
engine into a distributed system with a per-event fan-out.

Rules needing state belong in the [windowed engine](./windowed-detections.md);
rules needing enrichment should match on the enriched fields fusion already
adds, rather than fetching their own.

## Choosing between the three authoring modes

| Mode | Use when | Reviewable by |
|------|----------|---------------|
| YAML / Sigma | The condition is a property of one event's fields | Anyone |
| Python spec | The logic compares fields, computes, or iterates | A Python reviewer |
| Windowed spec | The signal is in a set of events over time | A Python reviewer |

Prefer the declarative form. A Python rule is more expressive and harder to
audit, and the detection corpus is content other people are trusted to read.

## See also

- [Detection content](./detections.md)
- [Windowed detections](./windowed-detections.md)
- [Truth table](https://github.com/beenuar/AiSOC/blob/main/docs/detections/truth-table.md)
