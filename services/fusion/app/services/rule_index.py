"""An index that stops fusion running every rule against every event.

Parity plan 6.9 / depth plan 4.4.

Why not "index by log source", which is what the plan says
---------------------------------------------------------
Because the engine's own docstring already records why that cannot be the
index: connector product names do not line up with the products the specs
name — ``aws_cloudtrail`` against ``aws``, ``crowdstrike_falcon`` against
``edr`` — and a pre-filter built on them silently drops real matches. A
previous attempt at exactly that was tried and reverted. Shipping it again
with a mapping table would mean every new connector is one missing table
entry away from a detection that stops firing, with nothing failing.

What is indexed instead
-----------------------
The fields a rule **requires**. ``match_when`` is an AND at the top level,
so if any one of its clauses cannot be satisfied by an event that lacks a
field, that field's presence is necessary for the rule to fire at all. A
rule requiring ``Image`` cannot match an event with no ``Image``, whatever
the product names say.

That is a strictly stronger filter than log source *and* it is provably
lossless, which log source is not. It also needs no mapping table, so a
new connector cannot silently fall out of coverage.

How "required" is decided
-------------------------
Not by reading the operator name. By **running the real matcher** against
an empty event, once per clause at load time:

    _check(field, op, expected, {}) is False  =>  the field is required

That is the definition, executed rather than restated. An operator that
tolerates absence — ``neq`` against a missing field is true, ``not_in`` is
true, ``eq: null`` is a presence *check* — answers True on the empty event
and the field is correctly not treated as required. A matcher that grows a
new operator is classified correctly the day it is added, because nothing
here enumerates operators.

Anything that raises, or that the shape of the clause makes unclear, is
treated as **not** required. The failure directions are not symmetric:
over-claiming a requirement drops a real detection silently, while
under-claiming only costs the full pass for that rule.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from app.services.detection_matcher import _check, _split_op


@dataclass(frozen=True)
class IndexStats:
    """What the index did, for the log line and for the gate."""

    rules: int
    indexed: int
    always_evaluated: int
    distinct_fields: int

    @property
    def indexed_fraction(self) -> float:
        return self.indexed / self.rules if self.rules else 0.0


def required_fields(match_when: dict[str, Any]) -> set[str]:
    """Fields whose absence guarantees this rule cannot match.

    Only the top level is considered. ``any_of`` and ``all_of`` are
    skipped: a field inside an ``any_of`` is not required, because another
    branch may satisfy it, and a nested ``all_of`` is only required if the
    whole group is — a refinement that would buy little and could be
    wrong, which is the one thing this must not be.
    """
    if not isinstance(match_when, dict):
        return set()
    required: set[str] = set()
    for key, expected in match_when.items():
        if key in {"any_of", "all_of"}:
            continue
        field, op = _split_op(key)
        if not field:
            continue
        try:
            satisfied_by_absence = _check(field, op, expected, {})
        except Exception:  # noqa: BLE001 — see the module docstring
            # A clause the matcher cannot evaluate against an empty event
            # is not evidence that the field is required. Treated as not
            # required, which costs a full pass and loses nothing.
            continue
        if not satisfied_by_absence:
            required.add(field)
    return required


class RuleIndex:
    """Maps an event's field names to the rules that could possibly match.

    One pivot field per rule, chosen as the **rarest** of its required
    fields. Rarest rather than first: ``EventID`` is required by hundreds
    of Windows rules and ``Provider_Name`` by a handful, so pivoting on
    the first key encountered would put most of the corpus in one bucket
    and index almost nothing in practice.
    """

    def __init__(self, rules: list[dict[str, Any]]) -> None:
        self._rules = rules
        self._by_field: dict[str, list[int]] = defaultdict(list)
        #: Rules with no required field at all. Evaluated against every
        #: event, because nothing about the event can rule them out.
        self._always: list[int] = []

        requirements = [required_fields(rule.get("match_when") or {}) for rule in rules]

        frequency: dict[str, int] = defaultdict(int)
        for fields in requirements:
            for field in fields:
                frequency[field] += 1

        for position, fields in enumerate(requirements):
            if not fields:
                self._always.append(position)
                continue
            pivot = min(sorted(fields), key=lambda f: (frequency[f], f))
            self._by_field[pivot].append(position)

        self._stats = IndexStats(
            rules=len(rules),
            indexed=len(rules) - len(self._always),
            always_evaluated=len(self._always),
            distinct_fields=len(self._by_field),
        )

    @property
    def stats(self) -> IndexStats:
        return self._stats

    def candidates(self, fields: dict[str, Any]) -> list[dict[str, Any]]:
        """Rules that could match an event carrying these field names.

        Returned in the corpus's own order. The full pass yields hits in
        rule order and callers (and the alert the hits become) depend on
        that, so an index that returned them bucket by bucket would change
        behaviour while claiming only to change cost.
        """
        positions: set[int] = set(self._always)
        by_field = self._by_field
        for name in fields:
            bucket = by_field.get(name)
            if bucket is not None:
                positions.update(bucket)
        return [self._rules[i] for i in sorted(positions)]
