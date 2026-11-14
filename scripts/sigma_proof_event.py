#!/usr/bin/env python3
"""Build a vendor-shaped event that should trigger a given Sigma rule.

Fixtures synthesized from the rule they test are tautological — replaying one
proves the matcher works and says nothing about whether the field exists. This
repository has already paid for that: roughly 600 of 825 fixtures were in that
state, and none of them could catch the 663 rules matching on fields no
connector emitted.

The event built here is different in one specific, load-bearing way. It is
written in the **vendor's own document shape** — a Windows event with its
``System`` and ``EventData`` containers, a CloudTrail record inside its
``CloudTrailEvent`` envelope — and the proof replays it through the real
connector's ``normalize()`` and the real ``DetectionEngine``. Neither the
connector's mapping nor the engine's flattening is reimplemented anywhere in
the test, so a field the connector fails to propagate makes the replay fail.
That is exactly the class of defect the synthesized fixtures could not see.

Sigma field names are vendor-native by design, so placing ``CommandLine`` in
``EventData`` is transcribing the Windows event schema rather than copying the
connector. What remains shared with the rule is the choice of *values*, which
is unavoidable: some value has to satisfy the clause. The proof is therefore
"this rule is reachable and fires on a well-formed event of its own log
source", not "this rule detects an attack" — no gate in this repository claims
the latter.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any

#: Fields that live in a Windows event's ``System`` header rather than in the
#: event-specific ``EventData`` payload. From the Windows event schema.
_WINDOWS_SYSTEM_FIELDS = {
    "EventID",
    "Channel",
    "Computer",
    "Provider_Name",
    "EventRecordID",
    "TimeCreated",
    "Task",
    "Level",
    "Keywords",
    "Opcode",
    "Version",
    "SecurityUserID",
    "Correlation",
    "Execution",
}


def _literal(v: Any) -> str:
    """Materialise a Sigma value's wildcards into concrete characters."""
    s = "true" if v is True else "false" if v is False else str(v)
    out: list[str] = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s) and s[i + 1] in "*?\\":
            out.append(s[i + 1])
            i += 2
            continue
        out.append("wild" if ch == "*" else "z" if ch == "?" else ch)
        i += 1
    return "".join(out)


@dataclass
class _Constraints:
    """Everything one field must satisfy, gathered across selections.

    Collecting before rendering matters more than it looks. A Sigma rule
    routinely constrains the same field from several selections at once —
    ``all of selection_*`` with ``CommandLine|contains`` in one and
    ``CommandLine|contains|all`` in another is the single most common shape in
    the corpus. Satisfying whichever clause was seen first leaves the rest
    unmet, and the rule then fails its own proof for a reason that has nothing
    to do with the rule.
    """

    equals: str | None = None
    prefix: str | None = None
    suffix: str | None = None
    substrings: list[str] = dc_field(default_factory=list)
    absent: bool = False

    def render(self) -> str | None:
        if self.absent:
            return None
        if self.equals is not None:
            return self.equals
        head = self.prefix or ""
        tail = self.suffix or ""
        middle = "-".join(s for s in self.substrings if s not in head and s not in tail)
        parts = [p for p in (head, middle) if p]
        body = "-".join(parts)
        return f"{body}{tail}" if body else tail or "proof-value"


def _add_constraint(bag: dict[str, _Constraints], raw_key: str, value: Any) -> None:
    parts = raw_key.split("|")
    name = parts[0]
    mods = {m.lower() for m in parts[1:]}
    con = bag.setdefault(name, _Constraints())

    items = [i for i in (value if isinstance(value, list) else [value]) if i is not None]
    if not items:
        # `field: null` asks for the field to be absent; an earlier positive
        # constraint wins, since a contradictory rule cannot be proven anyway.
        if not con.substrings and con.equals is None and con.prefix is None and con.suffix is None:
            con.absent = True
        return
    con.absent = False

    if "all" in mods and "contains" in mods:
        con.substrings.extend(_literal(i) for i in items)
        return

    first = _literal(items[0])
    if "windash" in mods and first and first[0] in "-/":
        first = "-" + first[1:]
    if "contains" in mods:
        con.substrings.append(first)
    elif "startswith" in mods:
        con.prefix = first if con.prefix is None else con.prefix
    elif "endswith" in mods:
        con.suffix = first if con.suffix is None else con.suffix
    elif con.equals is None:
        con.equals = first


def _flat_fields(sel: Any, bag: dict[str, _Constraints]) -> None:
    """Gather constraints for every entry in a selection body."""
    if isinstance(sel, list):
        for item in sel:
            if isinstance(item, dict):
                # A list of maps is an OR; satisfying the first is enough.
                _flat_fields(item, bag)
                return
        return
    if not isinstance(sel, dict):
        return
    for key, value in sel.items():
        _add_constraint(bag, key, value)


def required_selection_keys(detection: dict[str, Any], condition: str) -> list[str]:
    """Detection keys the condition needs satisfied, ignoring its filters.

    Filters are deliberately skipped. A filter excludes events, so leaving its
    fields unset is the right way to build an event the rule should fire on —
    and if that guess is wrong the replay simply fails and the rule is refused,
    which costs coverage but never correctness.
    """
    keys = [k for k in detection if k != "condition"]
    lowered = condition.lower()
    positive: list[str] = []
    for key in keys:
        if key.startswith("filter"):
            continue
        # `1 of selection*` only needs one; take the first that appears.
        if key in lowered or any(key.startswith(tok.rstrip("*")) for tok in lowered.split() if tok.endswith("*")):
            positive.append(key)
    if not positive:
        positive = [k for k in keys if not k.startswith("filter")]
    if " 1 of " in f" {lowered} " or lowered.startswith("1 of "):
        groups = [k for k in positive if k.startswith("selection")]
        if groups:
            positive = [groups[0]] + [k for k in positive if not k.startswith("selection")]
    return positive


def build_vendor_event(doc: dict[str, Any], emitter: str) -> dict[str, Any] | None:
    """Build the raw vendor payload a connector would receive, or None."""
    detection = doc.get("detection") or {}
    condition = detection.get("condition")
    if not isinstance(condition, str):
        return None

    bag: dict[str, _Constraints] = {}
    for key in required_selection_keys(detection, condition):
        _flat_fields(detection.get(key), bag)
    fields = {name: rendered for name, con in bag.items() if (rendered := con.render()) is not None}
    if not fields:
        return None

    if emitter == "windows_event":
        system = {k: v for k, v in fields.items() if k in _WINDOWS_SYSTEM_FIELDS}
        data = {k: v for k, v in fields.items() if k not in _WINDOWS_SYSTEM_FIELDS}
        system.setdefault("EventID", "1")
        system.setdefault("Channel", "Microsoft-Windows-Sysmon/Operational")
        system.setdefault("Computer", "WIN-PROOF-01")
        system.setdefault("EventRecordID", "1")
        return {"System": system, "EventData": data}

    if emitter == "aws_cloudtrail":
        # The connector unpacks the record from this JSON string.
        return {
            "EventName": fields.get("eventName", "ProofEvent"),
            "CloudTrailEvent": json.dumps({"eventTime": "2026-01-01T00:00:00Z", **fields}),
        }

    # okta / azure_activity keep the vendor record at the top level.
    return dict(fields)


def build_null_event(emitter: str) -> dict[str, Any]:
    """A well-formed but empty event of the same shape.

    Replayed to catch a rule that compiled to something vacuous. A rule that
    fires on this fires on everything, which is worse than not shipping it.
    """
    if emitter == "windows_event":
        return {
            "System": {"EventID": "4689", "Channel": "Security", "Computer": "WIN-NULL-01", "EventRecordID": "2"},
            "EventData": {},
        }
    if emitter == "aws_cloudtrail":
        return {"EventName": "Noop", "CloudTrailEvent": json.dumps({"eventTime": "2026-01-01T00:00:00Z"})}
    return {}
