"""The shape a hunting agent is allowed to produce. It is not query text.

Gap-closure Phase 8.3.

Phase 4 drew a boundary and this module is the same boundary in a second
place: **the model supplies structure, the platform owns translation and
tenant scoping.** There, an agent searching a customer's SIEM names an
indicator *type* from a closed set and the platform resolves the field per
backend. Here, an agent proposing a hunt names a *field* from a closed set and
an *operator* from a closed set, and the platform compiles the result into
SQL.

Why that matters more for hunting than for anything else
---------------------------------------------------------

A hunt is a question about a whole estate's history, and the hypothesis that
prompts one comes from somewhere: an advisory, a ticket, an analyst pasting
something a customer sent them. All of those are attacker-influenceable, so a
model relaying one into a query language is one injected instruction away from
an arbitrary read across every tenant-visible row in the warehouse. A read at
that scale is not harmless. It can exfiltrate an estate's worth of telemetry
and, on a metered licence, cost real money.

So there is no field on :class:`HuntPlan` that can carry SQL, SPL, KQL or free
text, and ``scripts/check_hunt_agent_boundary.py`` reads the JSON schema the
model is handed and fails if one appears. Asserting on the schema rather than
on this module's code is deliberate: the schema is what actually constrains a
model, and a validator behind a permissive schema still lets the model spend a
turn producing something that gets rejected.

Why the field vocabulary is the lake's columns
-----------------------------------------------

The hand-authored corpus in ``hunts/`` matches vendor-native fields
(``EventID``, ``TargetUserName``), which is right for a human writing a
hypothesis about a specific product. It is the wrong vocabulary to offer a
model, because nothing can tell the model which of those fields a given
deployment actually records: the estate's connectors decide that, and a hunt
naming a field nothing emits returns zero while looking like it worked. This
repository has shipped that twice at scale.

The lake's columns do not have that problem. Every one is written by
``lake_writer.event_to_row`` on every event, so a plan over them is a plan the
platform can guarantee is answerable. ``scripts/check_hunt_agent_boundary.py``
checks this list against the ClickHouse DDL, so a column that stops existing
stops being offered.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "HUNT_FIELDS",
    "HUNT_OPERATORS",
    "MAX_CLAUSES",
    "HuntClause",
    "HuntPlan",
    "HuntPlanError",
    "plan_json_schema",
    "validate_plan",
]


class HuntPlanError(ValueError):
    """A plan was refused. Always with a reason the model can act on."""


#: Fields a hunting agent may name, with prose the model selects on.
#:
#: Every one is a column of ``aisoc.raw_events`` that
#: ``services/fusion/app/services/lake_writer.py`` populates. The descriptions
#: are written for a model rather than for a schema reference, because the
#: choice this vocabulary has to get right is "which field carries the thing I
#: am looking for", and a bare column name does not answer it.
HUNT_FIELDS: dict[str, str] = {
    "user_name": "The account an event is about. Taken from the actor's user name.",
    "src_hostname": "The host that reported the event, or the source endpoint's hostname. This is the customer's own machine.",
    "dst_hostname": "The hostname an event reached out to. Use this for a domain or a destination, never src_hostname.",
    "process_name": "An executable or image name, for example powershell.exe.",
    "file_path": "A file path named by the event.",
    "hash_sha256": "A file digest. Holds whichever hash the source reported first, so it may be an MD5 or a SHA-1 despite the name.",
    "source_ip": "The source address of a connection.",
    "dest_ip": "The destination address of a connection.",
    "src_port": "The source port, as a number.",
    "dst_port": "The destination port, as a number.",
    "protocol": "The network protocol name, for example tcp.",
    "connector_type": "Which product the event came from, for example aws_cloudtrail. Use this to scope a hunt to one source.",
    "severity_id": "The event's severity as a number, 1 (info) through 5 (critical).",
    "class_uid": "The OCSF event class, as a number. Use only when the hypothesis is genuinely about an event class.",
    "mitre_techniques": "Technique identifiers attached to the event, for example T1059.001. A list.",
    "mitre_tactics": "Tactic names attached to the event. A list.",
    "iocs": "Addresses and hashes extracted from the event. A list.",
}

#: Columns holding ``Array(String)``. Membership is the only sensible test.
_ARRAY_FIELDS = frozenset({"mitre_techniques", "mitre_tactics", "iocs"})

#: Columns holding a number. A string comparison against one is a type error
#: in ClickHouse rather than a wrong answer, but refusing here gives the model
#: a reason instead of a stack trace.
_NUMERIC_FIELDS = frozenset({"src_port", "dst_port", "severity_id", "class_uid"})

#: Columns holding an IP. Values go through ``toIPv6`` at compile time because
#: the writer stores an IPv4 address in its IPv4-mapped form.
_IP_FIELDS = frozenset({"source_ip", "dest_ip"})

#: Operators, with the prose the model selects on. A closed set: anything
#: outside it is refused rather than passed through, because "pass an unknown
#: operator to the compiler" is how a vocabulary becomes a query language.
HUNT_OPERATORS: dict[str, str] = {
    "eq": "Exactly equal to the value.",
    "neq": "Not equal to the value.",
    "contains": "The field contains the value as a substring. Only for text fields.",
    "starts_with": "The field begins with the value. Only for text fields.",
    "ends_with": "The field ends with the value. Only for text fields.",
    "gte": "Greater than or equal to. Only for numeric fields.",
    "lte": "Less than or equal to. Only for numeric fields.",
    "has": "The list field contains this exact value. Only for list fields.",
}

_TEXT_ONLY = frozenset({"contains", "starts_with", "ends_with"})
_NUMERIC_ONLY = frozenset({"gte", "lte"})

#: How many clauses one plan may carry.
#:
#: Bounded because a plan is a cost. Every clause is a predicate over a
#: partition of the warehouse, and a model that has been told to be thorough
#: will keep adding them. Seven is more than any hunt in the hand-authored
#: corpus uses.
MAX_CLAUSES = 7

#: Longest value a clause may carry. A multi-kilobyte "hostname" is a payload
#: rather than a value, and length is the cheapest thing to bound.
_MAX_VALUE_LENGTH = 512


@dataclass(frozen=True)
class HuntClause:
    """One predicate. Field and operator from closed sets, value bound later."""

    field: str
    operator: str
    value: str

    def as_dict(self) -> dict[str, str]:
        return {"field": self.field, "operator": self.operator, "value": self.value}


@dataclass
class HuntPlan:
    """A hunting agent's proposal, before the platform compiles it.

    ``rationale`` is the only free-text field, it is never compiled into
    anything, and it exists so a finding can say why the hunt was shaped this
    way. It is rendered to a human and stored, never executed.
    """

    hypothesis: str
    clauses: list[HuntClause]
    rationale: str = ""
    lookback_hours: int = 168
    log_source_hint: str = ""
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "hypothesis": self.hypothesis,
            "clauses": [c.as_dict() for c in self.clauses],
            "rationale": self.rationale,
            "lookback_hours": self.lookback_hours,
            "log_source_hint": self.log_source_hint,
            "warnings": list(self.warnings),
        }


def plan_json_schema() -> dict[str, Any]:
    """The schema the model is handed, and the thing the gate reads.

    Every property is typed ``string`` or ``integer`` and the two that matter
    are closed enums, so a query cannot arrive as a field name, as structured
    data, or as an unconstrained string. Same construction as the Phase 4 tool
    schemas, and checked the same way.
    """
    return {
        "type": "object",
        "required": ["clauses"],
        "additionalProperties": False,
        "properties": {
            "clauses": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_CLAUSES,
                "items": {
                    "type": "object",
                    "required": ["field", "operator", "value"],
                    "additionalProperties": False,
                    "properties": {
                        "field": {
                            "type": "string",
                            "enum": sorted(HUNT_FIELDS),
                            "description": "Which recorded field to test. "
                            + " ".join(f"{name}: {desc}" for name, desc in sorted(HUNT_FIELDS.items())),
                        },
                        "operator": {
                            "type": "string",
                            "enum": sorted(HUNT_OPERATORS),
                            "description": " ".join(f"{name}: {desc}" for name, desc in sorted(HUNT_OPERATORS.items())),
                        },
                        "value": {
                            "type": "string",
                            "description": (
                                "The value to test against. A literal, never an expression and never a fragment of a query language."
                            ),
                        },
                    },
                },
            },
            "rationale": {
                "type": "string",
                "description": ("Why this shape answers the hypothesis. Rendered to an analyst; never executed."),
            },
            "lookback_hours": {
                "type": "integer",
                "minimum": 1,
                "maximum": 2160,
                "description": "How far back to look, in hours. Default 168 (seven days).",
            },
        },
    }


def _refuse(reason: str) -> HuntPlanError:
    return HuntPlanError(reason)


def validate_plan(raw: Any, *, hypothesis: str) -> HuntPlan:
    """Turn whatever the model returned into a plan, or refuse it by name.

    Every refusal names the offending value and lists the alternatives, so a
    model can correct itself on the next turn rather than retrying the same
    thing. A silent drop would produce a narrower hunt than the one the
    rationale describes, which reads to an analyst as a hunt that found
    nothing.
    """
    if not isinstance(raw, dict):
        raise _refuse(f"the plan must be an object, got {type(raw).__name__}")

    clauses_raw = raw.get("clauses")
    if not isinstance(clauses_raw, list) or not clauses_raw:
        raise _refuse("the plan must carry at least one clause; a hunt with no clauses matches the whole window")
    if len(clauses_raw) > MAX_CLAUSES:
        raise _refuse(f"a plan may carry at most {MAX_CLAUSES} clauses, got {len(clauses_raw)}")

    clauses: list[HuntClause] = []
    for index, entry in enumerate(clauses_raw):
        if not isinstance(entry, dict):
            raise _refuse(f"clause {index} must be an object")
        name = str(entry.get("field") or "").strip()
        operator = str(entry.get("operator") or "").strip()
        value = entry.get("value")

        if name not in HUNT_FIELDS:
            raise _refuse(f"{name!r} is not a field a hunt may name. Choose one of: {', '.join(sorted(HUNT_FIELDS))}.")
        if operator not in HUNT_OPERATORS:
            raise _refuse(f"{operator!r} is not an operator a hunt may use. Choose one of: {', '.join(sorted(HUNT_OPERATORS))}.")
        if isinstance(value, bool) or value is None:
            raise _refuse(f"clause {index} on {name!r} needs a value")
        text = str(value).strip()
        if not text:
            raise _refuse(f"clause {index} on {name!r} needs a non-empty value")
        if len(text) > _MAX_VALUE_LENGTH:
            raise _refuse(f"a value longer than {_MAX_VALUE_LENGTH} characters is a payload rather than a value")

        is_array = name in _ARRAY_FIELDS
        is_numeric = name in _NUMERIC_FIELDS

        if operator == "has" and not is_array:
            raise _refuse(f"'has' tests membership of a list, and {name!r} is not a list field. Use 'eq' instead.")
        if is_array and operator != "has":
            raise _refuse(f"{name!r} is a list field, so the only operator that applies is 'has'.")
        if operator in _NUMERIC_ONLY and not is_numeric:
            raise _refuse(
                f"{operator!r} compares numbers, and {name!r} is not numeric. Numeric fields are: {', '.join(sorted(_NUMERIC_FIELDS))}."
            )
        if operator in _TEXT_ONLY and (is_numeric or name in _IP_FIELDS):
            raise _refuse(f"{operator!r} is a text comparison and {name!r} is not text. Use 'eq'.")
        if is_numeric:
            try:
                int(float(text))
            except ValueError as exc:
                raise _refuse(f"{name!r} is numeric, so {text!r} is not a value it can hold") from exc

        clauses.append(HuntClause(field=name, operator=operator, value=text))

    lookback = raw.get("lookback_hours", 168)
    try:
        hours = max(1, min(int(lookback), 2160))
    except (TypeError, ValueError):
        hours = 168

    return HuntPlan(
        hypothesis=hypothesis,
        clauses=clauses,
        rationale=str(raw.get("rationale") or "")[:2000],
        lookback_hours=hours,
    )
