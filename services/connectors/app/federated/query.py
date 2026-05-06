"""Unified query model for federated SIEM search.

A ``UnifiedQuery`` is the single in-memory representation that can be
translated into Splunk SPL, Microsoft Sentinel KQL, or Elastic ES|QL.
The model is intentionally small — we resist the urge to model every
backend's full grammar because the goal is *cross-SIEM pivot*, not
"replace your SIEM's query language".

Three building blocks:

* ``Indicator`` — a single ``field <op> value`` triple. Stacking
  indicators implies AND-conjunction; OR is expressed by composing
  multiple queries client-side and merging the result sets.
* ``UnifiedQuery`` — the top-level envelope: free-text search, indicator
  list, time window, and a result cap.
* ``parse_unified_query`` — accepts a JSON-shaped dict from the wire and
  validates it into the dataclass form. We do not depend on Pydantic
  here so this module stays usable from the connectors microservice
  without dragging the whole API stack.

Trust boundary: this module never sees plaintext credentials. It only
shapes the query that gets handed to a connector instance the API
service has already constructed with decrypted auth_config.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# Operator vocabulary kept deliberately narrow. Adding a new operator
# means updating every translator, so we keep the surface tight.
Operator = Literal[
    "eq",            # field == value
    "ne",            # field != value
    "contains",      # substring match (case-insensitive when the backend supports it)
    "starts_with",   # prefix match
    "ends_with",     # suffix match
    "gt",            # field > value (numeric / timestamp)
    "gte",           # field >= value
    "lt",            # field < value
    "lte",           # field <= value
    "in",            # field is one of [...]
]

_VALID_OPERATORS: frozenset[str] = frozenset(
    [
        "eq",
        "ne",
        "contains",
        "starts_with",
        "ends_with",
        "gt",
        "gte",
        "lt",
        "lte",
        "in",
    ]
)


class QueryError(ValueError):
    """Raised when an incoming query payload fails validation.

    Distinct from ``ValueError`` so the API layer can map it to a 422
    without swallowing other validation errors.
    """


@dataclass(frozen=True)
class Indicator:
    """A single ``field <op> value`` triple."""

    field: str
    operator: Operator
    value: Any

    def __post_init__(self) -> None:
        if not isinstance(self.field, str) or not self.field.strip():
            raise QueryError("indicator.field must be a non-empty string")
        if self.operator not in _VALID_OPERATORS:
            raise QueryError(
                f"indicator.operator '{self.operator}' is not one of {sorted(_VALID_OPERATORS)}"
            )
        if self.operator == "in":
            if not isinstance(self.value, (list, tuple)) or not self.value:
                raise QueryError("indicator with operator='in' requires a non-empty list value")
        elif self.value is None:
            raise QueryError(f"indicator.value must not be None for operator '{self.operator}'")


@dataclass(frozen=True)
class UnifiedQuery:
    """A SIEM-agnostic query.

    ``free_text`` is a substring (or full-text) search executed against
    the backend's default search field. ``indicators`` are AND-joined
    field/op/value filters. ``since_seconds`` is a relative-from-now
    window, kept simple to match how alerts are typically queried in
    SOC pivots; absolute time ranges can be added later if the eval
    harness needs them.

    ``limit`` caps the number of rows returned per backend; the API
    service then merges and re-caps at the federated level.
    """

    free_text: str = ""
    indicators: tuple[Indicator, ...] = field(default_factory=tuple)
    since_seconds: int = 3600
    limit: int = 100

    def __post_init__(self) -> None:
        if not isinstance(self.since_seconds, int) or self.since_seconds <= 0:
            raise QueryError("since_seconds must be a positive integer")
        if self.since_seconds > 7 * 24 * 3600:
            raise QueryError("since_seconds must be ≤ 7 days; use a SIEM-native search for longer windows")
        if not isinstance(self.limit, int) or self.limit <= 0:
            raise QueryError("limit must be a positive integer")
        if self.limit > 1000:
            raise QueryError("limit must be ≤ 1000")
        if not self.free_text.strip() and not self.indicators:
            raise QueryError("query must include free_text or at least one indicator")

    def to_dict(self) -> dict[str, Any]:
        return {
            "free_text": self.free_text,
            "indicators": [
                {"field": i.field, "operator": i.operator, "value": i.value}
                for i in self.indicators
            ],
            "since_seconds": self.since_seconds,
            "limit": self.limit,
        }


def parse_unified_query(payload: dict[str, Any]) -> UnifiedQuery:
    """Turn a JSON-shaped dict into a validated ``UnifiedQuery``.

    Accepts both ``indicators`` (preferred) and ``filters`` (alias kept
    so older clients don't break) for the indicator list.
    """
    if not isinstance(payload, dict):
        raise QueryError("query payload must be a JSON object")

    raw_indicators = payload.get("indicators")
    if raw_indicators is None:
        raw_indicators = payload.get("filters", [])
    if not isinstance(raw_indicators, list):
        raise QueryError("indicators must be a list")

    parsed: list[Indicator] = []
    for entry in raw_indicators:
        if not isinstance(entry, dict):
            raise QueryError("each indicator must be an object with field/operator/value")
        try:
            parsed.append(
                Indicator(
                    field=entry["field"],
                    operator=entry["operator"],
                    value=entry["value"],
                )
            )
        except KeyError as exc:
            raise QueryError(f"indicator missing key: {exc.args[0]}") from exc

    return UnifiedQuery(
        free_text=str(payload.get("free_text", "") or "").strip(),
        indicators=tuple(parsed),
        since_seconds=int(payload.get("since_seconds", 3600) or 3600),
        limit=int(payload.get("limit", 100) or 100),
    )
