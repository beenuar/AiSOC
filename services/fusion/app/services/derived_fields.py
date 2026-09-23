"""Fields the detection engine can compute from an event it already has.

138 of 833 executable rules match on fields no connector emits, so they can
never fire — a rule that never fires and a rule with nothing to fire on look
identical from outside, which is why the number went unnoticed for so long.

Most of those 138 genuinely need something that does not exist: a windowed
evaluator (73), identity enrichment (24), per-tenant allowlists (15). This
module handles the ones that need nothing at all — where the answer is
already in the event and only the arithmetic is missing.

Two families:

**Field comparisons.** `actor_eq_target`, `actor_uid_neq_owner_uid`,
`object_tenant_id_eq_caller_tenant_id`. The rule wants to know whether two
fields of the same event agree. Both values are present; nothing was
comparing them.

**Time of day.** `is_business_hours`, `is_after_hours`, `is_weekend`. A pure
function of the event timestamp.

The rule that governs everything here: **an underivable field is absent, not
false.** If either side of a comparison is missing, the derived key is not
set, so a rule matching `actor_eq_target: false` does not fire on an event
where neither actor nor target is known. Defaulting to `False` would make
every event with missing data look like a cross-account access, which is a
detection that fires on ignorance.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

#: `<left>_eq_<right>` / `<left>_neq_<right>`. Non-greedy on the left so
#: `actor_uid_neq_owner_uid` splits at the *first* separator, giving
#: (actor_uid, owner_uid) rather than (actor, uid_neq_owner_uid).
_COMPARISON_RE = re.compile(r"^(?P<left>.+?)_(?P<op>eq|neq)_(?P<right>.+)$")

#: Business hours in the tenant's local time. A default rather than a
#: constant: "outside business hours" means nothing without knowing whose
#: business, and a rule that assumes UTC fires all night for half the world.
DEFAULT_BUSINESS_START_HOUR = 8
DEFAULT_BUSINESS_END_HOUR = 18

#: Timestamp fields, in the order they are trusted. `event_time` is when the
#: thing happened; `ingest_time` is when we heard about it, and using the
#: latter would make a batch import at 03:00 look like a night-time attack.
_TIME_FIELDS = ("event_time", "timestamp", "time", "@timestamp", "ingest_time")


def _parse_time(event: dict[str, Any]) -> datetime | None:
    for field in _TIME_FIELDS:
        raw = event.get(field)
        if raw is None:
            continue
        if isinstance(raw, datetime):
            return raw
        if isinstance(raw, int | float):
            try:
                # Milliseconds if it is far too large to be seconds.
                seconds = raw / 1000 if raw > 1e11 else raw
                return datetime.fromtimestamp(seconds)  # noqa: DTZ006 - local by design
            except (OSError, ValueError, OverflowError):
                continue
        if isinstance(raw, str):
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                continue
    return None


def _normalise(value: Any) -> Any:
    """Compare case-insensitively for strings, exactly for everything else.

    `Alice` and `alice` are the same principal in every directory this
    platform reads, and a comparison that says otherwise produces a
    cross-account finding for a casing difference.
    """
    return value.strip().lower() if isinstance(value, str) else value


def comparison_fields(event: dict[str, Any], requested: set[str] | None = None) -> dict[str, bool]:
    """Compute `<a>_eq_<b>` / `<a>_neq_<b>` keys the rules ask for.

    ``requested`` bounds the work to the field names some rule actually
    matches on. Without it this would have to enumerate every pair of keys
    in the event, which is quadratic and produces thousands of keys nothing
    reads.
    """
    if not requested:
        return {}

    out: dict[str, bool] = {}
    for name in requested:
        match = _COMPARISON_RE.match(name)
        if not match:
            continue
        left = event.get(match.group("left"))
        right = event.get(match.group("right"))
        # Absent, not false. A rule must not fire because we did not know.
        if left is None or right is None:
            continue
        equal = _normalise(left) == _normalise(right)
        out[name] = equal if match.group("op") == "eq" else not equal
    return out


def time_of_day_fields(
    event: dict[str, Any],
    *,
    business_start: int = DEFAULT_BUSINESS_START_HOUR,
    business_end: int = DEFAULT_BUSINESS_END_HOUR,
) -> dict[str, bool]:
    """Compute `is_business_hours`, `is_after_hours` and `is_weekend`.

    Returns nothing when the event carries no parseable timestamp, for the
    same reason as above: an unknown time is not "outside business hours".
    """
    when = _parse_time(event)
    if when is None:
        return {}

    weekend = when.weekday() >= 5
    in_hours = (not weekend) and business_start <= when.hour < business_end
    return {
        "is_business_hours": in_hours,
        "is_after_hours": not in_hours,
        "is_weekend": weekend,
    }


def enrich(
    event: dict[str, Any],
    requested: set[str] | None = None,
    *,
    business_start: int = DEFAULT_BUSINESS_START_HOUR,
    business_end: int = DEFAULT_BUSINESS_END_HOUR,
) -> dict[str, Any]:
    """Return ``event`` plus every derivable field the rules ask for.

    Non-destructive: a derived key never overwrites one the connector
    supplied. If a vendor genuinely emits `is_business_hours`, its value is
    the vendor's answer about its own tenant's hours, which is better than
    ours.
    """
    derived: dict[str, Any] = {}
    derived.update(time_of_day_fields(event, business_start=business_start, business_end=business_end))
    derived.update(comparison_fields(event, requested))

    if not derived:
        return event
    return {**derived, **event}


def requested_derived_fields(rules: list[dict[str, Any]]) -> set[str]:
    """Collect the derivable field names the ruleset matches on.

    Computed once at ruleset load rather than per event: the set changes
    when rules change, not when traffic arrives, and doing it per event was
    the difference between a cheap enrichment and a hot-path regex over
    every rule for every event.
    """
    from app.services.detection_matcher import _split_op  # noqa: PLC0415

    names: set[str] = set()

    def walk(clause: Any) -> None:
        if isinstance(clause, dict):
            for key, value in clause.items():
                if key in {"any_of", "all_of", "not"}:
                    walk(value)
                    continue
                field, _ = _split_op(key)
                if _COMPARISON_RE.match(field) or field.startswith("is_"):
                    names.add(field)
        elif isinstance(clause, list):
            for item in clause:
                walk(item)

    for rule in rules:
        walk(rule.get("match_when") or {})
    return names
