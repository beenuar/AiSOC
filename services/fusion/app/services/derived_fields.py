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

import ipaddress
import re
from datetime import datetime
from typing import Any

#: `<left>_eq_<right>` / `<left>_neq_<right>`. Non-greedy on the left so
#: `actor_uid_neq_owner_uid` splits at the *first* separator, giving
#: (actor_uid, owner_uid) rather than (actor, uid_neq_owner_uid).
#: Derived fields whose names are not self-describing by prefix.
#: `ip_class` is here rather than under an `is_` prefix because it is
#: a class, not a boolean: a boolean would have to answer "false" for
#: an address the dataset has never heard of.
_NAMED_DERIVED_FIELDS = frozenset({"ip_is_internal", "ip_class"})

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


def parse_event_time(event: dict[str, Any]) -> datetime | None:
    """When the event happened, from the first timestamp field it carries.

    Public because the windowed engine orders sequences by event time and
    must read it the same way this module does. Two independent readers of
    "when did this happen" is how a rule comes to mean one thing to the
    stateless engine and another to the windowed one.
    """
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
    when = parse_event_time(event)
    if when is None:
        return {}

    weekend = when.weekday() >= 5
    in_hours = (not weekend) and business_start <= when.hour < business_end
    return {
        "is_business_hours": in_hours,
        "is_after_hours": not in_hours,
        "is_weekend": weekend,
    }


#: Internal address space, by explicit list rather than `ipaddress.is_private`
#: / `is_global`: those predicates have moved between Python minors (the
#: documentation ranges flipped under the IANA special-registry alignment),
#: and a security predicate must not answer differently under two interpreter
#: builds of the same commit. RFC 1918, loopback and link-local plus their
#: IPv6 equivalents are internal; everything else — including carrier-grade
#: NAT and the documentation ranges — is not, so a runner registering from a
#: CGN address reads as external, which is the alarm an operator wants.
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
)


def ip_privacy_fields(event: dict[str, Any], requested: set[str] | None = None) -> dict[str, bool]:
    """Compute `ip_is_internal` from `src_ip`, when some rule asks for it.

    Absent, not false, when the event carries no parseable source address —
    an unknown origin is not an external one, and a rule gated on
    `ip_is_internal: false` must not fire because we did not know.
    """
    if not requested or "ip_is_internal" not in requested:
        return {}
    raw = event.get("src_ip")
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        addr = ipaddress.ip_address(raw.strip())
    except ValueError:
        return {}
    return {"ip_is_internal": any(addr in net for net in _INTERNAL_NETWORKS)}


def ip_class_fields(event: dict[str, Any], requested: set[str] | None = None) -> dict[str, str]:
    """Compute `ip_class` from `src_ip` when some rule asks for it.

    Live events never reach this: ingest stamps the class onto the activity
    projection from the same pinned dataset, and the detection engine lifts
    it into the flat namespace, where it wins because `enrich` lets the
    event's own value stand. This exists so a committed fixture, which
    carries a `src_ip` and no activity projection, classifies the same way.
    Without it a rule matching `ip_class` would pass its fixtures and never
    fire live, or the reverse.

    Absent, never false: three of the five classes ship with no records, so
    "no entry" is the ordinary answer and a rule gated on
    `ip_class: hosting_provider` must not fire because we did not know.
    """
    if not requested or "ip_class" not in requested:
        return {}
    answer = _classify_source_ip(event)
    if answer is None:
        return {}
    return {
        "ip_class": answer.ip_class,
        "ip_class_source": answer.source,
        "ip_class_dataset_version": answer.version,
    }


def _classify_source_ip(event: dict[str, Any]) -> Any:
    """Classify through the vendored loader, held byte-identical by
    `scripts/sync_vendored_ip_class.py`.

    Returns None where the dataset is not on disk, which is the deployed
    fusion image: it ships `app/` only. Nothing is lost there, because every
    event arriving from ingest already carries the stamp.
    """
    from app.services.ip_class import classify  # noqa: PLC0415

    raw = event.get("src_ip")
    return classify(raw) if isinstance(raw, str) else None


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
    derived.update(ip_privacy_fields(event, requested))
    derived.update(ip_class_fields(event, requested))

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
                if _COMPARISON_RE.match(field) or field.startswith("is_") or field in _NAMED_DERIVED_FIELDS:
                    names.add(field)
        elif isinstance(clause, list):
            for item in clause:
                walk(item)

    for rule in rules:
        walk(rule.get("match_when") or {})
    return names
