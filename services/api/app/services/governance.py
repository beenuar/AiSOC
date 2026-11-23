"""Legal hold, field-level access and residency, as decisions.

Gap-closure wave 14.

The retention worker can purge and nothing can stop it, so the correct
answer to "preserve everything relating to this account pending
litigation" was to disable retention for the whole tenant and remember
to turn it back on.

The ordering that is not negotiable
--------------------------------------
A legal hold outranks retention **unconditionally**. Any arrangement
where retention can win is a system that deletes evidence under
litigation, which is the one outcome that cannot be apologised for.
So :func:`retention_decision` returns a refusal carrying the hold
rather than a boolean — the caller cannot accidentally treat "held"
as "not expired" and move on.

Field access hides, it does not error
----------------------------------------
A field a caller may not see is returned with its treatment applied
and **named in the response**, not silently dropped. A missing field
and a hidden field look identical to a client, and an analyst reading
an alert needs to know whether the source IP is absent or withheld —
those lead to opposite next steps.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "FieldRule",
    "LegalHold",
    "RetentionDecision",
    "apply_field_access",
    "residency_decision",
    "retention_decision",
]


#: Subject kinds whose rows the purge can exempt individually:
#: these map onto columns the purge statements can test per row. Any other
#: kind — `tenant` above all — keeps the fail-closed whole-tenant freeze,
#: because that is what such a hold means.
NARROWABLE_HOLD_KINDS: frozenset[str] = frozenset({"user", "host", "ip"})


@dataclass(frozen=True)
class LegalHold:
    id: str
    subject_kind: str
    subject_value: str
    matter_ref: str | None = None
    released_at: datetime | None = None
    #: Scoped holds (migration 172): the hold covers records whose event time is
    #: inside this window. Null bounds mean open-ended in that direction —
    #: a hold with neither covers all time, which is what every hold meant
    #: before the columns existed.
    covers_from: datetime | None = None
    covers_until: datetime | None = None

    def live(self) -> bool:
        return self.released_at is None

    def narrows_purge(self) -> bool:
        """Whether the purge can exempt exactly this hold's rows instead of
        freezing the whole tenant."""
        return self.subject_kind in NARROWABLE_HOLD_KINDS

    def covers(self, subjects: dict[str, str], *, at: datetime | None = None) -> bool:
        """Whether this hold covers a record with these subjects.

        Case-insensitive on the value: `SVC-Backup` and `svc-backup`
        are one account, and a hold that missed one spelling would
        preserve half the evidence. When the record's own time is known,
        the hold's window applies; a caller that cannot date the record
        passes ``at=None`` and gets the time-unbounded answer — the
        over-retaining direction, which is the recoverable one.
        """
        actual = subjects.get(self.subject_kind)
        if actual is None:
            return False
        if str(actual).strip().lower() != self.subject_value.strip().lower():
            return False
        if at is not None:
            if self.covers_from is not None and at < self.covers_from:
                return False
            if self.covers_until is not None and at > self.covers_until:
                return False
        return True


@dataclass
class RetentionDecision:
    may_purge: bool
    #: The hold that refused, when one did. Carried rather than
    #: flattened to a boolean so a caller cannot treat "held" as "not
    #: expired" and move on.
    held_by: LegalHold | None = None
    reason: str = ""


def retention_decision(
    *,
    expired: bool,
    subjects: dict[str, str],
    holds: list[LegalHold],
) -> RetentionDecision:
    """Whether a record may be purged.

    A live hold wins over expiry every time. The check runs even when
    the record has not expired, so a caller asking the question early
    gets the same answer it will get later.
    """
    for hold in holds:
        if hold.live() and hold.covers(subjects):
            return RetentionDecision(
                may_purge=False,
                held_by=hold,
                reason=(
                    f"legal hold {hold.id}"
                    + (f" ({hold.matter_ref})" if hold.matter_ref else "")
                    + f" covers {hold.subject_kind}={hold.subject_value!r}"
                ),
            )
    if not expired:
        return RetentionDecision(may_purge=False, reason="the retention window has not elapsed")
    return RetentionDecision(may_purge=True, reason="expired and under no hold")


@dataclass(frozen=True)
class FieldRule:
    field_path: str
    visible_to_roles: tuple[str, ...] = ()
    treatment: str = "redact"


_MASK = "••••"
_REDACTED = "[redacted]"


def _treat(value: Any, treatment: str) -> Any:
    if treatment == "omit":
        return None
    if treatment == "mask":
        text = str(value)
        # Keep the last four so an analyst can still correlate two
        # masked values without seeing either in full.
        return _MASK + text[-4:] if len(text) > 4 else _MASK
    if treatment == "hash":
        # Stable across records, so the same value is recognisably the
        # same without being readable.
        return "sha256:" + hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]
    return _REDACTED


@dataclass
class FieldAccessResult:
    record: dict[str, Any] = field(default_factory=dict)
    #: Fields the caller may not see in full, named. A hidden field
    #: and an absent one look identical otherwise, and they lead to
    #: opposite next steps.
    withheld: list[str] = field(default_factory=list)


def apply_field_access(
    record: dict[str, Any],
    rules: list[FieldRule],
    *,
    role: str,
) -> FieldAccessResult:
    """Apply field rules for this caller's role.

    Dotted paths are walked, so `raw_event.user.email` is reachable —
    which matters because the raw event is where a source puts
    whatever it likes and is the field most worth constraining.
    """
    result = FieldAccessResult(record=_deep_copy(record))
    for rule in rules:
        if role in rule.visible_to_roles:
            continue
        if _apply_at_path(result.record, rule.field_path.split("."), rule.treatment):
            result.withheld.append(rule.field_path)
    return result


def _deep_copy(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _deep_copy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep_copy(v) for v in value]
    return value


def _apply_at_path(node: Any, path: list[str], treatment: str) -> bool:
    """Returns whether anything was actually treated.

    A rule naming a field the record does not carry is not an error —
    records are heterogeneous — but it must not be reported as
    withheld, or the response claims to be hiding something it never
    had.
    """
    if not isinstance(node, dict) or not path:
        return False
    head, *rest = path
    if head not in node:
        return False
    if not rest:
        if treatment == "omit":
            node.pop(head, None)
        else:
            node[head] = _treat(node[head], treatment)
        return True
    return _apply_at_path(node[head], rest, treatment)


@dataclass
class ResidencyDecision:
    allowed: bool
    reason: str = ""
    #: Recorded even when the operation is refused. A refusal nobody
    #: counted cannot answer "has this ever happened".
    record_violation: bool = False


def residency_decision(
    *,
    tenant_region: str | None,
    target_region: str | None,
    enforced: bool,
    operation: str,
) -> ResidencyDecision:
    """Whether this operation may send the tenant's data to that region."""
    if not enforced:
        return ResidencyDecision(allowed=True, reason="residency is not enforced for this tenant")
    if not tenant_region:
        # Enforcement on with no region declared is a misconfiguration,
        # and refusing is the safe reading: the alternative permits
        # everything under a setting an operator believes is strict.
        return ResidencyDecision(
            allowed=False,
            reason="residency is enforced but the tenant declares no data_region",
            record_violation=True,
        )
    if target_region and target_region != tenant_region:
        return ResidencyDecision(
            allowed=False,
            reason=f"{operation} targets {target_region} and this tenant's data must stay in {tenant_region}",
            record_violation=True,
        )
    if not target_region:
        return ResidencyDecision(
            allowed=False,
            reason=f"{operation} declares no region, so it cannot be shown to respect {tenant_region}",
            record_violation=True,
        )
    return ResidencyDecision(allowed=True, reason=f"{operation} stays in {tenant_region}")


def now_utc() -> datetime:  # pragma: no cover - trivial, exists for injection in tests
    return datetime.now(UTC)
