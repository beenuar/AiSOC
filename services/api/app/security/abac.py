"""Conditions that narrow a permission, and time-boxed elevation.

Gap-closure wave 13.

`cases:write` is true everywhere, always, from any address. There is
no way to say "from the corporate network", "during this incident" or
"for the next thirty minutes", so the only way to let an analyst
isolate a host once is to give them that power every day.

Conditions narrow, never grant
---------------------------------
:func:`evaluate_conditions` can only turn an allow into a deny. A
condition that could grant would be a second authorization system
reaching a different answer from the first, and the two would
disagree on the day it mattered.

So this runs **after** the role check, not instead of it, and the
worst it can do to a misconfigured deployment is refuse work — which
is visible — rather than permit it, which is not.

Why the operators are a closed set
-------------------------------------
Every operator here is total and side-effect free. An expression
language would be more flexible and would also be an evaluator running
caller-influenced input inside the authorization path, which is the
shape this repository already removed from the rule engine once.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime, time
from typing import Any

__all__ = [
    "OPERATORS",
    "ConditionResult",
    "PrivilegeGrant",
    "effective_permissions",
    "evaluate_conditions",
]

#: Closed, total, side-effect free. See the module docstring for why
#: this is not an expression language.
OPERATORS = (
    "ip_in_cidr",
    "ip_not_in_cidr",
    "time_between_utc",
    "weekday_in",
    "attribute_equals",
    "attribute_in",
    "mfa_satisfied",
)


@dataclass
class ConditionResult:
    allowed: bool = True
    #: Which condition refused, in words an operator can act on. A
    #: bare 403 on an attribute condition is indistinguishable from a
    #: missing role, and people debug the wrong thing for an hour.
    denied_by: str | None = None
    evaluated: int = 0
    #: Conditions skipped because the request carried nothing to judge
    #: them on. Reported, never treated as satisfied.
    indeterminate: list[str] = field(default_factory=list)


def _check(operator: str, expected: Any, context: dict[str, Any]) -> tuple[bool | None, str]:
    """`(verdict, description)`, where `None` means indeterminate.

    Indeterminate is a third state on purpose. A condition on source
    address, evaluated on a request whose address is unknown, has not
    passed — and treating it as passed is how an attribute condition
    becomes decorative.
    """
    if operator == "mfa_satisfied":
        value = context.get("mfa_satisfied")
        if value is None:
            return None, "the request does not say whether MFA was satisfied"
        return bool(value) == bool(expected), f"MFA satisfied is {bool(value)}, required {bool(expected)}"

    if operator in {"ip_in_cidr", "ip_not_in_cidr"}:
        raw = context.get("source_ip")
        if not raw:
            return None, "the request carries no source address"
        try:
            address = ipaddress.ip_address(str(raw))
            networks = [ipaddress.ip_network(str(c), strict=False) for c in _as_list(expected)]
        except ValueError:
            return None, f"{raw!r} or the configured range is not a valid address"
        inside = any(address in network for network in networks)
        wanted = operator == "ip_in_cidr"
        return inside == wanted, f"{raw} is {'inside' if inside else 'outside'} {_as_list(expected)}"

    if operator == "time_between_utc":
        now = context.get("now") or datetime.now(UTC)
        bounds = _as_list(expected)
        if len(bounds) != 2:
            return None, "time_between_utc needs exactly two HH:MM bounds"
        try:
            start = time.fromisoformat(str(bounds[0]))
            end = time.fromisoformat(str(bounds[1]))
        except ValueError:
            return None, f"{bounds!r} are not HH:MM times"
        current = now.timetz().replace(tzinfo=None)
        # A window crossing midnight is the normal case for a night
        # shift, so it is handled rather than rejected.
        inside = start <= current <= end if start <= end else (current >= start or current <= end)
        return inside, f"{current.strftime('%H:%M')} UTC is {'inside' if inside else 'outside'} {bounds[0]}–{bounds[1]}"

    if operator == "weekday_in":
        now = context.get("now") or datetime.now(UTC)
        allowed_days = {str(d).lower()[:3] for d in _as_list(expected)}
        today = now.strftime("%a").lower()
        return today in allowed_days, f"today is {today}, allowed {sorted(allowed_days)}"

    if operator in {"attribute_equals", "attribute_in"}:
        if not isinstance(expected, dict) or "attribute" not in expected:
            return None, "attribute conditions need an 'attribute' and a 'value'"
        name = str(expected["attribute"])
        actual = context.get(name)
        if actual is None:
            return None, f"the request carries no {name!r}"
        if operator == "attribute_equals":
            return actual == expected.get("value"), f"{name}={actual!r}, required {expected.get('value')!r}"
        return actual in _as_list(expected.get("value")), f"{name}={actual!r} against {expected.get('value')!r}"

    return None, f"unknown operator {operator!r}"


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def evaluate_conditions(
    conditions: list[dict[str, Any]],
    context: dict[str, Any],
    *,
    deny_on_indeterminate: bool = True,
) -> ConditionResult:
    """Apply every condition. Any refusal denies the whole request.

    `deny_on_indeterminate` defaults to **True**, which is the
    decision worth stating: a condition the request carries no data
    for has not been satisfied. Treating it as satisfied would mean a
    caller who omits a header is less constrained than one who sends
    it, which inverts the control.
    """
    result = ConditionResult()
    for condition in conditions:
        if not condition.get("enabled", True):
            continue
        operator = str(condition.get("operator") or "")
        if operator not in OPERATORS:
            # Unknown operators deny. A condition nobody can evaluate
            # is not a condition that passes.
            result.allowed = False
            result.denied_by = f"condition uses unknown operator {operator!r}"
            return result

        result.evaluated += 1
        verdict, description = _check(operator, condition.get("value"), context)
        label = condition.get("description") or f"{operator}: {description}"

        if verdict is None:
            result.indeterminate.append(label)
            if deny_on_indeterminate:
                result.allowed = False
                result.denied_by = f"could not evaluate — {label}"
                return result
            continue

        if not verdict:
            result.allowed = False
            result.denied_by = label
            return result

    return result


@dataclass(frozen=True)
class PrivilegeGrant:
    permissions: tuple[str, ...]
    expires_at: datetime
    revoked_at: datetime | None = None

    def live_at(self, moment: datetime) -> bool:
        return self.revoked_at is None and moment < self.expires_at


def effective_permissions(
    base: frozenset[str],
    grants: list[PrivilegeGrant],
    *,
    now: datetime | None = None,
) -> frozenset[str]:
    """Standing permissions plus any elevation that is live right now.

    Expiry is checked at **use** rather than by a sweep. A background
    job that revokes grants is a job that can be down, and a grant
    outliving its window because a worker crashed is the failure mode
    JIT elevation exists to remove.
    """
    moment = now or datetime.now(UTC)
    elevated: set[str] = set(base)
    for grant in grants:
        if grant.live_at(moment):
            elevated.update(grant.permissions)
    return frozenset(elevated)
