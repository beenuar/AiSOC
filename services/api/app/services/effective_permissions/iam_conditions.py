"""IAM condition-operator evaluation for the AWS effective-permissions resolver.

Why this is its own module
--------------------------
``aws.py`` modelled exactly two operators, ``StringEquals`` and
``StringLike``, and treated every other one as *unevaluable*, which it then
spelled as "does not match". That direction sounds like the safe one and is
not. ``Condition: {"Bool": {"aws:SecureTransport": "true"}}`` is on a large
share of real bucket policies, and against a request that *is* over TLS the
resolver answered "this identity cannot read the bucket". An access review
built on that under-reports real access, and an under-reported permission is
the one nobody revokes.

The three-valued result is the point
------------------------------------
:func:`evaluate` returns ``True``, ``False`` or ``None``:

* ``True`` — the condition is satisfied by the supplied context.
* ``False`` — the condition is contradicted by the supplied context.
* ``None`` — **undecidable**: the operator is modelled but the request
  context does not carry the key, or the operator is one this module still
  does not model.

``None`` is not a third flavour of "no". The caller decides what an
undecidable condition means for the effect it guards, and the two effects
want opposite answers: an undecidable ``Allow`` must not be counted as
granted (that would over-report), while an undecidable ``Deny`` must not be
dropped (that would also over-report). Collapsing the three values into two
anywhere in this file would put that decision here, where the effect is not
known.

Coverage, stated rather than implied
------------------------------------
Modelled: ``StringEquals``, ``StringNotEquals``, ``StringEqualsIgnoreCase``,
``StringNotEqualsIgnoreCase``, ``StringLike``, ``StringNotLike``, ``Bool``,
``Null``, the six ``Numeric*`` operators, the six ``Date*`` operators,
``IpAddress``, ``NotIpAddress``, and the four ``Arn*`` operators — each with
the ``...IfExists`` suffix and the ``ForAnyValue:`` / ``ForAllValues:`` set
qualifiers.

Not modelled: ``BinaryEquals`` (the context values AiSOC collects are never
base64 blobs) and the ``aws:TagKeys`` multi-value edge cases beyond the set
qualifiers above. Both return ``None`` rather than guessing, and
:data:`UNMODELLED_OPERATORS` names them so the resolver can put the gap in
its ``notes`` instead of silently answering.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "UNMODELLED_OPERATORS",
    "evaluate",
    "evaluate_block",
    "unmodelled_operators_in",
]

#: Operators this module deliberately does not evaluate. Named so the
#: resolver can report the gap rather than returning a confident answer it
#: has not earned.
UNMODELLED_OPERATORS: frozenset[str] = frozenset({"BinaryEquals", "BinaryNotEquals"})

_SET_QUALIFIERS = ("ForAnyValue:", "ForAllValues:")
_IF_EXISTS = "IfExists"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list | tuple):
        return list(value)
    return [value]


def _parse_date(value: Any) -> datetime | None:
    """ISO-8601 or epoch seconds, both of which IAM accepts.

    Returns ``None`` on anything else so the caller reports undecidable
    rather than ordering a string against a datetime.
    """
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), tz=UTC)
    text = str(value).strip()
    if not text:
        return None
    if text.replace(".", "", 1).isdigit():
        return datetime.fromtimestamp(float(text), tz=UTC)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _parse_number(value: Any) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _ip_in(supplied: Any, patterns: Sequence[Any]) -> bool | None:
    try:
        address = ipaddress.ip_address(str(supplied).strip())
    except ValueError:
        return None
    for pattern in patterns:
        try:
            network = ipaddress.ip_network(str(pattern).strip(), strict=False)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            return True
    return False


def _string_cmp(supplied: Any, patterns: Sequence[Any], *, like: bool, fold: bool) -> bool:
    text = str(supplied)
    if fold:
        text = text.casefold()
    for pattern in patterns:
        candidate = str(pattern)
        if fold:
            candidate = candidate.casefold()
        if fnmatch.fnmatchcase(text, candidate) if like else text == candidate:
            return True
    return False


def _base_operator(operator: str) -> tuple[str, bool, str | None]:
    """Split ``ForAnyValue:StringLikeIfExists`` into its three parts."""
    qualifier: str | None = None
    for candidate in _SET_QUALIFIERS:
        if operator.startswith(candidate):
            qualifier = candidate.rstrip(":")
            operator = operator[len(candidate) :]
            break
    if_exists = operator.endswith(_IF_EXISTS)
    if if_exists:
        operator = operator[: -len(_IF_EXISTS)]
    return operator, if_exists, qualifier


def _evaluate_one(operator: str, supplied: Any, patterns: Sequence[Any]) -> bool | None:
    """One operator against one present context value."""
    match operator:
        case "StringEquals":
            return _string_cmp(supplied, patterns, like=False, fold=False)
        case "StringNotEquals":
            return not _string_cmp(supplied, patterns, like=False, fold=False)
        case "StringEqualsIgnoreCase":
            return _string_cmp(supplied, patterns, like=False, fold=True)
        case "StringNotEqualsIgnoreCase":
            return not _string_cmp(supplied, patterns, like=False, fold=True)
        case "StringLike":
            return _string_cmp(supplied, patterns, like=True, fold=False)
        case "StringNotLike":
            return not _string_cmp(supplied, patterns, like=True, fold=False)
        # ARN operators compare as strings; ArnLike alone takes wildcards.
        # Treating ArnEquals as a wildcard match would make
        # `arn:aws:iam::*:role/admin` an exact-match pattern that matches
        # nothing, which reads as a correctly-denied grant.
        case "ArnEquals":
            return _string_cmp(supplied, patterns, like=False, fold=False)
        case "ArnNotEquals":
            return not _string_cmp(supplied, patterns, like=False, fold=False)
        case "ArnLike":
            return _string_cmp(supplied, patterns, like=True, fold=False)
        case "ArnNotLike":
            return not _string_cmp(supplied, patterns, like=True, fold=False)
        case "Bool":
            expected = {str(p).strip().lower() == "true" for p in patterns}
            return (str(supplied).strip().lower() == "true") in expected
        case "IpAddress":
            return _ip_in(supplied, patterns)
        case "NotIpAddress":
            inside = _ip_in(supplied, patterns)
            return None if inside is None else not inside
        case _:
            pass

    if operator.startswith("Numeric"):
        left = _parse_number(supplied)
        rights = [_parse_number(p) for p in patterns]
        if left is None or any(r is None for r in rights):
            return None
        values = [r for r in rights if r is not None]
        return _ordered(operator.removeprefix("Numeric"), left, values)

    if operator.startswith("Date"):
        left_dt = _parse_date(supplied)
        right_dts = [_parse_date(p) for p in patterns]
        if left_dt is None or any(r is None for r in right_dts):
            return None
        return _ordered(operator.removeprefix("Date"), left_dt, [r for r in right_dts if r is not None])

    return None


def _ordered(comparison: str, left: Any, rights: list[Any]) -> bool | None:
    """Shared ordering for the Numeric* and Date* families.

    One implementation rather than two because the operator suffixes are
    identical and two copies drift: an earlier draft had ``LessThanEquals``
    on one family and not the other.
    """
    match comparison:
        case "Equals":
            return any(left == r for r in rights)
        case "NotEquals":
            return all(left != r for r in rights)
        case "LessThan":
            return any(left < r for r in rights)
        case "LessThanEquals":
            return any(left <= r for r in rights)
        case "GreaterThan":
            return any(left > r for r in rights)
        case "GreaterThanEquals":
            return any(left >= r for r in rights)
        case _:
            return None


def evaluate(operator: str, key: str, expected: Any, context: dict[str, Any]) -> bool | None:
    """Evaluate one ``operator``/``key`` pair against the request context.

    ``None`` means undecidable — see the module docstring for why that is a
    distinct answer and not a polite "no".
    """
    base, if_exists, qualifier = _base_operator(operator)

    if base in UNMODELLED_OPERATORS:
        return None

    patterns = _as_list(expected)

    # Null is the one operator that asks about *presence*, so it is decidable
    # precisely when every other operator is not.
    if base == "Null":
        present = key in context and context[key] is not None
        wants_absent = any(str(p).strip().lower() == "true" for p in patterns)
        return (not present) if wants_absent else present

    if key not in context or context[key] is None:
        # `...IfExists` is explicitly "ignore me when the key is absent",
        # which is a decided True rather than an undecidable.
        return True if if_exists else None

    supplied = context[key]
    supplied_values = _as_list(supplied) if isinstance(supplied, list | tuple) else [supplied]

    results = [_evaluate_one(base, value, patterns) for value in supplied_values]
    if any(r is None for r in results):
        return None
    decided = [bool(r) for r in results]

    if qualifier == "ForAllValues":
        return all(decided)
    if qualifier == "ForAnyValue":
        return any(decided)
    # Single-valued key: IAM evaluates the one value. A multi-valued context
    # key with no set qualifier is a policy-authoring error; `all` is the
    # reading that cannot over-grant.
    return all(decided)


def evaluate_block(condition: dict[str, Any] | None, context: dict[str, Any]) -> bool | None:
    """Evaluate a whole ``Condition`` block.

    IAM ANDs every operator and every key inside the block. A single ``False``
    therefore decides the block; otherwise a single undecidable makes the
    block undecidable.
    """
    if not condition:
        return True

    saw_undecidable = False
    for operator, pairs in condition.items():
        if not isinstance(pairs, dict):
            # A malformed block is not an empty one. Reporting it as
            # satisfied would turn a typo into a grant.
            return None
        for key, expected in pairs.items():
            result = evaluate(operator, key, expected, context)
            if result is False:
                return False
            if result is None:
                saw_undecidable = True
    return None if saw_undecidable else True


def unmodelled_operators_in(condition: dict[str, Any] | None) -> set[str]:
    """Operators present in ``condition`` that this module cannot evaluate.

    The resolver puts these into ``ResolverResult.notes`` so a reader sees
    "this answer ignored BinaryEquals" rather than an answer that silently
    assumed something.
    """
    if not condition:
        return set()
    found: set[str] = set()
    for operator in condition:
        base, _, _ = _base_operator(str(operator))
        if base in UNMODELLED_OPERATORS:
            found.add(str(operator))
    return found
