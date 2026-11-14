"""Normalising a SCIM PATCH request, which is where providers disagree.

RFC 7644 section 3.5.2 describes PATCH in terms that two conforming clients
read differently, and the two clients this platform has to serve read them
differently in five separate places. A handler written against one provider's
payloads fails against the other's in ways that look like a logic bug rather
than a parsing one, because the request is accepted, the operation is applied
to nothing, and the provider is told 204.

The five disagreements, each of which this module resolves
----------------------------------------------------------

1. ``op`` casing. RFC 7644 spells the values lowercase. One provider sends
   ``"replace"``; the other sends ``"Replace"``. Compared literally, half the
   operations fall through whatever ``if`` the handler wrote.

2. A missing ``path``. ``path`` is optional, and when it is absent ``value``
   is an object whose keys are the attributes to change:
   ``{"op": "replace", "value": {"active": false}}``. A handler that reads
   ``op["path"]`` raises ``KeyError`` on one provider and works on the other.

3. ``value`` typed as a string. A deactivation arrives as boolean ``false``
   from one provider and as the *string* ``"False"`` from the other. Python
   evaluates ``bool("False")`` as ``True``, so the naive read does not merely
   fail, it deactivates nothing while reporting success, which is the worst
   available outcome for the one operation that has to work.

4. Member removal expressed two ways. Either a filter in the path,
   ``members[value eq "abc"]`` with no ``value``, or ``path: "members"`` with
   a list of member objects to remove. Both providers emit both shapes
   depending on version and on whether the group is being emptied.

5. Attribute-name casing generally. ``userName``, ``username`` and
   ``UserName`` all appear across providers and versions; SCIM declares
   attribute names case-insensitive and clients take that at their word.

What this module deliberately does not do
------------------------------------------
It does not apply anything. It turns a request body into a list of
:class:`ScimPatchOp` with a resolved attribute, an optional member filter and
a coerced value, and the caller decides what those mean for its resource.
Parsing and applying were one function in the first draft, and the tests for
it could not distinguish "we misread the payload" from "we misapplied it".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

#: The PATCH request envelope every provider sends.
PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

#: Operations RFC 7644 defines. Compared case-folded, never literally.
VALID_OPS = frozenset({"add", "remove", "replace"})

#: ``members[value eq "abc"]`` and its single-quoted and unspaced variants.
_MEMBER_FILTER = re.compile(
    r"""^members\[\s*value\s+eq\s+["'](?P<id>[^"']+)["']\s*\]$""",
    re.IGNORECASE,
)

#: Strings a provider may send where the attribute is a boolean. Anything
#: outside this set raises rather than defaulting, because the failure this
#: exists to prevent is a deactivation silently read as an activation.
_TRUE_STRINGS = frozenset({"true", "t", "1", "yes"})
_FALSE_STRINGS = frozenset({"false", "f", "0", "no"})


class ScimPatchError(ValueError):
    """A PATCH body that cannot be honoured.

    Carries the SCIM ``scimType`` the caller should return, so the error
    response is a SCIM error rather than a generic 400.
    """

    def __init__(self, detail: str, *, scim_type: str = "invalidSyntax") -> None:
        super().__init__(detail)
        self.detail = detail
        self.scim_type = scim_type


@dataclass(frozen=True)
class ScimPatchOp:
    """One normalised operation.

    ``attribute`` is lowercased, and is the last segment of a sub-attribute
    path: ``name.givenName`` resolves to ``attribute="name.givenname"`` so a
    caller can match on the whole path. ``member_id`` is set only for the
    filtered member-removal shape, where the id lives in the path rather
    than in the value.
    """

    op: str
    attribute: str | None
    value: Any
    member_id: str | None = None


def coerce_bool(raw: Any, *, attribute: str) -> bool:
    """Read a SCIM boolean that may have arrived as a string.

    Refuses anything it does not recognise instead of falling back. A
    fallback here would mean a payload the provider considered a
    deactivation being applied as something else, and the caller would have
    no way to tell that happened.
    """
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        folded = raw.strip().casefold()
        if folded in _TRUE_STRINGS:
            return True
        if folded in _FALSE_STRINGS:
            return False
    raise ScimPatchError(
        f"attribute {attribute!r} expects a boolean; received {raw!r}",
        scim_type="invalidValue",
    )


def _normalise_path(path: Any) -> tuple[str | None, str | None]:
    """Return ``(attribute, member_id)`` for one ``path`` value."""
    if path is None:
        return None, None
    if not isinstance(path, str):
        raise ScimPatchError(f"PATCH path must be a string; received {path!r}")

    stripped = path.strip()
    if not stripped:
        return None, None

    filtered = _MEMBER_FILTER.match(stripped)
    if filtered is not None:
        return "members", filtered.group("id")

    # A path may be schema-qualified:
    # `urn:ietf:params:scim:schemas:core:2.0:User:active`. Everything up to
    # the last colon is the schema URN, and the URN itself contains colons,
    # so this splits from the right rather than parsing the URN.
    if stripped.lower().startswith("urn:"):
        _, _, tail = stripped.rpartition(":")
        stripped = tail or stripped

    if "[" in stripped:
        # A filter this module does not implement. Refusing is correct:
        # applying the unfiltered attribute would act on more than the
        # provider asked for, and on `members` that means removing every
        # member when one was named.
        raise ScimPatchError(
            f"unsupported PATCH path filter {path!r}",
            scim_type="invalidPath",
        )

    return stripped.casefold(), None


def _expand_valueless_op(op: str, value: Any) -> list[ScimPatchOp]:
    """Turn a pathless operation into one operation per attribute.

    ``{"op": "replace", "value": {"active": false, "userName": "a@b"}}``
    becomes two operations, so the caller sees the same shape it would have
    seen from a provider that sends an explicit path for each.
    """
    if not isinstance(value, dict):
        raise ScimPatchError(
            f"a {op!r} operation with no path must carry an object value; received {type(value).__name__}",
        )
    expanded: list[ScimPatchOp] = []
    for attribute, attribute_value in value.items():
        if not isinstance(attribute, str):
            raise ScimPatchError("PATCH attribute names must be strings")
        expanded.append(ScimPatchOp(op=op, attribute=attribute.casefold(), value=attribute_value))
    return expanded


def parse_patch(body: Any) -> list[ScimPatchOp]:
    """Normalise a SCIM PATCH body into operations this codebase can apply.

    Raises :class:`ScimPatchError` for anything malformed. It never returns
    an empty list for a well-formed request with operations in it, because
    "parsed nothing" and "there was nothing to do" would otherwise be the
    same answer.
    """
    if not isinstance(body, dict):
        raise ScimPatchError("PATCH body must be a JSON object")

    schemas = body.get("schemas")
    if isinstance(schemas, list) and schemas:
        # Compared case-insensitively: the URN is spelled with different
        # casing by different providers and RFC 7643 treats it as a URI.
        if not any(isinstance(s, str) and s.casefold() == PATCH_OP_SCHEMA.casefold() for s in schemas):
            raise ScimPatchError(
                f"PATCH body must declare the {PATCH_OP_SCHEMA} schema",
                scim_type="invalidSyntax",
            )

    # `Operations` is the RFC spelling and the one both providers send, but
    # the attribute is case-insensitive like every other SCIM attribute.
    operations = None
    for key, candidate in body.items():
        if isinstance(key, str) and key.casefold() == "operations":
            operations = candidate
            break

    if not isinstance(operations, list) or not operations:
        raise ScimPatchError("PATCH body must carry a non-empty Operations array")

    parsed: list[ScimPatchOp] = []
    for entry in operations:
        if not isinstance(entry, dict):
            raise ScimPatchError("each PATCH operation must be an object")

        raw_op = None
        raw_path: Any = None
        has_value = False
        raw_value: Any = None
        for key, candidate in entry.items():
            if not isinstance(key, str):
                continue
            folded = key.casefold()
            if folded == "op":
                raw_op = candidate
            elif folded == "path":
                raw_path = candidate
            elif folded == "value":
                has_value = True
                raw_value = candidate

        if not isinstance(raw_op, str):
            raise ScimPatchError("each PATCH operation must carry an 'op'")
        op = raw_op.strip().casefold()
        if op not in VALID_OPS:
            raise ScimPatchError(
                f"unsupported PATCH op {raw_op!r}; expected one of {sorted(VALID_OPS)}",
                scim_type="invalidSyntax",
            )

        attribute, member_id = _normalise_path(raw_path)

        if attribute is None:
            if op == "remove":
                # RFC 7644: "remove" requires a target. Without one the
                # request is asking to delete the resource through a PATCH,
                # which DELETE already expresses.
                raise ScimPatchError("a 'remove' operation requires a path", scim_type="noTarget")
            if not has_value:
                raise ScimPatchError(f"a pathless {op!r} operation requires a value")
            parsed.extend(_expand_valueless_op(op, raw_value))
            continue

        parsed.append(ScimPatchOp(op=op, attribute=attribute, value=raw_value if has_value else None, member_id=member_id))

    return parsed


def member_ids(op: ScimPatchOp) -> list[str]:
    """Every member id one ``members`` operation names.

    Covers the filtered path form, a list of member objects, a single member
    object and a bare string, because all four reach this platform from one
    provider or the other.
    """
    if op.member_id is not None:
        return [op.member_id]

    def _one(candidate: Any) -> str | None:
        if isinstance(candidate, str):
            return candidate or None
        if isinstance(candidate, dict):
            for key, value in candidate.items():
                if isinstance(key, str) and key.casefold() == "value" and isinstance(value, str) and value:
                    return value
        return None

    raw = op.value
    if raw is None:
        return []
    candidates = raw if isinstance(raw, list) else [raw]
    return [found for found in (_one(entry) for entry in candidates) if found is not None]
