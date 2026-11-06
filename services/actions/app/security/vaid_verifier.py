"""Optional VAID badge verification at the response-dispatch boundary
(beenuar/AiSOC#1739).

Off by default (``AISOC_VAID_PLUGIN_ENABLED``). This is the *other*
boundary named on the issue: ``services/actions`` is a separate service
from ``services/agents`` and never sees an ``AgentIdentity`` Python
object — the only thing that can cross that boundary is whatever travels
with the request. A VAID badge (a signed JSON document) is exactly that,
which is the point of minting one at all rather than keeping identity as
an in-process-only concept (see ``app.security.vaid_plugin`` in the agents
service for the mint side).

Verification here is **public-key-only** — ``vaid_mint.verify`` is built
for exactly this: a party holding the issuer's kernel *public* key, no
issuer instance, no private key (this service has no business holding the
agents service's signing key). It therefore cannot resolve a delegation
lineage on its own; this plugin only ever mints and verifies root badges
(see the agents-side module), so lineage assembly is trivial and needs no
resolver.

Fails closed, same posture as the agents-side module: no badge, an
unparseable badge, a bad signature, an expired badge, a revoked badge, or
a revocation list this process could not read are all refused. None of
those states is distinguished from the others in the returned error any
more than necessary for an operator to act on it, but they are distinguished
in the raised reason string for the audit log.

Why the badge is parsed before it is verified
---------------------------------------------
An earlier draft of this module claimed "the vaid-mint verifiers this calls
are themselves total over arbitrary JSON-shaped input". Measured against
0.11.0, that is false: ``assemble_lineage`` opens with ``leaf["vaid_id"]``
and ``has_capability`` with ``vaid["capability_set"]``, both bare
subscripts. ``verify_badge_for_dispatch({}, "isolate_host")`` therefore
raised ``KeyError``, which ``dispatch()`` did not catch — so a request body
carrying ``"vaid_badge": {}`` turned an identity check into an unhandled
exception, past a route whose own docstring promises it "never returns 5xx
for executor failures" because "the agent loop relies on a uniform
success-shape". The action still did not run, so the refusal held; the
*structured* refusal, the audit line naming why, and the route contract did
not.

The gate is vaid-mint's own :func:`~vaid_mint.verify.parse_vaid_document`,
which is written for exactly this ("Parse failure is UNPARSEABLE — a
refusal, never a raise") rather than a hand-written list of required members
here. A second definition of "is this a VAID" maintained in AiSOC would
drift from the library's, and the drift would show up as this same class of
crash one release later.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any
from uuid import UUID

__all__ = [
    "BadgeDenied",
    "vaid_plugin_enabled",
    "verify_badge_for_dispatch",
]

_ENABLED_ENV = "AISOC_VAID_PLUGIN_ENABLED"
_KERNEL_PUBLIC_KEY_ENV = "AISOC_VAID_KERNEL_PUBLIC_KEY_HEX"
_REVOCATION_LIST_PATH_ENV = "AISOC_VAID_REVOCATION_LIST_PATH"


class BadgeDenied(RuntimeError):
    """A VAID badge was missing, unverifiable, expired, revoked, or did not
    grant the capability this dispatch is about to execute."""


def vaid_plugin_enabled() -> bool:
    return os.environ.get(_ENABLED_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _kernel_public_key() -> bytes:
    raw = os.environ.get(_KERNEL_PUBLIC_KEY_ENV, "").strip()
    if not raw:
        raise BadgeDenied(f"VAID plugin is enabled but {_KERNEL_PUBLIC_KEY_ENV} is not set; refusing fail-closed")
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise BadgeDenied(f"{_KERNEL_PUBLIC_KEY_ENV} is not valid hex") from exc
    if len(key) != 32:
        raise BadgeDenied(f"{_KERNEL_PUBLIC_KEY_ENV} must decode to 32 bytes (Ed25519 public key), got {len(key)}")
    return key


class _FileRevocationList:
    """Read-only mirror of the agents-side revocation list loader.

    Duplicated rather than imported: these are two different services with
    independent dependency trees and deploy units, and this is ~15 lines of
    JSON loading — the kind of thing this repository's own conventions
    favour re-stating per service over a cross-service import (services
    here do not import each other's ``app`` packages).
    """

    def __init__(self, path: str | os.PathLike[str] | None) -> None:
        self._path = Path(path) if path else None
        self._lock = threading.Lock()

    def revoked_ids(self) -> set[str] | None:
        if self._path is None:
            return None
        with self._lock:
            try:
                raw = self._path.read_text(encoding="utf-8")
                data = json.loads(raw)
            except (OSError, ValueError):
                return None
        if not isinstance(data, dict):
            return None
        revoked = data.get("revoked")
        if not isinstance(revoked, list) or not all(isinstance(v, str) for v in revoked):
            return None
        return set(revoked)


def _parsed_or_denied(badge: dict[str, Any]) -> dict[str, Any]:
    """``badge`` as a structurally valid VAID document, or :class:`BadgeDenied`.

    See the module docstring for why this gate exists and why it delegates to
    vaid-mint rather than listing the required members here. The round-trip
    through JSON text is what ``parse_vaid_document`` takes; a ``badge`` that
    will not even serialise is refused for the same reason an unparseable one
    is, rather than being allowed to raise ``TypeError`` out of a verifier.
    """
    from vaid_mint.verify import parse_vaid_document  # noqa: PLC0415

    try:
        as_text = json.dumps(badge)
    except (TypeError, ValueError):
        raise BadgeDenied("vaid_badge is not a JSON document; refusing fail-closed") from None
    parsed = parse_vaid_document(as_text)
    if parsed is None:
        raise BadgeDenied("vaid_badge is not a well-formed VAID document; refusing fail-closed")
    return parsed


def _deny_unless_badge_is_for_this_tenant(badge: dict[str, Any], tenant_id: UUID | str | None) -> None:
    """Refuse a badge minted under one tenant's authority and presented under
    another's.

    ``verify_vaid_standing`` answers "is this badge genuine", which is not the
    same question as "is this badge *this caller's*". Without this, a badge
    legitimately minted for tenant A verified cleanly against a dispatch
    carrying tenant B — measured, and squarely against the point of the
    feature, which is proving *under whose authority* an action ran.

    ``tenant_id`` is a signed member of the document, so an attacker cannot
    edit it without invalidating the signature; the only thing needed here is
    to read it and compare. A badge naming a tenant presented on a dispatch
    naming none is refused rather than waved through: this plugin is
    off by default and has no legacy tenant-less caller to accommodate, so the
    permissive reading would be a hole kept open for nobody.
    """
    badge_tenant = badge.get("tenant_id")
    if not isinstance(badge_tenant, str) or not badge_tenant:
        raise BadgeDenied("badge names no tenant; refusing fail-closed")
    if tenant_id is None:
        raise BadgeDenied(f"badge is bound to tenant {badge_tenant!r} and this dispatch names no tenant; refusing fail-closed")
    if badge_tenant != str(tenant_id):
        raise BadgeDenied(f"badge is bound to tenant {badge_tenant!r}, not to this dispatch's tenant")


def verify_badge_for_dispatch(
    badge: dict[str, Any] | None,
    required_capability: str,
    *,
    tenant_id: UUID | str | None = None,
) -> None:
    """Refuse the dispatch unless ``badge`` is a currently-valid VAID, issued
    for ``tenant_id``, that grants ``required_capability``. A no-op when the
    plugin is disabled.

    Raises :class:`BadgeDenied` on any failure, naming the reason, and nothing
    else for any JSON-shaped ``badge`` — see the module docstring for the
    measured case where that was not true.
    """
    if not vaid_plugin_enabled():
        return
    if badge is None:
        raise BadgeDenied("VAID plugin is enabled and this request carries no vaid_badge; refusing fail-closed")

    from vaid_mint.document import has_capability  # noqa: PLC0415
    from vaid_mint.revocation import RevocationStatus, assemble_lineage  # noqa: PLC0415
    from vaid_mint.verify import verify_vaid_standing  # noqa: PLC0415

    badge = _parsed_or_denied(badge)
    kernel_public_key = _kernel_public_key()

    # Root badges only (module docstring): `assemble_lineage` never actually
    # calls the resolver when `parent_vaid` is None, so no resolver object
    # is needed. A badge that DOES carry a parent is refused here, rather
    # than handed a resolver that would silently vouch for an ancestry this
    # service cannot verify.
    if badge.get("parent_vaid") is not None:
        raise BadgeDenied("this plugin verifies root VAID badges only; a delegated (child) badge was presented")
    lineage = assemble_lineage(badge, None)
    if lineage is None:
        raise BadgeDenied("badge lineage could not be assembled; refusing fail-closed")

    revocation_list = _FileRevocationList(os.environ.get(_REVOCATION_LIST_PATH_ENV) or None)
    revoked_ids = revocation_list.revoked_ids()
    if revoked_ids is None:
        revocation_status = RevocationStatus.UNAVAILABLE
    elif any(vaid_id in revoked_ids for vaid_id in lineage):
        revocation_status = RevocationStatus.REVOKED
    else:
        revocation_status = RevocationStatus.NOT_REVOKED

    verdict = verify_vaid_standing(kernel_public_key, badge, revocation_status)
    if not verdict.is_valid():
        raise BadgeDenied(f"badge {badge.get('vaid_id')!r} failed verification: {verdict.code}")

    # Only after the signature: a complaint about the content of bytes that
    # have not been authenticated is meaningless, and `tenant_id` is only
    # trustworthy once the document it sits in has been shown to be genuine.
    _deny_unless_badge_is_for_this_tenant(badge, tenant_id)

    if not has_capability(badge, required_capability):
        raise BadgeDenied(f"badge {badge.get('vaid_id')!r} does not grant capability {required_capability!r}")
