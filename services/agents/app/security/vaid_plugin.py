"""Optional VAID badge for AiSOC's own agent identities (beenuar/AiSOC#1739).

Off by default (``AISOC_VAID_PLUGIN_ENABLED``). Builds on
``app.security.agent_identity.AgentIdentity`` rather than introducing a
second identity system: ``AgentIdentity`` still does the real authorization
(the scope table and expiry in ``agent_identity.py``); a VAID is a signed,
portable *badge* of that decision, mintable here and verifiable by a party
that holds no Python object at all — the thing an unsigned, in-process
dataclass cannot be.

Why a badge and not a second authorizer
----------------------------------------
Two identity systems in one trust path would be worse than one unsigned
one (the maintainer's framing on #1739, agreed). So this module never
*decides* whether a tool call or an action is allowed — ``AgentIdentity``
already does that, before this plugin is ever consulted. What this module
adds is: can a party that is not this process prove, after the fact, which
agent and which scope produced a given call? Verifying the badge is a
precondition laid *on top of* the existing scope check, not a replacement
for it, and when the plugin is disabled, nothing about the existing
boundary changes.

Why root VAIDs only, no delegation chain
------------------------------------------
``AgentIdentity.with_granted_tools()`` *expands* ``scopes`` — MCP discovers a
tenant's tools at run time and ``app/mcp/policy.py`` grants the
non-destructive ones (see ``agent_identity.py``'s own docstring: "the one
legitimate way the scope grows"). vaid-mint's delegation (`mint_child`) only
ever *attenuates* (child ⊆ parent); it has no operation for "parent's
badge, plus tools another control just approved". Modelling the grant as a
vaid-mint child would therefore be backwards. Instead this module re-mints a
fresh **root** badge whenever the identity's scope changes, whose
``capability_set`` always mirrors ``identity.scopes`` at the moment of
minting — the badge tracks the identity, derived from it every time,
never drifting into a parallel credential with its own lifecycle.

Why this fails closed on a bare ``AgentIdentity``
----------------------------------------------------
``ToolRegistry.execute`` already refuses ``identity=None``. The hole the
maintainer asked to close is the *other* unidentified case this plugin
introduces: a caller holding a real, scope-checked ``AgentIdentity`` but no
badge. When the plugin is enabled, that must refuse too, or "fails closed"
would be true only for the literal ``None`` case and decorative for every
other.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.security.agent_identity import AgentIdentity

logger = logging.getLogger(__name__)

__all__ = [
    "BadgeDenied",
    "VaidBackedIdentity",
    "vaid_plugin_enabled",
    "issue_vaid_identity",
    "verify_identity_badge",
    "install_into",
    "uninstall_from",
    "badge_sha256",
    "AGENT_ACTION_CAPABILITIES",
]

_ENABLED_ENV = "AISOC_VAID_PLUGIN_ENABLED"
_TRUST_DOMAIN_ENV = "AISOC_VAID_TRUST_DOMAIN"
_TTL_HOURS_ENV = "AISOC_VAID_TTL_HOURS"
_REVOCATION_LIST_PATH_ENV = "AISOC_VAID_REVOCATION_LIST_PATH"
_KERNEL_SEED_PATH_ENV = "AISOC_VAID_KERNEL_SEED_PATH"
_ALLOW_EPHEMERAL_SEED_ENV = "AISOC_VAID_ALLOW_EPHEMERAL_KERNEL_SEED"

#: Default badge lifetime. Short by design (asmeyatsky on #1739): in an
#: air-gapped deployment the revocation list is shipped, not fetched live, so
#: the badge's own expiry is the control that actually bounds exposure of a
#: leaked or stale badge between deployments of a fresher list.
DEFAULT_VAID_TTL_HOURS = 1


class BadgeDenied(RuntimeError):
    """A VAID badge was missing, unverifiable, expired or revoked.

    Distinct from ``app.security.agent_identity.ScopeDenied``: that is a
    scope decision this process made about its own identity table; this is
    "the badge presented for that identity does not stand up", which is a
    different accusation and worth a reader being able to tell apart in the
    audit log.
    """


def vaid_plugin_enabled() -> bool:
    return os.environ.get(_ENABLED_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _trust_domain() -> str:
    return os.environ.get(_TRUST_DOMAIN_ENV, "").strip() or "agents.aisoc.local"


def _ttl_hours() -> int:
    raw = os.environ.get(_TTL_HOURS_ENV, "").strip()
    if not raw:
        return DEFAULT_VAID_TTL_HOURS
    try:
        ttl = int(raw)
    except ValueError:
        # `logger` here is the stdlib one, not structlog: this service's
        # module-level loggers are `logging.getLogger(__name__)`, and
        # `logger.warning("event", value=raw)` — the structlog call shape used
        # over in `services/actions` — raises `TypeError: Logger._log() got an
        # unexpected keyword argument`. So the branch that exists to *tolerate*
        # a mistyped `AISOC_VAID_TTL_HOURS` was the branch that crashed minting
        # outright. Found by mypy's `call-arg`, reproduced by setting the
        # variable to a non-integer, which is the only way to reach this line.
        logger.warning("vaid_plugin.bad_ttl_env: %r is not an integer, using the default", raw)
        return DEFAULT_VAID_TTL_HOURS
    # 0 is a legitimate (if unusual) value: a badge that expires
    # immediately, useful mainly for testing the expiry path. Only a
    # negative value is nonsensical and falls back to the default.
    return ttl if ttl >= 0 else DEFAULT_VAID_TTL_HOURS


class FileRevocationList:
    """An air-gapped revocation list, read from a file shipped with the
    deployment — never fetched live (asmeyatsky on #1739).

    Three states, same as the spec: the file is absent, unreadable or
    malformed → :data:`RevocationStatus.UNAVAILABLE` (fails closed, never
    collapsed into "nothing is revoked"); readable and well-formed → the
    revoked set it names, however empty. Re-read on every check rather than
    cached, because the whole point of shipping a *new* list with a
    deployment is that it takes effect without a process restart.
    """

    def __init__(self, path: str | os.PathLike[str] | None) -> None:
        self._path = Path(path) if path else None
        self._lock = threading.Lock()

    def _load(self) -> set[str] | None:
        if self._path is None:
            return None
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

    def check_lineage(self, lineage: list[str]) -> Any:
        from vaid_mint.revocation import RevocationStatus  # noqa: PLC0415

        with self._lock:
            revoked = self._load()
        if revoked is None:
            return RevocationStatus.UNAVAILABLE
        if any(vaid_id in revoked for vaid_id in lineage):
            return RevocationStatus.REVOKED
        return RevocationStatus.NOT_REVOKED


def _kernel_seed() -> bytes:
    """A 32-byte Ed25519 seed for the kernel key.

    Read from ``AISOC_VAID_KERNEL_SEED_PATH`` (raw 32 bytes on disk) when
    set — the production path, where the seed is a real secret managed like
    any other key material in this repository.

    With no seed path configured, this refuses rather than silently
    generating one: a fresh, process-local seed is exactly correct for a
    single process (tests, a one-replica dev stack) and exactly wrong
    across a fleet — every replica would mint under its own trust root, and
    a badge minted by replica A would never verify against replica B's
    issuer, let alone against ``services/actions``' configured
    ``AISOC_VAID_KERNEL_PUBLIC_KEY_HEX``. That failure mode is silent (every
    individual replica verifies its own badges fine) and would only surface
    as "dispatch intermittently refuses a request, seemingly at random,
    depending which replica handled it" — exactly the kind of thing that
    should fail loudly at startup instead. ``AISOC_VAID_ALLOW_EPHEMERAL_KERNEL_SEED``
    is the explicit, named opt-out for the cases where the fallback is
    actually correct.
    """
    path = os.environ.get(_KERNEL_SEED_PATH_ENV, "").strip()
    if path:
        data = Path(path).read_bytes()
        if len(data) != 32:
            raise BadgeDenied(f"{_KERNEL_SEED_PATH_ENV} does not name a 32-byte Ed25519 seed")
        return data
    if os.environ.get(_ALLOW_EPHEMERAL_SEED_ENV, "").strip().lower() not in {"1", "true", "yes", "on"}:
        raise BadgeDenied(
            f"VAID plugin is enabled but neither {_KERNEL_SEED_PATH_ENV} nor "
            f"{_ALLOW_EPHEMERAL_SEED_ENV} is set — refusing to mint under a fresh, "
            "unnamed, per-process trust root. Set the former to a real key in any "
            "deployment with more than one replica of this service; set the latter "
            "only for a single-process dev stack or a test"
        )
    return os.urandom(32)


@dataclass(frozen=True)
class _IssuerHandle:
    issuer: Any  # vaid_mint.issuer.ReferenceIssuer
    revocation: FileRevocationList


_issuer_lock = threading.Lock()
_issuer_handle: _IssuerHandle | None = None


def _issuer_handle_singleton() -> _IssuerHandle:
    """The process-wide issuer, built lazily so importing this module never
    requires ``vaid-mint`` to be installed unless the plugin is actually used.
    """
    global _issuer_handle
    with _issuer_lock:
        if _issuer_handle is None:
            from vaid_mint import ReferenceIssuer  # noqa: PLC0415
            from vaid_mint.revocation import InMemoryLineageStore, RevocationBackend  # noqa: PLC0415

            revocation = FileRevocationList(os.environ.get(_REVOCATION_LIST_PATH_ENV) or None)
            issuer = ReferenceIssuer.from_seed(_kernel_seed(), _ttl_hours(), _trust_domain())
            # Root VAIDs only (module docstring): the lineage store never
            # needs to resolve anything, but `with_revocation_backend`
            # requires both halves, and an in-memory resolver is the correct
            # one here — the actions-service side never needs a resolver at
            # all, for the same reason.
            issuer.with_revocation_backend(RevocationBackend(check=revocation, lineage=InMemoryLineageStore()))
            _issuer_handle = _IssuerHandle(issuer=issuer, revocation=revocation)
        return _issuer_handle


def reset_issuer_for_tests() -> None:
    """Drop the process-wide issuer so the next call rebuilds it from the
    current environment. Test-only: production has one issuer per process."""
    global _issuer_handle
    with _issuer_lock:
        _issuer_handle = None


#: A *second* vocabulary, deliberately distinct from ``AGENT_TOOL_SCOPES``.
#:
#: ``AGENT_TOOL_SCOPES`` answers "what Python functions may this agent call
#: in-process" (``ToolRegistry.execute``, this service). This table answers a
#: different question, for a different service: "what ``services/actions``
#: live-action capability may this agent's badge be presented for, at the
#: ``dispatch()`` boundary". The two vocabularies never overlap — tool names
#: like ``extract_iocs`` versus ``ActionType`` strings like ``isolate_host`` —
#: and conflating them is exactly the bug this table exists to close: a badge
#: minted with ``capability_set = identity.scopes`` alone can never satisfy
#: ``has_capability(badge, "isolate_host")`` on the actions side, because no
#: agent's tool scope ever contains an ActionType string. Every real dispatch
#: would refuse, which is "fails closed" in letter only — in effect it is the
#: feature not working at all.
#:
#: Only ``"respond"`` holds anything, matching ``AGENT_TOOL_SCOPES``'s own
#: comment on that agent: it is the only one whose job is to request a
#: response action. No other agent gets an entry — the correct default,
#: same reasoning as ``AGENT_TOOL_SCOPES``'s "absent from every set is
#: reachable by nobody" — so a triage or investigation badge can never
#: clear the actions-service boundary for any capability.
#:
#: This does **not** decide whether a given request actually executes.
#: ``services/actions`` keeps every one of its own gates — the kill switch,
#: the per-capability contract, the approval matrix, the blast-radius tier —
#: fully in force regardless of this plugin; VAID verification is a
#: *precondition* layered in front of them (see ``dispatch()``'s own
#: ordering), proving identity, not re-grading risk. Granting the full
#: response vocabulary to "respond" is therefore the correct scope for an
#: identity check: narrowing it further would be duplicating policy this
#: plugin is not the right place to hold.
#:
#: Why duplicated rather than imported: ``services/agents`` and
#: ``services/actions`` are independently deployable and do not import each
#: other's ``app`` package (see ``vaid_verifier.py``'s matching comment on
#: its own revocation-list loader). The values below are literally
#: ``app.models.action.ActionType`` in ``services/actions`` as of this
#: writing; `tests/test_vaid_cross_service_capability_mapping.py` at the
#: repo root loads that real enum (via a sys.path swap, never a cross-service
#: import at runtime) and asserts every value here is still a real one, so a
#: rename there is caught by a test rather than discovered as "every
#: dispatch refused in production" — the way this table's *absence* was
#: first found.
AGENT_ACTION_CAPABILITIES: dict[str, frozenset[str]] = {
    "respond": frozenset(
        {
            "block_ip",
            "block_domain",
            "isolate_host",
            "disable_user",
            "reset_password",
            "kill_process",
            "quarantine_file",
            "capture_forensics",
            "notify_slack",
            "create_ticket",
        }
    ),
}


def _mint_badge(identity: AgentIdentity, *, tenant_id: str) -> dict[str, Any]:
    handle = _issuer_handle_singleton()
    capability_set = identity.scopes | AGENT_ACTION_CAPABILITIES.get(identity.agent, frozenset())
    return handle.issuer.issue_vaid_with_lineage(
        agent_class=identity.agent,
        version="1",
        tenant_id=tenant_id,
        parent_vaid=None,
        scope_boundary=[],
        capability_set=sorted(capability_set),
    )


def badge_sha256(badge: dict[str, Any]) -> str:
    """A stable hex digest of a badge, for the audit/ledger row.

    Never log the badge itself — it carries ``public_key_der`` and the
    signature, and a ledger read by more people than a single run's
    operator should not become a second place those bytes live. The hash is
    enough to prove, against a copy the issuer or an archive holds, which
    exact badge acted.
    """
    canonical = json.dumps(badge, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class VaidBackedIdentity:
    """An :class:`AgentIdentity` plus the signed VAID badge minted from it.

    Delegates every authorization decision to the wrapped identity — this
    type adds a badge, it does not add a second opinion about scope. Code
    that only knows ``AgentIdentity``'s interface (``require``, ``may``,
    ``expired``, ``audit_row``, ``agent``, ``run_id``, ``scopes``,
    ``credential_id``) keeps working unchanged against this wrapper.
    """

    __slots__ = ("_identity", "_tenant_id", "_badge")

    def __init__(self, identity: AgentIdentity, tenant_id: str, badge: dict[str, Any]) -> None:
        self._identity = identity
        self._tenant_id = tenant_id
        self._badge = badge

    @property
    def identity(self) -> AgentIdentity:
        return self._identity

    @property
    def badge(self) -> dict[str, Any]:
        return self._badge

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    # ── AgentIdentity-shaped surface, delegated ──────────────────────────
    @property
    def agent(self) -> str:
        return self._identity.agent

    @property
    def run_id(self) -> str:
        return self._identity.run_id

    @property
    def scopes(self) -> frozenset[str]:
        return self._identity.scopes

    @property
    def credential_id(self) -> str:
        return self._identity.credential_id

    def expired(self, *, now: float | None = None) -> bool:
        return self._identity.expired(now=now)

    def may(self, tool: str) -> bool:
        return self._identity.may(tool)

    def require(self, tool: str, *, now: float | None = None) -> None:
        self._identity.require(tool, now=now)

    def audit_row(self, tool: str, *, allowed: bool, reason: str | None = None) -> dict[str, object]:
        row = self._identity.audit_row(tool, allowed=allowed, reason=reason)
        row["vaid_id"] = self._badge.get("vaid_id")
        return row

    def with_granted_tools(self, tools: frozenset[str] | set[str] | list[str]) -> VaidBackedIdentity:
        """A copy of this identity extended with newly-granted tools, with a
        freshly minted badge whose ``capability_set`` mirrors the new scope.

        See the module docstring: the grant can only *expand* scope, so this
        is a fresh root mint, not a vaid-mint attenuated child.
        """
        new_identity = self._identity.with_granted_tools(tools)
        new_badge = _mint_badge(new_identity, tenant_id=self._tenant_id)
        return VaidBackedIdentity(new_identity, self._tenant_id, new_badge)


def issue_vaid_identity(
    agent: str,
    *,
    run_id: str,
    tenant_id: str,
    ttl_seconds: int | None = None,
) -> VaidBackedIdentity:
    """Mint a base :class:`AgentIdentity` (unmodified existing path) and a
    VAID badge from it. Raises whatever :func:`issue_identity` raises for an
    unknown agent — this function adds a badge, it does not add a new way
    to fail that authorization check.
    """
    from app.security.agent_identity import issue_identity  # noqa: PLC0415

    identity = issue_identity(agent, run_id=run_id, ttl_seconds=ttl_seconds)
    badge = _mint_badge(identity, tenant_id=tenant_id)
    return VaidBackedIdentity(identity, tenant_id, badge)


def verify_identity_badge(identity: Any) -> None:
    """``ToolRegistry``'s identity-verifier hook. Raises :class:`BadgeDenied`
    on anything other than a currently-valid badge.

    Called only when the plugin is wired into the registry (see
    :func:`install_into`), which itself only happens when
    :func:`vaid_plugin_enabled` is true — so this function's own early
    return for "disabled" is defence in depth, not the only gate.
    """
    if not vaid_plugin_enabled():
        return
    if not isinstance(identity, VaidBackedIdentity):
        # The hole the maintainer asked to close on #1739: a bare
        # AgentIdentity is not None, so the registry's existing
        # "identity is None" refusal does not catch it. With the plugin on,
        # every call must carry a badge.
        raise BadgeDenied("VAID plugin is enabled and this identity carries no badge; mint one with issue_vaid_identity()")

    from vaid_mint.revocation import assemble_lineage  # noqa: PLC0415
    from vaid_mint.verify import parse_vaid_document, verify_vaid_standing  # noqa: PLC0415

    handle = _issuer_handle_singleton()

    # Parse before verifying. vaid-mint's verifiers are not total over
    # arbitrary dicts — ``assemble_lineage`` opens with ``leaf["vaid_id"]`` —
    # so a ``VaidBackedIdentity`` holding a malformed badge reached the
    # registry's ``except Exception`` and was refused with the reason
    # ``"'vaid_id'"``, a bare KeyError repr. It refused, which is the half
    # that matters, and it named nothing an operator could act on, which is
    # the half this repository asks for as well. ``parse_vaid_document`` is
    # vaid-mint's own total gate; re-stating the member list here would be a
    # second definition of "is this a VAID" that drifts from the library's.
    try:
        as_text = json.dumps(identity.badge)
    except (TypeError, ValueError):
        raise BadgeDenied("badge is not a JSON document; refusing fail-closed") from None
    badge = parse_vaid_document(as_text)
    if badge is None:
        raise BadgeDenied("badge is not a well-formed VAID document; refusing fail-closed")

    lineage = assemble_lineage(badge, handle.issuer)
    if lineage is None:
        raise BadgeDenied(f"badge {badge.get('vaid_id')!r} lineage could not be assembled; refusing fail-closed")
    revocation_status = handle.revocation.check_lineage(lineage)
    verdict = verify_vaid_standing(handle.issuer.kernel_public_key(), badge, revocation_status)
    if not verdict.is_valid():
        raise BadgeDenied(f"badge {badge.get('vaid_id')!r} failed verification: {verdict.code}")

    # A genuine badge is not necessarily *this* identity's badge. Verification
    # above answers "was this issued under our kernel key and does it still
    # stand", which a correctly-signed badge minted for a different agent
    # passes — measured: a ``triage`` identity carrying a real ``respond``
    # badge was accepted. Scope is unaffected (``identity.require`` had
    # already run against the triage scope table), so this is not an
    # authorization escape; it is an attribution one, and attribution is the
    # entire thing #1739 asked for. The ledger row written by
    # ``record_badge_in_ledger`` would have named the wrong agent.
    if badge.get("agent_class") != identity.agent:
        raise BadgeDenied(f"badge {badge.get('vaid_id')!r} was issued for agent {badge.get('agent_class')!r}, not for {identity.agent!r}")


def install_into(registry: Any) -> bool:
    """Wire the badge check into a ``ToolRegistry`` instance, if the plugin
    is enabled. Returns whether it did. Safe to call unconditionally at
    service startup — a disabled plugin leaves the registry untouched."""
    if not vaid_plugin_enabled():
        return False
    registry.identity_verifier = verify_identity_badge
    return True


def uninstall_from(registry: Any) -> None:
    """Test/ops helper: remove the hook regardless of the env flag."""
    registry.identity_verifier = None


async def record_badge_in_ledger(
    identity: VaidBackedIdentity,
    *,
    run_id: uuid.UUID,
    tenant_id: uuid.UUID,
    seq: int,
    _record_event: Any = None,
) -> uuid.UUID | None:
    """Write the badge's hash — never the badge itself — into the
    Investigation Ledger (``app.investigator.ledger.record_event``).

    Why the hash and not the badge: the ledger is read by more people than
    a single run's operator, and the badge carries ``public_key_der`` and
    ``kernel_signature`` — bytes with no investigative value that a wider
    audience gains nothing from and that widen what a ledger compromise
    exposes. The hash is enough to prove, against a copy the issuer or an
    archive holds, exactly which badge acted; that is the Investigation
    Ledger's job here — naming what happened, not re-hosting the evidence.

    A no-op (returns ``None``) when the plugin is disabled or ``identity``
    carries no badge, so a caller may invoke this unconditionally from an
    orchestrator's existing per-event sequence without branching on the
    flag itself.

    ``_record_event`` is test-only dependency injection: the real
    ``app.investigator.ledger`` module pulls in this service's full
    dependency tree (LangGraph, OpenTelemetry, asyncpg) through its
    package ``__init__``, which a unit test for this plugin has no
    business requiring. Production callers never pass it.
    """
    if not vaid_plugin_enabled():
        return None

    record_event = _record_event
    if record_event is None:
        from app.investigator.ledger import record_event  # noqa: PLC0415

    return await record_event(
        run_id=run_id,
        tenant_id=tenant_id,
        seq=seq,
        kind="vaid_badge_issued",
        agent=identity.agent,
        summary=f"VAID badge {identity.badge.get('vaid_id')} issued for agent {identity.agent!r}",
        payload={
            "vaid_id": identity.badge.get("vaid_id"),
            "credential_id": identity.credential_id,
            "badge_sha256": badge_sha256(identity.badge),
            "capability_set": sorted(identity.scopes),
            "expires_at": identity.badge.get("expires_at"),
        },
    )
