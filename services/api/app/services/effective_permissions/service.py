"""Effective-permissions dispatcher + Neo4j cache writer (T3.2).

The API endpoint calls :func:`resolve_effective_permissions` with a provider
string and a principal id. This module:

1. Picks the right :class:`Resolver` (raising :class:`ValueError` for an
   unknown provider — translated to HTTP 400 by the endpoint).
2. Loads the provider's snapshot. Production wiring would read from S3 /
   Neo4j; the in-tree implementation accepts an explicit ``snapshot_loader``
   so tests inject fixtures without monkey-patching.
3. Calls :meth:`Resolver.resolve` and gets a :class:`ResolverResult`.
4. Best-effort caches the result into Neo4j as
   ``(:Identity {id})-[:EFFECTIVE_PERMISSION {actions, ...}]->(:Resource {id})``
   so downstream queries can hop to it without re-running the resolver. The
   cache write is wrapped in a broad ``try/except`` and logged — Neo4j being
   down must never break the synchronous read path.

The :data:`SUPPORTED_PROVIDERS` mapping is the single source of truth for the
provider list — the API endpoint imports it for input validation and the UI
calls ``GET /v1/identity/effective-permissions/providers`` to render the
provider switcher.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from app.services.effective_permissions.aws import AwsIamResolver
from app.services.effective_permissions.azure import AzureRbacResolver
from app.services.effective_permissions.base import (
    Resolver,
    ResolverResult,
    chain_ids,
)
from app.services.effective_permissions.gcp import GcpIamResolver
from app.services.effective_permissions.gws import GoogleWorkspaceResolver
from app.services.effective_permissions.okta import OktaResolver

logger = logging.getLogger(__name__)


SUPPORTED_PROVIDERS: dict[str, type[Resolver]] = {
    "aws": AwsIamResolver,
    "azure": AzureRbacResolver,
    "gcp": GcpIamResolver,
    "okta": OktaResolver,
    "gws": GoogleWorkspaceResolver,
}


# Maps a user-supplied provider name to the *hardcoded literal* that is safe
# to log. Looking up the value (rather than passing the raw ``provider``
# argument through a conditional ``if ... else "<unsupported>"`` expression)
# breaks CodeQL's taint flow because the value side of the mapping is never
# derived from the input — it is a compile-time string literal. This satisfies
# ``py/log-injection`` without losing the operational signal.
_PROVIDER_LOG_TOKENS: dict[str, str] = {
    "aws": "aws",
    "azure": "azure",
    "gcp": "gcp",
    "okta": "okta",
    "gws": "gws",
}


SnapshotLoader = Callable[[str], dict[str, Any]]


def _default_snapshot_loader(provider: str) -> dict[str, Any]:
    """Production snapshot loader stub.

    Real implementation will read the most-recent reconciliation snapshot
    from object storage (keyed by ``{tenant}/{provider}/{snapshot_id}.json``)
    and back it with a small in-process LRU. For now it returns an empty
    dict — the API endpoint catches the resulting ``ResolverError`` and
    surfaces a 412 Precondition Failed ("no policy snapshot ingested yet").
    """

    # ``provider`` is user-supplied (it arrives via the API endpoint's path
    # / query parameters). Even though the calling resolver only dispatches
    # on values in ``SUPPORTED_PROVIDERS``, the loader stub is reachable
    # before that dispatch, so we constrain what we put into the log
    # record. We look up a hardcoded literal from ``_PROVIDER_LOG_TOKENS``
    # so the value that lands in the log line is provably independent of
    # the input string — anything outside the known allowlist is logged as
    # the literal ``"<unsupported>"``. This stops an attacker from smuggling
    # control characters or fake log lines through this code path and
    # resolves CodeQL ``py/log-injection`` without losing the operational
    # signal.
    safe_provider = _PROVIDER_LOG_TOKENS.get(provider, "<unsupported>")
    logger.warning(
        "no production snapshot loader wired for provider=%s — returning {}",
        safe_provider,
    )
    return {}


def resolve_effective_permissions(
    provider: str,
    principal_id: str,
    *,
    snapshot: dict[str, Any] | None = None,
    snapshot_loader: SnapshotLoader | None = None,
) -> ResolverResult:
    """Synchronous dispatcher used by the API endpoint and tests.

    Notes
    -----

    * The Neo4j write is performed via :func:`cache_result_into_neo4j` from
      the API endpoint after the result is built — keeping this function
      pure makes it trivial to unit-test.
    * Either ``snapshot`` or ``snapshot_loader`` must produce a non-empty
      dict for full providers; scaffolds raise ``NotImplementedError``
      regardless.
    """

    resolver_cls = SUPPORTED_PROVIDERS.get(provider)
    if resolver_cls is None:
        raise ValueError(
            f"unknown provider {provider!r}; supported: "
            f"{sorted(SUPPORTED_PROVIDERS)}"
        )

    resolver = resolver_cls()
    if snapshot is None:
        loader = snapshot_loader or _default_snapshot_loader
        snapshot = loader(provider)

    return resolver.resolve(principal_id, snapshot=snapshot)


CacheWriter = Callable[[ResolverResult], Awaitable[int]]


async def cache_result_into_neo4j(result: ResolverResult) -> int:
    """Materialise the resolver result as ``:EFFECTIVE_PERMISSION`` edges.

    Returns the number of edges written. Best-effort — any Neo4j failure is
    logged and ``0`` is returned so the API response is not poisoned by a
    background-cache outage.
    """

    if not result.decisions:
        return 0

    try:
        from app.db.neo4j import get_session  # imported lazily so unit
        # tests of the dispatcher don't pay the import cost.
    except Exception as exc:  # pragma: no cover - import-time wiring only
        logger.warning("neo4j module not importable, skipping cache: %s", exc)
        return 0

    cypher = """
    MERGE (i:Identity {id: $principal_id})
    MERGE (r:Resource {id: $resource_id})
    MERGE (i)-[e:EFFECTIVE_PERMISSION {provider: $provider}]->(r)
    SET e.actions = $actions,
        e.deny_actions = $deny_actions,
        e.policy_chain_ids = $policy_chain_ids,
        e.last_resolved = datetime($last_resolved),
        e.snapshot_id = $snapshot_id,
        e.resolver_version = $resolver_version
    """

    written = 0
    last_resolved_iso = result.last_resolved.isoformat()
    snapshot_id = f"{result.provider}:{result.last_resolved.timestamp():.0f}"
    try:
        async with get_session() as session:
            for decision in result.decisions:
                await session.run(
                    cypher,
                    principal_id=decision.principal_id,
                    resource_id=decision.resource_id,
                    provider=result.provider,
                    actions=list(decision.actions),
                    deny_actions=list(decision.deny_actions),
                    policy_chain_ids=chain_ids(decision.policy_chain),
                    last_resolved=last_resolved_iso,
                    snapshot_id=snapshot_id,
                    resolver_version=result.resolver_version,
                )
                written += 1
    except Exception as exc:  # pragma: no cover - Neo4j may be down in dev
        logger.warning("EFFECTIVE_PERMISSION cache write failed: %s", exc)
        return 0
    logger.info(
        "cached %d EFFECTIVE_PERMISSION edges for %s/%s",
        written,
        result.provider,
        result.principal_id,
    )
    return written
