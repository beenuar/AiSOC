"""Per-tenant detection tuning, loaded into fusion as a versioned overlay.

Parity plan 5.4: "Fusion loads static JSON and never reads tenant tuning.
Load per-tenant suppressions, thresholds, disables, custom rules and MSSP
rule packs into fusion as versioned overlays with hot reload. A tuning
change applies to that tenant only and is recorded with its author and
reason."

What was wrong
--------------
`DetectionEngine` loads `app/data/detection_ruleset.json` at construction
and evaluates every rule against every event. The console lets a tenant
disable a rule, raise its threshold or suppress it for a field value, and
all of that is written to `detection_rules` in Postgres where **the
streaming engine never looks**. A tenant who turned a noisy rule off kept
getting alerts from it, and the console showed the rule as disabled.

Why an overlay rather than a per-tenant ruleset
------------------------------------------------
Building a full ruleset per tenant would mean holding N copies of 833
rules and rebuilding one whenever anybody edits anything. The overlay is
the *difference*: a small set of disables, thresholds and suppressions
applied over the shared corpus at match time. One corpus, one small
per-tenant delta.

Versioning and hot reload
-------------------------
Each tenant's overlay carries a version derived from the rows it was built
from. The engine refetches on a short interval and swaps atomically, so a
tuning change applies within one reload rather than at the next restart.
A reload that fails keeps the previous overlay rather than falling back to
"no tuning": losing a tenant's suppressions because the database blinked
would turn their queue back on.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()

#: How often a tenant's overlay is refetched. Short, because the plan asks
#: for hot reload and a tenant who just disabled a noisy rule should stop
#: seeing it quickly.
RELOAD_SECONDS = float(os.getenv("AISOC_TENANT_OVERLAY_RELOAD_SECONDS", "30"))


@dataclass(frozen=True)
class RuleOverride:
    """One tenant's tuning of one rule."""

    rule_id: str
    enabled: bool = True
    #: Minimum severity this rule may still fire at, if raised.
    min_severity: str | None = None
    #: Field/value pairs that suppress a match entirely.
    suppress_when: dict[str, list[str]] = field(default_factory=dict)
    #: Who changed it and why, carried so an alert that did *not* fire can
    #: be explained without opening the database.
    author: str | None = None
    reason: str | None = None


_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class TenantOverlay:
    """The whole delta for one tenant, plus the version it was built at."""

    tenant_id: str
    overrides: dict[str, RuleOverride] = field(default_factory=dict)
    #: Field name to the values this tenant has declared fine. Feeds the
    #: `<x>_in_allowlist` booleans 15 rules read and nothing computed.
    allowlists: dict[str, list[str]] = field(default_factory=dict)
    #: External ids of this tenant's privileged principals, lower-cased.
    #: Feeds the `*_priv` / `*_is_admin` booleans 18 rules read.
    privileged_principals: frozenset[str] = frozenset()
    #: External ids of this tenant's privileged roles, lower-cased.
    privileged_roles: frozenset[str] = frozenset()
    version: str = ""
    loaded_at: float = 0.0

    def derived_allowlist_fields(self, event: dict[str, Any]) -> dict[str, bool]:
        if not self.allowlists:
            return {}
        return allowlist_fields(self.allowlists, event)

    def derived_identity_fields(self, event: dict[str, Any]) -> dict[str, bool]:
        if not self.privileged_principals and not self.privileged_roles:
            return {}
        return identity_fields(self.privileged_principals, self.privileged_roles, event)

    def suppresses(self, rule_id: str, event: dict[str, Any]) -> str | None:
        """Why this rule must not fire for this tenant, or None.

        A reason string rather than a bool, so a suppressed match can be
        recorded with the tuning that suppressed it. "No alert" with no
        explanation is indistinguishable from a rule that simply did not
        match, and an analyst asking why they stopped seeing something
        deserves an answer.
        """
        override = self.overrides.get(rule_id)
        if override is None:
            return None

        if not override.enabled:
            return _explain("disabled for this tenant", override)

        for field_name, values in override.suppress_when.items():
            actual = event.get(field_name)
            if actual is None:
                continue
            if str(actual) in {str(v) for v in values}:
                return _explain(f"suppressed where {field_name}={actual!r}", override)
        return None

    def raises_severity_floor(self, rule_id: str, severity: str) -> str | None:
        """Whether this tenant raised the bar above this match's severity."""
        override = self.overrides.get(rule_id)
        if override is None or not override.min_severity:
            return None
        try:
            if _SEVERITY_ORDER.index(severity.lower()) < _SEVERITY_ORDER.index(override.min_severity.lower()):
                return _explain(
                    f"below this tenant's floor of {override.min_severity} for this rule",
                    override,
                )
        except ValueError:
            return None
        return None


def _explain(what: str, override: RuleOverride) -> str:
    """The tuning, its author and its reason, in one line."""
    parts = [what]
    if override.author:
        parts.append(f"by {override.author}")
    if override.reason:
        parts.append(f"({override.reason})")
    return " ".join(parts)


def _version_of(rows: list[dict[str, Any]]) -> str:
    """A digest of the rows the overlay was built from.

    Content-derived rather than a timestamp, so an overlay rebuilt from
    unchanged rows keeps its version and a consumer can tell a real change
    from a periodic refetch.
    """
    canonical = json.dumps(
        sorted(
            (
                str(r.get("rule_id") or r.get("id")),
                r.get("status"),
                json.dumps(r.get("suppression_config") or {}, sort_keys=True, default=str),
                json.dumps(r.get("threshold_config") or {}, sort_keys=True, default=str),
            )
            for r in rows
        ),
        default=str,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def build_overlay(
    tenant_id: str,
    rows: list[dict[str, Any]],
    *,
    identities: list[dict[str, Any]] | None = None,
    now: float | None = None,
) -> TenantOverlay:
    """Turn `detection_rules` rows into an overlay.

    `identities` carries this tenant's privileged principals and roles from
    `identity_nodes`, which is a different table with a different lifecycle,
    so it is a separate argument rather than more rows: a tenant may have
    tuned nothing and imported a directory, or the reverse.

    `now` is injectable because the reload interval is a behaviour worth
    testing, and a cache whose clock cannot be controlled can only be
    tested by sleeping.
    """
    overrides: dict[str, RuleOverride] = {}
    for row in rows:
        rule_id = str(row.get("rule_id") or row.get("id") or "")
        if not rule_id:
            continue
        suppression = row.get("suppression_config") or {}
        if isinstance(suppression, str):
            try:
                suppression = json.loads(suppression)
            except ValueError:
                suppression = {}
        threshold = row.get("threshold_config") or {}
        if isinstance(threshold, str):
            try:
                threshold = json.loads(threshold)
            except ValueError:
                threshold = {}

        suppress_when: dict[str, list[str]] = {}
        raw_when = suppression.get("suppress_when") or suppression.get("exclude") or {}
        if isinstance(raw_when, dict):
            for key, value in raw_when.items():
                suppress_when[str(key)] = [str(v) for v in value] if isinstance(value, list) else [str(value)]

        overrides[rule_id] = RuleOverride(
            rule_id=rule_id,
            # `status` is the console's enabled flag: anything other than
            # `active` means the tenant turned it off.
            enabled=str(row.get("status") or "active") == "active",
            min_severity=threshold.get("min_severity"),
            suppress_when=suppress_when,
            author=row.get("author") or suppression.get("author"),
            reason=suppression.get("reason") or threshold.get("reason"),
        )

    # A tenant's allowlists live beside their suppressions: the console
    # writes both, and an allowlist is the same decision expressed for a
    # field rather than for a rule.
    allowlists: dict[str, list[str]] = {}
    for row in rows:
        suppression = row.get("suppression_config") or {}
        if isinstance(suppression, str):
            try:
                suppression = json.loads(suppression)
            except ValueError:
                continue
        raw = suppression.get("allowlists") if isinstance(suppression, dict) else None
        if isinstance(raw, dict):
            for key, value in raw.items():
                values = [str(v) for v in value] if isinstance(value, list) else [str(value)]
                allowlists.setdefault(str(key), []).extend(values)

    principals: set[str] = set()
    roles: set[str] = set()
    for row in identities or ():
        external_id = str(row.get("external_id") or "").strip().lower()
        if not external_id:
            continue
        (roles if str(row.get("node_type") or "") == "role" else principals).add(external_id)

    return TenantOverlay(
        tenant_id=tenant_id,
        overrides=overrides,
        allowlists=allowlists,
        privileged_principals=frozenset(principals),
        privileged_roles=frozenset(roles),
        version=_version_of([*rows, *(identities or ())]),
        loaded_at=now if now is not None else time.monotonic(),
    )


# ── Per-tenant allowlists (parity 5.5) ──────────────────────────────────
#
# 15 of the 133 rules that cannot fire need an `<x>_in_allowlist` boolean
# that nothing computed. They were the cheapest family to close, because
# an allowlist is the same thing a tenant already configures as a
# suppression: a list of values they have decided are fine.
#
# Each entry maps the boolean a rule reads to the event field its value
# comes from. Derived here rather than in `derived_fields.py` because the
# answer is per tenant, and a shared derived field would make one tenant's
# allowlist apply to everybody.
ALLOWLIST_FIELDS: dict[str, str] = {
    "image_registry_in_allowlist": "image_registry",
    "dst_registry_in_allowlist": "dst_registry",
    "external_account_in_allowlist": "external_account",
    "impersonator_in_allowlist": "impersonator",
    "share_target_domain_in_allowlist": "share_target_domain",
    "backup_dst_in_allowlist": "backup_dst",
    "src_country_in_allowlist": "src_country",
    "src_country_not_in_allowlist": "src_country",
    "source_image_not_in_allowlist": "source_image",
    "source_image_basename_not_in_allowlist": "source_image_basename",
    "image_basename_in_allowlist": "image_basename",
    "dst_in_allowlist": "dst",
    "src_in_allowlist": "src",
}


def allowlist_fields(allowlists: dict[str, list[str]], event: dict[str, Any]) -> dict[str, bool]:
    """The `<x>_in_allowlist` booleans this event's values produce.

    An absent allowlist yields **no key at all** rather than `False`. The
    distinction matters: `not_in_allowlist` with an unconfigured list
    would be `True` for every event and the rule would fire on all of
    them, which is exactly the "a negation flips on a missing field"
    failure recorded for the Sigma import.
    """
    out: dict[str, bool] = {}
    for boolean, source in ALLOWLIST_FIELDS.items():
        configured = allowlists.get(source)
        if configured is None:
            continue
        value = event.get(source)
        if value is None:
            continue
        member = str(value) in {str(v) for v in configured}
        out[boolean] = member if boolean.endswith("_in_allowlist") and "_not_in_" not in boolean else not member
    return out


#: `<boolean the rules read>` → the event fields that name its subject, in
#: the order they are trusted, and which privileged set answers for it.
#:
#: Depth plan 3.3. 18 rules read one of these booleans and nothing computed
#: any of them, so each rule read `None` on that clause and could never fire.
#: They are answered from `identity_nodes.privilege_tier`, the column that
#: migration 018 created for exactly this question.
#:
#: Four more booleans in the same family are **not** here, and that is the
#: honest half: `scope_priv`, `act_as_user_priv`, `gpo_link_priv` and
#: `account_is_dc` have no subject field any source emits and no inventory
#: to answer from. Guessing a subject would produce a boolean that is
#: confidently wrong rather than absent.
IDENTITY_FIELDS: dict[str, tuple[tuple[str, ...], str]] = {
    "user_priv": (("user", "user_name", "actor_email", "actor", "user_arn"), "principals"),
    "target_user_priv": (("target_user", "target"), "principals"),
    "role_priv": (("role",), "roles"),
    # The actor's *role* is not on the event, and a principal's privilege
    # tier is derived from the roles it holds, so the two questions have one
    # answer. Recorded rather than silently equated.
    "actor_role_priv": (("actor_email", "actor", "user"), "principals"),
    "actor_is_admin": (("actor_email", "actor", "user"), "principals"),
}


def identity_fields(principals: frozenset[str], roles: frozenset[str], event: dict[str, Any]) -> dict[str, bool]:
    """The `*_priv` booleans this event's subjects produce.

    An unknown subject yields **no key at all**, never `False`. A tenant
    that has imported no identities gets no keys, so a rule reading
    `user_priv: true` stays silent instead of being told the account is not
    privileged — which is a different and much more confident statement than
    "we do not know".
    """
    out: dict[str, bool] = {}
    sets = {"principals": principals, "roles": roles}
    for boolean, (candidates, which) in IDENTITY_FIELDS.items():
        known = sets[which]
        if not known:
            continue
        for candidate in candidates:
            value = event.get(candidate)
            if value is None or value == "":
                continue
            out[boolean] = str(value).strip().lower() in known
            break
    return out


#: An overlay with nothing in it. Returned for a tenant that has tuned
#: nothing, which is the common case and must cost nothing.
EMPTY = TenantOverlay(tenant_id="", overrides={}, version="empty")


class OverlayCache:
    """Per-tenant overlays with hot reload.

    A failed reload keeps the previous overlay rather than falling back to
    `EMPTY`. Losing a tenant's suppressions because the database blinked
    would turn their queue back on, which is the opposite of what the
    tuning was for.
    """

    def __init__(self, pool: Any, *, reload_seconds: float | None = None) -> None:
        self._pool = pool
        self._reload = reload_seconds if reload_seconds is not None else RELOAD_SECONDS
        self._cache: dict[str, TenantOverlay] = {}

    async def get(self, tenant_id: str, *, now: float | None = None) -> TenantOverlay:
        if not tenant_id or self._pool is None:
            return EMPTY
        current = self._cache.get(tenant_id)
        clock = now if now is not None else time.monotonic()
        if current is not None and (clock - current.loaded_at) < self._reload:
            return current

        fetched = await self._fetch(tenant_id)
        rows = fetched[0] if fetched is not None else None
        identities = fetched[1] if fetched is not None else None
        if rows is None:
            if current is not None:
                logger.warning(
                    "tenant_overlay.reload_failed_keeping_previous",
                    tenant_id=tenant_id,
                    version=current.version,
                )
                return current
            return EMPTY

        overlay = build_overlay(tenant_id, rows, identities=identities, now=clock)
        if current is not None and current.version != overlay.version:
            logger.info(
                "tenant_overlay.changed",
                tenant_id=tenant_id,
                was=current.version,
                now=overlay.version,
                overrides=len(overlay.overrides),
            )
        self._cache[tenant_id] = overlay
        return overlay

    async def _fetch(self, tenant_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]] | None:
        """(tuning rows, privileged identities), or None when unreadable.

        None and an empty list mean different things: no tuning, versus no
        answer. Collapsing them is what would drop a tenant's suppressions
        on a transient failure.
        """
        try:
            async with self._pool.acquire() as conn:
                # `detection_rules` has no `rule_id` or `updated_by` column.
                # It did not have one when this query was first written
                # either, and the query failed into the `except` below,
                # logged a warning and returned None — so the overlay
                # never loaded and the whole feature silently did nothing
                # while every unit test passed against a fake.
                #
                # The engine's `det-*` id lives in `provenance->>'source_id'`
                # (migration 036), which is the stable external identifier
                # by design. `author` is the column that records who
                # changed the rule.
                rows = await conn.fetch(
                    """
                    SELECT COALESCE(provenance->>'source_id', name) AS rule_id,
                           status,
                           suppression_config,
                           threshold_config,
                           author
                      FROM detection_rules
                     WHERE tenant_id = $1::uuid
                       AND (status <> 'active'
                            OR suppression_config <> '{}'::jsonb
                            OR threshold_config <> '{}'::jsonb)
                    """,
                    tenant_id,
                )
                # Depth plan 3.3. `privilege_tier` is 0=standard, 1=elevated,
                # 2=admin, 3=super-admin (migration 018). "Privileged" is the
                # admin tiers: treating `elevated` as privileged would put
                # most of a directory in the set and make every `*_priv` rule
                # fire on ordinary work.
                identities = await conn.fetch(
                    """
                    SELECT node_type, external_id
                      FROM identity_nodes
                     WHERE tenant_id = $1::uuid
                       AND is_active
                       AND privilege_tier >= 2
                    """,
                    tenant_id,
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("tenant_overlay.fetch_failed", tenant_id=tenant_id, error=str(exc))
            return None
        return [dict(r) for r in rows], [dict(r) for r in identities]

    def invalidate(self, tenant_id: str) -> None:
        """Force the next read to refetch. For an explicit console save."""
        self._cache.pop(tenant_id, None)
