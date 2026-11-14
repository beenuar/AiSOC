"""One permission model, and the database is authoritative.

Two models shipped side by side. 275 route dependencies called the
synchronous `require_permission`, which reads the hardcoded
`ROLE_PERMISSIONS` map; 27 called `require_permission_db`, which reads the
`user_roles` / `role_permissions` tables. The console ships a full RBAC
administration surface writing to those tables — so an operator could grant
a permission, watch it appear in the UI, and have **275 of 302 routes
ignore it**.

Tested in both directions, which is the only way this means anything:

* a permission the database grants and the static map does not must be
  **allowed** — otherwise the RBAC screen is decorative;
* a permission the static map grants and the database does not must be
  **denied** — otherwise revoking access does nothing.

The second is the one that was broken in a subtle way. `has_permission_db`
fell back to the static map whenever a user had no rows in `user_roles`,
which is right for a fresh tenant and wrong for a deprovisioned user:
**removing every role restored their static permissions.** The two cases
are indistinguishable from the user's row count alone, so the resolver asks
one level up — does the *tenant* have any roles at all?
"""

from __future__ import annotations

import uuid

import pytest
from app.api.v1.deps import CurrentUser
from app.core.permission_cache import (
    CACHE,
    FALLBACK_TTL_SECONDS,
    PermissionCache,
    grants,
    reset_for_tests,
    resolve_permissions,
)
from app.core.security import ROLE_PERMISSIONS
from fastapi import HTTPException


@pytest.fixture(autouse=True)
def _clean_cache():
    reset_for_tests()
    yield
    reset_for_tests()


class _FakeResult:
    def __init__(self, rows: list[tuple[str]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[str]]:
        return self._rows


class _FakeSession:
    """A session that answers the two queries the resolver makes.

    `granted` is what `user_roles` joins to; `tenant_grant_count` is how many
    grants exist anywhere in the tenant, which is the fact that separates a
    fresh tenant from a deprovisioned user.

    Note what this double cannot see. `scalar()` answers the same number for
    any query, so these tests read identically whether the resolver counts
    role rows or grants -- and the distinction turned out to matter: a
    migration that seeds a role into every tenant took the bootstrap path
    away from all of them while every test here still passed.
    `test_bootstrap_fallback_survives_a_seeded_role.py` covers that against a
    real database, because this fake structurally cannot.
    """

    def __init__(self, *, granted: list[str], tenant_grant_count: int) -> None:
        self._granted = granted
        self._tenant_grant_count = tenant_grant_count
        self.executed = 0

    async def execute(self, *_args, **_kwargs):
        self.executed += 1
        return _FakeResult([(name,) for name in self._granted])

    async def scalar(self, *_args, **_kwargs) -> int:
        return self._tenant_grant_count


TENANT = uuid.uuid4()
USER = uuid.uuid4()


class TestTheDatabaseIsAuthoritative:
    async def test_a_database_grant_the_static_map_lacks_is_allowed(self) -> None:
        """Otherwise the console's RBAC screen is decorative."""
        assert "lake:admin" not in ROLE_PERMISSIONS["viewer"]
        resolved = await resolve_permissions(
            _FakeSession(granted=["lake:admin"], tenant_grant_count=3),
            tenant_id=TENANT,
            user_id=USER,
            static_role="viewer",
        )
        assert grants(resolved, "lake:admin")

    async def test_a_static_grant_the_database_lacks_is_denied(self) -> None:
        """Otherwise revoking access does nothing.

        `tenant_admin` holds `alerts:write` statically. A tenant that has
        configured roles and given this user none has answered the
        question, and the answer is "none".
        """
        assert "alerts:write" in ROLE_PERMISSIONS["tenant_admin"]
        resolved = await resolve_permissions(
            _FakeSession(granted=[], tenant_grant_count=4),
            tenant_id=TENANT,
            user_id=USER,
            static_role="tenant_admin",
        )
        assert not grants(resolved, "alerts:write")
        assert resolved == frozenset()

    async def test_a_tenant_with_no_roles_falls_back_to_the_static_map(self) -> None:
        """Bootstrap. A fresh tenant has nothing for the database to answer with.

        This is the case the old fallback was written for, and it stays —
        the defect was that it also covered the case above.
        """
        resolved = await resolve_permissions(
            _FakeSession(granted=[], tenant_grant_count=0),
            tenant_id=TENANT,
            user_id=USER,
            static_role="tenant_admin",
        )
        assert grants(resolved, "alerts:write")

    async def test_the_two_empty_cases_are_distinguished_by_the_tenant_not_the_user(self) -> None:
        """The whole correction, stated as one assertion.

        Both principals have zero rows in `user_roles`. One is a fresh
        tenant and must work; the other was deprovisioned and must not.
        """
        fresh = await resolve_permissions(
            _FakeSession(granted=[], tenant_grant_count=0),
            tenant_id=TENANT,
            user_id=USER,
            static_role="soc_analyst",
        )
        deprovisioned = await resolve_permissions(
            _FakeSession(granted=[], tenant_grant_count=7),
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            static_role="soc_analyst",
        )
        assert fresh != deprovisioned
        assert fresh and not deprovisioned


class TestThePrincipalUsesWhatWasResolved:
    def test_a_resolved_set_overrides_the_static_role(self) -> None:
        user = CurrentUser(
            user_id=USER,
            tenant_id=TENANT,
            role="tenant_admin",
            email="a@example.com",
            resolved_permissions=frozenset({"alerts:read"}),
        )
        user.require_permission("alerts:read")
        with pytest.raises(HTTPException) as exc:
            user.require_permission("alerts:write")
        assert exc.value.status_code == 403

    def test_no_resolved_set_falls_through_to_the_static_map(self) -> None:
        """Which is what keeps directly-constructed principals working.

        Every test that drives a route with a mocked session builds a
        `CurrentUser` by hand. Making the permission dependency itself
        query would have broken 84 of them — and, more importantly, would
        mean a database blip denies every request on the platform.
        """
        user = CurrentUser(user_id=USER, tenant_id=TENANT, role="tenant_admin", email="a@example.com")
        user.require_permission("alerts:write")

    def test_an_api_key_still_uses_its_own_scopes(self) -> None:
        """A key's scopes are a deliberately narrower grant.

        Resolving a key to its owner's full role would widen it, which is
        the opposite of what a scoped key is for.
        """
        user = CurrentUser(
            user_id=USER,
            tenant_id=TENANT,
            role="tenant_admin",
            email="a@example.com",
            scopes=["alerts:read"],
            resolved_permissions=frozenset({"*"}),
        )
        user.require_permission("alerts:read")
        with pytest.raises(HTTPException):
            user.require_permission("alerts:write")


class TestTheCacheInvalidates:
    def test_a_version_change_beats_a_live_ttl(self) -> None:
        """A revoke must not wait for a clock.

        A TTL alone means a revoked permission keeps working for the length
        of the TTL on every replica holding it — which for an access
        revocation is the wrong failure mode.
        """
        cache = PermissionCache()
        cache.put(tenant_id="t", user_id="u", version="1", permissions=frozenset({"a"}))
        assert cache.get(tenant_id="t", user_id="u", version="1") == frozenset({"a"})
        assert cache.get(tenant_id="t", user_id="u", version="2") is None

    def test_invalidating_a_tenant_leaves_other_tenants_alone(self) -> None:
        cache = PermissionCache()
        cache.put(tenant_id="t1", user_id="u", version="1", permissions=frozenset({"a"}))
        cache.put(tenant_id="t2", user_id="u", version="1", permissions=frozenset({"b"}))
        assert cache.invalidate_tenant("t1") == 1
        assert cache.get(tenant_id="t1", user_id="u", version="1") is None
        assert cache.get(tenant_id="t2", user_id="u", version="1") == frozenset({"b"})

    def test_the_entry_count_is_bounded(self) -> None:
        """So an attacker cycling user ids cannot grow the map without limit."""
        from app.core.permission_cache import MAX_ENTRIES

        cache = PermissionCache()
        for index in range(MAX_ENTRIES + 50):
            cache.put(tenant_id="t", user_id=str(index), version="1", permissions=frozenset())
        assert len(cache._entries) <= MAX_ENTRIES

    def test_the_ttl_is_short_enough_to_bound_a_redis_outage(self) -> None:
        """It is the whole staleness window when no version counter answers."""
        assert 0 < FALLBACK_TTL_SECONDS <= 30

    async def test_a_second_resolution_does_not_requery(self) -> None:
        """A four-table join per request is what the cache exists to avoid."""
        session = _FakeSession(granted=["alerts:read"], tenant_grant_count=2)
        for _ in range(3):
            await resolve_permissions(session, tenant_id=TENANT, user_id=USER, static_role="viewer")
        assert session.executed == 1, f"queried {session.executed} times; the cache is not holding"


class TestWildcards:
    @pytest.mark.parametrize(
        ("held", "wanted", "expected"),
        [
            (frozenset({"*"}), "anything:at:all", True),
            (frozenset({"alerts:*"}), "alerts:write", True),
            (frozenset({"alerts:*"}), "cases:write", False),
            (frozenset({"alerts:read"}), "alerts:write", False),
            (frozenset(), "alerts:read", False),
        ],
    )
    def test_grants(self, held: frozenset[str], wanted: str, expected: bool) -> None:
        assert grants(held, wanted) is expected


def test_the_cache_is_a_single_process_wide_instance() -> None:
    """One per replica by construction, which is what the version counter assumes."""
    from app.core import permission_cache

    assert isinstance(permission_cache.CACHE, PermissionCache)
    assert permission_cache.CACHE is CACHE
