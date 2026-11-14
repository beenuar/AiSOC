"""ABAC conditions, elevation and workload identities, offline.

Depth plan item 8.2. The live half is
``tests/isolation/test_abac_elevation_live.py``, which drives real routes
against real Postgres; this half covers the decisions that do not need a
database and the two vocabularies that have to agree with each other.

What this file cannot prove, and says so
-----------------------------------------
That the tables have readers. A fake session answers any query, which is
the exact shape that let three tables ship with no reader and every
offline suite stay green. Everything here is about *shape*: given a
principal already carrying grants and conditions, does the one permission
path reach the right verdict.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from app.api.v1.deps import SERVICE_TENANT_HEADER, CurrentUser, _condition_applies
from app.api.v1.endpoints.access_conditions import ADDRESSABLE_ATTRIBUTES, SUPPORTED
from app.api.v1.endpoints.api_keys import VALID_SCOPES
from app.api.v1.endpoints.elevation import MAX_DURATION
from app.core.rbac_catalog import PERMISSIONS
from app.core.security import ROLE_PERMISSIONS
from app.models.enterprise_iam import WorkloadIdentity
from app.security.abac import OPERATORS, PrivilegeGrant
from app.services import workload_identity as wi
from fastapi import HTTPException

TENANT = uuid.uuid4()
USER = uuid.uuid4()


def _principal(
    *,
    role: str = "viewer",
    scopes: list[str] | None = None,
    resolved_permissions: frozenset[str] | None = frozenset({"alerts:read"}),
    elevation: tuple[PrivilegeGrant, ...] = (),
    conditions: tuple[dict[str, Any], ...] = (),
    attributes: dict[str, Any] | None = None,
) -> CurrentUser:
    """A principal with the defaults these tests vary from.

    Explicit keywords rather than `**kwargs`: a dict splatted into a typed
    constructor widens every value to `object`, which cost 13 `arg-type`
    findings and, more to the point, means a test could pass a `conditions`
    list where a tuple is expected and nothing would say so.
    """
    return CurrentUser(
        user_id=USER,
        tenant_id=TENANT,
        role=role,
        email="v@example.com",
        scopes=scopes,
        resolved_permissions=resolved_permissions,
        elevation=elevation,
        conditions=conditions,
        attributes=attributes,
    )


def _digest(label: str) -> str:
    """A real SHA-256 digest, computed rather than written as a literal.

    Two reasons. A 64-character hex literal in a test file is
    credential-shaped, and the secret scanner is right to say so. And a
    computed digest is what the code under test actually compares, so the
    fixture cannot drift from the real hash function.
    """
    return wi.hash_workload_secret(f"fixture-{label}")


def _row(**overrides: Any) -> WorkloadIdentity:
    """A real `WorkloadIdentity`, not a stand-in class.

    The hand-rolled double this replaced answered for whichever attributes a
    test happened to read, which is the shape that lets a double be more
    capable than the thing it stands for. The ORM model constructs fine
    without a session, so there is no reason to use anything else.
    """
    fields: dict[str, Any] = {
        "id": uuid.uuid4(),
        "service": "agents",
        "description": None,
        "scopes": ["alerts:read"],
        "secret_prefix": wi.WORKLOAD_KEY_PREFIX + "abc1234",
        "secret_hash": _digest("current"),
        "previous_hash": None,
        "previous_expires_at": None,
        "expires_at": None,
        "last_used_at": None,
        "revoked_at": None,
        "created_at": None,
    }
    fields.update(overrides)
    return WorkloadIdentity(**fields)


def _grant(permissions: list[str], *, minutes: int = 30, revoked: bool = False) -> PrivilegeGrant:
    return PrivilegeGrant(
        permissions=tuple(permissions),
        expires_at=datetime.now(UTC) + timedelta(minutes=minutes),
        revoked_at=datetime.now(UTC) if revoked else None,
    )


class TestElevationAppliesAtUse:
    def test_a_live_grant_widens_the_resolved_set(self) -> None:
        user = _principal(elevation=(_grant(["cases:write"]),))
        user.require_permission("cases:write")

    def test_an_expired_grant_does_not(self) -> None:
        """Expiry with no sweep job in the path.

        The grant is held rather than merged precisely so this is decided
        here, on every check, instead of when a cache entry lapses.
        """
        user = _principal(elevation=(_grant(["cases:write"], minutes=-1),))
        with pytest.raises(HTTPException) as exc:
            user.require_permission("cases:write")
        assert exc.value.status_code == 403

    def test_a_revoked_grant_does_not(self) -> None:
        user = _principal(elevation=(_grant(["cases:write"], revoked=True),))
        with pytest.raises(HTTPException):
            user.require_permission("cases:write")

    def test_elevation_does_not_widen_an_api_key(self) -> None:
        """A key's scopes are a narrower grant chosen at mint time.

        Letting a person's temporary elevation flow into a bearer key they
        minted last year would make the elevation outlive its own window
        by however long the key lives.
        """
        user = _principal(scopes=["alerts:read"], elevation=(_grant(["cases:write"]),))
        with pytest.raises(HTTPException):
            user.require_permission("cases:write")

    def test_the_downstream_list_agrees_with_the_check(self) -> None:
        """`services/actions` re-authorises against `effective_permissions`.

        Two answers from two orders would surface as an intermittent 403
        on approval rather than as a bug.
        """
        user = _principal(elevation=(_grant(["cases:write"]),))
        user.require_permission("cases:write")
        assert "cases:write" in user.effective_permissions()

    def test_an_expired_grant_is_absent_from_the_downstream_list_too(self) -> None:
        user = _principal(elevation=(_grant(["cases:write"], minutes=-1),))
        assert "cases:write" not in user.effective_permissions()


class TestConditionsNarrowAndNeverGrant:
    def test_a_failing_condition_denies_a_permission_the_role_holds(self) -> None:
        user = _principal(
            resolved_permissions=frozenset({"cases:write"}),
            conditions=({"permission": "cases:write", "operator": "ip_in_cidr", "value": "10.0.0.0/8"},),
            attributes={"source_ip": "203.0.113.4"},
        )
        with pytest.raises(HTTPException) as exc:
            user.require_permission("cases:write")
        assert exc.value.status_code == 403
        assert "access condition" in str(exc.value.detail)

    def test_a_condition_cannot_grant_a_permission_the_role_lacks(self) -> None:
        """The property the whole design rests on.

        A condition that could grant would be a second authorization
        system reaching a different answer from the first.
        """
        user = _principal(
            resolved_permissions=frozenset({"alerts:read"}),
            conditions=({"permission": "cases:write", "operator": "ip_in_cidr", "value": "0.0.0.0/0"},),
            attributes={"source_ip": "10.1.1.1"},
        )
        with pytest.raises(HTTPException):
            user.require_permission("cases:write")

    def test_conditions_bind_an_api_key_too(self) -> None:
        """Narrowing applies on every branch.

        A rule that bound console sessions and silently not keys would be
        the kind of partial control nobody notices until an audit.
        """
        user = _principal(
            scopes=["cases:write"],
            conditions=({"permission": "cases:write", "operator": "ip_in_cidr", "value": "10.0.0.0/8"},),
            attributes={"source_ip": "203.0.113.4"},
        )
        with pytest.raises(HTTPException):
            user.require_permission("cases:write")

    def test_conditions_bind_the_static_map_branch_too(self) -> None:
        user = CurrentUser(
            user_id=USER,
            tenant_id=TENANT,
            role="tenant_admin",
            email="a@example.com",
            conditions=({"permission": "cases:write", "operator": "ip_in_cidr", "value": "10.0.0.0/8"},),
            attributes={"source_ip": "203.0.113.4"},
        )
        with pytest.raises(HTTPException):
            user.require_permission("cases:write")

    def test_an_indeterminate_condition_denies(self) -> None:
        """A request carrying nothing to judge on has not satisfied anything.

        Treating it as satisfied would mean a caller who omits a header is
        less constrained than one who sends it, which inverts the control.
        """
        user = _principal(
            resolved_permissions=frozenset({"cases:write"}),
            conditions=({"permission": "cases:write", "operator": "ip_in_cidr", "value": "10.0.0.0/8"},),
            attributes={},
        )
        with pytest.raises(HTTPException):
            user.require_permission("cases:write")

    def test_an_unconditioned_permission_is_untouched(self) -> None:
        """The negative control: narrowing only narrows what it names."""
        user = _principal(
            resolved_permissions=frozenset({"cases:write", "alerts:read"}),
            conditions=({"permission": "cases:write", "operator": "ip_in_cidr", "value": "10.0.0.0/8"},),
            attributes={"source_ip": "203.0.113.4"},
        )
        user.require_permission("alerts:read")

    @pytest.mark.parametrize(
        ("row_permission", "checked", "applies"),
        [
            ("cases:write", "cases:write", True),
            ("cases:*", "cases:write", True),
            ("*", "cases:write", True),
            ("cases:read", "cases:write", False),
            ("alerts:*", "cases:write", False),
        ],
    )
    def test_scope_matching(self, row_permission: str, checked: str, applies: bool) -> None:
        row = {"permission": row_permission, "role": None}
        assert _condition_applies(row, checked, "viewer") is applies

    def test_a_role_scoped_condition_does_not_bind_other_roles(self) -> None:
        row = {"permission": "cases:write", "role": "soc_analyst"}
        assert _condition_applies(row, "cases:write", "soc_analyst") is True
        assert _condition_applies(row, "cases:write", "tenant_admin") is False


class TestAttributeBindingNeverBreaksAuthentication:
    """Binding attributes is advisory; it must not be able to 401 a valid session.

    `bind_connection_attributes` reads the connection, and the graph
    WebSocket upgrade goes through it as well as every HTTP route. A
    `WebSocket` is not a `Request`, and an ASGI connection is not
    obliged to expose a peer address at all, so reading one must
    degrade rather than raise -- an `AttributeError` here surfaces as
    an authenticated user being unable to open a socket, which reads
    as an outage and not as a permission problem.

    Degrading is safe in the direction that matters: an unknown
    address makes an address condition indeterminate, and
    indeterminate denies.
    """

    class _NoPeer:
        """An ASGI connection that exposes no peer, like the graph socket's."""

    class _Peer:
        def __init__(self, host: str) -> None:
            self.client = SimpleNamespace(host=host)
            self.headers: dict[str, str] = {}

    def test_a_connection_without_a_peer_binds_rather_than_raising(self) -> None:
        user = _principal(resolved_permissions=frozenset({"cases:write"}))
        user.bind_connection_attributes(self._NoPeer())
        assert user.attributes["source_ip"] is None

    def test_an_address_condition_then_denies_rather_than_passing(self) -> None:
        """The fail-closed half. If an unknown address passed, every
        attribute condition would be bypassable by connecting over a
        transport that reports no peer."""
        user = _principal(
            resolved_permissions=frozenset({"cases:write"}),
            conditions=({"permission": "cases:write", "operator": "ip_in_cidr", "value": "10.0.0.0/8"},),
        )
        user.bind_connection_attributes(self._NoPeer())
        with pytest.raises(HTTPException):
            user.require_permission("cases:write")

    def test_a_connection_with_a_peer_still_carries_the_address(self) -> None:
        """The negative control. Binding that always produced `None`
        would pass both tests above and silently deny every address
        condition on every real request."""
        user = _principal(resolved_permissions=frozenset({"cases:write"}))
        user.bind_connection_attributes(self._Peer("10.1.2.3"))
        assert user.attributes["source_ip"] == "10.1.2.3"
        user.require_permission("cases:write")


class TestElevationAndConditionsCompose:
    def test_an_elevated_permission_is_still_narrowed(self) -> None:
        """Order matters: if grants were applied after conditions,
        elevation would be a way around every attribute rule."""
        user = _principal(
            elevation=(_grant(["cases:write"]),),
            conditions=({"permission": "cases:write", "operator": "ip_in_cidr", "value": "10.0.0.0/8"},),
            attributes={"source_ip": "203.0.113.4"},
        )
        with pytest.raises(HTTPException):
            user.require_permission("cases:write")


class TestTheTwoVocabulariesAgree:
    def test_every_supported_operator_is_a_real_one(self) -> None:
        assert set(SUPPORTED) <= set(OPERATORS)

    def test_every_new_permission_is_in_the_seeded_catalog(self) -> None:
        """A permission no catalog row names cannot be granted from the
        console, so the Roles screen renders the grant as a blank."""
        catalog = {name for name, _d, _c in PERMISSIONS}
        for permission in (
            "elevation:read",
            "elevation:request",
            "elevation:approve",
            "access_conditions:read",
            "access_conditions:write",
            "workload_identities:read",
            "workload_identities:write",
        ):
            assert permission in catalog, f"{permission} is enforced but not seeded"

    def test_every_new_permission_is_mintable_into_a_key(self) -> None:
        """`hunts:read` was once held by no role and absent from this set,
        so only a wildcard key could exercise it."""
        for permission in (
            "elevation:read",
            "elevation:request",
            "elevation:approve",
            "access_conditions:read",
            "access_conditions:write",
            "workload_identities:read",
            "workload_identities:write",
        ):
            assert permission in VALID_SCOPES, f"{permission} can only be reached by a wildcard key"

    def test_every_agent_tool_permission_is_mintable_into_a_key(self) -> None:
        """The MCP server authenticates with an API key. `aisoc_lake_schema`
        (GET /lake/schema, `lake:read_schema`) and `aisoc_preview_action`
        (POST /live-actions/dry-run, `actions:execute`) answered 403 to any
        key short of `*`, because neither permission could be minted."""
        for permission in ("lake:query", "lake:read_schema", "actions:read", "actions:execute", "hunts:read"):
            assert permission in VALID_SCOPES, f"{permission} can only be reached by a wildcard key"
            assert permission in ROLE_PERMISSIONS["tenant_admin"], f"{permission} is mintable but held by no admin"

    def test_a_non_wildcard_role_can_request_and_approve_an_elevation(self) -> None:
        """Otherwise the feature is reachable only by principals who do not
        need it, which is how `hunts:read` ended up held by nobody."""
        assert "elevation:request" in ROLE_PERMISSIONS["soc_analyst"]
        assert "elevation:approve" in ROLE_PERMISSIONS["soc_lead"]
        assert "elevation:approve" in ROLE_PERMISSIONS["tenant_admin"]

    def test_an_analyst_cannot_approve_their_own_class_of_request(self) -> None:
        """Separation of duties starts in the role map, before the
        per-request check that an approver is not the requester."""
        assert "elevation:approve" not in ROLE_PERMISSIONS["soc_analyst"]
        assert "elevation:approve" not in ROLE_PERMISSIONS["threat_hunter"]
        assert "elevation:approve" not in ROLE_PERMISSIONS["viewer"]

    def test_workload_credentials_are_a_platform_act_not_a_tenant_one(self) -> None:
        """Deliberate, and the reason is in the route module: a workload
        credential acts for whichever tenant it names, so minting one from
        a tenant-scoped session would confer cross-tenant authority."""
        for role, permissions in ROLE_PERMISSIONS.items():
            if "*" in permissions:
                continue
            assert "workload_identities:write" not in permissions, f"{role} can mint a deployment-wide credential"

    def test_the_addressable_attributes_are_ones_the_binding_produces(self) -> None:
        """A condition on an attribute nothing supplies is indeterminate,
        and indeterminate denies — a permanent 403 with no explanation.

        Read off the binding's source rather than by calling it, because
        constructing a request good enough to bind against would mock the
        very thing in question.
        """
        import inspect  # noqa: PLC0415

        source = inspect.getsource(CurrentUser.bind_connection_attributes)
        for attribute in ADDRESSABLE_ATTRIBUTES:
            assert f'"{attribute}"' in source, f"{attribute!r} is addressable but the binding never sets it"

    def test_the_elevation_ceiling_is_short_enough_to_mean_something(self) -> None:
        """A grant that can run for a month is standing access with paperwork."""
        assert timedelta(minutes=5) < MAX_DURATION <= timedelta(hours=24)


class TestWorkloadSecrets:
    def test_a_workload_secret_is_not_mistaken_for_an_api_key(self) -> None:
        """`aisoc_wl_` is a strict extension of `aisoc_`, so the API-key
        branch matches it too and the ordering in `get_current_user` is
        load-bearing. Pinned here so an edit that reorders the branches
        fails rather than producing a 401 that reads as a bad credential.
        """
        import inspect  # noqa: PLC0415

        from app.api.v1 import deps  # noqa: PLC0415

        secret, _prefix, _digest = wi.mint_workload_secret()
        assert secret.startswith("aisoc_"), "the overlap this test exists for has gone; simplify the branches"
        assert wi.is_workload_secret(secret)

        source = inspect.getsource(deps.get_current_user)
        assert source.index("is_workload_secret(token)") < source.index("token.startswith(_API_KEY_PREFIX)"), (
            "the API-key branch now runs before the workload branch, so every workload credential "
            "is resolved as an unknown API key and answered 401"
        )

    def test_the_secret_is_never_stored_in_the_clear(self) -> None:
        secret, prefix, digest = wi.mint_workload_secret()
        assert digest != secret
        assert digest == wi.hash_workload_secret(secret)
        assert secret.startswith(prefix)
        assert len(secret) > len(prefix) + 32, "the stored prefix leaves too little secret material"

    def test_describe_carries_no_secret_material(self) -> None:
        """This is the list response. A hash in it is a hash to grind."""
        current, superseded = _digest("current"), _digest("superseded")
        row = _row(secret_hash=current, previous_hash=superseded)

        rendered = wi.describe(row)

        assert current not in str(rendered)
        assert superseded not in str(rendered)
        assert rendered["secret_prefix"] == wi.WORKLOAD_KEY_PREFIX + "abc1234"

    def test_a_superseded_secret_with_no_window_is_refused(self) -> None:
        """ "Not set" must not be the most permissive state of a credential."""
        current, superseded = _digest("current"), _digest("superseded")
        row = _row(secret_hash=current, previous_hash=superseded, previous_expires_at=None)

        assert wi._digest_matches(row, superseded, now=datetime.now(UTC)) is False
        assert wi._digest_matches(row, current, now=datetime.now(UTC)) is True

    def test_a_superseded_secret_inside_its_window_still_works(self) -> None:
        """Rotation without downtime is the whole reason those columns exist."""
        current, superseded = _digest("current"), _digest("superseded")
        row = _row(
            secret_hash=current,
            previous_hash=superseded,
            previous_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        assert wi._digest_matches(row, superseded, now=datetime.now(UTC)) is True

    def test_a_superseded_secret_past_its_window_does_not(self) -> None:
        current, superseded = _digest("current"), _digest("superseded")
        row = _row(
            secret_hash=current,
            previous_hash=superseded,
            previous_expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )

        assert wi._digest_matches(row, superseded, now=datetime.now(UTC)) is False


class TestTheTenantIsNeverCallerChosen:
    def test_the_service_tenant_header_is_the_only_channel(self) -> None:
        """One shared credential with no tenant is a cross-tenant read, and
        a tenant read from a body is a tenant the caller picked."""
        import inspect  # noqa: PLC0415

        from app.api.v1 import deps  # noqa: PLC0415

        source = inspect.getsource(deps._resolve_workload_principal)
        assert "_resolve_tenant_for_service" in source, "the workload path no longer verifies the declared tenant"
        assert SERVICE_TENANT_HEADER == "X-AiSOC-Tenant-ID"
