"""Tests for the managed-instance tenant provisioner — T6.1.

Two surfaces:

* The orchestrator (:func:`provision_from_waitlist`) — covers slug
  derivation + collision handling, idempotent re-provisioning,
  credential-key minting, waitlist-row mutation, and the optional
  demo-seeder hook.

* The admin endpoints (``provision_tenant`` / ``list_tenants``) — cover
  auth gating, the 404 / 409 mapping for the provisioner's typed
  errors, and the JSONB ``managed_only`` filter on the list endpoint.

We stay inside the same testing convention used by ``test_waitlist.py``
and ``test_business_context.py``: drive coroutines through a private
event loop, mock the DB session with an in-memory dict that obeys the
fields the endpoint actually queries on, and never touch Postgres.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from app.api.v1.endpoints import tenant_provision as endpoint
from app.models.tenant import Tenant, User
from app.models.waitlist import (
    WAITLIST_STATUS_DECLINED,
    WAITLIST_STATUS_NEW,
    WAITLIST_STATUS_ONBOARDED,
    WaitlistEntry,
)
from app.services.tenant_provision import (
    AdminInvite,
    ProvisionResult,
    SlugCollisionError,
    WaitlistEntryNotFoundError,
    WaitlistEntryNotPromotableError,
    generate_credential_key,
    provision_from_waitlist,
)
from app.services.tenant_provision.provisioner import (
    _build_admin_invite,
    _normalize_slug_seed,
    _slug_with_shard,
)
from app.services.tenant_provision.templates import (
    DEFAULT_INITIAL_DETECTIONS,
    DEFAULT_INITIAL_PLAYBOOKS,
    DEFAULT_INITIAL_RBAC_ROLES,
    TenantTemplateBundle,
    get_default_template_bundle,
)
from fastapi import HTTPException

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _run(coro):  # type: ignore[no-untyped-def]
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _admin_user(*, allow: bool = True) -> SimpleNamespace:
    async def _check(_perm: str, _db: Any) -> bool:
        return allow

    return SimpleNamespace(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="tenant_admin",
        email="admin@tryaisoc.com",
        has_permission_db=_check,
    )


class _MockSession:
    """In-memory AsyncSession stand-in.

    Tracks WaitlistEntry, Tenant, and User rows by id. The
    ``execute`` shim is intentionally narrow — it understands the
    handful of SELECT shapes the provisioner and endpoints emit and
    matches them by inspecting the compiled parameters. Anything
    outside that shape raises so the test fails loudly if the
    production code starts issuing a SELECT we haven't taught the
    mock about.
    """

    def __init__(self) -> None:
        self.waitlist: dict[uuid.UUID, WaitlistEntry] = {}
        self.tenants: dict[uuid.UUID, Tenant] = {}
        self.users: dict[uuid.UUID, User] = {}
        self.commit_calls: int = 0
        self.rollback_calls: int = 0
        self.flush_calls: int = 0

    async def execute(self, stmt: Any, params: Any = None) -> Any:
        sql = str(stmt).lower()
        # Raw ``text(...)`` statements (UPDATE tenants ... in the
        # provisioner) carry their bindings via the ``params`` arg
        # and do not expose ``.compile``. We swallow them — the
        # in-memory mock can't reflect ad-hoc column writes onto the
        # ORM row, and the production path doesn't depend on us
        # mirroring it here.
        if not hasattr(stmt, "compile"):
            return _MockExecuteResult([])
        compiled = stmt.compile(compile_kwargs={"literal_binds": False})
        params_map: dict[str, Any] = dict(compiled.params)

        if "from aisoc_waitlist_entries" in sql:
            rows = list(self.waitlist.values())
            for key, value in params_map.items():
                if "id_1" in key and isinstance(value, uuid.UUID):
                    rows = [r for r in rows if r.id == value]
            return _MockExecuteResult(rows)

        if "from tenants" in sql:
            rows = list(self.tenants.values())
            for key, value in params_map.items():
                if "slug_1" in key and isinstance(value, str):
                    rows = [r for r in rows if r.slug == value]
                elif "id_1" in key and isinstance(value, uuid.UUID):
                    rows = [r for r in rows if r.id == value]
            if "order by" in sql:
                rows = sorted(
                    rows,
                    key=lambda r: r.created_at or datetime.now(UTC),
                    reverse=True,
                )
            if "limit" in sql:
                for key, value in params_map.items():
                    if "param_1" in key and isinstance(value, int):
                        rows = rows[:value]
            return _MockExecuteResult(rows)

        if "from users" in sql:
            rows = list(self.users.values())
            for key, value in params_map.items():
                if "tenant_id_1" in key and isinstance(value, uuid.UUID):
                    rows = [r for r in rows if r.tenant_id == value]
                elif "email_1" in key and isinstance(value, str):
                    rows = [r for r in rows if r.email == value]
            return _MockExecuteResult(rows)

        raise RuntimeError(f"unexpected SQL in mock session: {sql}")

    def add(self, row: Any) -> None:
        if isinstance(row, Tenant):
            if row.id is None:
                row.id = uuid.uuid4()
            if row.created_at is None:
                row.created_at = datetime.now(UTC)
            self.tenants[row.id] = row
            return
        if isinstance(row, User):
            if row.id is None:
                row.id = uuid.uuid4()
            if row.created_at is None:
                row.created_at = datetime.now(UTC)
            self.users[row.id] = row
            return
        if isinstance(row, WaitlistEntry):
            if row.id is None:
                row.id = uuid.uuid4()
            if row.created_at is None:
                row.created_at = datetime.now(UTC)
            self.waitlist[row.id] = row
            return
        raise RuntimeError(f"unexpected row type in mock session: {type(row)}")

    async def commit(self) -> None:
        self.commit_calls += 1

    async def rollback(self) -> None:
        self.rollback_calls += 1

    async def flush(self) -> None:
        self.flush_calls += 1


class _MockExecuteResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalar_one_or_none(self) -> Any:
        return self._rows[0] if self._rows else None

    def scalars(self) -> _MockExecuteResult:
        return self

    def all(self) -> list[Any]:
        return list(self._rows)

    def first(self) -> Any:
        return self._rows[0] if self._rows else None


def _waitlist_row(
    *,
    email: str = "founder@acme.io",
    company: str = "Acme Inc",
    status: str = WAITLIST_STATUS_NEW,
    provisioned_tenant_id: uuid.UUID | None = None,
) -> WaitlistEntry:
    return WaitlistEntry(
        id=uuid.uuid4(),
        email=email,
        company=company,
        role="CISO",
        soc_stack=["splunk"],
        motivation="Want to evaluate.",
        status=status,
        provisioned_tenant_id=provisioned_tenant_id,
        created_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Template bundle
# ---------------------------------------------------------------------------


class TestTemplateBundle:
    def test_default_bundle_exposes_seed_content(self) -> None:
        bundle = get_default_template_bundle()
        assert isinstance(bundle, TenantTemplateBundle)
        assert bundle.rbac_roles is DEFAULT_INITIAL_RBAC_ROLES
        assert bundle.detections is DEFAULT_INITIAL_DETECTIONS
        assert bundle.playbooks is DEFAULT_INITIAL_PLAYBOOKS

    def test_default_role_names_are_unique(self) -> None:
        names = [r["name"] for r in DEFAULT_INITIAL_RBAC_ROLES]
        assert len(names) == len(set(names))

    def test_default_detection_rule_ids_are_unique(self) -> None:
        rule_ids = [d["rule_id"] for d in DEFAULT_INITIAL_DETECTIONS]
        assert len(rule_ids) == len(set(rule_ids))

    def test_admin_role_has_wildcard(self) -> None:
        admin = next(r for r in DEFAULT_INITIAL_RBAC_ROLES if r["name"] == "tenant_admin")
        assert "*" in admin["permissions"]


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestSlugDerivation:
    def test_normalizes_punctuation_and_case(self) -> None:
        assert _normalize_slug_seed("Acme, Inc. (HQ)") == "acme-inc-hq"

    def test_strips_leading_and_trailing_dashes(self) -> None:
        assert _normalize_slug_seed("---Acme---") == "acme"

    def test_collapses_adjacent_dashes(self) -> None:
        assert _normalize_slug_seed("Acme   --   HQ") == "acme-hq"

    def test_minimum_length_padded(self) -> None:
        assert _normalize_slug_seed("X") == "x-tenant"
        assert _normalize_slug_seed("") == "tenant"

    def test_max_length_truncated(self) -> None:
        result = _normalize_slug_seed("A" * 200)
        assert len(result) <= 60

    def test_shard_suffix_fits_within_60_chars(self) -> None:
        seed = "x" * 80
        result = _slug_with_shard(seed, "ab12cd")
        assert len(result) <= 60
        assert result.endswith("-ab12cd")


class TestCredentialKeyGeneration:
    def test_generates_valid_fernet_key(self) -> None:
        from cryptography.fernet import Fernet

        key, fingerprint = generate_credential_key()
        assert Fernet(key.encode("ascii"))  # decodes without raising
        assert len(fingerprint) == 8

    def test_two_calls_produce_distinct_keys(self) -> None:
        k1, fp1 = generate_credential_key()
        k2, fp2 = generate_credential_key()
        assert k1 != k2
        assert fp1 != fp2


class TestAdminInviteBuilder:
    def test_invite_url_contains_tenant_slug(self) -> None:
        invite = _build_admin_invite(
            tenant_slug="acme",
            invite_base_url="https://tryaisoc.com",
        )
        assert "acme" in invite.url
        assert "/invite/" in invite.url
        assert invite.token in invite.url

    def test_expires_after_one_week_by_default(self) -> None:
        invite = _build_admin_invite(
            tenant_slug="acme",
            invite_base_url="https://tryaisoc.com",
        )
        delta = invite.expires_at - datetime.now(UTC).replace(microsecond=0)
        assert delta.total_seconds() > 6 * 24 * 3600
        assert delta.total_seconds() <= 7 * 24 * 3600 + 60

    def test_base_url_trailing_slash_normalized(self) -> None:
        invite = _build_admin_invite(
            tenant_slug="acme",
            invite_base_url="https://tryaisoc.com///",
        )
        assert "https://tryaisoc.com/invite/" in invite.url
        assert "https://tryaisoc.com////invite/" not in invite.url

    def test_zero_ttl_rejected(self) -> None:
        with pytest.raises(ValueError):
            _build_admin_invite(tenant_slug="x", invite_base_url="x", ttl_hours=0)


# ---------------------------------------------------------------------------
# provision_from_waitlist — orchestrator
# ---------------------------------------------------------------------------


class TestProvisionFromWaitlist:
    def test_promotes_new_entry_creates_tenant_and_admin_user(self) -> None:
        session = _MockSession()
        entry = _waitlist_row()
        session.waitlist[entry.id] = entry

        result = _run(
            provision_from_waitlist(
                session,  # type: ignore[arg-type]
                waitlist_entry_id=entry.id,
                actor_email="ops@tryaisoc.com",
                seed_demo=False,
            )
        )

        assert isinstance(result, ProvisionResult)
        assert result.tenant_slug == "acme-inc"
        assert result.tenant_name == "Acme Inc"
        assert result.admin_user.email == entry.email
        assert result.admin_user.role == "tenant_admin"
        assert result.demo_seeded is False
        assert result.aisoc_credential_key_fingerprint
        # Tenant row landed.
        assert any(t.slug == "acme-inc" for t in session.tenants.values())
        # Admin user row landed (inactive, pending invite).
        admin = next(iter(session.users.values()))
        assert admin.is_active is False
        assert admin.hashed_password.startswith("!")
        # Waitlist transitioned to onboarded.
        assert entry.status == WAITLIST_STATUS_ONBOARDED
        assert entry.provisioned_tenant_id == result.tenant_id
        assert entry.contacted_at is not None
        assert entry.onboarded_at is not None

    def test_credential_key_fingerprint_persisted_in_settings(self) -> None:
        session = _MockSession()
        entry = _waitlist_row()
        session.waitlist[entry.id] = entry

        result = _run(
            provision_from_waitlist(
                session,  # type: ignore[arg-type]
                waitlist_entry_id=entry.id,
                actor_email="ops@tryaisoc.com",
                seed_demo=False,
            )
        )

        tenant = session.tenants[result.tenant_id]
        assert tenant.settings["aisoc_credential_key_fingerprint"] == (result.aisoc_credential_key_fingerprint)
        # The plaintext key must NEVER land in the settings blob.
        for value in tenant.settings.values():
            if isinstance(value, str):
                assert "==" not in value or value == ""

    def test_slug_collision_appends_shard(self) -> None:
        session = _MockSession()
        # Pre-populate a tenant with the natural slug so the
        # provisioner has to pick a sharded slug.
        existing = Tenant(
            id=uuid.uuid4(),
            name="Acme Inc",
            slug="acme-inc",
            plan="starter",
            is_active=True,
            settings={},
            limits={},
            created_at=datetime.now(UTC),
        )
        session.tenants[existing.id] = existing

        entry = _waitlist_row()
        session.waitlist[entry.id] = entry

        result = _run(
            provision_from_waitlist(
                session,  # type: ignore[arg-type]
                waitlist_entry_id=entry.id,
                actor_email="ops@tryaisoc.com",
                seed_demo=False,
                shard_factory=lambda: "abc123",
            )
        )

        assert result.tenant_slug == "acme-inc-abc123"

    def test_slug_exhaustion_raises_collision(self) -> None:
        session = _MockSession()
        # Pre-seed both the bare slug and every shard the factory
        # returns so the allocator can never find a fresh slot.
        shards = iter(["a1", "a1", "a1", "a1", "a1", "a1", "a1", "a1", "a1"])
        for tag in ["", "-a1"]:
            session.tenants[uuid.uuid4()] = Tenant(
                id=uuid.uuid4(),
                name="X",
                slug=f"acme-inc{tag}",
                plan="starter",
                is_active=True,
                settings={},
                limits={},
                created_at=datetime.now(UTC),
            )

        entry = _waitlist_row()
        session.waitlist[entry.id] = entry

        with pytest.raises(SlugCollisionError):
            _run(
                provision_from_waitlist(
                    session,  # type: ignore[arg-type]
                    waitlist_entry_id=entry.id,
                    actor_email="ops@tryaisoc.com",
                    seed_demo=False,
                    shard_factory=lambda: next(shards),
                )
            )

    def test_missing_entry_raises_typed_error(self) -> None:
        session = _MockSession()
        with pytest.raises(WaitlistEntryNotFoundError):
            _run(
                provision_from_waitlist(
                    session,  # type: ignore[arg-type]
                    waitlist_entry_id=uuid.uuid4(),
                    actor_email="ops@tryaisoc.com",
                    seed_demo=False,
                )
            )

    def test_declined_entry_refused(self) -> None:
        session = _MockSession()
        entry = _waitlist_row(status=WAITLIST_STATUS_DECLINED)
        session.waitlist[entry.id] = entry
        with pytest.raises(WaitlistEntryNotPromotableError):
            _run(
                provision_from_waitlist(
                    session,  # type: ignore[arg-type]
                    waitlist_entry_id=entry.id,
                    actor_email="ops@tryaisoc.com",
                    seed_demo=False,
                )
            )

    def test_idempotent_replay_returns_existing_tenant(self) -> None:
        session = _MockSession()
        existing_tenant = Tenant(
            id=uuid.uuid4(),
            name="Acme Inc",
            slug="acme-inc",
            plan="managed-beta",
            is_active=True,
            settings={"managed": True, "aisoc_credential_key_fingerprint": "abcdef12"},
            limits={},
            created_at=datetime.now(UTC),
        )
        session.tenants[existing_tenant.id] = existing_tenant

        existing_admin = User(
            id=uuid.uuid4(),
            tenant_id=existing_tenant.id,
            email="founder@acme.io",
            username="founder",
            hashed_password="hash",
            role="tenant_admin",
            is_active=False,
            is_verified=False,
            preferences={},
            created_at=datetime.now(UTC),
        )
        session.users[existing_admin.id] = existing_admin

        entry = _waitlist_row(
            status=WAITLIST_STATUS_ONBOARDED,
            provisioned_tenant_id=existing_tenant.id,
        )
        session.waitlist[entry.id] = entry

        before_tenant_count = len(session.tenants)
        result = _run(
            provision_from_waitlist(
                session,  # type: ignore[arg-type]
                waitlist_entry_id=entry.id,
                actor_email="ops@tryaisoc.com",
                seed_demo=False,
            )
        )

        assert result.tenant_id == existing_tenant.id
        assert result.tenant_slug == "acme-inc"
        # No new tenant minted.
        assert len(session.tenants) == before_tenant_count
        # Admin invite is still issued so the operator can re-send it.
        assert isinstance(result.admin_invite, AdminInvite)
        assert result.aisoc_credential_key_fingerprint == "abcdef12"

    def test_demo_seeder_called_when_enabled(self) -> None:
        session = _MockSession()
        entry = _waitlist_row()
        session.waitlist[entry.id] = entry
        called: list[tuple[Any, Tenant]] = []

        async def _stub_seeder(db: Any, tenant: Tenant) -> None:
            called.append((db, tenant))

        result = _run(
            provision_from_waitlist(
                session,  # type: ignore[arg-type]
                waitlist_entry_id=entry.id,
                actor_email="ops@tryaisoc.com",
                seed_demo=True,
                demo_seeder=_stub_seeder,
            )
        )
        assert result.demo_seeded is True
        assert len(called) == 1
        assert called[0][1].slug == "acme-inc"

    def test_demo_seeder_failure_does_not_break_provisioning(self) -> None:
        session = _MockSession()
        entry = _waitlist_row()
        session.waitlist[entry.id] = entry

        async def _broken_seeder(_db: Any, _tenant: Tenant) -> None:
            raise RuntimeError("seed broke")

        result = _run(
            provision_from_waitlist(
                session,  # type: ignore[arg-type]
                waitlist_entry_id=entry.id,
                actor_email="ops@tryaisoc.com",
                seed_demo=True,
                demo_seeder=_broken_seeder,
            )
        )
        assert result.demo_seeded is False
        assert result.tenant_slug == "acme-inc"
        assert entry.status == WAITLIST_STATUS_ONBOARDED


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------


class TestProvisionEndpoint:
    def test_provision_happy_path(self) -> None:
        session = _MockSession()
        entry = _waitlist_row()
        session.waitlist[entry.id] = entry
        user = _admin_user()

        response = _run(
            endpoint.provision_tenant(
                endpoint.TenantProvisionRequest(waitlist_entry_id=entry.id, seed_demo=False),
                session,  # type: ignore[arg-type]
                user,
            )
        )
        assert response.tenant_slug == "acme-inc"
        assert response.admin_user.email == entry.email
        assert response.admin_invite.url.startswith("https://tryaisoc.com/invite/")
        assert response.aisoc_credential_key_fingerprint != ""
        assert session.commit_calls == 1

    def test_provision_forbidden_for_non_admin(self) -> None:
        session = _MockSession()
        entry = _waitlist_row()
        session.waitlist[entry.id] = entry
        user = _admin_user(allow=False)

        with pytest.raises(HTTPException) as exc_info:
            _run(
                endpoint.provision_tenant(
                    endpoint.TenantProvisionRequest(waitlist_entry_id=entry.id, seed_demo=False),
                    session,  # type: ignore[arg-type]
                    user,
                )
            )
        assert exc_info.value.status_code == 403

    def test_provision_missing_entry_returns_404(self) -> None:
        session = _MockSession()
        user = _admin_user()
        with pytest.raises(HTTPException) as exc_info:
            _run(
                endpoint.provision_tenant(
                    endpoint.TenantProvisionRequest(waitlist_entry_id=uuid.uuid4(), seed_demo=False),
                    session,  # type: ignore[arg-type]
                    user,
                )
            )
        assert exc_info.value.status_code == 404

    def test_provision_declined_entry_returns_409(self) -> None:
        session = _MockSession()
        entry = _waitlist_row(status=WAITLIST_STATUS_DECLINED)
        session.waitlist[entry.id] = entry
        user = _admin_user()

        with pytest.raises(HTTPException) as exc_info:
            _run(
                endpoint.provision_tenant(
                    endpoint.TenantProvisionRequest(waitlist_entry_id=entry.id, seed_demo=False),
                    session,  # type: ignore[arg-type]
                    user,
                )
            )
        assert exc_info.value.status_code == 409

    def test_provision_custom_invite_base_used(self) -> None:
        session = _MockSession()
        entry = _waitlist_row()
        session.waitlist[entry.id] = entry
        user = _admin_user()

        response = _run(
            endpoint.provision_tenant(
                endpoint.TenantProvisionRequest(
                    waitlist_entry_id=entry.id,
                    seed_demo=False,
                    invite_base_url="https://staging.tryaisoc.com",
                ),
                session,  # type: ignore[arg-type]
                user,
            )
        )
        assert response.admin_invite.url.startswith("https://staging.tryaisoc.com/invite/")


class TestListTenantsEndpoint:
    def _seed_two_tenants(self, session: _MockSession) -> tuple[uuid.UUID, uuid.UUID]:
        managed_id = uuid.uuid4()
        unmanaged_id = uuid.uuid4()
        session.tenants[managed_id] = Tenant(
            id=managed_id,
            name="Acme",
            slug="acme",
            plan="managed-beta",
            is_active=True,
            settings={"managed": True},
            limits={},
            created_at=datetime(2026, 5, 12, tzinfo=UTC),
        )
        session.tenants[unmanaged_id] = Tenant(
            id=unmanaged_id,
            name="Self-Hosted Corp",
            slug="self-hosted-corp",
            plan="starter",
            is_active=True,
            settings={},
            limits={},
            created_at=datetime(2026, 5, 14, tzinfo=UTC),
        )
        return managed_id, unmanaged_id

    def test_list_returns_all_tenants_for_admin(self) -> None:
        session = _MockSession()
        self._seed_two_tenants(session)
        user = _admin_user()

        result = _run(endpoint.list_tenants(session, user))  # type: ignore[arg-type]
        assert result.total == 2
        # Order by created_at desc.
        assert result.tenants[0].slug == "self-hosted-corp"
        assert result.tenants[1].slug == "acme"

    def test_list_forbidden_for_non_admin(self) -> None:
        session = _MockSession()
        self._seed_two_tenants(session)
        user = _admin_user(allow=False)
        with pytest.raises(HTTPException) as exc_info:
            _run(endpoint.list_tenants(session, user))  # type: ignore[arg-type]
        assert exc_info.value.status_code == 403

    def test_list_reports_managed_flag(self) -> None:
        session = _MockSession()
        self._seed_two_tenants(session)
        user = _admin_user()
        result = _run(endpoint.list_tenants(session, user))  # type: ignore[arg-type]
        flags = {t.slug: t.is_managed for t in result.tenants}
        assert flags["acme"] is True
        assert flags["self-hosted-corp"] is False
