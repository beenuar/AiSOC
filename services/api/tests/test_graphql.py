"""Smoke tests for the Strawberry GraphQL gateway.

These tests exercise the schema in isolation (no real DB required) by
using strawberry's execute_sync / execute helpers directly.  Integration
tests against a live Postgres are out of scope here; those live in e2e/.
"""

from __future__ import annotations

import strawberry

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_schema():
    """Import the schema lazily so env vars don't need to be set at collection time."""
    import os
    import sys

    sys.path.insert(0, ".")
    os.environ.setdefault("ENVIRONMENT", "development")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-bytes!!")
    os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")

    from app.graphql.schema import schema  # noqa: PLC0415

    return schema


# ─── SDL tests ────────────────────────────────────────────────────────────────


class TestGraphQLSchema:
    """Verify the SDL contains all expected types and query fields."""

    def setup_method(self):
        self.schema = _make_schema()
        self.sdl = strawberry.Schema.as_str(self.schema)

    def test_alert_type_in_schema(self):
        assert "AlertType" in self.sdl

    def test_case_type_in_schema(self):
        assert "CaseType" in self.sdl

    def test_detection_rule_type_in_schema(self):
        assert "DetectionRuleType" in self.sdl

    def test_connector_type_in_schema(self):
        assert "ConnectorType" in self.sdl

    def test_playbook_type_in_schema(self):
        assert "PlaybookType" in self.sdl

    def test_soc_stats_type_in_schema(self):
        assert "SocStatsType" in self.sdl

    def test_page_types_in_schema(self):
        for page_type in ("AlertPage", "CasePage", "DetectionRulePage", "ConnectorPage"):
            assert page_type in self.sdl, f"{page_type} missing from SDL"

    def test_query_fields_present(self):
        for field in ("alert", "alerts", "case", "cases", "detectionRules", "connectors", "playbooks", "playbookRuns", "socStats"):
            assert field in self.sdl, f"Query field '{field}' missing from SDL"

    def test_introspection_query(self):
        """GraphQL introspection must succeed without errors."""
        result = self.schema.execute_sync("{ __typename }")
        assert result.errors is None
        assert result.data == {"__typename": "Query"}

    def test_alert_field_args(self):
        """The 'alerts' field must accept pagination and filter args."""
        assert "pageSize" in self.sdl or "page_size" in self.sdl or "pageSize: Int" in self.sdl

    def test_soc_stats_fields(self):
        assert "totalAlerts" in self.sdl or "total_alerts" in self.sdl
        assert "openCases" in self.sdl or "open_cases" in self.sdl


# ─── Tenant isolation tests ───────────────────────────────────────────────────


class _FakeUser:
    def __init__(self, tenant_id):
        self.tenant_id = tenant_id


class _FakeInfo:
    def __init__(self, user):
        self.context = {"user": user, "db": None}


class TestGraphQLTenantIsolation:
    """Resolver helpers must scope every query to the caller's tenant.

    These tests exercise the ``_scope`` and ``_tenant_id`` helpers directly
    so we get fast, deterministic assertions without booting Postgres.
    A cross-tenant fetch must produce a ``WHERE tenant_id = <caller>`` clause
    that no row from another tenant can satisfy.
    """

    def setup_method(self):
        _make_schema()  # ensure env defaults are in place

    @staticmethod
    def _uuid_in_sql(tid, compiled: str) -> bool:
        """SQLAlchemy may compile UUIDs as 32-char hex (no dashes) or canonical 36-char form."""
        s = str(tid)
        return s in compiled or s.replace("-", "") in compiled

    def test_scope_adds_tenant_filter(self):
        import uuid as _uuid

        from app.graphql.query import _scope
        from app.models.alert import Alert
        from sqlalchemy import select

        tid = _uuid.uuid4()
        info = _FakeInfo(_FakeUser(tid))
        stmt = _scope(select(Alert), info, Alert)
        compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert self._uuid_in_sql(tid, compiled)
        assert "tenant_id" in compiled.lower()

    def test_scope_blocks_when_no_user(self):
        from app.graphql.query import _scope
        from app.models.alert import Alert
        from sqlalchemy import select

        info = _FakeInfo(user=None)
        # _scope should still emit a tenant_id filter (with the zero UUID)
        # so the query returns no rows rather than leaking.
        stmt = _scope(select(Alert), info, Alert)
        compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "tenant_id" in compiled.lower()
        assert "00000000-0000-0000-0000-000000000000" in compiled or "00000000000000000000000000000000" in compiled

    def test_scope_isolates_tenants(self):
        """A query scoped to tenant A must not match rows from tenant B."""
        import uuid as _uuid

        from app.graphql.query import _scope
        from app.models.alert import Alert
        from sqlalchemy import select

        tenant_a = _uuid.uuid4()
        tenant_b = _uuid.uuid4()

        info_a = _FakeInfo(_FakeUser(tenant_a))
        stmt_a = _scope(select(Alert), info_a, Alert)
        compiled_a = str(stmt_a.compile(compile_kwargs={"literal_binds": True}))

        assert self._uuid_in_sql(tenant_a, compiled_a)
        assert not self._uuid_in_sql(tenant_b, compiled_a)


class TestGraphiQLDisabledOutsideDev:
    """GraphiQL UI must be off in non-development environments."""

    def test_graphiql_disabled_in_production(self, monkeypatch):
        # Force a fresh import path with ENVIRONMENT=production
        import importlib
        import sys

        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-at-least-32-bytes!!")
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")

        # Drop cached config + schema so they pick up the new env.
        # Note: pop the package too — `app.graphql/__init__.py` re-exports the
        # `schema` *instance* under the name ``schema``, which would shadow the
        # submodule on subsequent imports.
        for mod in (
            "app.core.config",
            "app.graphql",
            "app.graphql.schema",
        ):
            sys.modules.pop(mod, None)

        # Import the *module* directly (not via re-export from the package)
        schema_mod = importlib.import_module("app.graphql.schema")
        importlib.reload(schema_mod)
        assert schema_mod._graphql_ide is None

    def test_graphiql_enabled_in_development(self, monkeypatch):
        import importlib
        import sys

        monkeypatch.setenv("ENVIRONMENT", "development")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-at-least-32-bytes!!")
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")

        for mod in (
            "app.core.config",
            "app.graphql",
            "app.graphql.schema",
        ):
            sys.modules.pop(mod, None)

        schema_mod = importlib.import_module("app.graphql.schema")
        importlib.reload(schema_mod)
        assert schema_mod._graphql_ide == "graphiql"
