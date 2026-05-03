"""Smoke tests for the Strawberry GraphQL gateway.

These tests exercise the schema in isolation (no real DB required) by
using strawberry's execute_sync / execute helpers directly.  Integration
tests against a live Postgres are out of scope here; those live in e2e/.
"""
from __future__ import annotations

import pytest
import strawberry


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_schema():
    """Import the schema lazily so env vars don't need to be set at collection time."""
    import sys
    import os

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
        for field in ("alert", "alerts", "case", "cases", "detectionRules", "connectors",
                      "playbooks", "playbookRuns", "socStats"):
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
