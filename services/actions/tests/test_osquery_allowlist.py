"""Tests for the osquery SQL allowlist module."""

from __future__ import annotations

import pytest
from app.clients.osquery_allowlist import (
    AllowlistError,
    list_templates,
    render_query,
    validate_raw_sql,
)


class TestListTemplates:
    def test_returns_sorted_list(self) -> None:
        templates = list_templates()
        assert templates == sorted(templates)

    def test_contains_expected_ids(self) -> None:
        expected = {
            "running_processes",
            "active_connections",
            "logged_in_users",
            "recent_files",
            "process_tree",
            "package_inventory",
        }
        assert expected.issubset(set(list_templates()))


class TestRenderQuery:
    def test_running_processes_defaults(self) -> None:
        sql = render_query("running_processes")
        assert "FROM processes" in sql
        assert "200" in sql  # default limit

    def test_running_processes_custom_limit(self) -> None:
        sql = render_query("running_processes", limit=50)
        assert "50" in sql

    def test_active_connections_defaults(self) -> None:
        sql = render_query("active_connections")
        assert "FROM process_open_sockets" in sql

    def test_logged_in_users_defaults(self) -> None:
        sql = render_query("logged_in_users")
        assert "FROM logged_in_users" in sql

    def test_recent_files_custom_directory(self) -> None:
        sql = render_query("recent_files", directory="/var/log")
        assert "/var/log" in sql

    def test_process_tree_custom_pid(self) -> None:
        sql = render_query("process_tree", pid=1234)
        assert "1234" in sql

    def test_package_inventory_defaults(self) -> None:
        sql = render_query("package_inventory")
        assert "deb_packages" in sql

    def test_unknown_template_raises(self) -> None:
        with pytest.raises(AllowlistError, match="Unknown template"):
            render_query("not_a_real_template")

    def test_unknown_param_raises(self) -> None:
        with pytest.raises(AllowlistError, match="does not accept parameter"):
            render_query("running_processes", bad_param="evil")

    def test_sql_injection_via_directory_raises(self) -> None:
        with pytest.raises(AllowlistError, match="disallowed characters"):
            render_query("recent_files", directory="/tmp'; DROP TABLE processes; --")

    def test_sql_comment_in_param_raises(self) -> None:
        with pytest.raises(AllowlistError, match="disallowed characters"):
            render_query("recent_files", directory="/tmp -- comment")

    def test_returns_string(self) -> None:
        result = render_query("running_processes")
        assert isinstance(result, str)
        assert len(result) > 10


class TestValidateRawSql:
    def test_valid_default_render_passes(self) -> None:
        for tid in list_templates():
            sql = render_query(tid)
            validate_raw_sql(sql)  # must not raise

    def test_raw_sql_rejected(self) -> None:
        with pytest.raises(AllowlistError, match="does not match any approved template"):
            validate_raw_sql("SELECT * FROM users;")

    def test_modified_template_rejected(self) -> None:
        sql = render_query("running_processes")
        tampered = sql + " UNION SELECT 1,2,3;"
        with pytest.raises(AllowlistError):
            validate_raw_sql(tampered)
