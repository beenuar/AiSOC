"""Tests for WS-H3 — audit export builders (CSV + HTML).

The builders in ``app.services.audit_export`` are pure functions: they take
an in-memory list of ``AuditRow`` plus an ``ExportContext`` and return a
``str``. That makes them easy to lock down against the wire-format expected
by SIEM ingest connectors and compliance binders.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

import pytest
from app.services.audit_export import (
    AuditRow,
    ExportContext,
    render_audit_csv,
    render_audit_html,
)

GENERATED_AT = datetime(2026, 5, 9, 16, 30, 0, tzinfo=UTC)


def _row(**overrides) -> AuditRow:
    """Builder with sensible defaults for an audit row."""
    base = {
        "id": "11111111-1111-1111-1111-111111111111",
        "tenant_id": "22222222-2222-2222-2222-222222222222",
        "actor_id": "33333333-3333-3333-3333-333333333333",
        "actor_email": "analyst@example.com",
        "actor_ip": "10.0.0.1",
        "action": "cases:update",
        "resource": "case",
        "resource_id": "case-42",
        "changes": {"status": ["open", "investigating"]},
        "created_at": datetime(2026, 5, 9, 12, 0, 0, tzinfo=UTC),
    }
    base.update(overrides)
    return AuditRow(**base)


def _context(rows: list[AuditRow], **overrides) -> ExportContext:
    base = {
        "tenant_id": "22222222-2222-2222-2222-222222222222",
        "generated_at": GENERATED_AT,
        "generated_by_email": "ops@example.com",
        "filters": {
            "action": "cases:",
            "resource": None,
            "actor_id": None,
            "search": None,
        },
        "total_rows": len(rows),
    }
    base.update(overrides)
    return ExportContext(**base)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


class TestCsvRenderer:
    def test_header_row_order_is_stable(self):
        """The column contract is part of the SIEM ingest interface — pin it."""
        out = render_audit_csv([])
        reader = csv.reader(io.StringIO(out))
        header = next(reader)
        assert header == [
            "id",
            "tenant_id",
            "created_at",
            "actor_id",
            "actor_email",
            "actor_ip",
            "action",
            "resource",
            "resource_id",
            "changes",
        ]

    def test_empty_rows_renders_only_header(self):
        out = render_audit_csv([])
        assert out.endswith("\r\n")
        assert out.count("\r\n") == 1

    def test_single_row_round_trips(self):
        row = _row()
        out = render_audit_csv([row])
        reader = csv.reader(io.StringIO(out))
        next(reader)  # skip header
        parsed = next(reader)
        assert parsed[0] == row.id
        assert parsed[1] == row.tenant_id
        assert parsed[2] == "2026-05-09T12:00:00Z"
        assert parsed[3] == row.actor_id
        assert parsed[4] == row.actor_email
        assert parsed[5] == row.actor_ip
        assert parsed[6] == row.action
        assert parsed[7] == row.resource
        assert parsed[8] == row.resource_id
        # changes should be JSON, not Python repr
        assert json.loads(parsed[9]) == {"status": ["open", "investigating"]}

    def test_changes_is_sorted_for_determinism(self):
        """Same payload should serialise identically across runs."""
        row_a = _row(changes={"b": 1, "a": 2})
        row_b = _row(changes={"a": 2, "b": 1})
        assert render_audit_csv([row_a]) == render_audit_csv([row_b])

    def test_null_changes_serialises_as_empty_string(self):
        out = render_audit_csv([_row(changes=None)])
        reader = csv.reader(io.StringIO(out))
        next(reader)
        assert next(reader)[9] == ""

    def test_null_optional_fields_become_empty_strings(self):
        row = _row(actor_id=None, actor_email=None, actor_ip=None, resource=None, resource_id=None)
        out = render_audit_csv([row])
        reader = csv.reader(io.StringIO(out))
        next(reader)
        parsed = next(reader)
        assert parsed[3] == ""  # actor_id
        assert parsed[4] == ""  # actor_email
        assert parsed[5] == ""  # actor_ip
        assert parsed[7] == ""  # resource
        assert parsed[8] == ""  # resource_id

    def test_quote_all_protects_embedded_separators(self):
        """Commas, quotes, and newlines in JSON must not break field boundaries."""
        nasty = {
            "note": 'has "quotes", commas, and \nnewlines',
            "list": [1, 2, 3],
        }
        row = _row(changes=nasty)
        out = render_audit_csv([row])
        # Re-parse with a strict reader; if QUOTE_ALL is missing this raises.
        reader = csv.reader(io.StringIO(out))
        next(reader)  # header
        parsed = next(reader)
        # round-trip the JSON cell back to a dict — proves the embedded
        # quotes/commas/newlines survived the CSV escaping pass.
        assert json.loads(parsed[9]) == nasty

    def test_uses_crlf_line_endings(self):
        """RFC 4180 mandates CRLF — Windows analysts open these files daily."""
        out = render_audit_csv([_row()])
        # exactly two CRLFs: header + single data row
        assert out.count("\r\n") == 2
        # and no bare LFs that aren't part of the CRLF pair
        assert out.replace("\r\n", "").count("\n") == 0

    def test_preserves_row_order(self):
        rows = [
            _row(id="11111111-aaaa-aaaa-aaaa-aaaaaaaaaaaa", action="alerts:create"),
            _row(id="22222222-bbbb-bbbb-bbbb-bbbbbbbbbbbb", action="cases:update"),
            _row(id="33333333-cccc-cccc-cccc-cccccccccccc", action="auth:login"),
        ]
        out = render_audit_csv(rows)
        reader = csv.reader(io.StringIO(out))
        next(reader)
        ids = [next(reader)[0] for _ in rows]
        assert ids == [r.id for r in rows]


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


class TestHtmlRenderer:
    def test_renders_a_full_html_document(self):
        out = render_audit_html([], _context([]))
        assert out.startswith("<!DOCTYPE html>")
        assert out.rstrip().endswith("</html>")
        assert "<title>AiSOC — Audit Export</title>" in out

    def test_header_includes_tenant_and_generator_metadata(self):
        ctx = _context([])
        out = render_audit_html([], ctx)
        assert ctx.tenant_id in out
        assert "ops@example.com" in out
        assert "2026-05-09 16:30:00 UTC" in out

    def test_falls_back_to_system_when_no_actor_email(self):
        out = render_audit_html([], _context([], generated_by_email=None))
        assert "by system" in out

    def test_empty_rows_shows_friendly_empty_message(self):
        out = render_audit_html([], _context([]))
        assert "No audit events match the selected filters." in out

    def test_filters_render_as_chips_when_present(self):
        out = render_audit_html([], _context([]))
        # default _context has action="cases:" set
        assert "action" in out
        assert "cases:" in out

    def test_no_filters_shows_full_audit_trail_message(self):
        ctx = _context(
            [],
            filters={"action": None, "resource": None, "actor_id": None, "search": None},
        )
        out = render_audit_html([], ctx)
        assert "No filters applied" in out

    def test_kpi_total_rows_matches_context(self):
        rows = [_row(), _row(id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")]
        ctx = _context(rows)
        out = render_audit_html(rows, ctx)
        # KPI block prints the total — make sure the integer surfaces.
        assert ">2<" in out

    def test_row_renders_action_chip_and_actor_block(self):
        row = _row()
        out = render_audit_html([row], _context([row]))
        assert "cases:update" in out
        assert "analyst@example.com" in out
        assert "10.0.0.1" in out
        assert "case" in out
        assert "case-42" in out

    def test_changes_payload_is_pretty_printed_json(self):
        row = _row(changes={"foo": "bar", "n": 1})
        out = render_audit_html([row], _context([row]))
        # The renderer HTML-escapes the JSON before injecting it, so quotes
        # show up as &quot; — that's correct, the table cell still renders
        # readable JSON to the eye but is XSS-safe.
        assert "&quot;foo&quot;: &quot;bar&quot;" in out
        assert "&quot;n&quot;: 1" in out
        # Pretty-printed with newlines preserved inside the <pre> block.
        assert "{\n  &quot;foo&quot;" in out

    def test_html_escapes_dangerous_field_values(self):
        """Audit rows hold tenant data — defensive escaping or it's an XSS hole."""
        evil = "<script>alert(1)</script>"
        row = _row(actor_email=evil, action=evil, resource=evil, resource_id=evil)
        out = render_audit_html([row], _context([row]))
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out

    def test_html_escapes_changes_payload(self):
        row = _row(changes={"payload": "<img src=x onerror=alert(1)>"})
        out = render_audit_html([row], _context([row]))
        assert "<img src=x onerror=alert(1)>" not in out
        assert "&lt;img src=x onerror=alert(1)&gt;" in out

    def test_action_chip_colour_is_deterministic_per_family(self):
        """Same action prefix must always render the same colour."""
        row_a = _row(action="auth:login")
        row_b = _row(action="auth:logout")
        out_a = render_audit_html([row_a], _context([row_a]))
        out_b = render_audit_html([row_b], _context([row_b]))
        # extract the auth chip colour from both renders and compare
        marker = "background:#1d4ed8"  # auth family
        assert marker in out_a
        assert marker in out_b

    def test_handles_non_serialisable_changes_without_crashing(self):
        """Defensive: if a payload sneaks through with a non-JSON value,
        we still want a renderable page rather than a 500."""

        class NotJsonable:
            pass

        # the dataclass is typed as ``dict | None`` but at runtime we may
        # have to cope with anything Postgres put in JSONB.
        row = _row(changes={"obj": NotJsonable()})
        out = render_audit_html([row], _context([row]))
        assert out.startswith("<!DOCTYPE html>")
        assert "NotJsonable" in out  # repr fallback fired


# ---------------------------------------------------------------------------
# Stability
# ---------------------------------------------------------------------------


def test_csv_output_is_deterministic():
    """Same input -> same bytes. Important for diffing exports during audits."""
    rows = [_row(), _row(id="44444444-4444-4444-4444-444444444444", action="alerts:ack")]
    assert render_audit_csv(rows) == render_audit_csv(rows)


def test_html_output_is_deterministic():
    rows = [_row()]
    ctx = _context(rows)
    assert render_audit_html(rows, ctx) == render_audit_html(rows, ctx)


@pytest.mark.parametrize(
    "fmt_func",
    [render_audit_csv, lambda rows: render_audit_html(rows, _context(rows))],
)
def test_handles_empty_input(fmt_func):
    """Both renderers must produce a valid artefact even with zero rows."""
    out = fmt_func([])
    assert isinstance(out, str)
    assert len(out) > 0
