"""Wave 7 (W7.1) - the dashboard / report builder."""

from __future__ import annotations

import pytest
from app.services.report_builder import (
    ReportError,
    parse_definition,
    render_report,
)


def _valid_payload():
    return {
        "name": "Exec weekly",
        "widgets": [
            {"id": "sev", "type": "bar", "title": "By severity", "source": "alerts_by_severity"},
            {"id": "mttr", "type": "metric", "title": "MTTR", "source": "mttr"},
            {"id": "note", "type": "text", "title": "Summary", "source": "static", "params": {"data": "All clear."}},
        ],
    }


def test_parse_valid_definition():
    definition = parse_definition(_valid_payload())
    assert definition.name == "Exec weekly"
    assert len(definition.widgets) == 3


def test_parse_rejects_missing_name():
    with pytest.raises(ReportError):
        parse_definition({"widgets": []})


def test_parse_rejects_unknown_type():
    with pytest.raises(ReportError):
        parse_definition({"name": "x", "widgets": [{"type": "hologram", "source": "mttr"}]})


def test_parse_rejects_unknown_source():
    with pytest.raises(ReportError):
        parse_definition({"name": "x", "widgets": [{"type": "metric", "source": "secret_db"}]})


def test_parse_rejects_duplicate_ids():
    payload = {
        "name": "x",
        "widgets": [
            {"id": "a", "type": "metric", "source": "mttr"},
            {"id": "a", "type": "metric", "source": "mttr"},
        ],
    }
    with pytest.raises(ReportError):
        parse_definition(payload)


def test_render_resolves_each_widget():
    definition = parse_definition(_valid_payload())
    resolvers = {
        "alerts_by_severity": lambda params: {"high": 3, "low": 10},
        "mttr": lambda params: 42.0,
    }
    report = render_report(definition, resolvers)
    by_id = {w["id"]: w for w in report["widgets"]}
    assert by_id["sev"]["data"] == {"high": 3, "low": 10}
    assert by_id["mttr"]["data"] == 42.0
    assert by_id["note"]["data"] == "All clear."  # static widget


def test_render_is_resilient_to_a_bad_widget():
    definition = parse_definition(_valid_payload())

    def _boom(_params):
        raise RuntimeError("resolver down")

    report = render_report(definition, {"alerts_by_severity": _boom, "mttr": lambda p: 1.0})
    by_id = {w["id"]: w for w in report["widgets"]}
    assert "error" in by_id["sev"]  # bad widget carries an error
    assert by_id["mttr"]["data"] == 1.0  # others still render


def test_render_flags_missing_resolver():
    definition = parse_definition({"name": "x", "widgets": [{"id": "f", "type": "metric", "source": "funnel"}]})
    report = render_report(definition, {})  # no resolvers
    assert "error" in report["widgets"][0]
