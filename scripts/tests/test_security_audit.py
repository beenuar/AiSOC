"""Tests for scripts/security_audit.py — ignore validation, classifiers, parsers."""

from __future__ import annotations

import datetime as dt
import textwrap
from pathlib import Path

import pytest

# Import the module under test
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from security_audit import (
    Finding,
    Ignore,
    Report,
    classify_govulncheck,
    classify_pip_audit,
    classify_pnpm_audit,
    exit_code_for,
    is_ignored,
    load_ignores,
    parse_govulncheck_json,
    parse_pip_audit_json,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

TODAY = dt.date(2026, 6, 1)
VALID_EXPIRY = "2026-07-01"  # 30 days out — within 90-day window


def _write_ignores(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "ignores.txt"
    p.write_text(textwrap.dedent(content))
    return p


# ─── load_ignores tests ──────────────────────────────────────────────────────


class TestLoadIgnores:
    def test_empty_file(self, tmp_path: Path):
        p = _write_ignores(tmp_path, "")
        assert load_ignores(p, today=TODAY) == []

    def test_comments_and_blanks_skipped(self, tmp_path: Path):
        p = _write_ignores(tmp_path, "# comment\n\n# another\n")
        assert load_ignores(p, today=TODAY) == []

    def test_valid_cve(self, tmp_path: Path):
        p = _write_ignores(tmp_path, f"python|CVE-2026-12345|reason here|{VALID_EXPIRY}\n")
        result = load_ignores(p, today=TODAY)
        assert len(result) == 1
        assert result[0].tool == "python"
        assert result[0].vuln_id == "CVE-2026-12345"
        assert result[0].reason == "reason here"
        assert result[0].expires == dt.date(2026, 7, 1)

    def test_valid_ghsa(self, tmp_path: Path):
        p = _write_ignores(tmp_path, f"pnpm|GHSA-abcd-efgh-ijkl|reason|{VALID_EXPIRY}\n")
        result = load_ignores(p, today=TODAY)
        assert len(result) == 1
        assert result[0].vuln_id == "GHSA-abcd-efgh-ijkl"

    def test_valid_go_id(self, tmp_path: Path):
        p = _write_ignores(tmp_path, f"go|GO-2026-1234|reason|{VALID_EXPIRY}\n")
        result = load_ignores(p, today=TODAY)
        assert len(result) == 1
        assert result[0].vuln_id == "GO-2026-1234"

    def test_valid_pysec(self, tmp_path: Path):
        p = _write_ignores(tmp_path, f"python|PYSEC-2026-42|reason|{VALID_EXPIRY}\n")
        result = load_ignores(p, today=TODAY)
        assert len(result) == 1
        assert result[0].vuln_id == "PYSEC-2026-42"

    def test_wrong_field_count(self, tmp_path: Path):
        p = _write_ignores(tmp_path, "python|CVE-2026-12345|reason\n")
        with pytest.raises(ValueError, match="expected 4 pipe-delimited fields"):
            load_ignores(p, today=TODAY)

    def test_invalid_tool(self, tmp_path: Path):
        p = _write_ignores(tmp_path, f"npm|CVE-2026-12345|reason|{VALID_EXPIRY}\n")
        with pytest.raises(ValueError, match="invalid tool 'npm'"):
            load_ignores(p, today=TODAY)

    def test_invalid_vuln_id(self, tmp_path: Path):
        p = _write_ignores(tmp_path, f"python|BADID-123|reason|{VALID_EXPIRY}\n")
        with pytest.raises(ValueError, match="invalid ID 'BADID-123'"):
            load_ignores(p, today=TODAY)

    def test_empty_reason(self, tmp_path: Path):
        p = _write_ignores(tmp_path, f"python|CVE-2026-12345||{VALID_EXPIRY}\n")
        with pytest.raises(ValueError, match="reason must not be empty"):
            load_ignores(p, today=TODAY)

    def test_invalid_date(self, tmp_path: Path):
        p = _write_ignores(tmp_path, "python|CVE-2026-12345|reason|not-a-date\n")
        with pytest.raises(ValueError, match="invalid date"):
            load_ignores(p, today=TODAY)

    def test_expired(self, tmp_path: Path):
        p = _write_ignores(tmp_path, "python|CVE-2026-12345|reason|2026-05-01\n")
        with pytest.raises(ValueError, match="expired on 2026-05-01"):
            load_ignores(p, today=TODAY)

    def test_exceeds_90_days(self, tmp_path: Path):
        far_future = "2026-12-01"
        p = _write_ignores(tmp_path, f"python|CVE-2026-12345|reason|{far_future}\n")
        with pytest.raises(ValueError, match="exceeds 90-day maximum"):
            load_ignores(p, today=TODAY)

    def test_missing_file_returns_empty(self, tmp_path: Path):
        p = tmp_path / "does_not_exist.txt"
        assert load_ignores(p, today=TODAY) == []

    def test_multiple_valid_entries(self, tmp_path: Path):
        content = (
            f"pnpm|CVE-2026-11111|reason one|{VALID_EXPIRY}\n"
            f"python|CVE-2026-22222|reason two|{VALID_EXPIRY}\n"
            f"go|GO-2026-3333|reason three|{VALID_EXPIRY}\n"
        )
        p = _write_ignores(tmp_path, content)
        result = load_ignores(p, today=TODAY)
        assert len(result) == 3


# ─── is_ignored tests ────────────────────────────────────────────────────────


class TestIsIgnored:
    def test_match(self):
        ig = Ignore(tool="pnpm", vuln_id="CVE-2026-111", reason="r", expires=TODAY)
        assert is_ignored("pnpm", ["CVE-2026-111"], [ig]) == ig

    def test_no_match_different_tool(self):
        ig = Ignore(tool="python", vuln_id="CVE-2026-111", reason="r", expires=TODAY)
        assert is_ignored("pnpm", ["CVE-2026-111"], [ig]) is None

    def test_no_match_different_id(self):
        ig = Ignore(tool="pnpm", vuln_id="CVE-2026-111", reason="r", expires=TODAY)
        assert is_ignored("pnpm", ["CVE-2026-999"], [ig]) is None

    def test_match_among_multiple_ids(self):
        ig = Ignore(tool="go", vuln_id="GO-2026-0001", reason="r", expires=TODAY)
        assert is_ignored("go", ["CVE-2026-111", "GO-2026-0001"], [ig]) == ig


# ─── classify_pnpm_audit tests ───────────────────────────────────────────────


class TestClassifyPnpmAudit:
    def test_empty_advisories(self):
        report = classify_pnpm_audit({"advisories": {}}, [])
        assert report.findings == []
        assert report.ignored == []

    def test_single_high(self):
        data = {
            "advisories": {
                "100": {
                    "id": 100,
                    "severity": "high",
                    "module_name": "lodash",
                    "title": "Prototype Pollution",
                    "cves": ["CVE-2026-00100"],
                    "github_advisory_id": "GHSA-aaaa-bbbb-cccc",
                }
            }
        }
        report = classify_pnpm_audit(data, [])
        assert len(report.findings) == 1
        f = report.findings[0]
        assert f.severity == "high"
        assert f.package == "lodash"
        assert f.vuln_id == "GHSA-aaaa-bbbb-cccc"

    def test_moderate_finding(self):
        data = {
            "advisories": {
                "200": {
                    "id": 200,
                    "severity": "moderate",
                    "module_name": "express",
                    "title": "Open redirect",
                    "cves": ["CVE-2026-00200"],
                    "github_advisory_id": "",
                }
            }
        }
        report = classify_pnpm_audit(data, [])
        assert len(report.moderate) == 1
        assert report.moderate[0].severity == "moderate"

    def test_ignored_advisory(self):
        data = {
            "advisories": {
                "300": {
                    "id": 300,
                    "severity": "critical",
                    "module_name": "foo",
                    "title": "RCE",
                    "cves": ["CVE-2026-00300"],
                    "github_advisory_id": "GHSA-xxxx-yyyy-zzzz",
                }
            }
        }
        ig = Ignore(tool="pnpm", vuln_id="CVE-2026-00300", reason="r", expires=TODAY)
        report = classify_pnpm_audit(data, [ig])
        assert len(report.findings) == 0
        assert len(report.ignored) == 1

    def test_unknown_severity_normalized(self):
        data = {
            "advisories": {
                "400": {
                    "id": 400,
                    "severity": "banana",
                    "module_name": "bad",
                    "title": "weird",
                    "cves": [],
                    "github_advisory_id": "",
                }
            }
        }
        report = classify_pnpm_audit(data, [])
        assert report.findings[0].severity == "unknown"


# ─── parse_pip_audit_json tests ──────────────────────────────────────────────


class TestParsePipAuditJson:
    def test_empty_string(self):
        assert parse_pip_audit_json("") == []

    def test_list_format(self):
        raw = '[{"name": "pkg", "version": "1.0", "vulns": []}]'
        result = parse_pip_audit_json(raw)
        assert len(result) == 1
        assert result[0]["name"] == "pkg"

    def test_dict_format(self):
        raw = '{"dependencies": [{"name": "pkg", "version": "1.0", "vulns": []}]}'
        result = parse_pip_audit_json(raw)
        assert len(result) == 1

    def test_dict_without_dependencies_key(self):
        raw = '{"something_else": true}'
        result = parse_pip_audit_json(raw)
        assert result == []


# ─── classify_pip_audit tests ────────────────────────────────────────────────


class TestClassifyPipAudit:
    def test_no_vulns(self):
        deps = [{"name": "requests", "version": "2.31.0", "vulns": []}]
        report = classify_pip_audit("services/api", deps, [])
        assert report.findings == []

    def test_single_vuln(self):
        deps = [
            {
                "name": "requests",
                "version": "2.25.0",
                "vulns": [
                    {
                        "id": "PYSEC-2026-10",
                        "aliases": ["CVE-2026-99999"],
                        "description": "SSRF in requests",
                    }
                ],
            }
        ]
        report = classify_pip_audit("services/api", deps, [])
        assert len(report.findings) == 1
        f = report.findings[0]
        assert f.severity == "high"
        assert f.vuln_id == "PYSEC-2026-10"
        assert f.package == "requests==2.25.0"
        assert f.location == "services/api"

    def test_vuln_id_used_when_aliases_empty(self):
        deps = [
            {
                "name": "requests",
                "version": "2.25.0",
                "vulns": [
                    {
                        "id": "PYSEC-2026-10",
                        "aliases": [],
                        "description": "Regression: vuln_id must not fall through",
                    }
                ],
            }
        ]
        report = classify_pip_audit("services/api", deps, [])
        assert report.findings[0].vuln_id == "PYSEC-2026-10"

    def test_ignored_vuln(self):
        deps = [
            {
                "name": "requests",
                "version": "2.25.0",
                "vulns": [
                    {
                        "id": "PYSEC-2026-10",
                        "aliases": ["CVE-2026-99999"],
                        "description": "SSRF",
                    }
                ],
            }
        ]
        ig = Ignore(tool="python", vuln_id="CVE-2026-99999", reason="r", expires=TODAY)
        report = classify_pip_audit("services/api", deps, [ig])
        assert len(report.findings) == 0
        assert len(report.ignored) == 1


# ─── parse_govulncheck_json tests ────────────────────────────────────────────


class TestParseGovulncheckJson:
    def test_empty(self):
        assert parse_govulncheck_json("") == []

    def test_osv_with_finding(self):
        lines = [
            '{"osv": {"id": "GO-2026-0001", "aliases": ["CVE-2026-11111"], "summary": "Bad thing"}}',
            '{"finding": {"osv": "GO-2026-0001", "trace": []}}',
        ]
        result = parse_govulncheck_json("\n".join(lines))
        assert len(result) == 1
        assert result[0]["id"] == "GO-2026-0001"
        assert result[0]["aliases"] == ["CVE-2026-11111"]

    def test_osv_without_finding_excluded(self):
        lines = [
            '{"osv": {"id": "GO-2026-0002", "aliases": [], "summary": "Not called"}}',
        ]
        result = parse_govulncheck_json("\n".join(lines))
        assert result == []

    def test_malformed_lines_skipped(self):
        lines = [
            "not json",
            '{"osv": {"id": "GO-2026-0003", "aliases": [], "summary": "yes"}}',
            '{"finding": {"osv": "GO-2026-0003"}}',
        ]
        result = parse_govulncheck_json("\n".join(lines))
        assert len(result) == 1


# ─── classify_govulncheck tests ──────────────────────────────────────────────


class TestClassifyGovulncheck:
    def test_no_vulns(self):
        report = classify_govulncheck("services/ingest", [], [])
        assert report.findings == []

    def test_single_vuln(self):
        vulns = [{"id": "GO-2026-0001", "aliases": ["CVE-2026-55555"], "summary": "Bad"}]
        report = classify_govulncheck("services/ingest", vulns, [])
        assert len(report.findings) == 1
        f = report.findings[0]
        assert f.severity == "high"
        assert f.vuln_id == "GO-2026-0001"

    def test_ignored_vuln(self):
        vulns = [{"id": "GO-2026-0001", "aliases": ["CVE-2026-55555"], "summary": "Bad"}]
        ig = Ignore(tool="go", vuln_id="GO-2026-0001", reason="r", expires=TODAY)
        report = classify_govulncheck("services/ingest", vulns, [ig])
        assert len(report.findings) == 0
        assert len(report.ignored) == 1


# ─── Report + exit_code_for tests ────────────────────────────────────────────


class TestExitCodeFor:
    def test_no_findings(self):
        assert exit_code_for(Report()) == 0

    def test_only_moderate(self):
        r = Report(findings=[Finding("pnpm", "moderate", "X", "p", "l", "t")])
        assert exit_code_for(r) == 0

    def test_only_low(self):
        r = Report(findings=[Finding("pnpm", "low", "X", "p", "l", "t")])
        assert exit_code_for(r) == 0

    def test_high_fails(self):
        r = Report(findings=[Finding("python", "high", "X", "p", "l", "t")])
        assert exit_code_for(r) == 1

    def test_critical_fails(self):
        r = Report(findings=[Finding("go", "critical", "X", "p", "l", "t")])
        assert exit_code_for(r) == 1

    def test_mixed_high_and_moderate(self):
        r = Report(
            findings=[
                Finding("pnpm", "moderate", "A", "p", "l", "t"),
                Finding("pnpm", "high", "B", "p", "l", "t"),
            ]
        )
        assert exit_code_for(r) == 1


# ─── Report property tests ───────────────────────────────────────────────────


class TestReportProperties:
    def test_high_critical(self):
        r = Report(
            findings=[
                Finding("a", "high", "1", "p", "l", "t"),
                Finding("a", "critical", "2", "p", "l", "t"),
                Finding("a", "moderate", "3", "p", "l", "t"),
            ]
        )
        assert len(r.high_critical) == 2

    def test_moderate(self):
        r = Report(
            findings=[
                Finding("a", "moderate", "1", "p", "l", "t"),
                Finding("a", "high", "2", "p", "l", "t"),
            ]
        )
        assert len(r.moderate) == 1

    def test_low_info(self):
        r = Report(
            findings=[
                Finding("a", "low", "1", "p", "l", "t"),
                Finding("a", "info", "2", "p", "l", "t"),
                Finding("a", "unknown", "3", "p", "l", "t"),
            ]
        )
        assert len(r.low_info) == 3
