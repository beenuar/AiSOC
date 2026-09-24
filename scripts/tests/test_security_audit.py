"""Tests for scripts/security_audit.py — ignore validation, classifiers, parsers."""

from __future__ import annotations

import argparse
import datetime as dt
import textwrap
from pathlib import Path

import pytest

# Import the module under test
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import security_audit
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
    run_govulncheck,
    run_pip_audit,
    run_pnpm_audit,
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

    def test_unscanned_alone_fails(self):
        """A clean scan and a skipped scan must not both exit 0.

        This is the property that makes an exit of 0 mean anything: without
        it, a service the gate could not read is indistinguishable from a
        service the gate read and cleared. `services/slack-bot` sat in that
        state behind a stale poetry.lock while its lock resolved advisories
        every other service had already moved past (#650).
        """
        r = Report(unscanned=["services/slack-bot: poetry export failed — NOT scanned"])
        assert exit_code_for(r) == 1

    def test_unscanned_fails_even_with_only_low_findings(self):
        r = Report(
            findings=[Finding("python", "low", "X", "p", "l", "t")],
            unscanned=["services/api: pip-audit exited 2 — NOT scanned"],
        )
        assert exit_code_for(r) == 1

    def test_warnings_alone_do_not_fail(self):
        """Warnings are observations about a scan that happened; they must stay
        non-fatal so that a coverage gap remains the only reason a finding-free
        run can still exit 1."""
        r = Report(warnings=["some non-fatal note"])
        assert exit_code_for(r) == 0


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


# ─── Coverage-gap tests: a scan that did not happen must not read as clean ───


class _Proc:
    """Minimal stand-in for subprocess.CompletedProcess."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestPnpmCoverageGaps:
    @staticmethod
    def _workspace(tmp_path: Path) -> Path:
        (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
        return tmp_path

    def test_unparseable_output_is_a_coverage_gap_not_a_warning(self, monkeypatch, tmp_path: Path):
        """pnpm audit that returns garbage has audited nothing.

        Recorded as `unscanned` so `exit_code_for` fails. As a `warning` the
        arm exited 0 and printed "pnpm: 0 findings" for a workspace it had
        never successfully read.
        """
        monkeypatch.setattr(
            security_audit.subprocess,
            "run",
            lambda *a, **k: _Proc(returncode=1, stdout="<html>not json</html>"),
        )

        report = run_pnpm_audit(self._workspace(tmp_path), [])

        assert report.unscanned, "unparseable pnpm output must be recorded as a coverage gap"
        assert not report.findings
        assert exit_code_for(report) == 1

    def test_successful_audit_records_no_gap(self, monkeypatch, tmp_path: Path):
        monkeypatch.setattr(
            security_audit.subprocess,
            "run",
            lambda *a, **k: _Proc(returncode=0, stdout='{"advisories": {}}'),
        )

        report = run_pnpm_audit(self._workspace(tmp_path), [])

        assert report.unscanned == []
        assert exit_code_for(report) == 0


class TestNothingToScanIsNotACleanScan:
    """Zero targets discovered is a coverage gap, not a clean result.

    Every arm of this audit printed "N findings" and exited 0 against a
    directory with no manifests in it — the same sentence, and the same exit
    status, as a clean audit of the real workspace. Found nothing and scanned
    nothing are different results and only one of them is good news.
    """

    def test_pnpm_refuses_a_workspace_with_no_lockfile(self, tmp_path: Path):
        report = run_pnpm_audit(tmp_path, [])

        assert report.unscanned, "no pnpm-lock.yaml must be a coverage gap"
        assert exit_code_for(report) == 1

    def test_pnpm_audits_every_install_root_not_only_the_repo_root(self, monkeypatch, tmp_path: Path):
        """A second install root must be audited, and its findings must name it.

        ``apps/mobile`` keeps its own ``pnpm-workspace.yaml`` so its installs
        stop rewriting the root lock. Auditing only the repo root therefore
        never reached it, and this arm reported a clean workspace while two
        high-severity advisories stood open there.
        """
        (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '6.0'\n")
        nested = tmp_path / "apps" / "mobile"
        nested.mkdir(parents=True)
        (nested / "pnpm-lock.yaml").write_text("lockfileVersion: '6.0'\n")

        monkeypatch.setattr(
            security_audit,
            "pnpm_install_roots",
            lambda root: [".", "apps/mobile"],
        )

        audited: list[Path] = []

        def fake_at(root: Path, label: str, ignores):
            audited.append(root)
            report = Report()
            if label.endswith("apps/mobile"):
                report.findings.append(
                    Finding(
                        tool="pnpm",
                        severity="high",
                        vuln_id="GHSA-5p2g-fcmc-qvqq",
                        package="image-size",
                        location=label,
                        title="denial of service",
                    )
                )
            return report

        monkeypatch.setattr(security_audit, "run_pnpm_audit_at", fake_at)

        report = run_pnpm_audit(tmp_path, [])

        assert audited == [tmp_path, tmp_path / "apps/mobile"], "both install roots must be audited"
        assert len(report.findings) == 1
        assert report.findings[0].location == "pnpm workspace apps/mobile", (
            "a finding must name the install root it came from, not a generic 'pnpm workspace'"
        )
        assert exit_code_for(report) == 1

    def test_pnpm_install_roots_are_read_from_the_tree(self, tmp_path: Path):
        """Discovery is structural, so a new install root needs no edit here."""
        import subprocess

        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '6.0'\n")
        nested = tmp_path / "apps" / "mobile"
        nested.mkdir(parents=True)
        (nested / "pnpm-lock.yaml").write_text("lockfileVersion: '6.0'\n")
        subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)

        assert security_audit.pnpm_install_roots(tmp_path) == [".", "apps/mobile"]

    def test_pnpm_refuses_a_tree_with_no_install_root_at_all(self, tmp_path: Path):
        """Zero install roots is not zero workspaces vulnerable."""
        report = run_pnpm_audit(tmp_path, [])

        assert report.unscanned, "a tree with no lockfile anywhere must be a coverage gap"
        assert exit_code_for(report) == 1

    def test_python_refuses_a_tree_with_no_manifests(self, tmp_path: Path):
        report = run_pip_audit(tmp_path, [])

        assert report.unscanned, "no pyproject.toml anywhere must be a coverage gap"
        assert exit_code_for(report) == 1

    def test_go_refuses_a_tree_with_no_modules(self, tmp_path: Path):
        report = run_govulncheck(tmp_path, [])

        assert report.unscanned, "no go.mod anywhere must be a coverage gap"
        assert exit_code_for(report) == 1

    def test_validate_ignores_refuses_a_missing_policy_file(self, monkeypatch, tmp_path: Path):
        monkeypatch.setattr(security_audit, "get_repo_root", lambda: tmp_path)

        assert security_audit.cmd_validate_ignores(argparse.Namespace()) == 1

    def test_validate_ignores_accepts_a_policy_file_with_no_entries(self, monkeypatch, tmp_path: Path):
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "security_audit_ignores.txt").write_text("# every suppression has been retired\n")
        monkeypatch.setattr(security_audit, "get_repo_root", lambda: tmp_path)

        assert security_audit.cmd_validate_ignores(argparse.Namespace()) == 0


class TestGoCoverageGaps:
    @staticmethod
    def _module(tmp_path: Path) -> Path:
        mod = tmp_path / "services" / "ingest"
        mod.mkdir(parents=True)
        (mod / "go.mod").write_text("module example.com/ingest\n")
        return tmp_path

    def test_unexpected_exit_is_a_coverage_gap(self, monkeypatch, tmp_path: Path):
        """govulncheck exits 0 (clean) or 3 (vulnerabilities found).

        Any other code means the module never got analysed — a build failure
        or a missing toolchain. Treated as a coverage gap for the same reason
        as the Python arm: otherwise the arm prints "go: 0 findings" for a
        module it could not read.
        """
        root = self._module(tmp_path)
        monkeypatch.setattr(
            security_audit.subprocess,
            "run",
            lambda *a, **k: _Proc(returncode=1, stderr="build failed: no required module provides package"),
        )

        report = run_govulncheck(root, [])

        assert report.unscanned, "a failed govulncheck run must be recorded as a coverage gap"
        assert "services/ingest" in report.unscanned[0]
        assert exit_code_for(report) == 1

    def test_missing_binary_is_a_coverage_gap(self, monkeypatch, tmp_path: Path):
        root = self._module(tmp_path)

        def _raise(*a, **k):
            raise FileNotFoundError("govulncheck")

        monkeypatch.setattr(security_audit.subprocess, "run", _raise)

        report = run_govulncheck(root, [])

        assert report.unscanned
        assert exit_code_for(report) == 1

    def test_clean_module_records_no_gap(self, monkeypatch, tmp_path: Path):
        root = self._module(tmp_path)
        monkeypatch.setattr(security_audit.subprocess, "run", lambda *a, **k: _Proc(returncode=0, stdout=""))

        report = run_govulncheck(root, [])

        assert report.unscanned == []
        assert report.findings == []
        assert exit_code_for(report) == 0

    def test_findings_exit_code_3_still_counts_as_scanned(self, monkeypatch, tmp_path: Path):
        root = self._module(tmp_path)
        stdout = "\n".join(
            [
                '{"osv": {"id": "GO-2026-0001", "aliases": ["CVE-2026-0001"], "summary": "boom"}}',
                '{"finding": {"osv": "GO-2026-0001"}}',
            ]
        )
        monkeypatch.setattr(
            security_audit.subprocess,
            "run",
            lambda *a, **k: _Proc(returncode=3, stdout=stdout),
        )

        report = run_govulncheck(root, [])

        assert report.unscanned == []
        assert [f.vuln_id for f in report.findings] == ["GO-2026-0001"]
        assert exit_code_for(report) == 1
