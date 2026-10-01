"""The four per-framework compliance routes exist, and nothing shadows them.

`apps/web/src/components/compliance/` made eight calls to four route shapes
that did not exist, so `/compliance/[framework]` and `/compliance/soc2` were
pages that could never load. The console also sends slugs (`soc2`) while
`FRAMEWORKS` is keyed `SOC2`, so both halves had to be wrong for the page to
be this broken and fixing one would have left a 404 behind the other.

The shadowing case is the one worth a test rather than a glance. A path
parameter compiles to `[^/]+`, so `/{framework}` will swallow the sibling
literals `/frameworks`, `/evidence` and `/report` if it is mounted first.
That exact defect has shipped in this tree before, on `/hunts/{hunt_id}`
against `/runs` and `/findings`, and the fix there was a path convertor
because declaration order is a convention a later edit can undo.

Here the ordering is what prevents it, so this asserts the **outcome**:
which handler a request actually reaches, read from the router rather than
inferred from the source.
"""

from __future__ import annotations

import asyncio

import pytest
from app.api.v1.endpoints.compliance import FRAMEWORKS
from app.api.v1.endpoints.compliance_framework import SLUG_TO_KEY, resolve_framework
from app.main import app
from fastapi import HTTPException


def _resolve(path: str, method: str = "GET") -> str | None:
    """The name of the handler this path reaches, or None."""

    async def go() -> str | None:
        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [],
            "query_string": b"",
            "root_path": "",
            "app": app,
        }
        for route in app.router.routes:
            match, _child = route.matches(scope)
            if match.name == "FULL":
                return getattr(route, "name", None)
        return None

    return asyncio.run(go())


class TestTheRoutesExist:
    @pytest.mark.parametrize(
        ("path", "method", "handler"),
        [
            ("/api/v1/compliance/soc2", "GET", "framework_detail"),
            ("/api/v1/compliance/soc2/heatmap", "GET", "framework_heatmap"),
            ("/api/v1/compliance/soc2/collect", "POST", "framework_collect"),
            ("/api/v1/compliance/soc2/export", "GET", "framework_export"),
        ],
    )
    def test_each_console_call_reaches_its_handler(self, path: str, method: str, handler: str) -> None:
        assert _resolve(path, method) == handler, f"{method} {path} does not reach {handler}; the console page calling it would 404"


class TestTheCatchAllDoesNotShadowItsSiblings:
    """The failure mode this ordering exists to prevent.

    `/{framework}` matches `frameworks`, `evidence` and `report` just as
    happily as `soc2`. If it were mounted first, three working routes would
    start answering from the wrong handler, and the symptom would be a
    confusing 404 or an empty framework rather than an error.
    """

    @pytest.mark.parametrize(
        ("path", "handler"),
        [
            ("/api/v1/compliance/frameworks", "list_frameworks"),
            ("/api/v1/compliance/report", "compliance_report"),
            ("/api/v1/compliance/evidence", "list_evidence"),
        ],
    )
    def test_the_literal_wins(self, path: str, handler: str) -> None:
        assert _resolve(path) == handler, (
            f"{path} now reaches {_resolve(path)!r} rather than {handler!r}: the "
            "`/{framework}` catch-all is mounted before its sibling literals"
        )

    def test_a_framework_slug_still_reaches_the_catch_all(self) -> None:
        """The other direction, so this cannot pass by breaking the new routes."""
        assert _resolve("/api/v1/compliance/pci-dss") == "framework_detail"


class TestTheSlugMapping:
    @pytest.mark.parametrize(
        ("slug", "expected"),
        [
            ("soc2", "SOC2"),
            ("SOC2", "SOC2"),
            ("soc-2", "SOC2"),
            ("pci-dss", "PCI-DSS"),
            ("pcidss", "PCI-DSS"),
            ("hipaa", "HIPAA"),
            ("iso27001", "ISO27001"),
            ("nist-csf", "NIST-CSF"),
        ],
    )
    def test_the_console_slug_resolves(self, slug: str, expected: str) -> None:
        assert resolve_framework(slug) == expected

    def test_an_unknown_framework_is_a_404_not_an_empty_page(self) -> None:
        """An empty compliance page reads as 'no evidence', which is a claim."""
        with pytest.raises(HTTPException) as exc:
            resolve_framework("gdpr")
        assert exc.value.status_code == 404
        assert "Known:" in exc.value.detail

    def test_the_mapping_is_derived_from_the_framework_keys(self) -> None:
        """So a new framework is reachable without a second edit here.

        Writing the slugs out by hand is what produced the original
        mismatch between the console and the API.
        """
        for key in FRAMEWORKS:
            assert resolve_framework(key) == key
            assert resolve_framework(key.lower()) == key
        assert len(SLUG_TO_KEY) >= len(FRAMEWORKS)


class TestCollectDoesNotFabricate:
    def test_it_writes_evidence_rather_than_returning_a_job_id(self) -> None:
        """The pre-existing `/evidence/collect` returns a queued job and
        creates nothing. This route must not copy that."""
        import inspect

        from app.api.v1.endpoints.compliance_framework import framework_collect

        source = inspect.getsource(framework_collect)
        assert "INSERT INTO aisoc_compliance_evidence" in source
        assert "await db.commit()" in source

    def test_automated_evidence_lands_pending_not_accepted(self) -> None:
        """The platform attesting its own state is a claim, not a finding.

        Auto-accepting would make the review step decorative, and the
        module splits collect and review across two permissions precisely
        so that whoever collects cannot accept.
        """
        import inspect

        from app.api.v1.endpoints.compliance_framework import framework_collect

        source = inspect.getsource(framework_collect)
        assert "'pending'" in source
        assert "'accepted'" not in source

    def test_a_control_with_no_automated_source_says_so(self) -> None:
        from app.api.v1.endpoints.compliance_framework import ATTESTATIONS

        automatable = set(ATTESTATIONS)
        every_control = {cid for controls in FRAMEWORKS.values() for cid in controls}
        # The honest shape: a small automatable subset, and the rest
        # reported as manual rather than silently counted as covered.
        assert automatable & every_control, "no attestation maps to a real control id"
        assert automatable < every_control, (
            "every control claims an automated source, which would mean the platform attests things it cannot observe"
        )
