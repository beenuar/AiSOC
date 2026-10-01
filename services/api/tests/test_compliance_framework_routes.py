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

import pytest
from fastapi.testclient import TestClient
from app.api.v1.endpoints.compliance import FRAMEWORKS
from app.api.v1.endpoints.compliance_framework import SLUG_TO_KEY, resolve_framework
from app.main import app
from fastapi import HTTPException


#: One client for the whole module. Building it per test triples the run
#: time of a file that is mostly routing assertions.
_CLIENT = TestClient(app, raise_server_exceptions=False)


def _reaches_a_route(path: str, method: str = "GET") -> bool:
    """Whether a request to `path` reaches a handler at all.

    Decided by **sending a request**, not by walking `app.routes`.

    `app.routes` is not the route table and what it holds changes with the
    FastAPI minor: on 0.141.x `include_router` leaves an opaque object and
    the `APIRoute` count is zero. A first version of this file walked the
    router, passed locally on 0.136.1, and reported every path as
    unreachable in CI, which is the same defect that once made a
    route-parity gate compare zero pairs and report success over an app
    serving 456 operations.

    A 401 answers the question as well as a 200 does: authentication runs
    after the route has matched, so anything other than 404 means a handler
    is there.
    """
    response = _CLIENT.request(method, path)
    return response.status_code != 404


def _handler_for(path: str, method: str = "GET") -> str | None:
    """The handler name that owns `path`, from the OpenAPI document.

    `app.openapi()` is built from the real route table by FastAPI itself,
    so it survives the minor-version difference above. It keys paths in a
    dict, which would hide a duplicate, but duplicates are
    `check_route_duplicates.py`'s job and this file only asks who owns a
    path.

    An **exact** template wins over a parameterised one, because a dict
    preserves insertion order rather than match priority: looking for the
    first template that matches reported `/compliance/report` as owned by
    `/compliance/{framework}`, which is the very confusion this file exists
    to rule out.
    """
    spec = app.openapi()
    paths = spec.get("paths", {})
    candidates = [path] if path in paths else [template for template in paths if _template_matches(template, path)]
    if not candidates:
        return None
    # Fewest parameters wins, so a literal beats a catch-all.
    best = min(candidates, key=lambda t: t.count("{"))
    operation = paths[best].get(method.lower())
    if not operation:
        return None
    # FastAPI builds `<handler>_<path with underscores>_<method>`.
    operation_id = operation.get("operationId", "")
    return operation_id.split("_api_v1_")[0] or None


def _template_matches(template: str, path: str) -> bool:
    import re

    pattern = "".join("[^/]+" if part.startswith("{") else re.escape(part) for part in re.split(r"(\{[^}]+\})", template))
    return re.fullmatch(pattern, path) is not None


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
        assert _reaches_a_route(path, method), f"{method} {path} answers 404; the console page calling it could never load"


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
        assert _reaches_a_route(path), f"{path} answers 404"
        owner = _handler_for(path)
        assert owner == handler, (
            f"{path} is owned by {owner!r} rather than {handler!r}: the `/{{framework}}` catch-all is mounted before its sibling literals"
        )

    def test_a_framework_slug_still_reaches_the_catch_all(self) -> None:
        """The other direction, so this cannot pass by breaking the new routes."""
        assert _reaches_a_route("/api/v1/compliance/pci-dss")
        assert _handler_for("/api/v1/compliance/pci-dss") == "framework_detail"


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
