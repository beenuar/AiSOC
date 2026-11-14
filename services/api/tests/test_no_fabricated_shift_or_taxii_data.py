"""Neither the shift board nor the STIX routes serve invented data.

Two surfaces served hand-written records from module-level lists with no
tenant filter and no demo gate:

* `shifts.py` returned three invented shifts with named analysts, an
  `alerts_handled` count and a fabricated ticket id. `POST` inserted into
  that same list and `PUT /{id}/handoff` wrote notes into it, so one tenant
  posted a handoff and another read it.
* `stix_taxii.py` returned invented indicators, bundles and TAXII
  collections, and its `POST` routes appended to the same lists.

Neither had a caller. Nothing in `apps/web`, no SDK, and no other service
referenced either surface; the console's shift page is demo-gated and renders
its own sample data client-side. So the shift board is deleted rather than
rebuilt — a route with no caller serving data nobody entered is not a feature
with a bug — and the STIX routes answer 404 outside demo mode until the real
TAXII server backed by the tenant IOC store lands.
"""

from __future__ import annotations

import pathlib

import pytest

SERVICE_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = SERVICE_ROOT.parents[1]


class TestTheShiftBoardIsGone:
    def test_the_module_no_longer_exists(self) -> None:
        module = SERVICE_ROOT / "app" / "api" / "v1" / "endpoints" / "shifts.py"
        assert not module.exists(), (
            "shifts.py is back. It served three invented shifts from a module-level list "
            "with no tenant filter, and POST and PUT wrote into that same list"
        )

    def test_nothing_mounts_it(self) -> None:
        router = (SERVICE_ROOT / "app" / "api" / "v1" / "router.py").read_text(encoding="utf-8")
        assert "shifts" not in router, "the shifts router is still mounted"

    def test_the_console_page_is_unaffected(self) -> None:
        """It never called the API: it renders its own demo-gated sample.

        Asserted so that deleting the route is not mistaken for deleting the
        page, and so a future reader does not restore the route believing the
        console needs it.
        """
        view = REPO_ROOT / "apps" / "web" / "src" / "components" / "shifts" / "ShiftsView.tsx"
        if not view.exists():
            pytest.skip("the console shift view is not in this checkout")
        source = view.read_text(encoding="utf-8")
        assert "canUseDemoData" in source, "the console shift view lost its demo gate"
        assert "/api/v1/shifts" not in source, "the console shift view now calls the deleted route"


class TestTheStixRoutesRefuseOutsideDemoMode:
    def test_every_handler_serving_invented_data_is_gated(self) -> None:
        source = (SERVICE_ROOT / "app" / "api" / "v1" / "endpoints" / "stix_taxii.py").read_text(encoding="utf-8")
        # The three read routes, plus the helper's own definition. The two
        # POST routes are deliberately not gated: what they do is real, they
        # translate the object and push it to the configured MISP instance,
        # and they no longer append to the shared lists — so the cross-tenant
        # write is gone without a working feature going with it.
        assert source.count("_demo_only()") == 4, (
            "expected the three read handlers plus the helper definition; the POST routes push to MISP for real and must stay reachable"
        )
        assert "DEMO_INDICATORS.append" not in source, "a POST is storing into shared state again"
        assert "DEMO_BUNDLES.append" not in source, "a POST is storing into shared state again"

    def test_the_gate_refuses_rather_than_returning_empty(self) -> None:
        """404, not an empty list.

        An empty list says "this tenant has no indicators", which is a claim
        about their data. 404 says the collection does not exist here, which
        is the true statement.
        """
        source = (SERVICE_ROOT / "app" / "api" / "v1" / "endpoints" / "stix_taxii.py").read_text(encoding="utf-8")
        assert "HTTP_404_NOT_FOUND" in source
        assert "AISOC_DEMO_MODE" in source

    def test_the_gate_sits_after_the_docstring(self) -> None:
        """A statement inserted before a docstring demotes it to dead code.

        The first attempt did exactly that, which would have emptied the
        `description` these operations publish in `docs/openapi.yaml` while
        every test still passed.
        """
        import ast

        source = (SERVICE_ROOT / "app" / "api" / "v1" / "endpoints" / "stix_taxii.py").read_text(encoding="utf-8")
        gated = {"list_indicators", "list_bundles", "list_taxii_collections"}
        seen = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in gated:
                seen.add(node.name)
                first = node.body[0]
                assert isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant), (
                    f"{node.name} no longer opens with a docstring, so its OpenAPI description is empty"
                )
        assert seen == gated, f"handlers missing from the module: {sorted(gated - seen)}"
