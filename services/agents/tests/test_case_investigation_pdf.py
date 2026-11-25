"""Case-bound warm PDF export in one replica-local operation."""

import json
import sys
import uuid
from types import SimpleNamespace

import pytest
from app.api import investigate
from app.security.tenant_scope import TenantPrincipal
from fastapi import HTTPException


def principal(tenant, subject="service"):
    return TenantPrincipal(tenant_ids=frozenset({tenant}), subject=subject)


@pytest.mark.asyncio
@pytest.mark.parametrize("case_representation", ["uuid", "case_number"])
async def test_case_pdf_uses_same_replica_for_owner_check_and_render(monkeypatch, case_representation):
    tenant, case, run = uuid.uuid4(), uuid.uuid4(), str(uuid.uuid4())
    case_number = "CASE-123"
    monkeypatch.setattr(
        investigate,
        "_runs",
        {
            run: {
                "tenant_id": str(tenant),
                "case_id": str(case) if case_representation == "uuid" else case_number,
                "status": "completed",
                "report_html": "<h1>Warm report</h1>",
            },
        },
    )
    reads = []

    def render(value):
        reads.append(value)
        return b"%PDF-test"

    monkeypatch.setattr(investigate, "_render_case_pdf", render)
    response = await investigate.get_case_report_export(run, principal(tenant), case, case_number, try_pdf=True)

    assert response.body == b"%PDF-test"
    assert response.media_type == "application/pdf"
    assert reads == ["<h1>Warm report</h1>"]


@pytest.mark.asyncio
@pytest.mark.parametrize("condition,expected", [("missing", 404), ("tenant", 404), ("case", 404), ("console", 403), ("running", 409)])
async def test_invalid_binding_or_status_never_renders(monkeypatch, condition, expected):
    tenant, case, run = uuid.uuid4(), uuid.uuid4(), str(uuid.uuid4())
    lookup = (
        {}
        if condition == "missing"
        else {
            run: {
                "tenant_id": str(uuid.uuid4() if condition == "tenant" else tenant),
                "case_id": str(uuid.uuid4() if condition == "case" else case),
                "status": "running" if condition == "running" else "completed",
                "report_html": "<h1>Non-exportable report</h1>",
            }
        }
    )
    monkeypatch.setattr(investigate, "_runs", lookup)

    def render(_value):
        pytest.fail("unavailable or unverified report must not render")

    monkeypatch.setattr(investigate, "_render_case_pdf", render)
    subject = "console:test" if condition == "console" else "service"
    with pytest.raises(HTTPException) as error:
        await investigate.get_case_report_export(run, principal(tenant, subject), case)
    assert error.value.status_code == expected


def test_warm_native_renderer_blocks_resource_loading(monkeypatch):
    class Document:
        def __init__(self, *, string, url_fetcher):
            assert string == "<h1>PDF</h1>"
            self.fetcher = url_fetcher

        def write_pdf(self):
            with pytest.raises(ValueError):
                self.fetcher("https://resources.invalid/picture.png")
            return b"%PDF-test"

    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=Document))
    assert investigate._render_case_pdf("<h1>PDF</h1>") == b"%PDF-test"


@pytest.mark.asyncio
@pytest.mark.parametrize("try_pdf", [False, True])
async def test_agents_without_optional_renderer_exports_verified_html(monkeypatch, try_pdf):
    tenant, case, run = uuid.uuid4(), uuid.uuid4(), str(uuid.uuid4())
    monkeypatch.setattr(
        investigate,
        "_runs",
        {run: {"tenant_id": str(tenant), "case_id": str(case), "status": "completed", "report_html": "<h1>Warm</h1>"}},
    )
    monkeypatch.setitem(sys.modules, "weasyprint", None)
    response = await investigate.get_case_report_export(run, principal(tenant), case, try_pdf=try_pdf)
    assert response.media_type == "application/json"
    assert json.loads(response.body) == {"report_html": "<h1>Warm</h1>"}
