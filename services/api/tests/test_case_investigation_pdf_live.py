"""Case PDF downloads through the production HTTP app and live PostgreSQL.

Authentication, case resolution, ledger queries and PDF rendering are real.
The agents boundary is a loopback HTTP server, so the real proxy exercises its
wire protocol and service credentials. No investigation or model is started.
Run with MSSP_ISOLATION_REQUIRED=1 against the API migration chain to make
missing PostgreSQL or the pdftotext binary a failure instead of a skip.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import pytest_asyncio
from app.api.v1.endpoints import cases
from app.core.security import create_access_token
from app.db.database import _normalize_async_pg_url, get_db
from app.main import create_application
from live_rls import bind_tenant
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

REPORT = """# Persisted incident evidence

The observed command used PowerShell. Technique: **T1059.001**.

| Evidence | Result |
| --- | --- |
| Investigation ledger | Retained after restart |
"""
SERVICE_TOKEN = "pdf-regression-service-credential"


def _required() -> bool:
    return os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")


@dataclass
class AgentsHTTP:
    replies: dict[str, tuple[int, bytes, str]] = field(default_factory=dict)
    runs: dict[str, tuple[str | None, str]] = field(default_factory=dict)
    requests: list[tuple[str, str, str | None, str | None]] = field(default_factory=list)
    disconnect: bool = False
    url: str = ""

    def json(self, path: str, body: dict, status: int = 200) -> None:
        self.replies[path] = (status, json.dumps(body).encode(), "application/json")

    def run(self, run_id: uuid.UUID, case_id: uuid.UUID | str | None, *, status: str = "completed") -> None:
        self.runs[str(run_id)] = (str(case_id) if case_id is not None else None, status)


@pytest.fixture
def agents_http(monkeypatch):
    upstream = AgentsHTTP()
    # This boundary is local: workstation proxy settings must not route the
    # loopback request away from the server or require optional SOCKS support.
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            upstream.requests.append((self.command, self.path, self.headers.get("X-AiSOC-Tenant-ID"), self.headers.get("Authorization")))
            if upstream.disconnect:
                self.close_connection = True
                return
            url = urlsplit(self.path)
            missing = (404, b'{"detail":"Run not found"}', "application/json")
            status, body, content_type = upstream.replies.get(url.path, missing)
            case_mismatch = False
            if url.path.endswith("/case-report-export"):
                run_id = url.path.split("/")[-2]
                case_id, run_status = upstream.runs.get(run_id, (None, "missing"))
                query = parse_qs(url.query)
                if case_id is None or case_id not in query.get("case_id", []) + query.get("case_number", []):
                    status, body, content_type = missing
                    case_mismatch = run_id in upstream.runs
                elif run_status != "completed":
                    status, body, content_type = (409, b'{"detail":"Not complete"}', "application/json")
                elif status == 200 and content_type == "application/pdf" and query.get("try_pdf") != ["true"]:
                    # The actual Agents endpoint does not produce a PDF unless
                    # requested; an over-capable stub would hide regressions.
                    body = b'{"report_html":"<h1>Verified warm export</h1>"}'
                    content_type = "application/json"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if case_mismatch:
                self.send_header("X-AiSOC-Report-Rejected", "case-mismatch")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            upstream.requests.append((self.command, self.path, None, None))
            self.send_error(405)

        def log_message(self, _format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    upstream.url = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    monkeypatch.setattr(cases, "_AGENTS_URL", upstream.url)
    monkeypatch.setattr(cases, "_AGENTS_SERVICE_TOKEN", SERVICE_TOKEN)
    try:
        yield upstream
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@dataclass
class PDFAPI:
    client: httpx.AsyncClient
    db: AsyncSession
    agents: AgentsHTTP
    tenant: uuid.UUID
    other_tenant: uuid.UUID
    case_id: uuid.UUID
    other_case_id: uuid.UUID
    case_number: str

    async def run(
        self,
        *,
        status: str = "completed",
        markdown: str | None = REPORT,
        tenant: uuid.UUID | None = None,
        case_id: uuid.UUID | str | None = None,
        run_id: uuid.UUID | None = None,
        artifact_tenant: uuid.UUID | None = None,
    ) -> uuid.UUID:
        tenant = tenant or self.tenant
        run_id = run_id or uuid.uuid4()
        await bind_tenant(self.db, tenant)
        await self.db.execute(
            text("""INSERT INTO investigation_runs
                (id, tenant_id, case_id, status, total_tokens, total_cost_usd)
                VALUES (:id, :tenant, :case, :status, 123, 0.1250)"""),
            {"id": run_id, "tenant": tenant, "case": str(case_id or self.case_id), "status": status},
        )
        if markdown is not None:
            artifact_tenant = artifact_tenant or tenant
            await bind_tenant(self.db, artifact_tenant)
            await self.db.execute(
                text("""INSERT INTO investigation_artifacts
                    (id, run_id, tenant_id, kind, content, sha256, size_bytes)
                    VALUES (:id, :run, :tenant, 'report_md', :content, :sha, :size)"""),
                {
                    "id": uuid.uuid4(),
                    "run": run_id,
                    "tenant": artifact_tenant,
                    "content": markdown,
                    "sha": hashlib.sha256(markdown.encode()).hexdigest(),
                    "size": len(markdown.encode()),
                },
            )
        await self.db.commit()
        return run_id

    async def pdf(self, run_id: uuid.UUID | str, *, case_id: uuid.UUID | str | None = None) -> httpx.Response:
        return await self.client.get(f"/api/v1/cases/{case_id or self.case_id}/investigations/{run_id}/report.pdf")


@pytest_asyncio.fixture
async def api(monkeypatch, agents_http):
    dsn = os.environ.get("DATABASE_URL", "")
    if "postgres" not in dsn:
        if _required():
            pytest.fail("live PostgreSQL is required")
        pytest.skip("requires PostgreSQL with the API migration chain")
    url, connect_args = _normalize_async_pg_url(dsn)
    engine = create_async_engine(url, connect_args=connect_args)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if _required():
            pytest.fail(f"PostgreSQL is required but unavailable: {type(exc).__name__}: {exc}")
        pytest.skip(f"PostgreSQL unavailable ({type(exc).__name__})")

    monkeypatch.setenv("AISOC_DEV_AUTH_BYPASS", "0")
    tenant, other_tenant, user_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    case_id, other_case_id = uuid.uuid4(), uuid.uuid4()
    case_number = f"PDF-{case_id.hex[:20]}"
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as db:
            for tid in (tenant, other_tenant):
                await db.execute(
                    text("INSERT INTO tenants (id, name, slug) VALUES (:id, 'PDF regression', :slug)"),
                    {"id": tid, "slug": f"pdf-{tid}"},
                )
            await bind_tenant(db, tenant)
            await db.execute(
                text("""INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active)
                    VALUES (:id, :tenant, :email, 'pdf-test', '!test-only!', 'soc_analyst', TRUE)"""),
                {"id": user_id, "tenant": tenant, "email": f"pdf-{user_id}@example.test"},
            )
            for cid, number in ((case_id, case_number), (other_case_id, f"PDF-{other_case_id.hex[:20]}")):
                await db.execute(
                    text("""INSERT INTO aisoc_cases (id, tenant_id, case_number, title, severity, status)
                        VALUES (:id, :tenant, :number, 'PDF regression fixture', 'high', 'investigating')"""),
                    {"id": cid, "tenant": tenant, "number": number},
                )
            await db.commit()
            token = create_access_token({"sub": str(user_id), "tenant_id": str(tenant), "role": "soc_analyst"})
            app = create_application()

            async def session():
                # Unbound reads expose omitted tenant predicates instead of
                # letting an RLS filter conceal a missing application guard.
                yield db

            app.dependency_overrides[get_db] = session
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app),
                base_url="http://api.test",
                headers={"Authorization": f"Bearer {token}"},
            ) as client:
                try:
                    yield PDFAPI(client, db, agents_http, tenant, other_tenant, case_id, other_case_id, case_number)
                finally:
                    await db.rollback()
                    for tid in (tenant, other_tenant):
                        await bind_tenant(db, tid)
                        for table in ("investigation_artifacts", "investigation_runs", "aisoc_cases", "users"):
                            await db.execute(text(f"DELETE FROM {table} WHERE tenant_id = :tenant"), {"tenant": tid})
                        await db.execute(text("DELETE FROM tenants WHERE id = :tenant"), {"tenant": tid})
                        await db.commit()
    finally:
        await engine.dispose()


@pytest.fixture
def upstream_pdf(api: PDFAPI) -> bytes:
    from weasyprint import HTML

    return HTML(string="<h1>Warm investigation report</h1><p>Existing agents PDF export.</p>").write_pdf()


def _assert_pdf(response: httpx.Response) -> None:
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/pdf")
    assert "attachment;" in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF-"), response.content[:100]
    assert response.content.rstrip().endswith(b"%%EOF")
    assert len(response.content) > 1000


def _pdf_text(body: bytes) -> str:
    binary = shutil.which("pdftotext")
    if not binary:
        if _required():
            pytest.fail("pdftotext is required to validate exported PDF text")
        pytest.skip("requires pdftotext to validate exported PDF text")
    assert binary is not None
    result = subprocess.run([binary, "-", "-"], input=body, capture_output=True, check=True)
    return result.stdout.decode()


@pytest.mark.parametrize("status", ["completed", "closed"])
async def test_persisted_report_downloads_without_agents_or_new_investigation(api: PDFAPI, status: str) -> None:
    run_id = await api.run(status=status)
    markdown = await api.client.get(f"/api/v1/cases/{api.case_id}/investigations/{run_id}/report.md")
    assert markdown.status_code == 200, markdown.text
    assert markdown.text == REPORT
    api.agents.requests.clear()
    before = (
        await api.db.execute(text("SELECT status, total_tokens, total_cost_usd FROM investigation_runs WHERE id = :id"), {"id": run_id})
    ).one()

    response = await api.pdf(run_id)

    _assert_pdf(response)
    exported = _pdf_text(response.content)
    for expected in ("Persisted incident evidence", "T1059.001", "Retained after restart"):
        assert expected in exported
    assert api.agents.requests == [], "a persisted report export must not depend on agents or invoke a model"
    after = (
        await api.db.execute(text("SELECT status, total_tokens, total_cost_usd FROM investigation_runs WHERE id = :id"), {"id": run_id})
    ).one()
    assert after == before


async def test_persisted_report_is_available_during_upstream_transport_failure(api: PDFAPI) -> None:
    run_id = await api.run()
    api.agents.disconnect = True
    _assert_pdf(await api.pdf(run_id))
    assert api.agents.requests == []


async def test_case_number_resolves_to_persisted_case_report(api: PDFAPI) -> None:
    run_id = await api.run()
    _assert_pdf(await api.pdf(run_id, case_id=api.case_number))


async def test_persisted_case_number_is_bound_to_its_existing_case(api: PDFAPI) -> None:
    run_id = await api.run(case_id=api.case_number)
    _assert_pdf(await api.pdf(run_id))
    response = await api.pdf(run_id, case_id=api.other_case_id)
    assert response.status_code == 404, response.text


async def test_persisted_markdown_preserves_code_tables_and_html_entities(api: PDFAPI) -> None:
    run_id = await api.run(
        markdown="""# Evidence formatting

The source is R&amp;D &lt;review&gt; with inline `Get-Item -LiteralPath C:\\Audit`.

| Observed value | Meaning |
| --- | --- |
| alpha \\| beta | Escaped separator retained |

```powershell
Get-Process | Select-Object Id
```
"""
    )
    response = await api.pdf(run_id)
    _assert_pdf(response)
    exported = " ".join(_pdf_text(response.content).split())
    for expected in ("R&D <review>", "Get-Item -LiteralPath C:\\Audit", "alpha | beta", "Get-Process | Select-Object Id"):
        assert expected in exported


async def test_markdown_and_raw_html_resources_are_never_fetched(api: PDFAPI) -> None:
    image_url = f"{api.agents.url}/private-evidence.svg"
    api.agents.replies["/private-evidence.svg"] = (
        200,
        b'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="40"><text x="0" y="20">Private resource</text></svg>',
        "image/svg+xml",
    )
    run_id = await api.run(
        markdown=f"# Untrusted report content\n\n![Markdown image]({image_url})\n\n"
        f'<img src="{image_url}">\n\n<style>@import url("{api.agents.url}/private-style.css");</style>\n'
    )

    _assert_pdf(await api.pdf(run_id))

    assert api.agents.requests == [], "rendering saved reports must not retrieve embedded images, styles or other remote resources"


@pytest.mark.parametrize("metadata_case", ["uuid", "number"])
async def test_warm_pdf_preserves_bytes_and_scoped_service_credentials(api: PDFAPI, upstream_pdf: bytes, metadata_case: str) -> None:
    run_id = uuid.uuid4()
    api.agents.run(run_id, api.case_id if metadata_case == "uuid" else api.case_number)
    api.agents.replies[f"/api/v1/investigations/{run_id}/case-report-export"] = (200, upstream_pdf, "application/pdf")

    response = await api.pdf(run_id)

    _assert_pdf(response)
    assert response.content == upstream_pdf
    assert len(api.agents.requests) == 1
    request = urlsplit(api.agents.requests[0][1])
    assert request.path == f"/api/v1/investigations/{run_id}/case-report-export"
    assert parse_qs(request.query) == {"case_id": [str(api.case_id)], "case_number": [api.case_number], "try_pdf": ["true"]}
    assert all(
        method == "GET" and tenant == str(api.tenant) and credential == f"Bearer {SERVICE_TOKEN}"
        for method, _, tenant, credential in api.agents.requests
    )


async def test_warm_completed_run_survives_stale_running_ledger(api: PDFAPI, upstream_pdf: bytes) -> None:
    run_id = await api.run(status="running")
    api.agents.run(run_id, api.case_id)
    api.agents.replies[f"/api/v1/investigations/{run_id}/case-report-export"] = (200, upstream_pdf, "application/pdf")

    response = await api.pdf(run_id)

    _assert_pdf(response)
    assert response.content == upstream_pdf


async def test_stale_running_ledger_cannot_override_warm_case_mismatch(api: PDFAPI, upstream_pdf: bytes) -> None:
    run_id = await api.run(status="running")
    api.agents.run(run_id, api.other_case_id)
    api.agents.replies[f"/api/v1/investigations/{run_id}/case-report-export"] = (200, upstream_pdf, "application/pdf")

    response = await api.pdf(run_id)

    assert response.status_code == 404, response.text
    assert len(api.agents.requests) == 1


@pytest.mark.parametrize("body", [b"invalid PDF", b"[]", b"%PDF-"])
async def test_malformed_warm_pdf_returns_readable_bad_gateway(api: PDFAPI, body: bytes) -> None:
    run_id = uuid.uuid4()
    api.agents.run(run_id, api.case_id)
    api.agents.replies[f"/api/v1/investigations/{run_id}/case-report-export"] = (200, body, "application/pdf")

    response = await api.pdf(run_id)

    assert response.status_code == 502, response.text
    assert response.json() == {"detail": "Invalid investigation PDF from agents"}
    assert len(api.agents.requests) == 1


@pytest.mark.parametrize("owner", ["other_case", "missing_case", "unknown_case"])
async def test_warm_run_requires_existing_matching_case(api: PDFAPI, upstream_pdf: bytes, owner: str) -> None:
    run_id = uuid.uuid4()
    requested_case = uuid.uuid4() if owner == "unknown_case" else api.case_id
    metadata_case = {"other_case": api.other_case_id, "missing_case": None, "unknown_case": requested_case}[owner]
    api.agents.run(run_id, metadata_case)
    api.agents.replies[f"/api/v1/investigations/{run_id}/case-report-export"] = (200, upstream_pdf, "application/pdf")

    response = await api.pdf(run_id, case_id=requested_case)

    assert response.status_code == 404, response.text
    assert len(api.agents.requests) == (0 if owner == "unknown_case" else 1)


@pytest.mark.parametrize("owner", ["other_case", "other_tenant", "run_id_alias", "other_artifact_tenant"])
async def test_persisted_report_cannot_cross_case_or_tenant(api: PDFAPI, owner: str) -> None:
    run_id = uuid.uuid4()
    await api.run(
        run_id=run_id,
        case_id={"other_case": api.other_case_id, "run_id_alias": run_id}.get(owner, api.case_id),
        tenant=api.other_tenant if owner == "other_tenant" else api.tenant,
        artifact_tenant=api.other_tenant if owner == "other_artifact_tenant" else None,
    )

    response = await api.pdf(run_id)

    assert response.status_code == 404, response.text
    assert "Persisted incident evidence" not in response.text


@pytest.mark.parametrize("status", ["running", "failed"])
async def test_incomplete_persisted_run_is_a_conflict_even_with_a_report(api: PDFAPI, status: str) -> None:
    run_id = await api.run(status=status)
    response = await api.pdf(run_id)
    assert response.status_code == 409, response.text
    assert isinstance(response.json()["detail"], str)


@pytest.mark.parametrize("markdown", [None, ""])
async def test_completed_run_without_report_returns_not_found(api: PDFAPI, markdown: str | None) -> None:
    response = await api.pdf(await api.run(markdown=markdown))
    assert response.status_code == 404, response.text
    assert isinstance(response.json()["detail"], str)
    assert not response.json()["detail"].startswith("{")


async def test_unknown_run_has_one_readable_error_detail(api: PDFAPI) -> None:
    response = await api.pdf(uuid.uuid4())
    assert response.status_code == 404, response.text
    assert isinstance(response.json()["detail"], str)
    assert not response.json()["detail"].startswith("{")
    assert '"detail"' not in response.json()["detail"]


async def test_warm_pdf_error_preserves_status_without_nesting_json(api: PDFAPI) -> None:
    run_id = uuid.uuid4()
    api.agents.run(run_id, api.case_id)
    api.agents.json(f"/api/v1/investigations/{run_id}/case-report-export", {"detail": "Report not yet generated"}, status=409)
    response = await api.pdf(run_id)
    assert response.status_code == 409, response.text
    assert response.json() == {"detail": "Report not yet generated"}


async def test_unauthenticated_download_does_not_contact_agents(api: PDFAPI) -> None:
    response = await api.client.get(
        f"/api/v1/cases/{api.case_id}/investigations/{uuid.uuid4()}/report.pdf", headers={"Authorization": "Bearer invalid"}
    )
    assert response.status_code == 401, response.text
    assert api.agents.requests == []


async def test_missing_native_renderer_returns_service_unavailable(api: PDFAPI, monkeypatch) -> None:
    run_id = await api.run()
    monkeypatch.setitem(sys.modules, "weasyprint", None)
    response = await api.pdf(run_id)
    assert response.status_code == 503, response.text
    assert response.headers["content-type"].startswith("application/json")
    assert isinstance(response.json()["detail"], str)
    assert len(api.agents.requests) == 1


async def test_native_render_failure_returns_service_unavailable(api: PDFAPI, monkeypatch) -> None:
    from weasyprint import HTML

    def fail_render(_self, *args, **kwargs):
        raise RuntimeError("native PDF renderer failed")

    run_id = await api.run()
    monkeypatch.setattr(HTML, "write_pdf", fail_render)
    response = await api.pdf(run_id)
    assert response.status_code == 503, response.text
    assert response.headers["content-type"].startswith("application/json")
    assert isinstance(response.json()["detail"], str)
    assert len(api.agents.requests) == 1


async def test_native_failure_falls_back_to_one_case_bound_warm_request(api: PDFAPI, upstream_pdf: bytes, monkeypatch) -> None:
    run_id = await api.run()
    api.agents.run(run_id, api.case_id)
    api.agents.replies[f"/api/v1/investigations/{run_id}/case-report-export"] = (200, upstream_pdf, "application/pdf")
    monkeypatch.setitem(sys.modules, "weasyprint", None)

    response = await api.pdf(run_id)

    _assert_pdf(response)
    assert response.content == upstream_pdf
    assert len(api.agents.requests) == 1
    assert parse_qs(urlsplit(api.agents.requests[0][1]).query)["try_pdf"] == ["true"]


async def test_structured_agents_error_keeps_the_readable_message(api: PDFAPI) -> None:
    run_id = uuid.uuid4()
    api.agents.run(run_id, api.case_id)
    api.agents.json(
        f"/api/v1/investigations/{run_id}/case-report-export",
        {"detail": [{"loc": ["query", "case_id"], "msg": "Invalid case identifier"}]},
        status=422,
    )
    response = await api.pdf(run_id)
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid case identifier"}


async def test_warm_html_renders_in_api_without_agents_native_dependency(api: PDFAPI) -> None:
    run_id = uuid.uuid4()
    api.agents.run(run_id, api.case_id)
    api.agents.json(f"/api/v1/investigations/{run_id}/case-report-export", {"report_html": "<h1>Verified warm export</h1>"})
    response = await api.pdf(run_id)
    _assert_pdf(response)
    assert "Verified warm export" in _pdf_text(response.content)
    assert len(api.agents.requests) == 1


@pytest.mark.parametrize("have_ledger", [False, True], ids=["no-run-row", "completed-run-no-markdown"])
async def test_api_renderer_unavailable_can_download_optional_warm_pdf(
    api: PDFAPI, upstream_pdf: bytes, monkeypatch, have_ledger: bool
) -> None:
    run_id = await api.run(markdown=None) if have_ledger else uuid.uuid4()
    api.agents.run(run_id, api.case_id)
    api.agents.replies[f"/api/v1/investigations/{run_id}/case-report-export"] = (200, upstream_pdf, "application/pdf")
    monkeypatch.setitem(sys.modules, "weasyprint", None)

    response = await api.pdf(run_id)

    _assert_pdf(response)
    assert response.content == upstream_pdf
    assert len(api.agents.requests) == 1
    assert parse_qs(urlsplit(api.agents.requests[0][1]).query)["try_pdf"] == ["true"]
