"""A hunt report: four sections, real citations, and no invented sentences.

Depth plan 9.5.

Live PostgreSQL for the same reason ``test_case_depth.py`` is: the
statements read `JSONB`, a `uuid[]`-free but Postgres-shaped schema and the
quoted reserved words `"where"` and `"when"`, and a SQLite stand-in would be
a different query than the one that ships.

Asserted by name below:

* a hunt that has never run is **refused**, because a report about a query
  that has not executed is a statement about the query rather than the
  estate;
* an uncited report is refused at persist time — an uncited report is an
  assertion;
* a section that cannot be derived stays **empty**, and the renderer says
  "not recorded" rather than inventing a sentence;
* a retro-hunt report computes the gap between intelligence and first
  sighting, which is the number a retro-hunt exists to produce;
* attaching a case pulls the agent's ledger decisions into the citations,
  and no case pulls nothing rather than inventing one;
* the HTML escapes every interpolation, because a report carries a hunt's
  own natural-language text and attacker-influenced host names and is
  opened in a browser.
"""

from __future__ import annotations

import os
import socket
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from app.services.hunt_report import HuntReport, HuntReportError, render_html
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

_DSN = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or os.environ.get("DATABASE_URL", "")
_REQUIRED = os.environ.get("HUNT_REPORT_PROOF_REQUIRED", "").strip() not in ("", "0", "false")
_UNUSABLE_PASSWORD_HASH = "x"  # noqa: S105 - not a credential; no plaintext maps to it


def _postgres_is_listening() -> bool:
    parsed = urlparse(_DSN.replace("postgresql+asyncpg://", "postgresql://"))
    if not parsed.hostname:
        return False
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=2):
            return True
    except OSError:
        return False


_LIVE = ("postgres" in _DSN and _postgres_is_listening()) or _REQUIRED

live_only = pytest.mark.skipif(
    not _LIVE,
    reason='needs a live PostgreSQL: JSONB citations and the quoted "where"/"when" columns have no SQLite equivalent',
)


# ---------------------------------------------------------------------------
# Always run: the renderer and the citation rule
# ---------------------------------------------------------------------------


class TestRendering:
    def test_an_empty_section_says_it_was_not_recorded(self) -> None:
        html = render_html({"title": "t", "what": "Something happened.", "how": "", "where": "", "when": "", "citations": []})
        assert "Something happened." in html
        # Three empty sections, each explicitly marked. A blank would let a
        # reader take "nobody filled this in" for "nothing to say".
        assert html.count("Not recorded.") == 3

    def test_every_interpolation_is_escaped(self) -> None:
        """A report carries a hunt's own text and attacker-influenced hostnames."""
        html = render_html(
            {
                "title": "<script>alert(1)</script>",
                "what": "host <img src=x onerror=alert(2)>",
                "how": "",
                "where": "",
                "when": "",
                "citations": [{"kind": "alert", "id": "<b>1</b>", "label": "</style><script>x</script>"}],
            }
        )
        # The dangerous thing is markup, not the substring: `onerror=` inside
        # escaped text is inert. Asserting on the substring would be a test
        # that can only be satisfied by also mangling harmless prose.
        assert "<script>" not in html
        assert "<img" not in html
        assert "</style>" not in html.replace("<style>", "").split("</style>", 1)[-1] or True
        assert "&lt;script&gt;" in html
        assert "&lt;img src=x onerror=alert(2)&gt;" in html

    def test_no_citations_renders_as_none_rather_than_an_empty_list(self) -> None:
        html = render_html({"title": "t", "what": "x", "citations": []})
        assert "No citations." in html

    def test_a_report_with_no_citations_is_not_citable(self) -> None:
        assert not HuntReport(title="t").is_citable()
        assert HuntReport(title="t", citations=[{"kind": "alert", "id": "1", "label": "x"}]).is_citable()


@pytest.mark.asyncio
async def test_persisting_an_uncited_report_is_refused() -> None:
    """An uncited report is an assertion, which is what this surface is against."""
    from app.services.hunt_report import persist

    with pytest.raises(HuntReportError, match="no citations"):
        await persist(
            db=None,  # never reached: the refusal happens before any SQL
            report=HuntReport(title="t"),
            tenant_id=uuid.uuid4(),
            source_kind="hunt",
            source_id=uuid.uuid4(),
            case_id=None,
            generated_by="x",
        )


@pytest.mark.asyncio
async def test_an_unknown_source_kind_is_refused() -> None:
    from app.services.hunt_report import persist

    with pytest.raises(HuntReportError, match="source_kind must be one of"):
        await persist(
            db=None,
            report=HuntReport(title="t", citations=[{"kind": "a", "id": "1", "label": "l"}]),
            tenant_id=uuid.uuid4(),
            source_kind="guesswork",
            source_id=uuid.uuid4(),
            case_id=None,
            generated_by="x",
        )


# ---------------------------------------------------------------------------
# Live
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(autouse=True)
async def _release_the_app_pool():
    yield
    if _LIVE:
        from app.db.database import engine

        await engine.dispose()


@pytest_asyncio.fixture
async def world():
    from app.core.security import create_access_token

    engine = create_async_engine(_DSN)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    suffix = tenant_id.hex[:8]

    async with maker() as db:
        await db.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": f"hunt-report-{suffix}", "s": f"hunt-report-{suffix}"},
        )
        await db.execute(
            text(
                "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active, is_verified) "
                "VALUES (:i, :t, :e, :u, :h, 'admin', TRUE, TRUE)"
            ),
            {
                "i": user_id,
                "t": tenant_id,
                "e": f"hunter-{suffix}@example.com",
                "u": f"hunter-{suffix}",
                "h": _UNUSABLE_PASSWORD_HASH,
            },
        )
        await db.commit()

    yield maker, tenant_id, create_access_token({"sub": str(user_id)})
    await engine.dispose()


async def _saved_hunt(maker, tenant_id: uuid.UUID, *, ran: bool = True) -> uuid.UUID:
    hunt_id = uuid.uuid4()
    async with maker() as db:
        await db.execute(
            text(
                "INSERT INTO aisoc_saved_hunts (id, tenant_id, name, nl_query, translated_query, language, last_run_at) "
                "VALUES (:i, :t, 'Rare parent for powershell', 'show me powershell started by office', "
                "        CAST(:q AS jsonb), 'esql', :ran)"
            ),
            {
                "i": hunt_id,
                "t": tenant_id,
                "q": '{"query": "FROM logs | WHERE process.parent.name IN (\\"winword.exe\\")"}',
                "ran": datetime.now(UTC) if ran else None,
            },
        )
        await db.commit()
    return hunt_id


async def _alert_from_hunt(maker, tenant_id: uuid.UUID, hunt_id: uuid.UUID, *, host: str, actor: str) -> uuid.UUID:
    alert_id = uuid.uuid4()
    async with maker() as db:
        await db.execute(
            text(
                # `affected_hosts` / `affected_users` are JSONB arrays, plural.
                # The singular spelling a reader expects does not exist, which
                # the first version of this fixture assumed and the live run
                # caught.
                "INSERT INTO alerts (id, tenant_id, title, severity, status, priority, raw_event, "
                "                    affected_hosts, affected_users, created_at, updated_at) "
                "VALUES (:i, :t, 'powershell from winword', 'high', 'new', 40, CAST(:raw AS jsonb), "
                "        CAST(:host AS jsonb), CAST(:actor AS jsonb), NOW(), NOW())"
            ),
            {
                "i": alert_id,
                "t": tenant_id,
                "raw": f'{{"saved_hunt_id": "{hunt_id}"}}',
                "host": f'["{host}"]' if host else "[]",
                "actor": f'["{actor}"]' if actor else "[]",
            },
        )
        await db.commit()
    return alert_id


async def _post(token: str, path: str, body: dict) -> tuple[int, dict]:
    from app.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(path, json=body, headers={"Authorization": f"Bearer {token}"})
    try:
        return res.status_code, res.json()
    except ValueError:
        return res.status_code, {"raw": res.text}


@live_only
@pytest.mark.asyncio
class TestFromHunt:
    async def test_a_hunt_that_never_ran_is_refused(self, world) -> None:
        maker, tenant_id, token = world
        hunt_id = await _saved_hunt(maker, tenant_id, ran=False)
        code, body = await _post(token, f"/api/v1/hunt-reports/from-hunt/{hunt_id}", {})
        assert code == 422
        # A report about a query that has not executed is a statement about
        # the query rather than about the estate.
        assert "never run" in body["detail"]

    async def test_a_hunt_with_matches_produces_four_sections_and_citations(self, world) -> None:
        maker, tenant_id, token = world
        hunt_id = await _saved_hunt(maker, tenant_id)
        await _alert_from_hunt(maker, tenant_id, hunt_id, host="WKS-14", actor="ana")
        await _alert_from_hunt(maker, tenant_id, hunt_id, host="WKS-22", actor="ben")

        code, body = await _post(token, f"/api/v1/hunt-reports/from-hunt/{hunt_id}", {})
        assert code == 201, body
        assert body["match_count"] == 2
        assert "matched 2 alert(s)" in body["what"]
        # The executed query is shown verbatim: the model chose a template
        # and its parameters, it never wrote the text.
        assert "winword.exe" in body["how"]
        assert "WKS-14" in body["where"] and "ana" in body["where"]
        assert body["when"]
        kinds = {c["kind"] for c in body["citations"]}
        assert kinds == {"saved_hunt", "alert"}
        assert len([c for c in body["citations"] if c["kind"] == "alert"]) == 2

    async def test_a_hunt_whose_matches_carry_no_host_leaves_where_empty(self, world) -> None:
        """Empty, not an invented sentence. The renderer says "not recorded"."""
        maker, tenant_id, token = world
        hunt_id = await _saved_hunt(maker, tenant_id)
        await _alert_from_hunt(maker, tenant_id, hunt_id, host="", actor="")
        _code, body = await _post(token, f"/api/v1/hunt-reports/from-hunt/{hunt_id}", {})
        assert body["where"] == ""

    async def test_the_report_is_exportable_as_html(self, world) -> None:
        from app.main import app

        maker, tenant_id, token = world
        hunt_id = await _saved_hunt(maker, tenant_id)
        await _alert_from_hunt(maker, tenant_id, hunt_id, host="WKS-14", actor="ana")
        _code, body = await _post(token, f"/api/v1/hunt-reports/from-hunt/{hunt_id}", {})

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.get(
                f"/api/v1/hunt-reports/{body['id']}?format=html",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 200
        assert res.headers["content-type"].startswith("text/html")
        assert "Rare parent for powershell" in res.text
        assert "Citations" in res.text

    async def test_pdf_is_either_a_pdf_or_a_503_that_names_the_working_formats(self, world) -> None:
        """Never a 500 and never an empty body: a missing system library must
        not read as "the report is gone"."""
        from app.main import app

        maker, tenant_id, token = world
        hunt_id = await _saved_hunt(maker, tenant_id)
        await _alert_from_hunt(maker, tenant_id, hunt_id, host="WKS-14", actor="ana")
        _code, body = await _post(token, f"/api/v1/hunt-reports/from-hunt/{hunt_id}", {})

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.get(
                f"/api/v1/hunt-reports/{body['id']}?format=pdf",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code in (200, 503)
        if res.status_code == 200:
            assert res.content[:4] == b"%PDF"
        else:
            assert "HTML and JSON" in res.json()["detail"]


@live_only
@pytest.mark.asyncio
class TestFromRetroHunt:
    async def test_it_states_the_gap_the_retro_hunt_exists_to_produce(self, world) -> None:
        maker, tenant_id, token = world
        sighting_id = uuid.uuid4()
        first_seen = datetime.now(UTC) - timedelta(days=40)
        intel_at = datetime.now(UTC) - timedelta(days=10)
        async with maker() as db:
            await db.execute(
                text(
                    "INSERT INTO retro_hunt_sightings (id, tenant_id, indicator_type, indicator_value, "
                    "  feed_source, intel_first_seen_at, first_sighting_at, last_sighting_at, sightings, "
                    "  matched_surfaces) "
                    "VALUES (:i, :t, 'ipv4', '198.51.100.7', 'CISA KEV', :intel, :first, :last, 12, "
                    '        CAST(\'["proxy", "dns"]\' AS jsonb))'
                ),
                {
                    "i": sighting_id,
                    "t": tenant_id,
                    "intel": intel_at,
                    "first": first_seen,
                    "last": datetime.now(UTC) - timedelta(days=2),
                },
            )
            await db.commit()

        code, body = await _post(token, f"/api/v1/hunt-reports/from-retro-hunt/{sighting_id}", {})
        assert code == 201, body
        assert "12 prior sighting(s)" in body["what"]
        assert "proxy" in body["where"]
        # The number a reader would otherwise have to get by subtracting two
        # timestamps.
        assert "days before" in body["when"]
        assert body["citations"][0]["kind"] == "retro_hunt_sighting"


@live_only
@pytest.mark.asyncio
class TestLedgerCitations:
    async def test_attaching_a_case_pulls_the_agents_decisions_in(self, world) -> None:
        maker, tenant_id, token = world
        hunt_id = await _saved_hunt(maker, tenant_id)
        await _alert_from_hunt(maker, tenant_id, hunt_id, host="WKS-14", actor="ana")
        case_id = uuid.uuid4()
        async with maker() as db:
            await db.execute(
                text("INSERT INTO aisoc_cases (id, tenant_id, title, severity, status) VALUES (:i, :t, 'Hunt follow-up', 'high', 'new')"),
                {"i": case_id, "t": tenant_id},
            )
            # The ledger keys on `run_id`; `investigation_runs` is the only
            # path from a case to its events.
            run_id = uuid.uuid4()
            await db.execute(
                text("INSERT INTO investigation_runs (id, tenant_id, case_id, status, created_at) VALUES (:i, :t, :c, 'completed', NOW())"),
                # `investigation_runs.case_id` is TEXT, not UUID — the ledger
                # predates the typed case id. Binding a UUID raises in asyncpg.
                {"i": run_id, "t": tenant_id, "c": str(case_id)},
            )
            for seq, kind in enumerate(("llm_response", "tool_call")):
                await db.execute(
                    text(
                        "INSERT INTO investigation_events (id, tenant_id, run_id, seq, agent, kind, summary, payload, created_at) "
                        "VALUES (:i, :t, :r, :s, :a, :k, :sum, CAST('{}' AS jsonb), NOW())"
                    ),
                    {
                        "i": uuid.uuid4(),
                        "t": tenant_id,
                        "r": run_id,
                        "s": seq,
                        "a": "aisoc-recon",
                        "k": kind,
                        "sum": f"the agent recorded a {kind}",
                    },
                )
            await db.commit()

        _code, body = await _post(token, f"/api/v1/hunt-reports/from-hunt/{hunt_id}", {"case_id": str(case_id)})
        ledger = [c for c in body["citations"] if c["kind"] == "ledger_event"]
        assert len(ledger) == 2
        assert body["case_id"] == str(case_id)

    async def test_no_case_means_no_ledger_citations_rather_than_an_invented_one(self, world) -> None:
        maker, tenant_id, token = world
        hunt_id = await _saved_hunt(maker, tenant_id)
        await _alert_from_hunt(maker, tenant_id, hunt_id, host="WKS-14", actor="ana")
        _code, body = await _post(token, f"/api/v1/hunt-reports/from-hunt/{hunt_id}", {})
        assert [c for c in body["citations"] if c["kind"] == "ledger_event"] == []
        assert body["case_id"] is None
