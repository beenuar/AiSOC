"""The rules the engine runs have to be the rules the console can see and tune.

Issue #1273: a core install loads 2,586 detection rules into fusion and fires
them, while `GET /api/v1/rules` and `GET /api/v1/detection/rules` both answer
with an empty list, because both read the Postgres `detection_rules` table and
**nothing in production ever writes a built-in row there**. An operator could
not view, disable or tune a single rule that was alerting at them.

There are two independent halves and a fix that closes one is not a fix:

*Packaging.* The compiled artefacts live under `services/fusion/app/data/`.
The API image is built with `services/api` as its Docker context, so its
`COPY . .` has never seen them. "Just read the file" works in a checkout and
fails in every container — the same defect discussion #374 reported for
`marketplace/index.json`, solved there by committing a packaged copy inside
the build context and gating the two for byte-identity. The first test below
is therefore about the *image*, not about a handler: a handler test passes in
a source checkout whatever the image contains.

*Surfacing and acting.* Reading the catalogue is only half of what was
reported. Disabling a built-in has to reach the engine, and the engine does
not read an API response — it reads `detection_rules` rows through
`services/fusion/app/services/tenant_overlay.py`, keyed on
`provenance->>'source_id'`. So the last test writes through the real console
route and then hands the stored row to **fusion's own `build_overlay`**,
loaded by path from the fusion tree. A test that asserted the API returned
200 would pass over a row the engine ignores.

Counting is done against the artefacts and against fusion's real loaders in a
subprocess, never against a second call into the thing under test.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints.detection_compat import router as compat_router
from app.api.v1.endpoints.detection_rules import router as rules_router
from app.db.database import Base, get_db
from app.models.detection_rule import DetectionRule
from app.models.mssp import MSSPRuleOverride, MSSPRulePackAssignment, MSSPRulePackRule
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

REPO = Path(__file__).resolve().parents[3]
FUSION_DATA = REPO / "services" / "fusion" / "app" / "data"
PACKAGED = REPO / "services" / "api" / "app" / "data" / "detections"

#: The artefacts and the number of rules each holds today. Hard-coded so a
#: regeneration that silently empties one is a failure here rather than a
#: quieter comparison of two numbers that moved together.
ARTEFACTS: dict[str, int] = {
    "detection_ruleset.json": 741,
    "detection_ruleset_imported.json": 1770,
    "windowed_ruleset.json": 72,
}

#: Windowed rules declared in fusion's Python rather than in any artefact.
#: `load_window_rules()` seeds from these before reading the file, which is
#: why the loaded windowed count is 73 against a file holding 72.
PYTHON_RESIDENT_WINDOWED = 3

#: 741 + 1770 stateless, 73 windowed (70 of the 72 file entries plus the three
#: above), 2 sequence (the other two file entries). Measured, not assumed —
#: `test_catalogue_matches_what_fusion_actually_loads` re-derives it by running
#: fusion's loaders.
FUSION_LOADED_TOTAL = 2586

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000a173")
ACTOR = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000b173")


# ── sqlite stand-ins for the Postgres column types ───────────────────────────


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


@compiles(PgUUID, "sqlite")
def _uuid_sqlite(_type_, _compiler_, **_kw_):
    return "CHAR(36)"


def _caller() -> CurrentUser:
    """A real principal, so `require_permission` runs rather than being bypassed."""
    return CurrentUser(user_id=ACTOR, tenant_id=TENANT, role="admin", email="analyst@example.com")


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[DetectionRule.__table__, MSSPRuleOverride.__table__, MSSPRulePackAssignment.__table__, MSSPRulePackRule.__table__],
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def session(session_factory):
    async with session_factory() as s:
        yield s


@pytest_asyncio.fixture
async def client(session_factory):
    """The real routers behind a real ASGI app.

    Calling a handler as a function leaves every `Query(...)` default
    unresolved, so a filter reads a `Query` object instead of its value and
    the test grades a code path the server never takes. It cost one round
    here: `source in ("all", "builtin")` was False against the sentinel and
    the list came back empty for a reason production does not have.
    """
    app = FastAPI()
    app.include_router(compat_router, prefix="/api/v1")
    app.include_router(rules_router, prefix="/api/v1")

    async def _override_db():
        async with session_factory() as db:
            try:
                yield db
                await db.commit()
            except Exception:
                await db.rollback()
                raise

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_current_user] = _caller
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://rules.test") as http:
        yield http


def _artefact_ids(path: Path) -> set[str]:
    return {str(rule["id"]) for rule in json.loads(path.read_text(encoding="utf-8"))["rules"]}


def _python_resident_window_ids() -> set[str]:
    """`_BUILTIN_RULES` ids, read out of fusion's source without importing it.

    `windowed_detection` imports the fusion `app` package, and this test runs
    inside the API service whose top-level package is *also* `app`, so an
    import here would resolve the wrong tree. The declaration is a tuple of
    `WindowRule(...)` calls with literal keywords, which the AST answers
    exactly.
    """
    source = (REPO / "services" / "fusion" / "app" / "services" / "windowed_detection.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign) or not isinstance(node.target, ast.Name):
            continue
        if node.target.id != "_BUILTIN_RULES" or node.value is None:
            continue
        ids: set[str] = set()
        for call in getattr(node.value, "elts", []):
            if not isinstance(call, ast.Call):
                continue
            for keyword in call.keywords:
                if keyword.arg == "id" and isinstance(keyword.value, ast.Constant):
                    ids.add(str(keyword.value.value))
        return ids
    raise AssertionError("_BUILTIN_RULES is no longer a tuple literal in windowed_detection.py")


def _fusion_loaded_ids() -> dict[str, list[str]] | None:
    """Every rule id fusion's own loaders return, or None if fusion cannot run.

    A subprocess rather than an import: both services name their top-level
    package `app`, so importing fusion in this process shadows the service
    under test. `None` means fusion's dependencies are not installed in this
    interpreter, which is an environment fact and not a verdict — the callers
    below say so rather than passing quietly.
    """
    program = (
        "import json\n"
        "from app.services.detection_engine import _load_ruleset\n"
        "from app.services.windowed_detection import load_window_rules, load_sequence_rules\n"
        "print(json.dumps({\n"
        "  'stateless': [r['id'] for r in _load_ruleset()],\n"
        "  'windowed': [r.id for r in load_window_rules()],\n"
        "  'sequence': [r.id for r in load_sequence_rules()],\n"
        "}))\n"
    )
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", program],
        cwd=REPO / "services" / "fusion",
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        return None
    return json.loads(out.stdout.strip().splitlines()[-1])


def _target(source_id: str) -> tuple[Any, uuid.UUID]:
    """A compiled rule and the console id ``TENANT`` knows it by."""
    from app.services.builtin_rules import builtin_rules, uuid_for

    rule = next(r for r in builtin_rules() if r.source_id == source_id)
    return rule, uuid_for(source_id, TENANT)


def _fusion_build_overlay():
    """fusion's real `build_overlay`, loaded by path.

    `tenant_overlay.py` imports only the standard library and structlog — no
    `app.` imports — so unlike `windowed_detection` it can be loaded directly
    without the package-name collision. Loading the real function is the whole
    point: a local re-implementation of the overlay would agree with itself.
    """
    name = "fusion_tenant_overlay_under_test"
    path = REPO / "services" / "fusion" / "app" / "services" / "tenant_overlay.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Registered before execution: the module uses `from __future__ import
    # annotations`, so `@dataclass` resolves its string annotations through
    # `sys.modules[cls.__module__]` and raises on a module that is not there.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# ── packaging ────────────────────────────────────────────────────────────────


class TestTheCompiledCorpusTravelsInsideTheApiImage:
    """`services/api` is the build context, so the corpus has to live under it."""

    @pytest.mark.parametrize("name", sorted(ARTEFACTS))
    def test_packaged_copy_exists_and_is_byte_identical(self, name: str) -> None:
        canonical = FUSION_DATA / name
        packaged = PACKAGED / name
        assert canonical.is_file(), f"{canonical} is missing; fusion's own engine reads it"
        assert packaged.is_file(), (
            f"{packaged.relative_to(REPO)} is missing. The API image is built from services/api, "
            "so services/fusion/app/data is outside its COPY. Run "
            "`python3 scripts/sync_packaged_detection_rulesets.py`."
        )
        assert hashlib.sha256(packaged.read_bytes()).hexdigest() == hashlib.sha256(canonical.read_bytes()).hexdigest(), (
            f"{name}: the packaged copy and the copy fusion runs describe different corpora"
        )

    def test_python_resident_windowed_rules_are_exported_too(self) -> None:
        exported = PACKAGED / "windowed_builtin_rules.json"
        assert exported.is_file(), (
            f"{exported.relative_to(REPO)} is missing. Three windowed rules are declared in "
            "services/fusion/app/services/windowed_detection.py rather than in any artefact, so "
            "copying the three JSON files alone leaves the catalogue three rules short of what runs."
        )
        payload = json.loads(exported.read_text(encoding="utf-8"))
        assert {str(r["id"]) for r in payload["rules"]} == _python_resident_window_ids()


# ── the catalogue ────────────────────────────────────────────────────────────


class TestTheCatalogueIsTheLoadedCorpus:
    def test_counts_match_the_artefacts(self) -> None:
        from app.services.builtin_rules import builtin_rules

        rules = builtin_rules()
        by_ruleset: dict[str, int] = {}
        for rule in rules:
            by_ruleset[rule.ruleset] = by_ruleset.get(rule.ruleset, 0) + 1

        for name, expected in ARTEFACTS.items():
            assert by_ruleset.get(name) == expected, f"{name}: catalogue holds {by_ruleset.get(name)}, artefact holds {expected}"
        assert by_ruleset.get("windowed_builtin_rules.json") == PYTHON_RESIDENT_WINDOWED
        assert len(rules) == FUSION_LOADED_TOTAL

    def test_catalogue_matches_what_fusion_actually_loads(self) -> None:
        """Equality against the real loaders, not against the files they read."""
        from app.services.builtin_rules import builtin_rules

        loaded = _fusion_loaded_ids()
        if loaded is None:
            pytest.skip("fusion's runtime dependencies are not installed in this interpreter; counts above still graded")
        assert loaded is not None

        fusion_ids = set(loaded["stateless"]) | set(loaded["windowed"]) | set(loaded["sequence"])
        catalogue_ids = {rule.source_id for rule in builtin_rules()}
        assert catalogue_ids == fusion_ids, (
            f"catalogue is missing {sorted(fusion_ids - catalogue_ids)[:5]} and invents {sorted(catalogue_ids - fusion_ids)[:5]}"
        )

    def test_ids_are_stable_and_per_tenant(self) -> None:
        """Deep links and tuning rows key on this, and so does a primary key.

        Stable for one tenant across processes, and *different* between two.
        `detection_rules.id` is a primary key and the row is per tenant: a
        shared id means the second tenant to tune a built-in writes onto the
        first tenant's row. CI found that before this assertion existed.
        """
        from app.services.builtin_rules import builtin_rules, uuid_for

        other = uuid.UUID("cccccccc-0000-0000-0000-00000000c173")
        for rule in builtin_rules()[:50]:
            assert uuid_for(rule.source_id, TENANT) == uuid_for(rule.source_id, TENANT)
            assert uuid_for(rule.source_id, TENANT) != uuid_for(rule.source_id, other)


# ── the two read surfaces the issue names ────────────────────────────────────


class TestTheConsoleReadsTheLoadedCorpus:
    async def test_detection_rules_reports_the_real_total(self, client) -> None:
        body = (await client.get("/api/v1/detection/rules")).json()
        assert body["total"] == FUSION_LOADED_TOTAL
        assert body["builtinTotal"] == FUSION_LOADED_TOTAL
        assert body["rules"], "the page renders from `rules`; a true total over an empty page is still an empty page"
        assert body["catalogError"] is None
        assert body["missingArtefacts"] == []

    async def test_the_page_is_bounded_and_the_total_is_not(self, client) -> None:
        """2,586 rules serialised is several MB; the header count must still be true."""
        body = (await client.get("/api/v1/detection/rules", params={"limit": 25})).json()
        assert len(body["rules"]) == 25
        assert body["returned"] == 25
        assert body["total"] == FUSION_LOADED_TOTAL

    async def test_filters_run_server_side(self, client) -> None:
        body = (await client.get("/api/v1/detection/rules", params={"search": "SQL Injection", "limit": 5})).json()
        assert 0 < body["total"] < FUSION_LOADED_TOTAL
        assert all("sql injection" in r["name"].lower() or "sql injection" in (r["description"] or "").lower() for r in body["rules"])

    async def test_canonical_rules_route_returns_built_ins(self, client) -> None:
        response = await client.get("/api/v1/rules", params={"limit": 5})
        assert response.status_code == 200
        rules = response.json()
        assert len(rules) == 5
        assert all(r["is_builtin"] for r in rules)
        assert all(r["source_id"] for r in rules)
        assert all(r["engine"] == "aisoc-engine" for r in rules)
        assert response.headers["X-Total-Count"] == str(FUSION_LOADED_TOTAL)

    async def test_an_unscored_rule_says_so_instead_of_reporting_a_confidence(self, client) -> None:
        rules = (await client.get("/api/v1/rules", params={"limit": 5})).json()
        assert all(r["confidence_measured"] is False for r in rules)

        confidence = (await client.get("/api/v1/detection/confidence")).json()
        assert confidence["summary"]["unscored"] == FUSION_LOADED_TOTAL
        assert confidence["summary"]["totalRules"] == 0, "a mean over placeholders is a number nobody measured"

        drift = (await client.get("/api/v1/detection/drift")).json()
        assert drift["summary"]["unscored"] == FUSION_LOADED_TOTAL
        assert drift["entries"] == []

    async def test_coverage_is_drawn_from_the_loaded_corpus(self, client) -> None:
        coverage = (await client.get("/api/v1/detection/coverage")).json()
        assert coverage["summary"]["totalRules"] == FUSION_LOADED_TOTAL
        assert coverage["summary"]["coveredTechniques"] > 100


# ── acting on a built-in, end to end into the engine ─────────────────────────


class TestDisablingABuiltInReachesTheEngine:
    async def test_the_stored_row_is_what_fusion_reads(self, client, session) -> None:
        target, target_id = _target("det-application-001")

        response = await client.patch(f"/api/v1/detection/rules/{target_id}", json={"enabled": False})
        assert response.status_code == 200, response.text
        assert response.json()["enabled"] is False

        row = (await session.execute(select(DetectionRule).where(DetectionRule.id == target_id))).scalar_one()
        assert row.tenant_id == TENANT, "a tuning row must belong to the tenant that made it, never to the platform"
        assert row.status != "active"
        assert row.provenance.get("source_id") == target.source_id, (
            "fusion keys the overlay on provenance->>'source_id'; any other key is tuning the engine cannot see"
        )

        overlay_module = _fusion_build_overlay()
        overlay = overlay_module.build_overlay(
            str(TENANT),
            [
                {
                    "rule_id": row.provenance.get("source_id"),
                    "status": row.status,
                    "suppression_config": row.suppression_config,
                    "threshold_config": row.threshold_config,
                    "author": row.author,
                }
            ],
        )
        assert overlay.suppresses(target.source_id, {}) is not None, "fusion would keep firing the rule the console shows as disabled"

    async def test_a_second_toggle_reuses_the_same_row(self, client, session) -> None:
        target, target_id = _target("det-application-002")
        for enabled in (False, True, False):
            assert (await client.patch(f"/api/v1/detection/rules/{target_id}", json={"enabled": enabled})).status_code == 200

        rows: list[Any] = list((await session.execute(select(DetectionRule).where(DetectionRule.id == target_id))).scalars().all())
        assert len(rows) == 1
        assert rows[0].status == "inactive"

    async def test_the_library_still_reports_one_entry_for_a_tuned_rule(self, client) -> None:
        """A stored row beside its compiled twin would list the rule twice."""
        target, target_id = _target("det-application-003")
        await client.patch(f"/api/v1/detection/rules/{target_id}", json={"enabled": False})

        whole = (await client.get("/api/v1/detection/rules", params={"limit": 1})).json()
        assert whole["total"] == FUSION_LOADED_TOTAL, "tuning a rule must not grow the library"

        body = (await client.get("/api/v1/detection/rules", params={"search": target.name, "limit": 50})).json()
        matches = [r for r in body["rules"] if r["sourceId"] == target.source_id]
        assert len(matches) == 1
        assert matches[0]["enabled"] is False
        assert matches[0]["tuned"] is True

    async def test_bulk_toggle_no_longer_skips_every_rule_in_the_product(self, client) -> None:
        from app.services.builtin_rules import builtin_rules, uuid_for

        targets = [r for r in builtin_rules() if r.ruleset == "windowed_builtin_rules.json"]
        assert targets, "the Python-resident windowed rules are the ones a brute-force queue is loudest about"

        body = (
            await client.post(
                "/api/v1/detection/rules/bulk-toggle",
                json={"ruleIds": [str(uuid_for(r.source_id, TENANT)) for r in targets], "enabled": False},
            )
        ).json()
        assert body["updated"] == len(targets)
        assert body["skipped"] == []

    async def test_two_tenants_tuning_one_rule_get_two_rows(self, session_factory) -> None:
        """The corpus is shared; the decision is not, and the row is a primary key.

        Found by `scripts/check_tenant_query_predicates.py` on the first CI
        run of this change. The console id was derived from the compiled rule
        id alone, so the second tenant to disable a built-in resolved the
        *first* tenant's row: their change landed on nothing and their page
        rendered somebody else's state. The id carries the tenant now, and
        this is the assertion that keeps it there.
        """
        from app.services.builtin_rules import uuid_for

        other_tenant = uuid.UUID("cccccccc-0000-0000-0000-00000000c173")
        mine = uuid_for("det-application-005", TENANT)
        theirs = uuid_for("det-application-005", other_tenant)
        assert mine != theirs

        async def _db():
            async with session_factory() as db:
                try:
                    yield db
                    await db.commit()
                except Exception:
                    await db.rollback()
                    raise

        for tenant, rule_id, enabled in ((TENANT, mine, False), (other_tenant, theirs, True)):
            app = FastAPI()
            app.include_router(compat_router, prefix="/api/v1")
            app.dependency_overrides[get_db] = _db
            app.dependency_overrides[get_current_user] = lambda t=tenant: CurrentUser(
                user_id=ACTOR, tenant_id=t, role="admin", email=f"analyst@{t}.example.com"
            )
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://rules.test") as http:
                response = await http.patch(f"/api/v1/detection/rules/{rule_id}", json={"enabled": enabled})
                assert response.status_code == 200, response.text

        async with session_factory() as db:
            rows = list((await db.execute(select(DetectionRule))).scalars().all())
        tuned = {r.tenant_id: r.status for r in rows if (r.provenance or {}).get("source_id") == "det-application-005"}
        assert tuned == {TENANT: "inactive", other_tenant: "active"}

    async def test_the_compiled_logic_is_not_editable(self, client) -> None:
        """Storing an edit the engine will not run is the inverse of #1273."""
        target, target_id = _target("det-application-004")
        response = await client.patch(f"/api/v1/detection/rules/{target_id}", json={"body": "{}"})
        assert response.status_code == 409
        assert "compiled corpus" in response.json()["detail"]


# ── negative control: the surface must fail loudly, not quietly ──────────────


class TestAnUnreadableCorpusIsNotAnEmptyOne:
    """`0` and "cannot see the file" are different answers.

    The first is what #1273 reported, and it is the more damaging of the two:
    an operator reading "No detection rules yet" concludes their coverage is
    zero and stops. So the resolver raises rather than returning an empty
    tuple, and both the catalogue and the console route carry the reason.
    """

    @pytest.fixture
    def nowhere(self, tmp_path, monkeypatch):
        from app.services import builtin_rules as module

        monkeypatch.setattr(module, "_PACKAGED_DIR", tmp_path / "packaged")
        monkeypatch.setattr(module, "_FUSION_DIR", tmp_path / "fusion")
        module.reset_cache()
        yield
        module.reset_cache()

    def test_the_catalogue_refuses_rather_than_returning_nothing(self, nowhere) -> None:
        from app.services.builtin_rules import BuiltinCatalogueUnavailable, builtin_catalogue

        with pytest.raises(BuiltinCatalogueUnavailable) as raised:
            builtin_catalogue()
        assert "detection_ruleset.json" in str(raised.value), "the error has to name what it looked for"
        assert "sync_packaged_detection_rulesets" in str(raised.value), "and what to run"

    async def test_the_console_route_reports_the_failure(self, client, nowhere) -> None:
        body = (await client.get("/api/v1/detection/rules")).json()
        assert body["total"] == 0
        assert body["builtinTotal"] == 0
        assert body["catalogError"], "an empty list with no error reads as 'you have no detection rules'"
        assert "detection_ruleset.json" in body["catalogError"]

    async def test_a_partial_read_is_reported_as_partial(self, tmp_path, monkeypatch, client) -> None:
        """Three artefacts of four is a short library, not a smaller one."""
        from app.services import builtin_rules as module

        packaged = tmp_path / "packaged"
        packaged.mkdir()
        for name in ("detection_ruleset.json", "windowed_ruleset.json", "windowed_builtin_rules.json"):
            (packaged / name).write_bytes((PACKAGED / name).read_bytes())

        monkeypatch.setattr(module, "_PACKAGED_DIR", packaged)
        monkeypatch.setattr(module, "_FUSION_DIR", tmp_path / "fusion")
        module.reset_cache()
        try:
            body = (await client.get("/api/v1/detection/rules")).json()
            assert body["catalogError"] is None
            assert body["missingArtefacts"] == ["detection_ruleset_imported.json"]
            assert body["builtinTotal"] == FUSION_LOADED_TOTAL - ARTEFACTS["detection_ruleset_imported.json"]
        finally:
            module.reset_cache()


class TestThePackagedCopyAnswersOnItsOwn:
    """The container case, where `services/fusion/` does not exist at all.

    A source checkout has both copies and the resolver prefers fusion's, so
    every other test here could pass over a packaged copy that was never
    read. This one removes the preferred path, which is what the image does.
    """

    def test_the_corpus_resolves_with_no_fusion_tree(self, tmp_path, monkeypatch) -> None:
        from app.services import builtin_rules as module

        monkeypatch.setattr(module, "_FUSION_DIR", tmp_path / "no-such-fusion-tree")
        module.reset_cache()
        try:
            catalogue = module.builtin_catalogue()
            assert len(catalogue.rules) == FUSION_LOADED_TOTAL
            assert catalogue.missing == ()
            assert all(str(PACKAGED) in source for source in catalogue.sources)
        finally:
            module.reset_cache()
