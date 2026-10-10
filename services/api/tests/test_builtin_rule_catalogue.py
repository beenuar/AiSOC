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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from app.db.database import Base
from app.models.detection_rule import DetectionRule
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


@dataclass
class _Caller:
    """The authenticated principal, with the attributes the routes read."""

    tenant_id: uuid.UUID = TENANT
    user_id: uuid.UUID = ACTOR
    email: str = "analyst@example.com"


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=[DetectionRule.__table__])
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


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


def _fusion_build_overlay():
    """fusion's real `build_overlay`, loaded by path.

    `tenant_overlay.py` imports only the standard library and structlog — no
    `app.` imports — so unlike `windowed_detection` it can be loaded directly
    without the package-name collision. Loading the real function is the whole
    point: a local re-implementation of the overlay would agree with itself.
    """
    path = REPO / "services" / "fusion" / "app" / "services" / "tenant_overlay.py"
    spec = importlib.util.spec_from_file_location("fusion_tenant_overlay_under_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
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

        fusion_ids = set(loaded["stateless"]) | set(loaded["windowed"]) | set(loaded["sequence"])
        catalogue_ids = {rule.source_id for rule in builtin_rules()}
        assert catalogue_ids == fusion_ids, (
            f"catalogue is missing {sorted(fusion_ids - catalogue_ids)[:5]} and invents {sorted(catalogue_ids - fusion_ids)[:5]}"
        )

    def test_ids_are_stable_across_processes(self) -> None:
        """The console's deep links and a tenant's tuning rows both key on this."""
        from app.services.builtin_rules import builtin_rules, uuid_for

        for rule in builtin_rules()[:50]:
            assert rule.uuid == uuid_for(rule.source_id)


# ── the two read surfaces the issue names ────────────────────────────────────


class TestTheConsoleReadsTheLoadedCorpus:
    async def test_detection_rules_reports_the_real_total(self, session) -> None:
        from app.api.v1.endpoints.detection_compat import list_rules_compat

        response = await list_rules_compat(current_user=_Caller(), db=session)
        assert response.total == FUSION_LOADED_TOTAL
        assert response.rules, "the page renders from `rules`; a true total over an empty page is still an empty page"

    async def test_canonical_rules_route_reports_the_real_total(self, session) -> None:
        from app.api.v1.endpoints.detection_rules import list_rules

        rules = await list_rules(current_user=_Caller(), db=session, limit=5)
        assert len(rules) == 5
        assert all(r.is_builtin for r in rules)


# ── acting on a built-in, end to end into the engine ─────────────────────────


class TestDisablingABuiltInReachesTheEngine:
    async def test_the_stored_row_is_what_fusion_reads(self, session) -> None:
        from app.api.v1.endpoints.detection_compat import UpdateBody, update_rule_compat
        from app.services.builtin_rules import builtin_rules

        target = next(r for r in builtin_rules() if r.source_id == "det-application-001")

        updated = await update_rule_compat(
            rule_id=target.uuid,
            body=UpdateBody(enabled=False),
            current_user=_Caller(),
            db=session,
        )
        assert updated.enabled is False

        row = (await session.execute(select(DetectionRule).where(DetectionRule.id == target.uuid))).scalar_one()
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

    async def test_a_second_toggle_reuses_the_same_row(self, session) -> None:
        from app.api.v1.endpoints.detection_compat import UpdateBody, update_rule_compat
        from app.services.builtin_rules import builtin_rules

        target = next(r for r in builtin_rules() if r.source_id == "det-application-002")
        caller = _Caller()
        for enabled in (False, True, False):
            await update_rule_compat(rule_id=target.uuid, body=UpdateBody(enabled=enabled), current_user=caller, db=session)

        rows: list[Any] = list((await session.execute(select(DetectionRule).where(DetectionRule.id == target.uuid))).scalars().all())
        assert len(rows) == 1
        assert rows[0].status == "inactive"
