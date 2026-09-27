"""Tenant skills: what the parser refuses, what the lifecycle refuses, and who may read.

Gap-closure Phase 6.1 and 6.2 gate.

Five properties, each asserted by name below:

* the document refuses what a skill cannot be without: no owner, no expiry, no
  match block, no plan, no pivots, and any key the server owns
* ``expected_pivots`` is checked against the tools *this tenant* can call,
  which is the built-in set plus the tools on an enabled MCP server's
  allowlist, and the refusal tells the author which of the two reasons applies
* an edit bumps the version and drops the skill back to draft, detaching the
  backtest, so a report can never describe text nobody is running
* activation refuses every way of reaching it without a current backtest, and
  the message names which one
* the internal route is service-token only, and a valid console session is not
  enough

The database is a real one, the same way ``test_mcp_registry.py`` does it:
Postgres-only column types compile down to their SQLite equivalents so these
exercise the real statements rather than a stub that agrees with them.

The CHECK constraints do not compile to SQLite, so the lifecycle refusals here
are the *store's*. The migration states the same rule and
``scripts/check_tenant_skill_contract.py`` fails the build if either place
loses it, which is what keeps one from becoming the only guard.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import tenant_skills as endpoint_module
from app.api.v1.endpoints.tenant_skills import router as skills_router
from app.db.database import Base, get_db
from app.db.rls import get_tenant_db
from app.models.connector import Connector
from app.models.mcp_server import McpServer
from app.models.tenant_skill import ACTIVE, BACKTESTED, DRAFT, RETIRED, TenantSkill, TenantSkillVersion
from app.services.agent_tools import vendor_reads
from app.services.tenant_skills import store
from app.services.tenant_skills.models import SkillParseError, parse_skill_yaml
from app.services.tenant_skills.tools import BUILTIN_PIVOTS, ToolInventory, tool_inventory_for_tenant, validate_expected_pivots
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
OTHER_TENANT = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")
USER = uuid.UUID("11111111-1111-1111-1111-111111111111")

SERVICE_TOKEN = "service-token-for-the-agents-worker"

FAR_FUTURE = "2099-01-31"


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


@compiles(PgUUID, "sqlite")
def _uuid_sqlite(_type_, _compiler_, **_kw_):
    return "CHAR(36)"


def _yaml(
    *,
    skill_id: str = "finance-batch-powershell",
    guidance: str = "Finance runs a nightly reconciliation batch on FIN-APP hosts.",
    pivots: str = "[process_activity, process_tree]",
    expires_at: str = FAR_FUTURE,
    extra: str = "",
) -> str:
    return f"""
id: {skill_id}
name: Finance nightly batch
owner: soc-leads@example.invalid
expires_at: {expires_at}
match:
  techniques: [T1059.001]
  rule_ids: [rule-encoded-powershell]
guidance: >
  {guidance}
verdict_guidance: >
  Encoded PowerShell from svc_batch inside the window is a benign true positive.
plan:
  - List what executed on the host around the alert.
  - Establish the process lineage.
expected_pivots: {pivots}
min_pivots: 2
{extra}
""".strip()


def _one_pivot(pivot: str) -> str:
    """A document naming exactly one pivot, with the floor lowered to match."""
    return _yaml(pivots=f"[{pivot}]").replace("min_pivots: 2", "min_pivots: 1")


@pytest.fixture(autouse=True)
def _quiet_action_registry(monkeypatch):
    """No action registry in a unit test, and that must not read as an outage.

    ``tool_inventory_for_tenant`` asks the actions service which vendor read
    verbs a tenant has. Left alone it would reach the network on every save,
    time out, and set ``customer_unknown``, which would make every tool
    refusal in this file pass for the wrong reason. Tests that care about the
    unreachable branch construct that inventory directly.
    """

    async def _none(db, *, tenant_id):
        return []

    monkeypatch.setattr(vendor_reads, "available_reads", _none)
    yield


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        # Only these three. A whole-metadata create_all drags in models using
        # Postgres ARRAY, which SQLite cannot render.
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[TenantSkill.__table__, TenantSkillVersion.__table__, McpServer.__table__, Connector.__table__],
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


# ---------------------------------------------------------------------------
# The document
# ---------------------------------------------------------------------------


class TestParsing:
    """What a skill document cannot be without, and why each refusal exists."""

    def test_a_complete_document_parses_into_every_field(self) -> None:
        skill = parse_skill_yaml(_yaml())
        assert skill.id == "finance-batch-powershell"
        assert skill.owner == "soc-leads@example.invalid"
        assert skill.match.techniques == ("T1059.001",)
        assert skill.match.rule_ids == ("rule-encoded-powershell",)
        assert skill.expected_pivots == ("process_activity", "process_tree")
        # A bare date means end of day, not midnight: a skill written to
        # expire "on the 31st" that stops working on the evening of the 30th
        # is a surprise nobody asked for.
        assert skill.expires_at == datetime(2099, 1, 31, 23, 59, 59, tzinfo=UTC)

    @pytest.mark.parametrize(
        ("drop", "fragment"),
        [
            ("owner", "someone to ask"),
            ("expires_at", "stops being true"),
            ("match", "every alert in the tenant"),
            ("plan", "cannot steer an investigation"),
            ("expected_pivots", "cannot be graded"),
        ],
    )
    def test_the_fields_a_skill_cannot_be_without(self, drop: str, fragment: str) -> None:
        """Each refusal carries the reason, not just the field name.

        An author told "owner is required" adds a placeholder. One told why it
        is required puts a name in it.
        """
        # ``min_pivots`` goes too, so dropping ``expected_pivots`` reports the
        # missing pivots rather than a floor above a list of zero. The two
        # refusals are both correct and only the first one is the subject.
        source = _drop_block(_yaml(), drop)
        if drop == "expected_pivots":
            source = _drop_block(source, "min_pivots")
        with pytest.raises(SkillParseError) as exc:
            parse_skill_yaml(source)
        assert fragment in str(exc.value)

    @pytest.mark.parametrize("key", ["version", "status", "enabled", "tenant_id"])
    def test_a_key_the_server_owns_is_refused_by_name(self, key: str) -> None:
        with pytest.raises(SkillParseError) as exc:
            parse_skill_yaml(_yaml(extra=f"{key}: 3"))
        assert key in str(exc.value)

    def test_an_unknown_key_is_refused_rather_than_ignored(self) -> None:
        """A typo in a field name is a skill that silently does half its job.

        ``verdict_guidence`` parses fine if unknown keys are ignored, and the
        author has no way to find out short of reading a prompt.
        """
        with pytest.raises(SkillParseError) as exc:
            parse_skill_yaml(_yaml(extra="verdict_guidence: oops"))
        assert "verdict_guidence" in str(exc.value)

    def test_an_empty_match_block_is_refused(self) -> None:
        source = _drop_block(_yaml(), "match") + "\nmatch: {}"
        with pytest.raises(SkillParseError) as exc:
            parse_skill_yaml(source)
        assert "every alert in the tenant" in str(exc.value)

    def test_a_technique_that_is_not_a_technique_id_is_refused(self) -> None:
        source = _drop_block(_yaml(), "match") + "\nmatch:\n  techniques: [powershell]"
        with pytest.raises(SkillParseError) as exc:
            parse_skill_yaml(source)
        assert "T1059" in str(exc.value)

    def test_min_pivots_above_the_pivot_count_is_refused(self) -> None:
        """A floor nothing can reach grades every run as shallow."""
        with pytest.raises(SkillParseError) as exc:
            parse_skill_yaml(_yaml(pivots="[process_activity]", extra="").replace("min_pivots: 2", "min_pivots: 4"))
        assert "min_pivots" in str(exc.value)


def _drop_block(source: str, key: str) -> str:
    """Remove a top-level YAML block and everything indented under it."""
    out: list[str] = []
    skipping = False
    for line in source.splitlines():
        if line.startswith(f"{key}:"):
            skipping = True
            continue
        if skipping and (line.startswith((" ", "\t", "-")) or not line.strip()):
            continue
        skipping = False
        out.append(line)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


class TestToolValidation:
    """A skill may only name a tool this tenant's agent can call."""

    def test_a_builtin_pivot_is_accepted(self) -> None:
        validate_expected_pivots(parse_skill_yaml(_yaml()), ToolInventory())

    def test_a_customer_tool_the_tenant_has_no_product_for_says_to_connect_one(self) -> None:
        """Phase 4's typed surface is per tenant, so a real name can still be wrong here.

        The message has to separate this from a typo: one is fixed by editing
        the document, the other by connecting a product.
        """
        skill = parse_skill_yaml(_one_pivot("edr_host_details"))
        with pytest.raises(SkillParseError) as exc:
            validate_expected_pivots(skill, ToolInventory())
        assert "no connected product behind that tool" in str(exc.value)

        validate_expected_pivots(skill, ToolInventory(customer=frozenset({"edr_host_details"})))

    def test_a_known_customer_tool_is_accepted_while_the_registry_is_unknown(self) -> None:
        """Could not check is not you do not have it.

        Refusing here would tell an author their EDR is not connected because
        a different service was briefly down, and they would delete a correct
        line from their document.
        """
        unknown = ToolInventory(customer_unknown=True, customer_unknown_reason="the action registry timed out")
        validate_expected_pivots(parse_skill_yaml(_one_pivot("edr_host_details")), unknown)

        # A name that is no tool at all is still a typo, and still refused.
        with pytest.raises(SkillParseError) as exc:
            validate_expected_pivots(parse_skill_yaml(_one_pivot("edr_host_detailz")), unknown)
        assert "not a tool this deployment has" in str(exc.value)

    def test_a_misspelt_builtin_names_the_available_ones(self) -> None:
        skill = parse_skill_yaml(_one_pivot("proccess_activity"))
        with pytest.raises(SkillParseError) as exc:
            validate_expected_pivots(skill, ToolInventory())
        message = str(exc.value)
        assert "proccess_activity" in message
        assert "process_activity" in message
        assert "mcp.<server>.<tool>" in message
        assert "edr_host_details" in message

    def test_an_mcp_tool_the_tenant_has_not_allowlisted_says_what_to_do(self) -> None:
        """The author's next action differs completely between the two reasons.

        A typo needs a correction. A tool on a server nobody enabled needs a
        registry change, and being told "not a built-in tool" would send the
        author looking for a spelling mistake that is not there.
        """
        skill = parse_skill_yaml(_one_pivot("mcp.crowdstrike.get_detections"))
        with pytest.raises(SkillParseError) as exc:
            validate_expected_pivots(skill, ToolInventory())
        assert "allowlists that tool" in str(exc.value)

    @pytest.mark.asyncio
    async def test_the_inventory_is_built_from_enabled_servers_only(self, session_factory) -> None:
        async with session_factory() as db:
            db.add_all(
                [
                    McpServer(
                        tenant_id=TENANT,
                        name="crowdstrike",
                        transport="streamable_http",
                        url="https://mcp.example.invalid",
                        tool_allowlist=["get_detections"],
                        timeout_seconds=20,
                        max_response_bytes=65536,
                        enabled=True,
                    ),
                    # Registered but not enabled: offers nothing to an
                    # investigation, so a skill must not be able to name it.
                    McpServer(
                        tenant_id=TENANT,
                        name="sentinelone",
                        transport="streamable_http",
                        url="https://mcp2.example.invalid",
                        tool_allowlist=["get_threats"],
                        timeout_seconds=20,
                        max_response_bytes=65536,
                        enabled=False,
                    ),
                    # Another tenant's, which must not appear at all.
                    McpServer(
                        tenant_id=OTHER_TENANT,
                        name="splunk",
                        transport="streamable_http",
                        url="https://mcp3.example.invalid",
                        tool_allowlist=["search"],
                        timeout_seconds=20,
                        max_response_bytes=65536,
                        enabled=True,
                    ),
                ]
            )
            await db.commit()

            inventory = await tool_inventory_for_tenant(db, TENANT)

        assert inventory.mcp == frozenset({"mcp.crowdstrike.get_detections"})
        assert inventory.builtin == BUILTIN_PIVOTS
        validate_expected_pivots(parse_skill_yaml(_one_pivot("mcp.crowdstrike.get_detections")), inventory)
        with pytest.raises(SkillParseError):
            validate_expected_pivots(parse_skill_yaml(_one_pivot("mcp.sentinelone.get_threats")), inventory)
        with pytest.raises(SkillParseError):
            validate_expected_pivots(parse_skill_yaml(_one_pivot("mcp.splunk.search")), inventory)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_a_new_skill_starts_at_version_one_and_draft(self, session_factory) -> None:
        async with session_factory() as db:
            row, created = await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            await db.commit()
            assert created is True
            assert (row.version, row.status) == (1, DRAFT)
            versions = await store.list_versions(db, TENANT, row.skill_id)
            assert [v.version for v in versions] == [1]

    @pytest.mark.asyncio
    async def test_reformatting_keeps_the_version_and_the_backtest(self, session_factory) -> None:
        """Comparison is on the parsed body, not on the YAML text.

        An author who reflows a comment has not changed what the agent reads,
        and bumping the version there would invalidate a backtest over nothing.
        """
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            await store.attach_backtest(
                db,
                tenant_id=TENANT,
                skill_id="finance-batch-powershell",
                baseline_evaluation_id=uuid.uuid4(),
                candidate_evaluation_id=uuid.uuid4(),
            )
            await db.commit()

            reformatted = _yaml() + "\n# a comment the agent never reads\n"
            row, created = await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=reformatted)
            await db.commit()

            assert created is False
            assert row.version == 1
            assert row.status == BACKTESTED
            assert row.backtest_evaluation_id is not None

    @pytest.mark.asyncio
    async def test_a_content_edit_bumps_the_version_and_detaches_the_backtest(self, session_factory) -> None:
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            await store.attach_backtest(
                db,
                tenant_id=TENANT,
                skill_id="finance-batch-powershell",
                baseline_evaluation_id=uuid.uuid4(),
                candidate_evaluation_id=uuid.uuid4(),
            )
            await db.commit()

            row, _ = await store.save_skill(
                db,
                tenant_id=TENANT,
                author_id=USER,
                source_yaml=_yaml(guidance="The batch moved to 03:00 UTC."),
            )
            await db.commit()

            assert row.version == 2
            assert row.status == DRAFT
            assert row.backtest_evaluation_id is None
            assert row.backtest_version is None
            # Both versions survive, which is what makes a recorded
            # ``skill@v1`` on a months-old verdict resolvable.
            assert [v.version for v in await store.list_versions(db, TENANT, row.skill_id)] == [2, 1]

    @pytest.mark.asyncio
    async def test_activation_refuses_a_skill_with_no_backtest(self, session_factory) -> None:
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            await db.commit()
            with pytest.raises(store.SkillLifecycleError) as exc:
                await store.activate_skill(db, tenant_id=TENANT, skill_id="finance-batch-powershell", actor_id=USER)
        assert "no backtest attached" in str(exc.value)

    @pytest.mark.asyncio
    async def test_activation_refuses_a_backtest_of_a_different_version(self, session_factory) -> None:
        """The refusal this whole ladder exists for.

        Backtest at v1, edit to v2, activate: without this check the report on
        the activation describes text nobody is running.
        """
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            await store.attach_backtest(
                db,
                tenant_id=TENANT,
                skill_id="finance-batch-powershell",
                baseline_evaluation_id=uuid.uuid4(),
                candidate_evaluation_id=uuid.uuid4(),
            )
            await db.commit()
            # Re-attaching is what a re-run does; here the edit happens after
            # the backtest and nothing re-runs it.
            row = await store.get_skill(db, TENANT, "finance-batch-powershell")
            row.version = 2
            await db.commit()

            with pytest.raises(store.SkillLifecycleError) as exc:
                await store.activate_skill(db, tenant_id=TENANT, skill_id="finance-batch-powershell", actor_id=USER)
        assert "graded version 1" in str(exc.value)
        assert "version 2" in str(exc.value)

    @pytest.mark.asyncio
    async def test_activation_refuses_an_expired_skill(self, session_factory) -> None:
        """Activating an expired skill would be a no-op that looks like a change."""
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml(expires_at="2020-01-01"))
            await store.attach_backtest(
                db,
                tenant_id=TENANT,
                skill_id="finance-batch-powershell",
                baseline_evaluation_id=uuid.uuid4(),
                candidate_evaluation_id=uuid.uuid4(),
            )
            await db.commit()
            with pytest.raises(store.SkillLifecycleError) as exc:
                await store.activate_skill(db, tenant_id=TENANT, skill_id="finance-batch-powershell", actor_id=USER)
        assert "expired" in str(exc.value)

    @pytest.mark.asyncio
    async def test_one_evaluation_cannot_be_its_own_baseline(self, session_factory) -> None:
        """A delta of zero by construction would read as a skill that changed nothing."""
        shared = uuid.uuid4()
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            await db.commit()
            with pytest.raises(store.SkillLifecycleError) as exc:
                await store.attach_backtest(
                    db,
                    tenant_id=TENANT,
                    skill_id="finance-batch-powershell",
                    baseline_evaluation_id=shared,
                    candidate_evaluation_id=shared,
                )
        assert "same evaluation" in str(exc.value)

    @pytest.mark.asyncio
    async def test_activation_stamps_the_version_row_with_the_backtest(self, session_factory) -> None:
        """ "Its backtest report is attached to its activation" is this assertion."""
        baseline, candidate = uuid.uuid4(), uuid.uuid4()
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            await store.attach_backtest(
                db,
                tenant_id=TENANT,
                skill_id="finance-batch-powershell",
                baseline_evaluation_id=baseline,
                candidate_evaluation_id=candidate,
            )
            row = await store.activate_skill(db, tenant_id=TENANT, skill_id="finance-batch-powershell", actor_id=USER)
            await db.commit()

            assert row.status == ACTIVE
            assert row.activated_at is not None
            version_row = (await store.list_versions(db, TENANT, "finance-batch-powershell"))[0]

        assert version_row.version == 1
        assert version_row.backtest_evaluation_id == candidate
        assert version_row.backtest_baseline_id == baseline
        assert version_row.activated_at is not None

    @pytest.mark.asyncio
    async def test_an_expired_active_skill_is_not_served_to_the_agent(self, session_factory) -> None:
        """Expiry is applied in the query, so a skill stops steering the moment it lapses."""
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            await store.attach_backtest(
                db,
                tenant_id=TENANT,
                skill_id="finance-batch-powershell",
                baseline_evaluation_id=uuid.uuid4(),
                candidate_evaluation_id=uuid.uuid4(),
            )
            await store.activate_skill(db, tenant_id=TENANT, skill_id="finance-batch-powershell", actor_id=USER)
            await db.commit()

            assert len(await store.resolve_active_skills(db, TENANT)) == 1
            # The same rows, read a day after the expiry.
            later = datetime(2099, 2, 1, tzinfo=UTC)
            assert await store.resolve_active_skills(db, TENANT, now=later) == []

    @pytest.mark.asyncio
    async def test_a_retired_skill_keeps_its_history_and_stops_being_served(self, session_factory) -> None:
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            await store.attach_backtest(
                db,
                tenant_id=TENANT,
                skill_id="finance-batch-powershell",
                baseline_evaluation_id=uuid.uuid4(),
                candidate_evaluation_id=uuid.uuid4(),
            )
            await store.activate_skill(db, tenant_id=TENANT, skill_id="finance-batch-powershell", actor_id=USER)
            row = await store.retire_skill(db, tenant_id=TENANT, skill_id="finance-batch-powershell")
            await db.commit()

            assert row.status == RETIRED
            assert await store.resolve_active_skills(db, TENANT) == []
            history = await store.list_versions(db, TENANT, "finance-batch-powershell")

        assert len(history) == 1
        assert history[0].retired_at is not None
        # Still resolvable, which is the reason retire exists beside delete.
        assert history[0].body["guidance"]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _app(session_factory, *, user: CurrentUser | None) -> FastAPI:
    app = FastAPI()
    app.include_router(skills_router, prefix="/api/v1")

    async def _db():
        async with session_factory() as session:
            yield session

    # Both, deliberately: ``TenantDBSession`` resolves through
    # ``get_tenant_db`` rather than ``get_db``, so overriding only the latter
    # leaves the console routes reaching for a real Postgres.
    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_tenant_db] = _db
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


def _console_user() -> CurrentUser:
    return CurrentUser(user_id=USER, tenant_id=TENANT, role="tenant_admin", email="admin@example.invalid", scopes=["*"])


@pytest.fixture
def _service_token(monkeypatch):
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", SERVICE_TOKEN)

    async def _noop(_db, _tenant):
        return None

    # The route sets the RLS GUC, which SQLite has no notion of.
    monkeypatch.setattr(endpoint_module, "set_rls_context", _noop)
    yield


class TestRoutes:
    def test_validate_returns_a_readable_failure_rather_than_a_422(self, session_factory) -> None:
        """The editor calls this as the author types.

        An error status on a half-typed document is a failed request in the
        network tab every few seconds, which is why the save route carries the
        422 and this one does not.
        """
        client = TestClient(_app(session_factory, user=_console_user()))
        response = client.post("/api/v1/tenant-skills/validate", json={"source_yaml": _one_pivot("nope")})
        assert response.status_code == 200
        body = response.json()
        assert body["valid"] is False
        assert "nope" in body["error"]
        assert "process_activity" in body["available_tools"]["builtin"]

    def test_saving_an_invalid_document_is_a_422_with_the_message_verbatim(self, session_factory) -> None:
        client = TestClient(_app(session_factory, user=_console_user()))
        response = client.put("/api/v1/tenant-skills", json={"source_yaml": _one_pivot("nope")})
        assert response.status_code == 422
        assert "nope" in response.json()["detail"]

    def test_save_then_read_then_version_history(self, session_factory) -> None:
        client = TestClient(_app(session_factory, user=_console_user()))
        assert client.put("/api/v1/tenant-skills", json={"source_yaml": _yaml()}).status_code == 200

        listed = client.get("/api/v1/tenant-skills").json()
        assert [s["skill_id"] for s in listed["skills"]] == ["finance-batch-powershell"]
        assert listed["skills"][0]["status"] == "draft"
        assert listed["skills"][0]["expired"] is False

        versions = client.get("/api/v1/tenant-skills/finance-batch-powershell/versions").json()
        assert [v["version"] for v in versions] == [1]
        assert versions[0]["source_yaml"].startswith("id: finance-batch-powershell")

    def test_activating_without_a_backtest_is_a_409_naming_the_reason(self, session_factory) -> None:
        client = TestClient(_app(session_factory, user=_console_user()))
        client.put("/api/v1/tenant-skills", json={"source_yaml": _yaml()})
        response = client.post("/api/v1/tenant-skills/finance-batch-powershell/activate")
        assert response.status_code == 409
        assert "no backtest attached" in response.json()["detail"]

    def test_another_tenants_skill_is_a_404_rather_than_a_read(self, session_factory) -> None:
        client = TestClient(_app(session_factory, user=_console_user()))
        client.put("/api/v1/tenant-skills", json={"source_yaml": _yaml()})

        other = CurrentUser(user_id=uuid.uuid4(), tenant_id=OTHER_TENANT, role="tenant_admin", email="other@example.invalid", scopes=["*"])
        other_client = TestClient(_app(session_factory, user=other))
        assert other_client.get("/api/v1/tenant-skills/finance-batch-powershell").status_code == 404
        assert other_client.get("/api/v1/tenant-skills").json()["skills"] == []

    def test_the_internal_route_refuses_a_missing_token(self, session_factory, _service_token) -> None:
        client = TestClient(_app(session_factory, user=None))
        response = client.get("/api/v1/tenant-skills/resolved/active", params={"tenant_id": str(TENANT)})
        assert response.status_code == 401

    def test_the_internal_route_refuses_a_valid_console_session(self, session_factory, _service_token) -> None:
        """A session is a credential for the console routes, not for this one.

        The route has exactly one caller, and a route with one caller should
        accept one kind of credential.
        """
        client = TestClient(_app(session_factory, user=_console_user()))
        response = client.get("/api/v1/tenant-skills/resolved/active", params={"tenant_id": str(TENANT)})
        assert response.status_code == 401

    def test_the_internal_route_serves_only_active_unexpired_skills_for_the_named_tenant(self, session_factory, _service_token) -> None:
        console = TestClient(_app(session_factory, user=_console_user()))
        console.put("/api/v1/tenant-skills", json={"source_yaml": _yaml()})
        console.put("/api/v1/tenant-skills", json={"source_yaml": _yaml(skill_id="never-activated")})

        agent = TestClient(_app(session_factory, user=None))
        headers = {"X-AiSOC-Service-Token": SERVICE_TOKEN}
        before = agent.get("/api/v1/tenant-skills/resolved/active", params={"tenant_id": str(TENANT)}, headers=headers)
        assert before.status_code == 200
        # Draft skills steer nothing, so the agent is served none of them.
        assert before.json()["skills"] == []

        _activate(session_factory, "finance-batch-powershell")
        after = agent.get("/api/v1/tenant-skills/resolved/active", params={"tenant_id": str(TENANT)}, headers=headers)
        served = after.json()["skills"]
        assert [s["skill_id"] for s in served] == ["finance-batch-powershell"]
        assert served[0]["version"] == 1
        assert served[0]["body"]["plan"]

        # And nothing at all for a tenant that authored nothing.
        other = agent.get("/api/v1/tenant-skills/resolved/active", params={"tenant_id": str(OTHER_TENANT)}, headers=headers)
        assert other.json()["skills"] == []


def _activate(session_factory, skill_id: str) -> None:
    """Attach a backtest and activate, outside the route, for route tests.

    The backtest route starts two real replay evaluations against a connector,
    which is a different subject. These tests are about what the *resolved*
    route serves once a skill is active.
    """
    import asyncio

    async def _run() -> None:
        async with session_factory() as db:
            await store.attach_backtest(
                db,
                tenant_id=TENANT,
                skill_id=skill_id,
                baseline_evaluation_id=uuid.uuid4(),
                candidate_evaluation_id=uuid.uuid4(),
            )
            await store.activate_skill(db, tenant_id=TENANT, skill_id=skill_id, actor_id=USER)
            await db.commit()

    asyncio.run(_run())


def test_the_expiry_shown_to_the_console_is_computed_not_inferred_from_status() -> None:
    """An active-but-expired skill steers nothing, and the console must say so.

    A console that showed only ``status`` would report the skill as working
    while the resolver silently drops it, which is the exact shape of failure
    an operator cannot diagnose.
    """
    row = TenantSkill(
        tenant_id=TENANT,
        skill_id="lapsed",
        version=1,
        status=ACTIVE,
        name="Lapsed",
        owner="soc@example.invalid",
        expires_at=datetime.now(UTC) - timedelta(days=1),
        body={},
        source_yaml="",
    )
    model = endpoint_module._to_model(row, now=datetime.now(UTC))
    assert model.status == ACTIVE
    assert model.expired is True
