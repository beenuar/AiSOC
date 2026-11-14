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
  the message names which one, including the two refusals that need the
  replay rows themselves: a run that did not complete, and a window holding
  no alert this skill's match block selects
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

import json
import sqlite3
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
from app.services.tenant_skills import backtest as skill_backtest
from app.services.tenant_skills import store
from app.services.tenant_skills.models import SkillParseError, parse_skill_yaml
from app.services.tenant_skills.tools import BUILTIN_PIVOTS, ToolInventory, tool_inventory_for_tenant, validate_expected_pivots
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

# The replay tables have no ORM model -- they are read and written through
# ``text()`` -- so their UUID parameters arrive at the driver as ``uuid.UUID``.
# asyncpg encodes those natively; sqlite3 refuses an unknown type outright, and
# the symptom is an InterfaceError rather than a wrong answer.
sqlite3.register_adapter(uuid.UUID, str)

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


#: The two replay tables activation now reads, reduced to the columns it
#: reads. Written out rather than created from metadata because migration 065
#: declares them in SQL and no ORM model exists to render; the column names and
#: types here are the ones the production statements bind against.
_REPLAY_DDL = (
    """
    CREATE TABLE aisoc_replay_evaluations (
        id        CHAR(36) PRIMARY KEY,
        tenant_id CHAR(36) NOT NULL,
        status    TEXT     NOT NULL,
        error     TEXT
    )
    """,
    """
    CREATE TABLE aisoc_replay_decisions (
        id                   INTEGER PRIMARY KEY AUTOINCREMENT,
        evaluation_id        CHAR(36) NOT NULL,
        tenant_id            CHAR(36) NOT NULL,
        finding_id           TEXT     NOT NULL,
        vendor               TEXT     NOT NULL DEFAULT '',
        rule_id              TEXT,
        expected_disposition TEXT     NOT NULL DEFAULT '',
        labelled             BOOLEAN  NOT NULL DEFAULT 0,
        verdict              TEXT,
        tier                 TEXT     NOT NULL DEFAULT '',
        decision             TEXT     NOT NULL DEFAULT '{}'
    )
    """,
)


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        # Only these four. A whole-metadata create_all drags in models using
        # Postgres ARRAY, which SQLite cannot render.
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[TenantSkill.__table__, TenantSkillVersion.__table__, McpServer.__table__, Connector.__table__],
        )
        for statement in _REPLAY_DDL:
            await conn.execute(sa_text(statement))
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _decision(
    *,
    finding_id: str,
    verdict: str,
    expected: str = "malicious",
    rule_id: str = "rule-unrelated",
    techniques: tuple[str, ...] = (),
    title: str = "Something happened",
    labelled: bool = True,
) -> dict:
    """One replayed decision, in the shape ``ReplayDecision.as_dict`` writes.

    ``evidence`` is the fused alert the agent was handed, which is where the
    source, the techniques and the title the match block reads come from.
    """
    return {
        "finding_id": finding_id,
        "vendor": "splunk",
        "rule_id": rule_id,
        "expected_disposition": expected,
        "labelled": labelled,
        "verdict": verdict,
        "tier": "llm",
        "evidence": {
            "title": title,
            "rule_id": rule_id,
            "connector_type": "splunk",
            "mitre_techniques": list(techniques),
        },
    }


async def _seed_evaluation(db, *, status: str, decisions: tuple[dict, ...] = (), error: str | None = None) -> uuid.UUID:
    """Insert one replay run and the decisions behind it. Returns its id."""
    evaluation_id = uuid.uuid4()
    await db.execute(
        sa_text("INSERT INTO aisoc_replay_evaluations (id, tenant_id, status, error) VALUES (:id, :tenant, :status, :error)").bindparams(
            id=evaluation_id, tenant=TENANT, status=status, error=error
        )
    )
    for decision in decisions:
        await db.execute(
            sa_text(
                "INSERT INTO aisoc_replay_decisions "
                "(evaluation_id, tenant_id, finding_id, vendor, rule_id, expected_disposition, labelled, verdict, tier, decision) "
                "VALUES (:evaluation_id, :tenant, :finding_id, :vendor, :rule_id, :expected, :labelled, :verdict, :tier, :decision)"
            ).bindparams(
                evaluation_id=evaluation_id,
                tenant=TENANT,
                finding_id=decision["finding_id"],
                vendor=decision["vendor"],
                rule_id=decision["rule_id"],
                expected=decision["expected_disposition"],
                labelled=decision["labelled"],
                verdict=decision["verdict"],
                tier=decision["tier"],
                decision=json.dumps(decision, sort_keys=True),
            )
        )
    return evaluation_id


#: One matched alert (the skill names this rule id) and one the skill does not
#: select, so a default backtest is enough to activate and the matched subset
#: is still a strict subset of the window.
def _default_window(*, matched_verdict: str) -> tuple[dict, ...]:
    return (
        _decision(finding_id="f-matched", verdict=matched_verdict, rule_id="rule-encoded-powershell"),
        _decision(finding_id="f-other", verdict="malicious", rule_id="rule-unrelated"),
    )


async def _attach_completed_backtest(
    db,
    *,
    skill_id: str = "finance-batch-powershell",
    baseline: tuple[dict, ...] | None = None,
    candidate: tuple[dict, ...] | None = None,
) -> tuple[uuid.UUID, uuid.UUID]:
    """Two completed runs over a window this skill matches, attached to it."""
    baseline_id = await _seed_evaluation(db, status="completed", decisions=baseline or _default_window(matched_verdict="benign"))
    candidate_id = await _seed_evaluation(db, status="completed", decisions=candidate or _default_window(matched_verdict="malicious"))
    await store.attach_backtest(
        db,
        tenant_id=TENANT,
        skill_id=skill_id,
        baseline_evaluation_id=baseline_id,
        candidate_evaluation_id=candidate_id,
    )
    return baseline_id, candidate_id


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
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            baseline, candidate = await _attach_completed_backtest(db)
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
            await _attach_completed_backtest(db)
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
            await _attach_completed_backtest(db)
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


class TestActivationReadsTheBacktest:
    """Activation reads the two runs it names, rather than only their ids.

    Fix-pass 3.8. The version check above answers "does this report describe
    this text". These answer the two questions after it: did the runs that
    produced the report finish, and did the report grade anything this skill
    applies to. A pair of ids that point at two crashed runs, or at a window
    holding no alert the skill selects, satisfies every earlier refusal.
    """

    @pytest.mark.asyncio
    async def test_activation_is_refused_when_an_attached_run_does_not_exist(self, session_factory) -> None:
        """Two ids pointing at nothing are not a backtest.

        Nothing in the schema makes the attached ids foreign keys, so a
        fix-up, a purge or a bug leaves a skill naming runs that are gone.
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
            with pytest.raises(store.SkillLifecycleError) as exc:
                await store.activate_skill(db, tenant_id=TENANT, skill_id="finance-batch-powershell", actor_id=USER)
        assert "no such replay run" in str(exc.value)

    @pytest.mark.asyncio
    async def test_activation_is_refused_when_both_runs_failed(self, session_factory) -> None:
        """A failed backtest measured nothing, and measured nothing loudly.

        This is the defect fix-pass 3.8 names: the two ids are attached, the
        version matches, and both runs died without grading a single finding.
        """
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            baseline = await _seed_evaluation(db, status="failed", error="the actions service is unreachable")
            candidate = await _seed_evaluation(db, status="failed", error="the actions service is unreachable")
            await store.attach_backtest(
                db,
                tenant_id=TENANT,
                skill_id="finance-batch-powershell",
                baseline_evaluation_id=baseline,
                candidate_evaluation_id=candidate,
            )
            await db.commit()
            with pytest.raises(store.SkillLifecycleError) as exc:
                await store.activate_skill(db, tenant_id=TENANT, skill_id="finance-batch-powershell", actor_id=USER)
        message = str(exc.value)
        assert "failed" in message
        # The reason the run gave, so the operator fixes the run rather than
        # the skill. A refusal naming only the status sends them to re-read
        # their YAML for a fault that is not in it.
        assert "actions service is unreachable" in message

    @pytest.mark.asyncio
    async def test_activation_is_refused_while_a_run_is_still_going(self, session_factory) -> None:
        """Queued and running are not failures, and the message must not read as one."""
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            baseline = await _seed_evaluation(db, status="completed", decisions=_default_window(matched_verdict="benign"))
            candidate = await _seed_evaluation(db, status="running")
            await store.attach_backtest(
                db,
                tenant_id=TENANT,
                skill_id="finance-batch-powershell",
                baseline_evaluation_id=baseline,
                candidate_evaluation_id=candidate,
            )
            await db.commit()
            with pytest.raises(store.SkillLifecycleError) as exc:
                await store.activate_skill(db, tenant_id=TENANT, skill_id="finance-batch-powershell", actor_id=USER)
        message = str(exc.value)
        assert "running" in message
        assert "has not finished" in message

    @pytest.mark.asyncio
    async def test_activation_is_refused_when_the_window_holds_no_alert_this_skill_matches(self, session_factory) -> None:
        """Two completed runs over a window the skill does not apply to.

        Both runs graded the same two hundred alerts and the skill selects
        none of them, so every difference between the two reports comes from
        alerts this skill never touches. The headline delta is a statement
        about the window, not about the skill.
        """
        unrelated = tuple(
            _decision(finding_id=f"f-{index}", verdict="malicious", rule_id="rule-unrelated", title="Impossible travel")
            for index in range(8)
        )
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            baseline = await _seed_evaluation(db, status="completed", decisions=unrelated)
            candidate = await _seed_evaluation(db, status="completed", decisions=unrelated)
            await store.attach_backtest(
                db,
                tenant_id=TENANT,
                skill_id="finance-batch-powershell",
                baseline_evaluation_id=baseline,
                candidate_evaluation_id=candidate,
            )
            await db.commit()
            with pytest.raises(store.SkillLifecycleError) as exc:
                await store.activate_skill(db, tenant_id=TENANT, skill_id="finance-batch-powershell", actor_id=USER)
        message = str(exc.value)
        assert "match block selects none of them" in message
        # The window size, so the operator can tell "nothing was graded" from
        # "plenty was graded and none of it was yours".
        assert "8" in message

    @pytest.mark.asyncio
    async def test_the_delta_is_computed_over_the_matched_alerts_and_not_the_window(self, session_factory) -> None:
        """The number activation records is the one about this skill.

        The window is twenty alerts; the skill matches four. The candidate run
        fixes all four and changes nothing else, so the matched delta is 1.00
        and the whole-window delta is 0.20. A gate reading the second would
        call a skill that fixed every alert it touches a 20% improvement, and
        would call a skill that broke every one of them a rounding error.
        """
        matched = tuple(_decision(finding_id=f"m-{index}", verdict="benign", rule_id="rule-encoded-powershell") for index in range(4))
        others = tuple(_decision(finding_id=f"o-{index}", verdict="malicious", rule_id="rule-unrelated") for index in range(16))
        fixed = tuple(_decision(finding_id=f"m-{index}", verdict="malicious", rule_id="rule-encoded-powershell") for index in range(4))

        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            await _attach_completed_backtest(db, baseline=matched + others, candidate=fixed + others)
            row = await store.activate_skill(db, tenant_id=TENANT, skill_id="finance-batch-powershell", actor_id=USER)
            await db.commit()
            assert row.status == ACTIVE

            delta = await skill_backtest.matched_delta(
                db,
                tenant_id=TENANT,
                match=skill_backtest.match_from_body(row.body),
                baseline_evaluation_id=row.backtest_baseline_id,
                candidate_evaluation_id=row.backtest_evaluation_id,
            )

        assert delta.blocked_reason is None
        assert (delta.window_compared, delta.matched, delta.matched_graded) == (20, 4, 4)
        assert (delta.baseline_accuracy, delta.candidate_accuracy) == (0.0, 1.0)
        assert delta.accuracy_delta == 1.0
        # The figure the old activation would have rested on, kept beside it
        # rather than dropped, because the gap between the two is the point.
        assert delta.window_accuracy_delta == pytest.approx(0.2)
        assert delta.verdicts_changed == 4

    @pytest.mark.asyncio
    async def test_a_skill_that_changed_nothing_still_activates(self, session_factory) -> None:
        """The gate is that a delta exists, never that it is favourable.

        A threshold on the value would be a target to tune a skill against,
        and an organisational fact that happens not to move last quarter's
        verdicts is still true about the estate.
        """
        window = _default_window(matched_verdict="malicious")
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            await _attach_completed_backtest(db, baseline=window, candidate=window)
            row = await store.activate_skill(db, tenant_id=TENANT, skill_id="finance-batch-powershell", actor_id=USER)
            await db.commit()

            delta = await skill_backtest.matched_delta(
                db,
                tenant_id=TENANT,
                match=skill_backtest.match_from_body(row.body),
                baseline_evaluation_id=row.backtest_baseline_id,
                candidate_evaluation_id=row.backtest_evaluation_id,
            )

        assert row.status == ACTIVE
        assert (delta.verdicts_changed, delta.accuracy_delta) == (0, 0.0)

    @pytest.mark.asyncio
    async def test_a_matched_alert_nobody_labelled_leaves_the_accuracy_unmeasured(self, session_factory) -> None:
        """An unlabelled window can still show what changed, and must not show an accuracy.

        Zero in an accuracy column reads as "the agent got every one of these
        wrong", which is a different fact from "no analyst said".
        """
        unlabelled = (
            _decision(finding_id="m-0", verdict="benign", rule_id="rule-encoded-powershell", labelled=False, expected="unlabeled"),
        )
        changed = (
            _decision(finding_id="m-0", verdict="malicious", rule_id="rule-encoded-powershell", labelled=False, expected="unlabeled"),
        )
        async with session_factory() as db:
            await store.save_skill(db, tenant_id=TENANT, author_id=USER, source_yaml=_yaml())
            await _attach_completed_backtest(db, baseline=unlabelled, candidate=changed)
            row = await store.activate_skill(db, tenant_id=TENANT, skill_id="finance-batch-powershell", actor_id=USER)
            await db.commit()

            delta = await skill_backtest.matched_delta(
                db,
                tenant_id=TENANT,
                match=skill_backtest.match_from_body(row.body),
                baseline_evaluation_id=row.backtest_baseline_id,
                candidate_evaluation_id=row.backtest_evaluation_id,
            )

        assert delta.matched == 1
        assert delta.matched_graded == 0
        assert delta.accuracy_delta is None
        assert delta.verdicts_changed == 1


class TestMatchBlockSelection:
    """Which alerts a skill's own ``match`` block selects.

    The four conditions are the ones ``select_skill`` scores on in the agents
    service, and each is asserted here against the evidence a replay records.
    """

    @pytest.mark.parametrize(
        ("decision_kwargs", "selected"),
        [
            ({"rule_id": "rule-encoded-powershell"}, True),
            ({"rule_id": "rule-something-else"}, False),
            # A sub-technique alert matches a skill written against the
            # parent, the reading both selectors use.
            ({"techniques": ("T1059.001",)}, True),
            ({"techniques": ("T1059",)}, False),
            ({"techniques": ("T1078.004",)}, False),
        ],
    )
    def test_each_condition(self, decision_kwargs, selected) -> None:
        skill = parse_skill_yaml(_yaml())
        decision = _decision(finding_id="f", verdict="benign", **{"rule_id": "rule-unrelated", **decision_kwargs})
        assert skill_backtest.selects(skill.match, decision) is selected

    def test_a_parent_technique_in_the_skill_selects_a_sub_technique_alert(self) -> None:
        source = _drop_block(_yaml(), "match") + "\nmatch:\n  techniques: [T1059]"
        skill = parse_skill_yaml(source)
        assert skill_backtest.selects(skill.match, _decision(finding_id="f", verdict="benign", techniques=("T1059.001",)))

    def test_a_keyword_is_read_from_the_title_the_agent_was_given(self) -> None:
        source = _drop_block(_yaml(), "match") + "\nmatch:\n  keywords: [svc_batch]"
        skill = parse_skill_yaml(source)
        assert skill_backtest.selects(skill.match, _decision(finding_id="f", verdict="benign", title="Encoded PowerShell by SVC_BATCH"))
        assert not skill_backtest.selects(skill.match, _decision(finding_id="f", verdict="benign", title="Impossible travel"))

    def test_the_source_condition_reads_the_connector_the_alert_came_from(self) -> None:
        source = _drop_block(_yaml(), "match") + "\nmatch:\n  sources: [splunk]"
        skill = parse_skill_yaml(source)
        assert skill_backtest.selects(skill.match, _decision(finding_id="f", verdict="benign"))

    def test_a_body_whose_casing_was_never_normalised_still_selects(self) -> None:
        """Activation reads the stored JSONB, not the document, so the read normalises too.

        A body the parser wrote is already canonical, so comparing
        ``match_from_body(skill.as_dict())`` against ``skill.match`` compares
        the parser with a copy of itself: it passes with the normalisation
        deleted. This body is the shape a direct fix-up or an older parser
        leaves behind, and it is the one that tells the two apart.
        """
        stored = {
            "match": {
                "techniques": ["t1059.001"],
                "rule_ids": ["rule-encoded-powershell"],
                "sources": ["CrowdStrike"],
                "keywords": ["SVC_Batch"],
            }
        }
        match = skill_backtest.match_from_body(stored)
        assert match.techniques == ("T1059.001",)
        assert match.sources == ("crowdstrike",)
        assert match.keywords == ("svc_batch",)
        assert skill_backtest.selects(match, _decision(finding_id="f", verdict="benign", techniques=("T1059.001",)))
        assert skill_backtest.selects(match, _decision(finding_id="f", verdict="benign", title="Encoded PowerShell by svc_batch"))

    def test_the_parser_and_the_stored_read_agree_on_a_document(self) -> None:
        """The round trip, which the casing test above cannot cover on its own."""
        skill = parse_skill_yaml(_yaml())
        assert skill_backtest.match_from_body(skill.as_dict()) == skill.match

    def test_a_body_with_no_match_block_selects_nothing(self) -> None:
        """A body whose block was emptied must refuse every alert, never accept every one.

        The parser already refuses an empty match block at authoring time, so
        this is the read path's own floor: the wrong direction here would let a
        skill with no conditions claim the whole window as its matched set,
        which is the comparison this module exists to stop activation resting
        on.
        """
        match = skill_backtest.match_from_body({})
        assert match.is_empty()
        assert not skill_backtest.selects(match, _decision(finding_id="f", verdict="benign", rule_id="rule-encoded-powershell"))


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
            await _attach_completed_backtest(db, skill_id=skill_id)
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
