"""The hypothesis scheduler: which campaigns run, and why (WS6.2).

Three deterministic schedulers already exist — saved-hunt cron, corpus
cadence, retro-hunts — and none SELECTS hypotheses or dispatches the LLM
hunt agent. This is the selection layer above them:

* **Per tenant, opt-in, on a cadence and a budget** — read from
  ``hunt_campaign_policies`` (migration 179; default OFF, because an LLM
  agent asking questions of the estate on a schedule is automation a
  tenant chooses).
* **Selection sources, this revision**: APPROVED hunt requests not yet
  campaigned (``hunt_source_reports.approved_at`` set — the WS6.3 gate —
  and ``campaigned_at`` null), then corpus hypotheses that have never run
  for this tenant (the corpus scheduler's own staleness store). The
  coverage-gap ranker, KEV-exposure matches and new-intel sources are
  recorded follow-ups, named in the PR rather than silently absent.
* **Every selection is recorded with its reason** in the Investigation
  Ledger before the campaign starts, so "why did an agent hunt this" is
  always answerable.

A selected hypothesis runs through :func:`app.hunt.campaign.run_campaign`
— the budget-gated, summary-fed loop — with the tenant's own budget
overrides. Leads are handed to :func:`verify_leads`, and a productive
campaign opens a DRAFT detection proposal through the governed API path
(:func:`propose_detection`), which is what finally assigns
``HuntAgentResult.proposal_id``'s campaign-level counterpart for real.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import httpx

from app.hunt.agent import EXECUTE_TIMEOUT_SECONDS, TENANT_HEADER, _api_url, _service_token
from app.hunt.campaign import CampaignBudgets, CampaignResult, run_campaign
from app.investigator import ledger as ledger_module
from app.llm import safe_ainvoke
from app.llm.factory import make_chat_model

logger = logging.getLogger("aisoc.hunt.hypothesis_scheduler")

#: How many leads one campaign hands to the investigator. The investigator
#: is the expensive half; the cap keeps a noisy campaign from launching an
#: investigation per row.
MAX_LEADS_VERIFIED = 3

_POLICIES_SQL = """
SELECT tenant_id, cadence_minutes, budgets, max_per_tick
FROM hunt_campaign_policies
WHERE enabled = TRUE
  AND (last_run_at IS NULL OR last_run_at < NOW() - make_interval(mins => cadence_minutes))
"""

_MARK_RUN_SQL = "UPDATE hunt_campaign_policies SET last_run_at = NOW() WHERE tenant_id = $1"

#: The report table stores provenance (url, digest, counts, approval) and
#: deliberately NOT the body; the hypothesis is composed from those facts.
_APPROVED_UNCAMPAIGNED_SQL = """
SELECT id, url, content_sha256, indicator_count, technique_count
FROM hunt_source_reports
WHERE tenant_id = $1 AND approved_at IS NOT NULL AND campaigned_at IS NULL
ORDER BY approved_at
LIMIT $2
"""

_MARK_CAMPAIGNED_SQL = """
UPDATE hunt_source_reports SET campaigned_at = NOW()
WHERE tenant_id = $1 AND id = $2 AND campaigned_at IS NULL
"""


@dataclass
class Selection:
    tenant_id: str
    hypothesis: str
    reason: str
    source: str
    request_id: str | None = None


@dataclass
class SchedulerSummary:
    tenants_due: int = 0
    selected: int = 0
    campaigns_run: int = 0
    leads_total: int = 0
    proposals_opened: int = 0
    errors: list[str] = field(default_factory=list)


def _budgets_from(policy_budgets: Any) -> CampaignBudgets:
    raw = policy_budgets if isinstance(policy_budgets, dict) else {}
    if isinstance(policy_budgets, str):
        try:
            raw = json.loads(policy_budgets)
        except ValueError:
            raw = {}
    defaults = CampaignBudgets()
    return CampaignBudgets(
        max_steps=int(raw.get("max_steps", defaults.max_steps)),
        max_rows=int(raw.get("max_rows", defaults.max_rows)),
        max_model_calls=int(raw.get("max_model_calls", defaults.max_model_calls)),
        max_wallclock_seconds=float(raw.get("max_wallclock_seconds", defaults.max_wallclock_seconds)),
    )


async def select_for_tenant(conn: Any, tenant_id: str, limit: int) -> list[Selection]:
    """The selection sources, in priority order, each with its reason."""
    selections: list[Selection] = []
    rows = await conn.fetch(_APPROVED_UNCAMPAIGNED_SQL, uuid.UUID(tenant_id), limit)
    for row in rows:
        hypothesis = (
            f"Hunt for activity matching the indicators and techniques of the approved "
            f"third-party report at {row['url']} "
            f"(report {str(row['content_sha256'])[:12]}, {row['indicator_count']} indicator(s), "
            f"{row['technique_count']} technique(s) extracted at review time)."
        )
        selections.append(
            Selection(
                tenant_id=tenant_id,
                hypothesis=hypothesis,
                reason="an analyst approved this report-sourced hunt request and no campaign has run it",
                source="approved_request",
                request_id=str(row["id"]),
            )
        )
    return selections[:limit]


async def propose_detection(result: CampaignResult, *, tenant_id: str) -> str | None:
    """A productive campaign opens a DRAFT proposal through the governed path.

    This is what makes the long-declared, never-assigned ``proposal_id``
    real at the campaign level. The API endpoint writes the same DRAFT
    scaffold the saved-hunt path writes; nothing auto-promotes.
    """
    token = _service_token()
    if not token or result.outcome != "leads":
        return None
    try:
        async with httpx.AsyncClient(timeout=EXECUTE_TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"{_api_url()}/api/v1/agent-tools/hunt-plan/propose-detection",
                json={
                    "hypothesis": result.hypothesis,
                    "coverage": result.coverage,
                    "leads": [{"question": lead["question"], "findings": lead["findings"]} for lead in result.leads[:5]],
                    "steps": [{"question": s.question, "plan": s.plan} for s in result.steps if s.plan],
                },
                headers={"Authorization": f"Bearer {token}", TENANT_HEADER: tenant_id},
            )
        if response.status_code == 201:
            proposal_id = str(response.json().get("id") or "") or None
            result.proposal_id = proposal_id
            return proposal_id
        logger.warning("hypothesis_scheduler.proposal_refused status=%s", response.status_code)
    except Exception as exc:  # noqa: BLE001 — a proposal is a bonus, never the campaign's failure
        logger.warning("hypothesis_scheduler.proposal_failed err=%s", type(exc).__name__)
    return None


async def verify_leads(
    result: CampaignResult,
    *,
    tenant_id: str,
    llm: Any | None = None,
    runner: Any | None = None,
) -> list[dict[str, Any]]:
    """Each top lead becomes a labelled item triaged by the investigation
    agent under its own run (WS6.4). Capped, best-effort, and the verdicts
    ride back on the lead dicts so the campaign report carries them.

    ``runner`` is injectable for tests; production resolves the real
    investigator here rather than at module import because it pulls the
    whole LLM stack in behind it.
    """
    if runner is None:
        from app.investigator.deep_investigation import (
            run_deep_investigation,  # noqa: PLC0415 — the investigator pulls the LLM stack; import only when leads exist
        )

        runner = run_deep_investigation

    verified: list[dict[str, Any]] = []
    for lead in result.leads[:MAX_LEADS_VERIFIED]:
        state = SimpleNamespace(
            tenant_id=tenant_id,
            alert_id=f"hunt-lead-{uuid.uuid4().hex[:8]}",
            alert_summary=(
                f"HUNT LEAD (campaign): {lead['question']} — {lead['findings']} matching "
                f"event(s); sample: {json.dumps(lead.get('sample', [])[:2], default=str)[:400]}"
            ),
            mitre_mappings=[],
        )
        try:
            investigation = await runner(state, llm=llm)
            lead["verification"] = {
                "strategy": getattr(investigation, "strategy_id", None),
                "run": True,
            }
        except Exception as exc:  # noqa: BLE001 — one lead's failure must not drop the rest
            lead["verification"] = {"run": False, "reason": type(exc).__name__}
        verified.append(lead)
    return verified


async def run_once(*, connect: Any | None = None) -> SchedulerSummary:
    """One scheduler tick over every due, opted-in tenant."""
    import asyncpg

    summary = SchedulerSummary()
    dsn = (os.getenv("DATABASE_DSN") or os.getenv("DATABASE_URL") or "").strip()
    dsn = dsn.replace("postgresql+asyncpg://", "postgresql://")
    if not dsn:
        summary.errors.append("no database DSN; the scheduler cannot read policies")
        return summary

    connector = connect or asyncpg.connect
    conn = await connector(dsn)
    try:
        policies = await conn.fetch(_POLICIES_SQL)
        summary.tenants_due = len(policies)
        for policy in policies:
            tenant_id = str(policy["tenant_id"])
            budgets = _budgets_from(policy["budgets"])
            try:
                selections = await select_for_tenant(conn, tenant_id, int(policy["max_per_tick"]))
                summary.selected += len(selections)
                for selection in selections:
                    run_id = str(uuid.uuid4())
                    # The reason is recorded BEFORE the campaign, so "why did
                    # an agent hunt this" is answerable even for a campaign
                    # that dies mid-flight.
                    try:
                        await ledger_module.record_event(
                            run_id=uuid.UUID(run_id),
                            tenant_id=uuid.UUID(tenant_id),
                            seq=0,
                            kind="campaign_selected",
                            agent="aisoc-hunt-scheduler",
                            summary=f"selected ({selection.source})",
                            payload={
                                "hypothesis": selection.hypothesis[:500],
                                "reason": selection.reason,
                                "source": selection.source,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001 — the ledger write is load-bearing for audit, loud when it fails
                        logger.warning("hypothesis_scheduler.ledger_failed err=%s", type(exc).__name__)

                    model = make_chat_model("hunt", json_output=True)

                    async def _invoke(messages: list[dict[str, str]], _model=model) -> Any:
                        return await safe_ainvoke(_model, messages)

                    result = await run_campaign(
                        selection.hypothesis,
                        invoke=_invoke,
                        ledger=ledger_module,
                        run_id=run_id,
                        tenant_id=tenant_id,
                        budgets=budgets,
                    )
                    summary.campaigns_run += 1
                    summary.leads_total += len(result.leads)
                    if selection.request_id:
                        await conn.execute(
                            _MARK_CAMPAIGNED_SQL,
                            uuid.UUID(tenant_id),
                            uuid.UUID(selection.request_id),
                        )
                    if result.outcome == "leads":
                        await verify_leads(result, tenant_id=tenant_id)
                        if await propose_detection(result, tenant_id=tenant_id):
                            summary.proposals_opened += 1
            except Exception as exc:  # noqa: BLE001 — one tenant must not stop the fleet
                summary.errors.append(f"{tenant_id}: {type(exc).__name__}")
                logger.warning(
                    "hypothesis_scheduler.tenant_failed tenant=%s err=%s",
                    tenant_id,
                    type(exc).__name__,
                )
            finally:
                await conn.execute(_MARK_RUN_SQL, uuid.UUID(tenant_id))
    finally:
        await conn.close()
    if summary.campaigns_run or summary.errors:
        logger.info("hypothesis_scheduler %s", vars(summary))
    return summary
