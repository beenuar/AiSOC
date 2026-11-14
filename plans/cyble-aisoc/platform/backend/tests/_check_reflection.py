"""End-to-end check for t2n-multimodel: tiered router + reflection.

Run from `platform/backend/`:
    AISOC_DB_PATH=/tmp/aisoc-reflect-test.db \
    python tests/_check_reflection.py

We verify:
 1. `route_for_agent` returns PREMIUM for investigator and responder, FAST for
    triager, and respects an explicit `tier_override`.
 2. Per-agent env override (`AISOC_LLM_MODEL_INVESTIGATOR`) wins over the
    global default and is reflected in the routing `reason`.
 3. `llm.complete` surfaces routing metadata at the top level
    (provider, model, tier, route_reason) and inside `model_choice`.
 4. `llm.reflect` always picks PREMIUM regardless of the caller's tier,
    parses the mock LLM's VERDICT line, and returns approve=True for benign
    plans and approve=False for risky destructive plans without evidence.
 5. The Responder agent's run() actually drafts a plan, runs the reflection,
    and writes a THINK trace step labelled "Reflection: APPROVE" or
    "Reflection: REVISE" with model_choice in the detail blob.

Exits non-zero on any failure.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-reflect-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    # Per-agent override — should show up in route_reason.
    os.environ["AISOC_LLM_MODEL_INVESTIGATOR"] = "claude-sonnet-test-override"
    return db_path


DB_PATH = _bootstrap_env()

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlmodel import Session, select  # noqa: E402

from app.agents.llm import (  # noqa: E402
    LLMModelTier,
    complete,
    reflect,
    route_for_agent,
)
from app.agents.responder import ResponderAgent  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.models.alert import Alert  # noqa: E402
from app.models.case import Case, CaseStatus, Severity  # noqa: E402
from app.models.trace import AgentTrace, TraceStep  # noqa: E402


FAILURES: list[str] = []


def _fail(msg: str) -> None:
    FAILURES.append(msg)
    print(f"  FAIL: {msg}")


def _ok(msg: str) -> None:
    print(f"  OK:   {msg}")


# ── 1. routing defaults ────────────────────────────────────────────────────
def test_routing_defaults() -> None:
    print("\n[1] route_for_agent defaults")
    inv = route_for_agent("investigator")
    if inv.tier is not LLMModelTier.PREMIUM:
        _fail(f"investigator tier expected PREMIUM, got {inv.tier}")
    else:
        _ok(f"investigator -> PREMIUM ({inv.model}, reason={inv.reason})")

    resp = route_for_agent("responder")
    if resp.tier is not LLMModelTier.PREMIUM:
        _fail(f"responder tier expected PREMIUM, got {resp.tier}")
    else:
        _ok(f"responder -> PREMIUM ({resp.model})")

    tri = route_for_agent("triager")
    if tri.tier is not LLMModelTier.FAST:
        _fail(f"triager tier expected FAST, got {tri.tier}")
    else:
        _ok(f"triager -> FAST ({tri.model})")

    # tier_override must beat the agent default
    forced = route_for_agent("triager", tier_override=LLMModelTier.PREMIUM)
    if forced.tier is not LLMModelTier.PREMIUM:
        _fail(f"tier_override didn't promote triager: {forced.tier}")
    else:
        _ok(f"tier_override beats agent default ({forced.reason})")


# ── 2. per-agent env override ──────────────────────────────────────────────
def test_per_agent_env_override() -> None:
    print("\n[2] per-agent env override")
    inv = route_for_agent("investigator")
    if inv.model != "claude-sonnet-test-override":
        _fail(f"per-agent env override not applied: model={inv.model}")
    else:
        _ok(f"AISOC_LLM_MODEL_INVESTIGATOR honored: {inv.model}")
    if "per_agent" not in inv.reason and "override" not in inv.reason:
        _fail(f"route reason should mention per-agent override, got {inv.reason!r}")
    else:
        _ok(f"route reason traceable: {inv.reason}")


# ── 3. llm.complete surfaces routing metadata ──────────────────────────────
async def test_complete_surfaces_metadata() -> None:
    print("\n[3] complete() returns top-level routing metadata")
    out = await complete(
        system="you are a soc analyst",
        user="say hello",
        max_tokens=64,
        agent="investigator",
    )
    for key in ("provider", "model", "tier", "route_reason", "model_choice"):
        if key not in out:
            _fail(f"complete() missing key {key!r}")
            return
    if out["tier"] != "premium":
        _fail(f"investigator tier should serialize as 'premium', got {out['tier']!r}")
    else:
        _ok(f"complete() surfaced tier={out['tier']} model={out['model']}")
    mc = out["model_choice"]
    if mc.get("tier") != out["tier"] or mc.get("model") != out["model"]:
        _fail("top-level and model_choice fields disagree")
    else:
        _ok("top-level fields match nested model_choice")


# ── 4. reflect() forces PREMIUM + parses verdict ───────────────────────────
async def test_reflect_verdicts() -> None:
    print("\n[4] reflect() forces PREMIUM and parses VERDICT lines")
    safe_plan = (
        "1. ticket.create severity=medium\n"
        "2. slack.notify channel=#soc-triage\n"
        "Risk: low; reversible."
    )
    safe = await reflect(
        system="senior soc reviewer",
        plan=safe_plan,
        context="alert confidence: 0.9, verdict: true_positive (phishing)",
        agent="responder",
    )
    if not safe.get("approve"):
        _fail(f"benign plan should approve, got text={safe.get('text')!r}")
    else:
        _ok("benign plan -> APPROVE")
    mc = safe.get("model_choice") or {}
    if mc.get("tier") != "premium":
        _fail(f"reflect didn't force PREMIUM, got {mc.get('tier')!r}")
    else:
        _ok(f"reflect forced PREMIUM ({mc.get('model')})")

    risky_plan = (
        "1. edr.isolate_host host=prod-db-01\n"
        "2. idp.disable_user user=ceo@acme.com\n"
        "Risk: high but yolo."
    )
    risky = await reflect(
        system="senior soc reviewer",
        plan=risky_plan,
        context="alert confidence: 0.3, verdict: indeterminate, no IOC match",
        agent="responder",
    )
    if risky.get("approve"):
        _fail(
            "risky destructive plan with weak evidence should be REVISE; "
            f"text={risky.get('text')!r}"
        )
    else:
        _ok("risky destructive plan w/o evidence -> REVISE")


# ── 5. Responder.run() actually traces a reflection step ───────────────────
async def test_responder_traces_reflection() -> None:
    print("\n[5] Responder.run() emits a Reflection trace step")
    init_db()
    with Session(engine) as s:
        case = Case(
            tenant_id="t-test",
            title="reflection-smoke",
            severity=Severity.HIGH,
            status=CaseStatus.NEW,
            narrative="dummy",
        )
        s.add(case)
        s.commit()
        s.refresh(case)
        case_id = case.id
        # Responder.run() expects at least one alert on the case.
        alert = Alert(
            tenant_id="t-test",
            case_id=case_id,
            external_id="ext-1",
            title="Suspicious login",
            description="Multiple failed logins followed by success from new geo",
            severity="high",
            source="okta",
            src_user="alice@acme.com",
        )
        s.add(alert)
        s.commit()
        s.refresh(alert)

    with Session(engine) as agent_session:
        agent = ResponderAgent(db=agent_session, case_id=case_id, tenant_id="t-test")
        try:
            await agent.run()
        except Exception as exc:  # pragma: no cover
            # Responder may bail late in the loop (tool not registered etc.) —
            # that's fine, we only need the reflection trace to have landed.
            print(f"  note: responder.run() raised {type(exc).__name__}: {exc}")

    with Session(engine) as s:
        traces = list(
            s.exec(
                select(AgentTrace)
                .where(AgentTrace.case_id == case_id)
                .where(AgentTrace.step == TraceStep.THINK)
            )
        )
        refl = [t for t in traces if t.summary and t.summary.startswith("Reflection:")]
        if not refl:
            _fail(
                "no THINK trace starting with 'Reflection:' was written "
                f"(got {[t.summary for t in traces]!r})"
            )
            return
        t = refl[0]
        _ok(f"reflection trace recorded: {t.summary}")
    detail = t.detail or {}
    if "model_choice" not in detail:
        _fail("reflection trace detail missing model_choice")
    else:
        mc = detail["model_choice"] or {}
        if mc.get("tier") != "premium":
            _fail(f"reflection trace model_choice tier != premium ({mc.get('tier')!r})")
        else:
            _ok(f"reflection trace pinned PREMIUM ({mc.get('model')})")
    if "draft_plan" not in detail:
        _fail("reflection trace missing draft_plan")
    else:
        _ok("draft_plan captured in trace")
    if "approve" not in detail:
        _fail("reflection trace missing approve flag")
    else:
        _ok(f"approve flag captured ({detail['approve']})")


async def _main() -> int:
    test_routing_defaults()
    test_per_agent_env_override()
    await test_complete_surfaces_metadata()
    await test_reflect_verdicts()
    await test_responder_traces_reflection()

    print()
    if FAILURES:
        print(f"FAIL: {len(FAILURES)} assertion(s) failed:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("PASS: t2n-multimodel reflection + routing checks all green.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
