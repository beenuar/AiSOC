"""End-to-end smoke check for the Brand Responder (Theme 3c).

Exercises the proactive Brand & typosquat takedown loop against an
isolated SQLite DB so we touch every wire-in surface:

  * The Cyble-native ``cti.brand_intel`` tool is loaded as a READ-class,
    cyble_native tool in the ToolRegistry.
  * The Brand Responder REST router is mounted under ``/brand/*`` and
    every endpoint resolves through ``require_tenant`` (anon dev fallback
    via ``AISOC_DEV_ALLOW_ANON_TENANT=true``).
  * ``POST /brand/assets`` persists a tenant-scoped BrandAsset and is
    idempotent on ``(tenant_id, root_domain)``.
  * ``POST /brand/sweep`` delegates to ``BrandResponderAgent.sweep`` and
    drives the full pipeline:
      - discover (cti.brand_intel mock yields ``{brand}-secure.com`` and
        ``{brand}-portal.duckdns.org``),
      - score (deterministic detector: brand_affix → +35),
      - persist candidates,
      - auto-file takedowns when score ≥ ``brand_auto_takedown_threshold``,
      - open proactive ``Case`` rows and record an ``AgentTrace`` with
        ``AgentName.BRAND_RESPONDER`` + ``TraceStep.HANDOFF``.
  * ``GET /brand/candidates`` returns the persisted rows, ordered by
    score; status filter works.
  * ``POST /brand/candidates/{id}/dismiss`` flips status to DISMISSED
    without deleting the audit row.
  * ``GET /brand/takedowns`` returns the takedown ledger and supports a
    ``candidate_id`` filter.
  * ``brand_responder.scheduler.start_background_tasks()`` honours
    ``settings.brand_scheduler_enabled`` and refuses to spawn the loop
    when disabled (the smoke test runs with the scheduler off).

The auto-takedown threshold is forced to ``30`` so the brand_affix
candidates (score 35) deterministically auto-file. Default is 80 in
production; lowering it here is the whole point of the smoke test —
exercising the gated auto-file path without booting a real LLM.

Run from ``platform/backend/``::

    PYTHONPATH=. python tests/_check_brand_responder.py

Exits non-zero on any failure and prints a PASS/FAIL summary per check.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    """Point AISOC at an isolated temp DB before importing app code."""
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-brand-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    # Brand Responder knobs — keep production-like behaviour but
    # lower the auto-takedown threshold so the deterministic mock
    # CTI brand-intel candidates (score 35 via brand_affix) actually
    # trip the auto-file path.
    os.environ["AISOC_BRAND_MIN_CANDIDATE_SCORE"] = "20"
    os.environ["AISOC_BRAND_AUTO_TAKEDOWN_THRESHOLD"] = "30"
    # The background scheduler must NOT spawn during the smoke test —
    # we drive sweeps explicitly via the /brand/sweep endpoint.
    os.environ["AISOC_BRAND_SCHEDULER_ENABLED"] = "false"
    # Allow the FastAPI TestClient to hit tenant-scoped routes without
    # minting a JWT; falls back to the synthetic default_tenant context.
    os.environ["AISOC_DEV_ALLOW_ANON_TENANT"] = "true"
    os.environ["AISOC_DEFAULT_TENANT"] = "demo-tenant"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app.brand_responder import scheduler as brand_scheduler  # noqa: E402
from app.brand_responder.responder import BrandResponderAgent  # noqa: E402
from app.config import settings  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.models.brand import (  # noqa: E402
    BrandAsset,
    CandidateStatus,
    TakedownRequest,
    TyposquatCandidate,
)
from app.models.case import Case  # noqa: E402
from app.models.trace import AgentName, AgentTrace, TraceStep  # noqa: E402
import app.tools  # noqa: F401, E402  -- forces tool registration on import
from app.tools.registry import registry as tool_registry  # noqa: E402


# ── Tiny test harness ───────────────────────────────────────────────────


_FAILED: list[str] = []


def check(label: str, ok: bool, *, detail: str = "") -> None:
    if ok:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"  -- {detail}" if detail else ""))
        _FAILED.append(label)


def section(label: str) -> None:
    print(f"\n── {label} ──")


# ── Checks ──────────────────────────────────────────────────────────────


def check_settings_loaded() -> None:
    section("Settings honour AISOC_* env overrides")
    check(
        "AISOC_BRAND_AUTO_TAKEDOWN_THRESHOLD=30 → settings.brand_auto_takedown_threshold == 30",
        settings.brand_auto_takedown_threshold == 30,
        detail=f"got {settings.brand_auto_takedown_threshold}",
    )
    check(
        "AISOC_BRAND_MIN_CANDIDATE_SCORE=20 → settings.brand_min_candidate_score == 20",
        settings.brand_min_candidate_score == 20,
        detail=f"got {settings.brand_min_candidate_score}",
    )
    check(
        "AISOC_BRAND_SCHEDULER_ENABLED=false → settings.brand_scheduler_enabled is False",
        settings.brand_scheduler_enabled is False,
        detail=f"got {settings.brand_scheduler_enabled!r}",
    )
    check(
        "AISOC_DEV_ALLOW_ANON_TENANT=true → settings.dev_allow_anon_tenant is True",
        settings.dev_allow_anon_tenant is True,
        detail=f"got {settings.dev_allow_anon_tenant!r}",
    )


def check_brand_intel_tool_registered() -> None:
    section("cti.brand_intel is registered in ToolRegistry")
    spec = tool_registry.get("cti.brand_intel")
    check(
        "cti.brand_intel exists in the tool registry",
        spec is not None,
    )
    if spec is None:
        return
    # The registry exposes ``risk_class`` (a RiskClass enum). Accept either
    # ``risk`` or ``risk_class`` so this check survives a future rename.
    risk = getattr(spec, "risk_class", None) or getattr(spec, "risk", None)
    risk_value = getattr(risk, "value", risk)
    check(
        "cti.brand_intel is risk=read",
        str(risk_value).lower() == "read",
        detail=f"risk={risk_value!r}",
    )
    check(
        "cti.brand_intel is flagged cyble_native",
        bool(getattr(spec, "cyble_native", False)),
    )


def check_scheduler_disabled_when_setting_off() -> None:
    section("Scheduler honours brand_scheduler_enabled=false")
    # No running asyncio loop required — start_background_tasks bails
    # before touching asyncio.Event / create_task when disabled.
    brand_scheduler.start_background_tasks()
    check(
        "start_background_tasks() did not spawn a task when disabled",
        brand_scheduler._task is None,  # type: ignore[attr-defined]
        detail=f"_task={brand_scheduler._task!r}",  # type: ignore[attr-defined]
    )


def _client() -> TestClient:
    # Importing app.main triggers lifespan-controlled work on startup.
    # We use TestClient inside a `with` block where the caller needs
    # lifespan; here we hit the routes directly without lifespan so we
    # don't accidentally spin schedulers — the disabled flag covers
    # brand, but other schedulers may still attempt to bind ports.
    # Import lazily so AISOC_* env vars above are already in effect.
    from app.main import app  # noqa: WPS433 — intentional lazy import

    return TestClient(app)


def check_register_brand_asset(client: TestClient) -> int:
    section("POST /brand/assets registers tenant-scoped brand asset")
    payload = {
        "name": "TestBrand",
        "root_domain": "testbrand.com",
        "aliases": ["test-brand.com"],
        "monitored_terms": ["testbrand"],
        "active": True,
    }
    resp = client.post("/brand/assets", json=payload)
    check(
        "POST /brand/assets → 201",
        resp.status_code == 201,
        detail=f"status={resp.status_code} body={resp.text[:200]}",
    )
    if resp.status_code != 201:
        return -1
    body = resp.json()
    check(
        "response body has integer id",
        isinstance(body.get("id"), int) and body["id"] > 0,
        detail=f"id={body.get('id')!r}",
    )
    check(
        "response tenant_id == settings.default_tenant",
        body.get("tenant_id") == settings.default_tenant,
        detail=f"tenant_id={body.get('tenant_id')!r}",
    )
    check(
        "root_domain normalised to lowercase",
        body.get("root_domain") == "testbrand.com",
        detail=f"root_domain={body.get('root_domain')!r}",
    )

    # Idempotency: re-posting same root domain must NOT create a duplicate.
    # We do NOT rename the brand here — the downstream Brand Responder
    # pipeline keys the CTI brand-intel lookup off the ``name`` field, so
    # mutating it mid-test would change which mock candidates we see.
    # Instead, verify that updating ``aliases`` is in-place on the same id.
    resp2 = client.post(
        "/brand/assets",
        json={**payload, "aliases": ["test-brand.com", "testbrnd.com"]},
    )
    check(
        "Re-posting same root_domain returns existing id (idempotent)",
        resp2.status_code == 201
        and resp2.json().get("id") == body.get("id")
        and "testbrnd.com" in (resp2.json().get("aliases") or []),
        detail=f"status={resp2.status_code} body={resp2.text[:200]}",
    )

    # List endpoint should expose the asset for this tenant.
    list_resp = client.get("/brand/assets")
    check(
        "GET /brand/assets includes the registered asset",
        list_resp.status_code == 200
        and any(
            a.get("root_domain") == "testbrand.com"
            for a in list_resp.json().get("assets", [])
        ),
        detail=f"status={list_resp.status_code} body={list_resp.text[:200]}",
    )

    return body["id"]


def check_trigger_sweep_auto_files(client: TestClient) -> dict | None:
    section("POST /brand/sweep auto-files takedowns and opens cases")
    resp = client.post("/brand/sweep")
    check(
        "POST /brand/sweep → 200",
        resp.status_code == 200,
        detail=f"status={resp.status_code} body={resp.text[:300]}",
    )
    if resp.status_code != 200:
        return None
    body = resp.json()
    # The cti.brand_intel mock yields 2 candidates for brand "TestBrand":
    #   testbrand-secure.com         → +35 (brand_affix:secure)
    #   testbrand-portal.duckdns.org → +35 (brand_affix:portal) + duckdns risk
    check(
        "sweep considered ≥ 2 candidates",
        body.get("candidates_considered", 0) >= 2,
        detail=f"considered={body.get('candidates_considered')}",
    )
    check(
        "sweep recorded ≥ 2 candidates (min_score=20)",
        body.get("candidates_recorded", 0) >= 2,
        detail=f"recorded={body.get('candidates_recorded')}",
    )
    check(
        "sweep auto-filed ≥ 2 candidates (threshold=30, brand_affix=35)",
        body.get("candidates_auto_filed", 0) >= 2,
        detail=f"auto_filed={body.get('candidates_auto_filed')}",
    )
    check(
        "sweep submitted ≥ 1 takedown",
        body.get("takedowns_submitted", 0) >= 1,
        detail=f"submitted={body.get('takedowns_submitted')}",
    )
    check(
        "sweep opened ≥ 2 cases",
        isinstance(body.get("cases_opened"), list)
        and len(body["cases_opened"]) >= 2,
        detail=f"cases_opened={body.get('cases_opened')}",
    )
    check(
        "sweep recorded no errors",
        body.get("errors") == [],
        detail=f"errors={body.get('errors')!r}",
    )
    return body


def check_persisted_state(sweep_body: dict | None) -> None:
    section("Sweep side effects are persisted to the DB")
    if sweep_body is None:
        check("DB assertions skipped because sweep failed", False)
        return

    tenant_id = settings.default_tenant
    with Session(engine) as session:
        candidates = session.exec(
            select(TyposquatCandidate).where(
                TyposquatCandidate.tenant_id == tenant_id
            )
        ).all()
        domains = {c.candidate_domain for c in candidates}
        check(
            "testbrand-secure.com persisted as candidate",
            "testbrand-secure.com" in domains,
            detail=f"domains={sorted(domains)}",
        )
        check(
            "testbrand-portal.duckdns.org persisted as candidate",
            "testbrand-portal.duckdns.org" in domains,
            detail=f"domains={sorted(domains)}",
        )
        check(
            "every persisted candidate scored ≥ min_candidate_score (20)",
            all(c.score >= settings.brand_min_candidate_score for c in candidates),
            detail=f"scores={[c.score for c in candidates]}",
        )

        takedowns = session.exec(
            select(TakedownRequest).where(
                TakedownRequest.tenant_id == tenant_id
            )
        ).all()
        check(
            "≥ 1 TakedownRequest row persisted",
            len(takedowns) >= 1,
            detail=f"count={len(takedowns)}",
        )

        case_ids = [int(cid) for cid in sweep_body.get("cases_opened", [])]
        cases = session.exec(
            select(Case).where(Case.id.in_(case_ids))  # type: ignore[attr-defined]
        ).all() if case_ids else []
        check(
            "every cases_opened id resolves to a Case row",
            len(cases) == len(case_ids) and len(cases) > 0,
            detail=f"requested={case_ids} found={[c.id for c in cases]}",
        )
        check(
            "every opened Case is tenant-scoped to default_tenant",
            all(c.tenant_id == tenant_id for c in cases),
            detail=f"tenants={[c.tenant_id for c in cases]}",
        )

        traces = session.exec(
            select(AgentTrace)
            .where(AgentTrace.agent == AgentName.BRAND_RESPONDER)
            .where(AgentTrace.step == TraceStep.HANDOFF)
        ).all()
        check(
            "≥ 1 AgentTrace with agent=BRAND_RESPONDER, step=HANDOFF recorded",
            len(traces) >= 1,
            detail=f"count={len(traces)}",
        )
        if traces:
            sample = traces[0]
            detail = sample.detail or {}
            check(
                "trace.detail.candidate_domain is one of the mock domains",
                detail.get("candidate_domain")
                in {"testbrand-secure.com", "testbrand-portal.duckdns.org"},
                detail=f"candidate_domain={detail.get('candidate_domain')!r}",
            )
            check(
                "trace.detail.score is recorded",
                isinstance(detail.get("score"), int) and detail["score"] >= 30,
                detail=f"score={detail.get('score')!r}",
            )
            check(
                "trace.detail.channels is non-empty list",
                isinstance(detail.get("channels"), list)
                and len(detail.get("channels", [])) >= 1,
                detail=f"channels={detail.get('channels')!r}",
            )


def check_candidate_triage(client: TestClient) -> None:
    section("Candidate triage surface (list + dismiss)")
    resp = client.get("/brand/candidates")
    check(
        "GET /brand/candidates → 200",
        resp.status_code == 200,
        detail=f"status={resp.status_code}",
    )
    if resp.status_code != 200:
        return
    body = resp.json()
    candidates = body.get("candidates", [])
    check(
        "candidates response is non-empty",
        len(candidates) >= 2,
        detail=f"count={len(candidates)}",
    )
    # min_score filter is honoured.
    resp_filtered = client.get("/brand/candidates", params={"min_score": 999})
    check(
        "GET /brand/candidates?min_score=999 → empty list",
        resp_filtered.status_code == 200
        and resp_filtered.json().get("candidates") == [],
        detail=f"body={resp_filtered.text[:200]}",
    )

    # Dismiss the first candidate; row must flip to DISMISSED.
    target = candidates[0]
    cid = target["id"]
    dismiss = client.post(f"/brand/candidates/{cid}/dismiss")
    check(
        f"POST /brand/candidates/{cid}/dismiss → 200",
        dismiss.status_code == 200,
        detail=f"status={dismiss.status_code} body={dismiss.text[:200]}",
    )
    if dismiss.status_code == 200:
        check(
            "dismissed candidate status == 'dismissed'",
            dismiss.json().get("status") == CandidateStatus.DISMISSED.value,
            detail=f"status={dismiss.json().get('status')!r}",
        )

    # Audit-trail guarantee: dismissed row still exists in DB.
    with Session(engine) as session:
        row = session.get(TyposquatCandidate, cid)
        check(
            "dismissed candidate row is NOT deleted (audit-trail)",
            row is not None and row.status == CandidateStatus.DISMISSED,
            detail=f"row={row!r}",
        )

    # status filter narrows correctly.
    resp_dismissed = client.get("/brand/candidates", params={"status": "dismissed"})
    check(
        "GET /brand/candidates?status=dismissed includes the dismissed row",
        resp_dismissed.status_code == 200
        and any(c["id"] == cid for c in resp_dismissed.json().get("candidates", [])),
        detail=f"body={resp_dismissed.text[:300]}",
    )

    # 404 on unknown candidate id.
    missing = client.post("/brand/candidates/9999999/dismiss")
    check(
        "POST /brand/candidates/<unknown>/dismiss → 404",
        missing.status_code == 404,
        detail=f"status={missing.status_code}",
    )


def check_takedowns_endpoint(client: TestClient) -> None:
    section("Takedown ledger (list + candidate_id filter)")
    resp = client.get("/brand/takedowns")
    check(
        "GET /brand/takedowns → 200",
        resp.status_code == 200,
        detail=f"status={resp.status_code}",
    )
    if resp.status_code != 200:
        return
    body = resp.json()
    takedowns = body.get("takedowns", [])
    check(
        "takedowns response is non-empty",
        len(takedowns) >= 1,
        detail=f"count={len(takedowns)}",
    )
    if not takedowns:
        return

    sample = takedowns[0]
    candidate_id = sample.get("candidate_id")
    check(
        "every takedown row carries a candidate_id",
        all(t.get("candidate_id") for t in takedowns),
    )
    check(
        "every takedown row carries a channel",
        all(t.get("channel") for t in takedowns),
        detail=f"channels={[t.get('channel') for t in takedowns]}",
    )

    resp_filtered = client.get(
        "/brand/takedowns", params={"candidate_id": candidate_id}
    )
    check(
        f"GET /brand/takedowns?candidate_id={candidate_id} narrows result set",
        resp_filtered.status_code == 200
        and all(
            t.get("candidate_id") == candidate_id
            for t in resp_filtered.json().get("takedowns", [])
        )
        and len(resp_filtered.json().get("takedowns", [])) >= 1,
        detail=f"body={resp_filtered.text[:300]}",
    )


def check_agent_rejects_blank_tenant() -> None:
    section("BrandResponderAgent refuses blank tenant_id")
    raised = False
    try:
        with Session(engine) as session:
            BrandResponderAgent(session=session, tenant_id="")
    except ValueError:
        raised = True
    check(
        "BrandResponderAgent('') raises ValueError",
        raised,
    )


# ── Driver ──────────────────────────────────────────────────────────────


def _main() -> int:
    init_db()

    check_settings_loaded()
    check_brand_intel_tool_registered()
    check_scheduler_disabled_when_setting_off()
    check_agent_rejects_blank_tenant()

    client = _client()
    asset_id = check_register_brand_asset(client)
    if asset_id < 0:
        print("\nAborting: asset registration failed; downstream checks skipped.")
    else:
        sweep_body = check_trigger_sweep_auto_files(client)
        check_persisted_state(sweep_body)
        check_candidate_triage(client)
        check_takedowns_endpoint(client)

    print()
    if _FAILED:
        print(f"FAILED ({len(_FAILED)}):")
        for f in _FAILED:
            print(f"  - {f}")
        return 1
    print("All Brand Responder smoke checks passed.")
    return 0


if __name__ == "__main__":
    try:
        rc = _main()
    except Exception:  # pragma: no cover — surface the traceback verbatim
        import traceback

        traceback.print_exc()
        rc = 2
    sys.exit(rc)
