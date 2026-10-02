"""Start a playbook from a fused alert. Off by default, preview before live.

Parity plan 5.1: "`find_matching()` has no production caller today. Call it
from the fused-alert path behind a setting that ships off. A playbook first
runs in preview, with its plan and simulated steps shown on the alert, and
then goes live per tenant and per playbook."

Why three switches rather than one
-----------------------------------
A playbook that runs from an alert is the most consequential thing in this
product: it can isolate a host nobody asked it to. One global flag is not
enough granularity to turn that on safely, so there are three and **all**
must agree:

1. the deployment switch, off by default;
2. the tenant, which must have opted in;
3. the playbook itself, which must be marked live rather than preview.

A playbook that clears the first two still runs in **preview**: its plan
and its simulated steps attach to the alert so an analyst can read what it
would have done. Going live is a separate, per-playbook decision made
after reading that.

The ordering matters: preview is the default state, not a mode somebody
has to remember to use first.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()

#: The deployment switch. Off, because the alternative is a fresh install
#: that can take a containment action on its first alert.
ENABLED_ENV = "AISOC_ALERT_PLAYBOOKS_ENABLED"

#: Per-tenant and per-playbook opt-in to **live** execution. Everything
#: else runs in preview.
LIVE_PLAYBOOKS_ENV = "AISOC_ALERT_PLAYBOOKS_LIVE"


def deployment_enabled() -> bool:
    return os.getenv(ENABLED_ENV, "").strip().lower() in ("1", "true", "yes")


def live_playbook_ids() -> set[str]:
    """Playbooks allowed to run live, as `tenant:playbook` or `playbook`.

    Read per call rather than cached, so turning one off takes effect on
    the next alert rather than on the next restart. A playbook that can
    take a containment action should be switchable off faster than a
    deploy.
    """
    raw = os.getenv(LIVE_PLAYBOOKS_ENV, "")
    return {part.strip() for part in raw.split(",") if part.strip()}


def is_live(*, tenant_id: str, playbook_id: str) -> bool:
    allowed = live_playbook_ids()
    return bool(allowed & {f"{tenant_id}:{playbook_id}", playbook_id})


@dataclass
class TriggerOutcome:
    """What the alert path did, and why. Attached to the alert."""

    considered: int = 0
    matched: list[str] = field(default_factory=list)
    previewed: list[dict[str, Any]] = field(default_factory=list)
    executed: list[dict[str, Any]] = field(default_factory=list)
    skipped_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "considered": self.considered,
            "matched": self.matched,
            "previewed": self.previewed,
            "executed": self.executed,
            "skipped_reason": self.skipped_reason,
        }


def alert_context(state: Any) -> dict[str, Any]:
    """The trigger context a playbook's conditions read.

    Flat, because `find_matching` filters on `severity` and `tags` at the
    top level and a nested alert would match nothing while looking like it
    should.
    """
    raw = getattr(state, "raw_alert", None) or {}
    if not isinstance(raw, dict):
        raw = {}
    context: dict[str, Any] = {
        "tenant_id": str(getattr(state, "tenant_id", "") or ""),
        "alert_id": str(getattr(state, "incident_id", "") or ""),
        "severity": raw.get("severity") or getattr(state, "severity", None),
        "tags": raw.get("tags") or [],
        "title": raw.get("title") or "",
        "verdict": getattr(state, "verdict", None),
        "confidence": getattr(state, "confidence", None),
    }
    for key in ("host", "hostname", "username", "user", "src_ip", "dst_ip", "domain", "file_hash"):
        value = raw.get(key)
        if value:
            context.setdefault(key, value)
    return context


async def run_for_alert(state: Any) -> TriggerOutcome:
    """Match and run playbooks for one fused alert.

    Never raises. A playbook failure must not lose the triage result it
    was attached to, so every error is captured into the outcome and the
    alert still carries its verdict.
    """
    outcome = TriggerOutcome()

    if not deployment_enabled():
        outcome.skipped_reason = f"alert-triggered playbooks are off; set {ENABLED_ENV}=1 to enable them"
        return outcome

    context = alert_context(state)
    tenant_id = context["tenant_id"]
    if not tenant_id:
        outcome.skipped_reason = "the alert carries no tenant, so no playbook can be scoped to it"
        return outcome

    try:
        from app.playbook.engine import PlaybookEngine
        from app.playbook.store import PlaybookStore

        store = PlaybookStore.default()
        matches = store.find_matching("alert.created", context)
    except Exception as exc:  # noqa: BLE001
        logger.warning("alert_playbooks.match_failed", error=str(exc))
        outcome.skipped_reason = f"could not match playbooks: {exc}"
        return outcome

    outcome.considered = len(matches)
    engine = PlaybookEngine()

    for playbook in matches:
        outcome.matched.append(playbook.id)
        live = is_live(tenant_id=tenant_id, playbook_id=playbook.id)
        try:
            run = await engine.run(playbook, context, dry_run=not live)
        except Exception as exc:  # noqa: BLE001
            logger.warning("alert_playbooks.run_failed", playbook_id=playbook.id, error=str(exc))
            outcome.previewed.append({"playbook_id": playbook.id, "error": str(exc)})
            continue

        record = {
            "playbook_id": playbook.id,
            "playbook_name": playbook.name,
            "run_id": run.run_id,
            "status": getattr(run.status, "value", str(run.status)),
            "steps": [
                {
                    "step_id": r.get("step_id"),
                    "name": r.get("name"),
                    "status": getattr(r.get("status"), "value", str(r.get("status"))),
                }
                for r in run.step_results
            ],
        }
        if live:
            outcome.executed.append(record)
            logger.info(
                "alert_playbooks.ran_live",
                playbook_id=playbook.id,
                run_id=run.run_id,
                status=record["status"],
            )
        else:
            # The reason is on the record, so an analyst reading the alert
            # sees why it previewed rather than wondering whether it
            # failed.
            record["preview"] = True
            record["reason"] = f"preview only: add {tenant_id}:{playbook.id} to {LIVE_PLAYBOOKS_ENV} to let this playbook act"
            outcome.previewed.append(record)

    return outcome
