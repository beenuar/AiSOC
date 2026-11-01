"""Pull a vendor's own evidence before triaging that vendor's alert.

Wave 2, Phase 4.5.

The gap, precisely
------------------
Read verbs already exist. `services/actions/app/live_actions/investigation_reads.py`
is 987 lines carrying five read-only capabilities across seven vendors, each
with a capability contract, an executor, an autospec'd signature test, a
closed agent allowlist and a parameter allowlist. Nothing here adds a verb.

What did not exist was any way for **auto-triage** to reach them. The verbs
are bound to the investigation agent in `deep_investigation.py`, which runs
only on the escalation path. `run_auto_triage` is a single `safe_ainvoke`
with no tool channel at all, and says so in its own comment:

    `called_tools` is empty and that is the point rather than a shortcut:
    this path is a single `safe_ainvoke` with no tool channel, so the
    Investigation Ledger holds no `tool_call` row for this run and can hold
    none.

So for a GuardDuty, Defender or EDR alert that auto-triages — the path every
fused alert takes — the vendor's own record of the host, the account or the
detection was never consulted. The verdict rested on the alert payload and
the model, and `unverified_tool_claims` correctly blocked auto-close if the
model so much as *claimed* a tool result.

Why a deterministic pre-fetch and not a tool-calling loop
----------------------------------------------------------
A ReAct loop would let the model choose. On this path that is the wrong
trade three ways over.

**Latency and cost are unbounded.** Auto-triage handles every fused alert.
A loop turns one model call into N plus N vendor round trips, on the hot
path, with no ceiling anybody declared.

**The model's choice is attacker-influenced.** The alert payload is
untrusted by construction — that is why it is fenced and injection-scanned
before anything reasons over it. A tool channel whose arguments the model
derives from that payload is a door an injected string can steer. The
existing parameter allowlist in `vendor_reads.py` stops the worst of it, and
not choosing at all is strictly stronger.

**A deterministic fetch makes the citation true.** The reads here are
decided by the alert's own connector and entities, so the result is in hand
before the model is asked anything. The ledger row is written because the
call happened, not because the model said it did.

So this is a *bounded channel*: triage reaches the real verbs, the set is
fixed per alert shape, the budget is declared, and the model selects
nothing.

Off by default
--------------
`AISOC_TRIAGE_VENDOR_EVIDENCE` is unset by default. This reaches out to the
customer's vendor API on every fused alert, which is the condition the plan
reserves for opt-in, and the latency argument above is the second reason.
An operator turns it on knowing both.

The results are untrusted
-------------------------
A vendor's description field carries attacker-influenced text — a file name,
a process command line, a repository name somebody chose. The rendered block
therefore goes through the same `EvidenceEnvelope` nonce fence the knowledge
base uses, and is **not** re-sanitised by the caller, because running
`sanitize_text` over a rendered block rewrites the nonce markers that are the
only thing holding the fence together.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from app.context.knowledge_base import BOUNDARY_NOTE
from app.prompting.envelope import EvidenceEnvelope

logger = structlog.get_logger()

#: Ceiling on reads per alert. Three covers the shapes that exist — a host
#: has a record and a detection history, an account has an activity trail —
#: and a ceiling that is not declared is not a ceiling.
MAX_READS_PER_ALERT = 3

#: Wall-clock budget for the whole pre-fetch, in seconds. Exceeded, the
#: partial results are kept and the rest are reported as not attempted:
#: triage must not wait on somebody else's API, and a timeout that discarded
#: what it already had would pay the cost and keep none of the benefit.
BUDGET_SECONDS = 8.0

#: Per-read timeout, inside the budget above.
READ_TIMEOUT_SECONDS = 5.0

_MAX_ENVELOPE_CHARS = 4000

#: Which verbs to run for which alert shape.
#:
#: Keyed on the entity the alert carries rather than on the vendor, because
#: the capability contract is per *verb* and a vendor is resolved from the
#: tenant's connectors downstream — the same reasoning `capability_contracts`
#: records for why adding a vendor to an existing verb inherits its
#: classification. An alert naming a host asks what the endpoint product
#: already knows about that host and what it has already raised on it; an
#: alert naming an account asks the identity provider for its recent
#: authentication.
_PLAN: tuple[tuple[str, str, str], ...] = (
    ("hostname", "get_host", "what the endpoint product records about this host"),
    ("hostname", "get_detections", "detections this endpoint product has already raised on this host"),
    ("username", "get_user_activity", "recent authentication for this account, from the identity provider"),
)


def enabled() -> bool:
    """Whether this deployment pulls vendor evidence during auto-triage."""
    return os.getenv("AISOC_TRIAGE_VENDOR_EVIDENCE", "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class VendorRead:
    """One read that was attempted, and what came back."""

    capability: str
    target: str
    purpose: str
    #: `executed` is the single field that means a vendor was touched. Every
    #: other status is a non-execution with its own reason, and each reaches
    #: the model as "could not check" rather than as a result.
    executed: bool
    status: str
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)
    elapsed_ms: int = 0

    def as_ledger_payload(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "target": self.target,
            "executed": self.executed,
            "status": self.status,
            "summary": self.summary[:1000],
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class VendorEvidence:
    """Everything the pre-fetch obtained, and everything it could not."""

    reads: list[VendorRead] = field(default_factory=list)
    #: Reads the budget stopped before they were attempted. Named rather than
    #: dropped: a model told nothing assumes it was told everything.
    not_attempted: list[str] = field(default_factory=list)

    @property
    def executed_capabilities(self) -> tuple[str, ...]:
        """The verbs a vendor really answered.

        This is what `unverified_tool_claims` is given. A verb that was
        attempted and failed is deliberately **not** here: the guard's
        question is whether a rationale credits a tool with a result, and a
        read that returned nothing produced no result to credit.
        """
        return tuple(r.capability for r in self.reads if r.executed)

    def as_state(self) -> dict[str, Any]:
        return {
            "reads": [r.as_ledger_payload() for r in self.reads],
            "not_attempted": list(self.not_attempted),
        }


def plan_reads(alert: dict[str, Any] | None) -> list[tuple[str, str, str]]:
    """The reads this alert's shape calls for, bounded and deduplicated.

    Pure, so the choice can be tested without a network. Returns
    ``(capability, target, purpose)`` triples.
    """
    payload = alert or {}
    chosen: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for field_name, capability, purpose in _PLAN:
        target = str(payload.get(field_name) or "").strip()
        if not target:
            continue
        key = (capability, target.lower())
        if key in seen:
            continue
        seen.add(key)
        chosen.append((capability, target, purpose))
    return chosen[:MAX_READS_PER_ALERT]


async def collect(
    alert: dict[str, Any] | None,
    *,
    tenant_id: str,
    runner: Any = None,
) -> VendorEvidence:
    """Run this alert's planned reads, within the budget. Never raises.

    ``runner`` is the injection seam, defaulting to the production
    `run_vendor_read`. It is a parameter rather than a module-level import so
    the suite can drive the real planning and rendering without a network,
    and so this module does not pull the tool package in at import time.
    """
    evidence = VendorEvidence()
    planned = plan_reads(alert)
    if not planned:
        return evidence

    if runner is None:
        from app.tools.customer_tools import run_vendor_read

        runner = run_vendor_read

    deadline = time.monotonic() + BUDGET_SECONDS
    for capability, target, purpose in planned:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            evidence.not_attempted.append(f"{capability} for {target}")
            continue

        started = time.monotonic()
        try:
            body = await asyncio.wait_for(
                runner(capability, target, tenant_id=tenant_id),
                timeout=min(READ_TIMEOUT_SECONDS, remaining),
            )
        except TimeoutError:
            evidence.reads.append(
                VendorRead(
                    capability=capability,
                    target=target,
                    purpose=purpose,
                    executed=False,
                    status="timeout",
                    summary="The vendor did not answer within the read timeout.",
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                )
            )
            continue
        except Exception as exc:  # noqa: BLE001 — evidence is additive, never the verdict
            logger.warning("vendor_evidence.read_failed", capability=capability, error=str(exc)[:200])
            evidence.reads.append(
                VendorRead(
                    capability=capability,
                    target=target,
                    purpose=purpose,
                    executed=False,
                    status="failed",
                    summary=f"The read could not be made ({type(exc).__name__}).",
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                )
            )
            continue

        body = body if isinstance(body, dict) else {}
        evidence.reads.append(
            VendorRead(
                capability=capability,
                target=target,
                purpose=purpose,
                executed=bool(body.get("executed")),
                status=str(body.get("status") or ("ok" if body.get("executed") else "unknown")),
                summary=str(body.get("summary") or body.get("detail") or "").strip(),
                detail={k: v for k, v in body.items() if k in {"result", "records", "count"}},
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
        )

    return evidence


def render_for_prompt(evidence: VendorEvidence | None, *, nonce: str) -> str:
    """The vendor-evidence block, fenced. Empty when nothing was read.

    Returns ``""`` rather than a "none" heading for the same reason the
    runbook renderer does: a heading over nothing invites the model to
    explain an absence it has no information about.

    **Do not sanitise the result.** The fence is placed here, and
    `sanitize_text` over a rendered block rewrites the nonce markers that are
    the only thing holding it together.
    """
    if evidence is None or (not evidence.reads and not evidence.not_attempted):
        return ""

    lines: list[str] = []
    for read in evidence.reads:
        if read.executed:
            lines.append(f"- [{read.capability}] {read.target} — {read.purpose}:\n  {read.summary or 'no detail returned'}")
        else:
            # The distinction the whole feature turns on. "We could not check"
            # must never render as "we checked and it was clean": a failed
            # read of an EDR is not evidence that the host is healthy.
            lines.append(f"- [{read.capability}] {read.target} — COULD NOT CHECK ({read.status}). {read.summary or ''}".rstrip())
    for missing in evidence.not_attempted:
        lines.append(f"- [{missing}] NOT ATTEMPTED — the evidence budget ran out before this read.")

    envelope = EvidenceEnvelope.wrap(
        "\n".join(lines),
        nonce=nonce,
        source="vendor_evidence",
        max_body_chars=_MAX_ENVELOPE_CHARS,
    )
    return (
        "What the vendors that raised or observe this alert say about it, read just now from "
        "their own APIs.\n"
        f"{BOUNDARY_NOTE}\n"
        "A read marked COULD NOT CHECK is the absence of an answer, not a clean one: it is never "
        "evidence that the host, account or detection is fine. Cite a read by its capability name "
        "when it informs your rationale, and cite no capability that is not listed above.\n"
        f"{envelope.render()}"
    )
