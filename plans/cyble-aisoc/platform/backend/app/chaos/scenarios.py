"""Built-in chaos scenarios (t6-chaos).

A small bundle of named scenarios that mirror the failure modes
real agents have to cope with in production:

* ``llm-provider-down`` — every agent's first LLM call raises an
  outage exception. Validates retry / fallback / degraded-mode
  behaviour across the orchestration mesh.
* ``edr-tool-flaky`` — the EDR isolation tool hits a 30-second
  artificial timeout on its next call. Validates the Responder's
  HITL escalation when a high-risk tool fails to complete.
* ``cti-malformed-response`` — CTI lookups return a payload with
  the wrong schema. Validates that the Investigator's defensive
  parsing surfaces a meaningful error rather than silently
  treating the response as trustworthy.
* ``mixed-light-degradation`` — an LLM slowness fault plus a tool
  malformed response, fired in sequence. Mimics the "everything is
  a bit broken" experience a real outage tends to produce.

Authors of new scenarios should keep them small (≤4 faults) and
narrow (target a single agent or surface). Bigger drills compose
multiple scenarios at the API.
"""
from __future__ import annotations

from app.chaos.engine import ChaosFault, ChaosKind, ChaosScenario


def builtin_scenarios() -> list[ChaosScenario]:
    return [
        ChaosScenario(
            name="llm-provider-down",
            description=(
                "The LLM provider is unreachable. Every agent's next "
                "completion raises a synthetic outage."
            ),
            faults=[
                ChaosFault(
                    kind=ChaosKind.llm_outage,
                    target="llm.complete*",
                    remaining=5,
                    message="provider unreachable (chaos)",
                ),
            ],
        ),
        ChaosScenario(
            name="edr-tool-flaky",
            description=(
                "The EDR isolation tool times out on its next call. "
                "Validates Responder's HITL escalation path."
            ),
            faults=[
                ChaosFault(
                    kind=ChaosKind.tool_timeout,
                    target="tool.edr.isolate_host",
                    remaining=1,
                    delay_ms=500,
                    message="EDR control plane non-responsive (chaos)",
                ),
            ],
        ),
        ChaosScenario(
            name="cti-malformed-response",
            description=(
                "CTI lookups return a payload with the wrong schema. "
                "Investigator must surface a defensive error."
            ),
            faults=[
                ChaosFault(
                    kind=ChaosKind.tool_malformed,
                    target="tool.cti.enrich_ioc",
                    remaining=2,
                    payload={"unexpected_key": "garbage", "schema_version": -1},
                    message="CTI feed garbled (chaos)",
                ),
            ],
        ),
        ChaosScenario(
            name="mixed-light-degradation",
            description=(
                "Combined LLM slowness + tool malformed response. The "
                "system should still complete the case albeit slowly."
            ),
            faults=[
                ChaosFault(
                    kind=ChaosKind.tool_slowness,
                    target="tool.cti.*",
                    remaining=2,
                    delay_ms=200,
                    message="CTI rate-limit surge (chaos)",
                ),
                ChaosFault(
                    kind=ChaosKind.tool_malformed,
                    target="tool.cti.actor_lookup",
                    remaining=1,
                    payload={"actor": None, "confidence": "broken"},
                    message="CTI actor feed garbled (chaos)",
                ),
            ],
        ),
    ]
