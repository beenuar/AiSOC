"""
Four-agent public façade (T2.5 — v8.0).

The internal codebase has historically referred to ~10 agent modules by name
(``auto_triage_agent``, ``phishing_agent``, ``identity_agent``,
``cloud_agent``, ``insider_threat_agent``, ``investigation_agent``,
``attack_path_agent``, ``enrichment_agent``, ``responder_agent``, …).

Buyers, design reviews, and the v8.0 narrative work expose **four** branded
agents instead — one per stage of the customer's mental model:

    Detect   →  fusion + entity-risk + native detections
    Triage   →  LLM auto-triage + the four sub-agent capabilities
                (phishing, identity, cloud, insider)
    Hunt     →  Hunt-as-Code engine + NL hunt surface
    Respond  →  ResponderAgent + SOAR + ChatOps

This module is the public entry point for that contract. Each branded class
is a thin façade that delegates to the existing internal implementations —
nothing is rewritten and no behaviour changes here. The sub-agents stay as
internal modules (``app.agents.phishing_agent`` etc.); they are surfaced as
*capabilities of TriageAgent*, never as first-class public agents.

Back-compat aliases (``AutoTriageAgent``, ``PhishingAgent``,
``IdentityAgent``, ``CloudAgent``, ``InsiderThreatAgent``,
``ResponderAgent``) resolve to the appropriate façade or capability shim so
existing internal callers don't break.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from ..tools.fusion import process_alert as _fusion_process_alert
from .auto_triage_agent import run_auto_triage as _run_auto_triage
from .cloud_agent import run_cloud as _run_cloud
from .enrichment_agent import run_enrichment as _run_enrichment
from .identity_agent import run_identity as _run_identity
from .insider_threat_agent import run_insider_threat as _run_insider_threat
from .investigation_agent import run_investigation as _run_investigation
from .phishing_agent import run_phishing as _run_phishing
from .triage_agent import run_triage as _run_triage

if TYPE_CHECKING:
    from app.models.state import InvestigationState

__all__ = [
    # Public branded agents — exactly four
    "DetectAgent",
    "TriageAgent",
    "HuntAgent",
    "RespondAgent",
    # Capability registry (sub-agents of TriageAgent)
    "TriageCapability",
    "PHISHING",
    "IDENTITY",
    "CLOUD",
    "INSIDER",
    # Back-compat aliases (do NOT use in new code)
    "AutoTriageAgent",
    "PhishingAgent",
    "IdentityAgent",
    "CloudAgent",
    "InsiderThreatAgent",
    "ResponderAgent",
    # Re-exported function entrypoints for orchestrator code that already
    # imports the underlying coroutines directly.
    "run_auto_triage",
    "run_triage",
    "run_phishing",
    "run_identity",
    "run_cloud",
    "run_insider_threat",
    "run_enrichment",
    "run_investigation",
]


# ---------------------------------------------------------------------------
# Re-exported function entrypoints (existing callers use these names directly)
# ---------------------------------------------------------------------------

run_auto_triage = _run_auto_triage
run_triage = _run_triage
run_phishing = _run_phishing
run_identity = _run_identity
run_cloud = _run_cloud
run_insider_threat = _run_insider_threat
run_enrichment = _run_enrichment
run_investigation = _run_investigation


# ---------------------------------------------------------------------------
# DetectAgent — fusion + entity-risk + native detections
# ---------------------------------------------------------------------------


class DetectAgent:
    """Public Detect façade — fusion + entity-risk + native detections.

    The actual detection plane lives in three places that pre-date this
    branding:

    * ``services/fusion/app/services/fusion_engine.py`` — dedup, correlation,
      ML scoring, and confidence labelling.
    * ``services/fusion/app/services/entity_risk.py`` — Risk-Based Alerting
      entity rollup (4-tier severity ladder, time-decayed scores).
    * ``detections/`` + ``services/api/app/services/detection_*`` — the
      native rule corpus (Sigma / KQL / EQL / SPL / DAC).

    ``DetectAgent.process(raw_alert)`` drives the full fusion pipeline
    (dedup, correlation, ML scoring, confidence labelling, RBA) via the
    fusion service's ``POST /process`` endpoint
    (``http://fusion:8003/process`` in the docker-compose network). The
    HTTP client lives at :mod:`app.tools.fusion`. The same
    ``FusionEngine`` instance backs both this synchronous path and the
    Kafka consumer path, so behaviour is identical regardless of how
    alerts arrive.
    """

    name: ClassVar[str] = "Detect"
    description: ClassVar[str] = (
        "Fuses raw alerts from connected sources, applies entity-risk "
        "rollups, and runs the native detection corpus. Output is a "
        "deduplicated, correlated, severity-labelled incident stream."
    )

    @classmethod
    def capabilities(cls) -> tuple[str, ...]:
        return ("fusion", "entity_risk", "native_detections")

    @classmethod
    async def process(
        cls,
        raw_alert: dict[str, Any],
        *,
        api_token: str | None = None,
    ) -> dict[str, Any]:
        """Run a raw alert through the full detection / fusion pipeline.

        This is the public synchronous detection entrypoint for callers
        outside the fusion service. It delegates to the fusion service
        over HTTP (see :mod:`app.tools.fusion`), so the same engine that
        services the Kafka consumer path also services this call —
        dedup, correlation, ML scoring, confidence labelling, RBA, and
        narrative generation all run with shared state.

        The input is intentionally typed as a plain dict rather than a
        Pydantic ``RawAlert``: this keeps the agents service decoupled
        from the fusion service's schema module, and the fusion service
        validates the payload on its boundary regardless. The dict must
        match the shape of ``services.fusion.app.models.alert.RawAlert``.

        Args:
            raw_alert: ``RawAlert``-shaped dict.
            api_token: Optional bearer token forwarded to the fusion service.

        Returns:
            ``FusedAlert``-shaped dict including ``fusion_decision``,
            ``incident_id``, ``priority_score``, ``confidence_label``,
            and the original alert envelope.

        Raises:
            httpx.HTTPStatusError: Fusion service returned non-2xx
                (e.g. 503 if the fusion worker is not yet ready, 422 on a
                malformed payload).
            httpx.HTTPError: Transport-level failure (timeout, connect
                error, etc.). Failures propagate intentionally: silent
                failure on the detection plane would lose alerts.
        """
        return await _fusion_process_alert(raw_alert, api_token=api_token)

    @classmethod
    def describe(cls) -> dict[str, Any]:
        return {
            "name": cls.name,
            "description": cls.description,
            "capabilities": list(cls.capabilities()),
            "internal_modules": [
                "services.fusion.app.services.fusion_engine",
                "services.fusion.app.services.entity_risk",
                "services.api.app.services.detection_engine",
            ],
        }


# ---------------------------------------------------------------------------
# TriageAgent — auto-triage + four sub-agent capabilities
# ---------------------------------------------------------------------------


class TriageCapability:
    """A named triage capability — *not* a top-level public agent.

    Capabilities are how TriageAgent specialises on alert type. They are
    deliberately not promoted to the public four-agent surface because
    capability count drifts (we add e.g. ``insider``, ``cloud``,
    ``phishing``, ``identity``…) and that drift would otherwise erode the
    "exactly four agents" promise we make to buyers.
    """

    __slots__ = ("name", "_runner")

    def __init__(self, name: str, runner: Any) -> None:
        self.name = name
        self._runner = runner

    async def __call__(self, state: InvestigationState) -> InvestigationState:
        return await self._runner(state)

    async def run(self, state: InvestigationState) -> InvestigationState:
        return await self._runner(state)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<TriageCapability {self.name}>"


PHISHING = TriageCapability("phishing", _run_phishing)
IDENTITY = TriageCapability("identity", _run_identity)
CLOUD = TriageCapability("cloud", _run_cloud)
INSIDER = TriageCapability("insider", _run_insider_threat)


class TriageAgent:
    """Public Triage façade — first responder for incoming alerts.

    Wraps two layers:

    * ``run_auto_triage`` — LLM-based classification (TP / FP / benign with
      a confidence score). High-confidence FP/benign are auto-closed; the
      rest escalate.
    * Four sub-agent **capabilities** — phishing, identity, cloud, insider
      — invoked when the alert payload matches one of those domains. They
      live in ``app.agents.{phishing,identity,cloud,insider_threat}_agent``
      and remain importable from those modules; the *public* surface here
      treats them as capabilities, not first-class agents.
    """

    name: ClassVar[str] = "Triage"
    description: ClassVar[str] = (
        "First responder. LLM-based auto-triage classifies the alert and "
        "either auto-closes high-confidence FP/benign or escalates into the "
        "specialised phishing / identity / cloud / insider capability for "
        "deeper analysis."
    )

    capabilities: ClassVar[dict[str, TriageCapability]] = {
        "phishing": PHISHING,
        "identity": IDENTITY,
        "cloud": CLOUD,
        "insider": INSIDER,
    }

    @staticmethod
    async def auto_triage(state: InvestigationState) -> InvestigationState:
        """LLM-based auto-triage entry point.

        Delegates to :func:`app.agents.auto_triage_agent.run_auto_triage`.
        """
        return await _run_auto_triage(state)

    @staticmethod
    async def heuristic_triage(state: InvestigationState) -> InvestigationState:
        """Deterministic heuristic triage (severity scoring + IOC extraction).

        Delegates to :func:`app.agents.triage_agent.run_triage`. Used by the
        eval harness and the offline / air-gapped path where the LLM is
        unavailable.
        """
        return await _run_triage(state)

    @classmethod
    async def analyse(
        cls,
        state: InvestigationState,
        *,
        capability: str,
    ) -> InvestigationState:
        """Dispatch to a named sub-agent capability.

        Args:
            state: live investigation state.
            capability: one of ``phishing``, ``identity``, ``cloud``,
                ``insider``.

        Raises:
            KeyError: if ``capability`` is not a registered sub-agent.
        """
        cap = cls.capabilities[capability]
        return await cap(state)

    # Convenience callable so ``await TriageAgent()(state)`` and
    # ``await TriageAgent.auto_triage(state)`` both work.
    async def __call__(self, state: InvestigationState) -> InvestigationState:
        return await _run_auto_triage(state)

    @classmethod
    def describe(cls) -> dict[str, Any]:
        return {
            "name": cls.name,
            "description": cls.description,
            "capabilities": sorted(cls.capabilities),
            "internal_modules": [
                "app.agents.auto_triage_agent",
                "app.agents.triage_agent",
                *(f"app.agents.{c}_agent" for c in ("phishing", "identity", "cloud")),
                "app.agents.insider_threat_agent",
            ],
        }


# ---------------------------------------------------------------------------
# HuntAgent — Hunt-as-Code engine + NL hunt surface
# ---------------------------------------------------------------------------


class HuntAgent:
    """Public Hunt façade — Hunt-as-Code engine + NL hunt surface.

    Stitches together two existing subsystems:

    * ``app.hunt`` — YAML hypothesis loader + indicator-matching engine
      (``HuntEngine``) + APScheduler-driven runner.
    * ``app.nl_query`` — deterministic NL → ES|QL/KQL/SPL translator with
      optional LLM enhancement.

    Returning the underlying classes / module-level helpers (rather than
    re-implementing) keeps a single source of truth for hunt behaviour and
    means the eval harness exercises the same code paths the public façade
    surfaces.
    """

    name: ClassVar[str] = "Hunt"
    description: ClassVar[str] = (
        "Hypothesis-driven hunting. Run YAML hunts on a schedule via the "
        "Hunt-as-Code engine, or ask security questions in plain English "
        "and get ES|QL / KQL / SPL back."
    )

    @staticmethod
    def engine(*, max_findings_per_run: int = 50):
        """Return a ready-to-use :class:`app.hunt.HuntEngine` instance."""
        from ..hunt import HuntEngine

        return HuntEngine(max_findings_per_run=max_findings_per_run)

    @staticmethod
    def corpus(hunt_dir: Any | None = None):
        """Return a loaded :class:`app.hunt.HuntCorpus`.

        With no argument, returns the cached default corpus
        (:meth:`HuntCorpus.default`). With ``hunt_dir`` set, returns a
        freshly-loaded corpus rooted at that path.
        """
        from ..hunt import HuntCorpus

        if hunt_dir is None:
            return HuntCorpus.default()
        corpus = HuntCorpus(hunt_dir)
        corpus.reload()
        return corpus

    @staticmethod
    def translate(
        question: str,
        *,
        index_pattern: str = "logs-*",
        time_range_hours: int = 24,
    ):
        """NL → query translation.

        Delegates to :func:`app.nl_query.translate`. Returns a
        :class:`TranslatedQuery` with ES|QL, KQL, and SPL renderings plus
        a short explanation.
        """
        from ..nl_query import translate as _translate

        return _translate(
            question,
            index_pattern=index_pattern,
            time_range_hours=time_range_hours,
        )

    @classmethod
    def capabilities(cls) -> tuple[str, ...]:
        return ("hunt_as_code", "nl_query", "scheduled_hunts")

    @classmethod
    def describe(cls) -> dict[str, Any]:
        return {
            "name": cls.name,
            "description": cls.description,
            "capabilities": list(cls.capabilities()),
            "internal_modules": [
                "app.hunt",
                "app.nl_query",
            ],
        }


# ---------------------------------------------------------------------------
# RespondAgent — ResponderAgent + SOAR + ChatOps
# ---------------------------------------------------------------------------


class RespondAgent:
    """Public Respond façade — incident response orchestration.

    Wraps the existing :func:`app.investigator.responder_agent.run_responder`
    LangGraph node and exposes it under the branded name. Live execution is
    DRY-RUN by default; the SOAR exec service (``services/api`` action
    endpoints) and ChatOps (``services/slack-bot``) are the surfaces that
    promote the dry-run plan into actual actions, gated by autonomy
    thresholds.
    """

    name: ClassVar[str] = "Respond"
    description: ClassVar[str] = (
        "Generate prioritised containment / eradication / recovery plans, "
        "expose them through SOAR for execution, and surface approvals "
        "through ChatOps. Every action is dry-run until a guardrailed "
        "approval promotes it."
    )

    @staticmethod
    async def plan(state_dict: dict[str, Any]) -> dict[str, Any]:
        """Build a response plan for a finished investigation.

        Delegates to :func:`app.investigator.responder_agent.run_responder`.
        """
        from ..investigator.responder_agent import run_responder

        return await run_responder(state_dict)

    # Convenience callable: ``await RespondAgent()(state_dict)``.
    async def __call__(self, state_dict: dict[str, Any]) -> dict[str, Any]:
        return await type(self).plan(state_dict)

    @classmethod
    def capabilities(cls) -> tuple[str, ...]:
        return ("response_planner", "soar_exec", "chatops_approvals")

    @classmethod
    def describe(cls) -> dict[str, Any]:
        return {
            "name": cls.name,
            "description": cls.description,
            "capabilities": list(cls.capabilities()),
            "internal_modules": [
                "app.investigator.responder_agent",
                "services.api.app.api.v1.endpoints.actions",
                "services.slack-bot",
            ],
        }


# ---------------------------------------------------------------------------
# Back-compat aliases
# ---------------------------------------------------------------------------
#
# These names pre-date the four-agent rebrand. Internal callers that import
# them keep working; **do not** introduce new uses in new code — pick one of
# the four branded classes above instead. We keep the aliases as concrete
# (sub)classes rather than bare assignments so ``isinstance`` and
# ``__name__`` checks still behave reasonably.


class AutoTriageAgent(TriageAgent):
    """Deprecated alias for :class:`TriageAgent`.

    Kept so ``from app.agents import AutoTriageAgent`` still resolves.
    """


class _CapabilityShim:
    """Class wrapper around a :class:`TriageCapability`.

    The legacy public surface exposed PhishingAgent / IdentityAgent / etc.
    as importable classes. The new public surface treats them as
    capabilities of TriageAgent. This shim lets old code keep working
    without giving these names first-class billing in the docs / hero copy.
    """

    capability: ClassVar[TriageCapability]

    def __init_subclass__(cls, *, capability: TriageCapability, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        cls.capability = capability

    @classmethod
    async def run(cls, state: InvestigationState) -> InvestigationState:
        return await cls.capability(state)

    async def __call__(self, state: InvestigationState) -> InvestigationState:
        return await type(self).capability(state)


class PhishingAgent(_CapabilityShim, capability=PHISHING):
    """Deprecated alias — phishing is a capability of :class:`TriageAgent`."""


class IdentityAgent(_CapabilityShim, capability=IDENTITY):
    """Deprecated alias — identity is a capability of :class:`TriageAgent`."""


class CloudAgent(_CapabilityShim, capability=CLOUD):
    """Deprecated alias — cloud is a capability of :class:`TriageAgent`."""


class InsiderThreatAgent(_CapabilityShim, capability=INSIDER):
    """Deprecated alias — insider is a capability of :class:`TriageAgent`."""


class ResponderAgent(RespondAgent):
    """Deprecated alias for :class:`RespondAgent`.

    Note: this is the *public* class name. The underlying LangGraph node
    function still lives at
    ``app.investigator.responder_agent.run_responder`` and is unchanged.
    """
