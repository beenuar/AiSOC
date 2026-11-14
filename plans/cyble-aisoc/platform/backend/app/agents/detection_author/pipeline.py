"""End-to-end orchestration for the Detection Author Agent.

The pipeline is a deliberately linear, side-effect-free flow:

    ThreatReport
      → generate()          # Sigma dict + YAML + synthetic events
      → parse_rule()        # parse for structural validity
      → run_self_test()     # rule must match positives, miss negatives
      → translate_all()     # SPL / KQL / Lucene
      → build_artifact()    # GitOps PR materials
      → DetectionProposal

Nothing here writes to disk, talks to git, or mutates the runtime
``DetectionEngine``. Hot-reload + tenant-scoped publication of the
rule live behind separate, explicitly-invoked entrypoints
(``activate_in_engine``) so an HTTP caller can preview a proposal
without changing the platform state.
"""

from __future__ import annotations

from app.detections.runtime import add_rule, get_engine

from .generator import generate
from .gitops import build_artifact
from .models import DetectionProposal, ThreatReport
from .validator import parse_rule, run_self_test, translate_all


def propose_detection(report: ThreatReport) -> DetectionProposal:
    """Run the full proposal flow for a single ``ThreatReport``.

    The output is *only* a proposal — it is NOT installed into the
    live engine. Use ``activate_in_engine`` if and when the analyst
    approves the proposal.
    """
    sigma_dict, yaml_text, events, techniques, iocs = generate(report)

    # parse_rule raises SigmaParseError on a malformed dict; we let
    # that bubble so the HTTP layer can convert it into a 422.
    rule = parse_rule(sigma_dict)

    self_test = run_self_test(rule, events)
    translations = translate_all(rule)
    gitops = build_artifact(
        report=report,
        rule_id=rule.id,
        title=rule.title,
        yaml_text=yaml_text,
        sigma_dict=sigma_dict,
        events=events,
        self_test=self_test,
        translations=translations,
        techniques=techniques,
        iocs=iocs,
    )

    return DetectionProposal(
        rule_id=rule.id,
        title=rule.title,
        yaml=yaml_text,
        sigma_dict=sigma_dict,
        translations=translations,
        synthetic_events=events,
        self_test=self_test,
        gitops=gitops,
        extracted_techniques=techniques,
        extracted_iocs=iocs,
    )


def activate_in_engine(proposal: DetectionProposal) -> None:
    """Hot-add the proposal's rule to the live ``DetectionEngine``.

    This is a deliberate, separate call from ``propose_detection`` —
    the HTTP layer should only invoke this once the proposal has been
    approved (HITL gate, MFA, etc.). Internally it relies on
    ``app.detections.runtime.add_rule`` which atomically replaces any
    existing rule with the same id, so re-activating an updated
    proposal is safe.
    """
    # Re-parse from the proposal's sigma_dict rather than reusing the
    # rule we built during validation, so the engine owns its own
    # ``SigmaRule`` instance and downstream code never sees a shared
    # mutable reference.
    rule = parse_rule(proposal.sigma_dict)
    # Make sure the engine is warm before mutating it. Without this,
    # the first request after process start would mutate a not-yet-
    # initialized pack.
    get_engine()
    add_rule(rule)
