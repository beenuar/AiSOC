"""DetectionEngine: evaluate a stream of events against a RulePack.

The engine is deliberately thin. It is the in-memory hot-path runner —
think "Splunk real-time search" but local to the Python process. The
much heavier batch / historical retro-hunt path goes through the
backend translators (translate_splunk/kql/lucene) and runs in the
customer's SIEM, not here.

Why two paths?
- The realtime path is what makes a Triage Agent feel instant: events
  land in Kafka, get OCSF-normalized (Theme 1: t1-realtime-data), and
  every rule in the pack evaluates against them in microseconds.
- The retro / batch path is what makes a new rule useful on day zero:
  when an analyst writes a Sigma rule via the Detection Author Agent
  (Theme 2a), we translate it once and let the SIEM scan months of
  cold storage. We don't try to replicate that here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator

from .pack import RulePack
from .sigma import Hit, SigmaRule

logger = logging.getLogger(__name__)


# Optional hook fired after every event evaluation. Useful for metrics
# (per-rule eval count, p99 latency) and for the FinOps dashboard
# (Theme 5: t5-finops) when we start attributing cost-per-rule.
EvalCallback = Callable[[str, bool], None]


@dataclass
class DetectionEngine:
    """Evaluate normalized events against every rule in a RulePack.

    Construct once per tenant per pack version; reuse across events.
    Engines are cheap (a thin wrapper) but rule loading is not, so
    the caller is expected to cache pack instances.
    """

    pack: RulePack
    on_eval: EvalCallback | None = None

    # --- single-event evaluation ---------------------------------------

    def evaluate(self, event: dict) -> list[Hit]:
        """Return every Hit triggered by ``event``.

        Multi-hit: a single event can fire many rules, and we return
        them all. The caller decides how to dedupe (often: collapse on
        rule_id, keep first).
        """
        hits: list[Hit] = []
        for rule in self.pack.rules:
            try:
                hit = rule.evaluate(event)
            except Exception:  # noqa: BLE001 — never let one rule kill the loop
                # A buggy rule must not stop the stream. We log and
                # continue; CI should have caught this in strict mode.
                logger.exception("detection_engine:rule_error rule_id=%s", rule.id)
                self._fire(rule, False)
                continue
            self._fire(rule, hit is not None)
            if hit is not None:
                hits.append(hit)
        return hits

    # --- stream evaluation ---------------------------------------------

    def run(self, events: Iterable[dict]) -> Iterator[Hit]:
        """Iterate ``events`` and yield every Hit, in source order."""
        for event in events:
            for hit in self.evaluate(event):
                yield hit

    # --- introspection -------------------------------------------------

    def explain(self, rule_id: str, event: dict) -> dict:
        """Return per-selection truth values for one rule against one event.

        Powers the "counterfactual why-not" feature (Theme 4) — analysts
        can ask "why didn't this rule fire?" and we return which
        selection blocks evaluated False.
        """
        rule = self.pack.by_id(rule_id)
        if rule is None:
            return {"error": f"unknown rule_id: {rule_id}"}
        results = {name: sel.evaluate(event) for name, sel in rule.selections.items()}
        fired = rule.condition.evaluate(results)
        return {
            "rule_id": rule.id,
            "title": rule.title,
            "fired": fired,
            "selections": results,
        }

    # --- internals -----------------------------------------------------

    def _fire(self, rule: SigmaRule, matched: bool) -> None:
        if self.on_eval is not None:
            try:
                self.on_eval(rule.id, matched)
            except Exception:  # noqa: BLE001 — telemetry must never break detection
                logger.exception("detection_engine:on_eval_error rule_id=%s", rule.id)


__all__ = ["DetectionEngine", "EvalCallback"]
