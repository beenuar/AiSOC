"""Parse, self-test, and multi-backend translate a generated Sigma rule.

The validator's job is to fail loudly *before* a rule gets PR'd to a
Git repo. We:

1. Parse the generated dict through ``SigmaRule.from_dict`` so a
   broken structure raises ``SigmaParseError`` here instead of in
   production at engine reload time.
2. Run the parsed rule against the synthetic events. The positive
   set must match, the negative set must not. Any deviation is
   reported in ``SelfTestResult`` — the proposal is still returned so
   the analyst can see *why* it failed (e.g. their hint pointed at
   the wrong logsource).
3. Translate to SPL/KQL/Lucene. Translation failures are captured in
   ``TranslationSet.errors`` rather than raising — a rule that
   matches in Elastic but not in Splunk is still valuable to ship.
"""

from __future__ import annotations

from typing import Any

from app.detections.sigma import SigmaParseError, SigmaRule
from app.detections.translator import (
    BackendError,
    translate_chronicle,
    translate_chronicle_yaral,
    translate_kql,
    translate_lucene,
    translate_splunk,
)

from .models import SelfTestResult, SyntheticEvent, TranslationSet


def parse_rule(sigma_dict: dict[str, Any]) -> SigmaRule:
    """Parse the generated dict into a ``SigmaRule``.

    Re-raised as ``SigmaParseError`` with the rule id for context, so
    the API layer can return a useful 422 instead of a generic 500.
    """
    rid = sigma_dict.get("id") or sigma_dict.get("title") or "<unknown>"
    try:
        return SigmaRule.from_dict(sigma_dict, source=f"author:{rid}")
    except SigmaParseError as exc:
        raise SigmaParseError(f"generated rule {rid!r} failed to parse: {exc}") from exc


def run_self_test(
    rule: SigmaRule,
    events: tuple[SyntheticEvent, ...],
) -> SelfTestResult:
    """Run the rule against the synthetic events and grade the result.

    ``passed`` is True only if *every* positive matched and *no*
    negative matched. We report human-readable failure reasons so the
    analyst sees exactly which synthetic case to fix.
    """
    failures: list[str] = []
    positives_matched = 0
    negatives_false_matched = 0
    positives_total = 0
    negatives_total = 0

    for ev in events:
        is_match = rule.matches(ev.payload)
        if ev.label == "positive":
            positives_total += 1
            if is_match:
                positives_matched += 1
            else:
                failures.append(f"positive[{ev.description!r}] did not match")
        else:
            negatives_total += 1
            if is_match:
                negatives_false_matched += 1
                failures.append(f"negative[{ev.description!r}] matched (should not)")

    passed = not failures
    return SelfTestResult(
        passed=passed,
        positives_total=positives_total,
        positives_matched=positives_matched,
        negatives_total=negatives_total,
        negatives_false_matched=negatives_false_matched,
        failures=tuple(failures),
    )


def translate_all(rule: SigmaRule) -> TranslationSet:
    """Translate the rule to SPL, KQL, Lucene, and Chronicle (UDM + YARA-L)
    with per-backend errors.

    Translation failures are surfaced via ``errors`` rather than
    raising, so a rule that lands cleanly in N of M backends still
    ships its useful translations. The GitOps layer can choose to
    gate the PR on no errors if strict mode is required.

    Chronicle gets two translations because Google's product splits
    interactive hunts (UDM Search) from stored detections (YARA-L 2.0).
    Analysts copy/paste UDM into the hunt console and YARA-L into the
    rule editor — emitting both removes a manual conversion step.
    """
    errors: dict[str, str] = {}
    splunk: str | None
    kql: str | None
    lucene: str | None
    chronicle: str | None
    chronicle_yaral: str | None

    try:
        splunk = translate_splunk(rule)
    except BackendError as exc:
        splunk = None
        errors["splunk"] = str(exc)

    try:
        kql = translate_kql(rule)
    except BackendError as exc:
        kql = None
        errors["kql"] = str(exc)

    try:
        lucene = translate_lucene(rule)
    except BackendError as exc:
        lucene = None
        errors["lucene"] = str(exc)

    try:
        chronicle = translate_chronicle(rule)
    except BackendError as exc:
        chronicle = None
        errors["chronicle"] = str(exc)

    try:
        chronicle_yaral = translate_chronicle_yaral(rule)
    except BackendError as exc:
        chronicle_yaral = None
        errors["chronicle_yaral"] = str(exc)

    return TranslationSet(
        splunk=splunk,
        kql=kql,
        lucene=lucene,
        chronicle=chronicle,
        chronicle_yaral=chronicle_yaral,
        errors=errors,
    )
