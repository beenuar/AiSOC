#!/usr/bin/env python3
"""A content pack is everything needed to handle a scenario, not a playbook.

Gap-closure wave 10.

Today a "pack" is a playbook and nothing else. The 62 shipped
playbooks do cover the named scenarios, and each one assumes something
already raised the alert, something already correlated the signals,
and somebody already knows the response worked. None of those three
ship with it.

So an operator adopting "ransomware" gets a response procedure and has
to supply the detections that trigger it, the correlation that groups
them, and any way of knowing the pack works at all. The pack is the
last fifth of the thing its name implies.

What a pack bundles
-------------------
**Detections** — what raises the alert. Named by rule id so a pack can
reference the shipped corpus rather than carry a fork of it, which is
how two copies of a rule end up disagreeing.

**Correlations** — which signals belong to the same incident. A
ransomware pack whose detections each raise a separate alert has made
the operator's day worse, not better.

**An investigation plan** — what to establish, in order. Not a
playbook: a playbook executes, a plan says what the answer needs to
contain, and the agent or the analyst decides how to get there.

**Response** — the playbook, which is what exists today.

**Validation** — how to prove the pack works on *this* deployment,
which is the piece whose absence makes the other four unfalsifiable.
A pack that cannot be validated is a document.

Scenario tags
-------------
Detections carry only three distinct non-MITRE tags across 877 rules,
so "which rules fire for ransomware" has no answer today. A pack
declares its scenario and the rules it claims, which is the same
information from the other direction and does not require retagging
the corpus first.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = ["PACK_SCHEMA_VERSION", "ContentPack", "PackProblem", "validate_pack"]

PACK_SCHEMA_VERSION = 1

#: The scenarios a pack may claim. A closed set, because a scenario
#: vocabulary that varies by author cannot be searched, and "which pack
#: covers ransomware" is the question a pack exists to answer.
SCENARIOS = (
    "ransomware",
    "business_email_compromise",
    "insider_threat",
    "cloud_account_compromise",
    "supply_chain",
    "credential_theft",
    "data_exfiltration",
    "living_off_the_land",
    "ai_runtime_abuse",
)

#: Every section a pack must carry. Listed rather than inferred so a
#: pack missing one fails loudly instead of being half a pack that
#: looks complete in a listing.
REQUIRED_SECTIONS = ("detections", "correlations", "investigation_plan", "response", "validation")


@dataclass
class PackProblem:
    code: str
    detail: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"[{self.code}] {self.detail}"


@dataclass
class ContentPack:
    id: str
    name: str
    scenario: str
    version: str = "1.0.0"
    schema_version: int = PACK_SCHEMA_VERSION
    description: str = ""
    detections: list[str] = field(default_factory=list)
    correlations: list[dict[str, Any]] = field(default_factory=list)
    investigation_plan: list[dict[str, Any]] = field(default_factory=list)
    response: list[str] = field(default_factory=list)
    validation: list[dict[str, Any]] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    owner: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ContentPack:
        return cls(
            id=str(raw.get("id", "")),
            name=str(raw.get("name", "")),
            scenario=str(raw.get("scenario", "")),
            version=str(raw.get("version", "1.0.0")),
            schema_version=int(raw.get("schema_version", PACK_SCHEMA_VERSION)),
            description=str(raw.get("description", "")),
            detections=list(raw.get("detections") or []),
            correlations=list(raw.get("correlations") or []),
            investigation_plan=list(raw.get("investigation_plan") or []),
            response=list(raw.get("response") or []),
            validation=list(raw.get("validation") or []),
            mitre_techniques=list(raw.get("mitre_techniques") or []),
            owner=str(raw.get("owner", "")),
        )


def validate_pack(
    pack: ContentPack,
    *,
    known_rule_ids: frozenset[str] | None = None,
    known_playbook_ids: frozenset[str] | None = None,
) -> list[PackProblem]:
    """Everything that would make this pack misleading to adopt.

    `known_rule_ids` and `known_playbook_ids` are optional so the
    schema can be checked without loading the corpus — but when they
    are supplied, a reference to something that does not exist is an
    error rather than a warning. A pack claiming a rule nobody ships is
    the exact failure this format exists to prevent: the operator
    adopts it, nothing fires, and there is no error anywhere.
    """
    problems: list[PackProblem] = []

    if not pack.id:
        problems.append(PackProblem("missing-id", "a pack with no id cannot be installed or referenced"))
    if pack.scenario not in SCENARIOS:
        problems.append(
            PackProblem(
                "unknown-scenario",
                f"{pack.scenario!r} is not in the declared vocabulary; a scenario that varies by "
                f"author cannot be searched. Known: {', '.join(SCENARIOS)}",
            )
        )
    if pack.schema_version != PACK_SCHEMA_VERSION:
        problems.append(
            PackProblem(
                "schema-version",
                f"pack declares schema {pack.schema_version}, this reader understands {PACK_SCHEMA_VERSION}",
            )
        )

    for section in REQUIRED_SECTIONS:
        if not getattr(pack, section):
            problems.append(
                PackProblem(
                    "empty-section",
                    f"{section!r} is empty. A pack missing a section is half a pack that looks "
                    "complete in a listing — which is how 'a pack' came to mean 'a playbook'",
                )
            )

    if known_rule_ids is not None:
        for rule_id in pack.detections:
            if rule_id not in known_rule_ids:
                problems.append(
                    PackProblem(
                        "unknown-detection",
                        f"{rule_id!r} is not a shipped rule. An operator adopts this pack, nothing fires, and no error appears anywhere",
                    )
                )

    if known_playbook_ids is not None:
        for playbook_id in pack.response:
            if playbook_id not in known_playbook_ids:
                problems.append(PackProblem("unknown-playbook", f"{playbook_id!r} is not a shipped playbook"))

    # Validation is the section whose absence makes the rest
    # unfalsifiable, so it is checked for substance and not just
    # presence.
    for index, check in enumerate(pack.validation):
        if not check.get("expect"):
            problems.append(
                PackProblem(
                    "validation-without-expectation",
                    f"validation[{index}] describes an action with no expected outcome, so running "
                    "it cannot fail — which is indistinguishable from not running it",
                )
            )

    for index, step in enumerate(pack.investigation_plan):
        if not step.get("question"):
            problems.append(
                PackProblem(
                    "plan-step-without-question",
                    f"investigation_plan[{index}] has no question. A plan says what the answer must "
                    "contain; a list of actions with no questions is a playbook under another name",
                )
            )

    return problems


def _self_test() -> int:
    good = ContentPack(
        id="pack-ransomware",
        name="Ransomware",
        scenario="ransomware",
        detections=["det-endpoint-001"],
        correlations=[{"key": "host", "window_minutes": 30}],
        investigation_plan=[{"question": "Which hosts encrypted files?", "tools": ["search_siem"]}],
        response=["pb-ransomware-contain"],
        validation=[{"action": "replay fixture", "expect": "one alert on det-endpoint-001"}],
    )

    cases: list[tuple[str, ContentPack, dict[str, Any], str | None]] = [
        ("a complete pack", good, {}, None),
        (
            "a playbook-only pack — what a pack means today",
            ContentPack(id="p", name="n", scenario="ransomware", response=["pb-1"]),
            {},
            "empty-section",
        ),
        (
            "a scenario nobody can search for",
            ContentPack(
                id="p",
                name="n",
                scenario="spooky_stuff",
                detections=["d"],
                correlations=[{}],
                investigation_plan=[{"question": "?"}],
                response=["pb"],
                validation=[{"expect": "x"}],
            ),
            {},
            "unknown-scenario",
        ),
        (
            "a detection the corpus does not ship",
            good,
            {"known_rule_ids": frozenset({"det-other"})},
            "unknown-detection",
        ),
        (
            "a validation step that cannot fail",
            ContentPack(
                id="p",
                name="n",
                scenario="ransomware",
                detections=["d"],
                correlations=[{}],
                investigation_plan=[{"question": "?"}],
                response=["pb"],
                validation=[{"action": "look at it"}],
            ),
            {},
            "validation-without-expectation",
        ),
        (
            "a plan that is a playbook under another name",
            ContentPack(
                id="p",
                name="n",
                scenario="ransomware",
                detections=["d"],
                correlations=[{}],
                investigation_plan=[{"action": "run a query"}],
                response=["pb"],
                validation=[{"expect": "x"}],
            ),
            {},
            "plan-step-without-question",
        ),
    ]

    failures = 0
    for name, pack, kwargs, expected in cases:
        problems = validate_pack(pack, **kwargs)
        ok = not problems if expected is None else any(p.code == expected for p in problems)
        print(f"  self-test [{'ok' if ok else 'FAIL'}] {name}")
        if not ok:
            failures += 1
            for problem in problems:
                print(f"      {problem}")

    print(f"pack_schema: self-test {'OK' if not failures else 'FAILED'} — {len(SCENARIOS)} scenarios")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--pack", help="validate a pack manifest")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not args.pack:
        parser.error("--pack or --self-test")

    raw = json.loads(Path(args.pack).read_text(encoding="utf-8"))
    problems = validate_pack(ContentPack.from_dict(raw))
    for problem in problems:
        print(f"  {problem}")
    print(f"{args.pack}: {'OK' if not problems else f'{len(problems)} problem(s)'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
