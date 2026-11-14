#!/usr/bin/env python3
"""Build the benchmark corpus from the in-tree eval data, labelled by provenance.

Regenerated rather than hand-maintained so the benchmark corpus and the
harness corpus cannot diverge — two hand-edited copies of 200 incidents drift
within a release, and the published figure then describes a corpus nobody has.

Provenance is stamped per incident. Everything sourced from
``synthetic_incidents.json`` is labelled ``synthetic``, because it is, and a
figure computed over it is a synthetic figure. Public-dataset and
adversary-emulation entries carry their own labels as they are folded in.

Run:  python3 packages/aisoc-benchmark/build_corpus.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aisoc_benchmark import replay  # noqa: E402
from corpus.benign_cases import benign_corpus_records  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EVAL_DATA = REPO_ROOT / "services" / "agents" / "tests" / "eval_data"
OUT = Path(__file__).resolve().parent / "corpus" / "soc-agent-benchmark-v1.json"

#: response_class in the harness corpus maps to the containment verbs an
#: agent might propose. Several verbs per class because a vendor's action
#: vocabulary is legitimately their own, and grading on an exact match would
#: measure naming rather than containment.
RESPONSE_CLASS_ACTIONS: dict[str, list[str]] = {
    "block_indicator": ["block_ip", "block_domain", "block_hash", "block_ioc"],
    "isolate_host": ["isolate_host", "quarantine_host", "contain_host"],
    "disable_account": ["disable_user", "suspend_user", "block_user_signin"],
    "reset_credentials": ["reset_password", "revoke_session", "suspend_session", "force_mfa"],
    "kill_process": ["kill_process", "terminate_process"],
    "quarantine_file": ["quarantine_file", "delete_file"],
    "escalate": ["escalate", "create_ticket", "notify"],
    "monitor": ["monitor", "no_action", "watchlist"],
}


def _disposition(record: dict) -> str:
    """Every harness incident is a real attack, so every one is a true positive.

    This used to derive three classes from ``response_class``, and both
    the mapping and the vocabulary were wrong.

    **The vocabulary** was ``malicious | suspicious | benign`` while
    `aisoc_benchmark.replay` grades
    ``true_positive | benign_true_positive | false_positive | benign`` —
    one label of four in common, so the corpus was ungradeable by this
    package's own scorer and nothing noticed.

    **The mapping** was worse. ``response_class == "monitor"`` became
    ``benign``, and those eight incidents are BloodHound domain
    enumeration tagged T1087.002 at medium severity. That is a real
    attack with a monitoring response. Calling it benign conflates
    "low-severity threat" with "not a threat", which is the distinction
    a triage agent exists to make — so the corpus claimed a benign class
    it did not have, and an agent answering "true positive" to
    everything would still have scored 100%.

    `response_class` says which action to take. It says nothing about
    whether the finding was true, and nothing in the harness corpus
    does. The benign and false-positive cases are authored separately in
    ``corpus/benign_cases.py``.
    """
    return replay.MALICIOUS


def build() -> dict:
    source = EVAL_DATA / "synthetic_incidents.json"
    raw = json.loads(source.read_text(encoding="utf-8"))
    records = raw if isinstance(raw, list) else raw.get("incidents", [])

    incidents = []
    for record in records:
        response = str(record.get("response_class", ""))
        incidents.append(
            {
                "id": record["id"],
                # Honest and unavoidable: these were generated for the
                # harness. Labelling them anything else would make every
                # figure derived from them a misrepresentation.
                "provenance": "synthetic",
                "title": record.get("title", ""),
                "description": record.get("description", ""),
                "severity": record.get("severity", "medium"),
                "raw_alert": {
                    "title": record.get("title", ""),
                    "severity": record.get("severity", "medium"),
                    "template_id": record.get("template_id", ""),
                },
                # The evidence the agent may reason over. An indicator cited
                # but absent from here is counted as a hallucination, so this
                # has to be the complete evidence set.
                "telemetry": record.get("telemetry") or [],
                "expected_disposition": _disposition(record),
                "expected_techniques": record.get("expected_techniques") or [],
                "expected_actions": RESPONSE_CLASS_ACTIONS.get(response, []),
            }
        )

    # The authored benign and false-positive cases. Without them the
    # corpus has one class and `score_replay_set.assert_gradeable`
    # correctly refuses it.
    incidents.extend(benign_corpus_records())

    return {
        "corpus_id": "soc-agent-benchmark-v1",
        "version": 1,
        "_readme": (
            "Every incident declares its provenance. A figure computed over "
            "synthetic incidents is a synthetic figure, and a scoreboard that "
            "omits that is misleading even when every number in it is "
            "arithmetically correct. Generated by "
            "packages/aisoc-benchmark/build_corpus.py — do not edit by hand, "
            "or this copy and the harness copy will drift within a release."
        ),
        "incidents": incidents,
    }


def main() -> int:
    corpus = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(corpus, indent=1) + "\n", encoding="utf-8")

    counts: dict[str, int] = {}
    for incident in corpus["incidents"]:
        counts[incident["provenance"]] = counts.get(incident["provenance"], 0) + 1
    print(f"wrote {len(corpus['incidents'])} incidents to {OUT}")
    for source, count in sorted(counts.items()):
        print(f"  {source:<20} {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
