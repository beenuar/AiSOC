#!/usr/bin/env python3
"""The verdict corpus stays a corpus a constant answer cannot win on.

Why this exists
---------------
Every other labelled set in ``services/agents/tests/eval_data/`` is malicious
by construction. ``synthetic_incidents.json`` and ``adversary_incidents.json``
are 200 attacks each and carry no ``expected_disposition`` at all, so an agent
that answers "true positive" to everything without reading anything would post
a perfect score. ``scripts/score_replay_set.py`` refuses both, correctly, and
depth plan 1.1 adds the corpus it accepts instead.

A balanced corpus is not a property of a file; it is a property that decays.
One contributor adding six malicious items because malicious items are the
interesting ones to write takes the majority class past the point where a
constant answer scores well, and every number published from the corpus
quietly becomes a description of the base rate. Nothing about the file would
look wrong. So the balance is asserted here rather than written down.

What it refuses
---------------
``balance``
    A class above :data:`MAX_CLASS_SHARE`, or a minority class below
    :data:`MIN_MINORITY_SHARE`. The first is the plan's bar — the share of the
    largest class *is* what a constant answer scores, so capping it at 60%
    caps the constant answer at 60%. The second mirrors the floor
    ``score_replay_set.assert_gradeable`` already enforces, so the corpus
    cannot drift into a shape the scorer would then refuse.

``source mix``
    Fewer than half the items from cloud, identity and SaaS, or any of the ten
    sources the plan names absent. That is where this repository's corpus was
    thinnest and the reason the item exists.

``twins``
    A non-malicious item with no malicious twin, a twin that does not point
    back, or a pair that differs in something other than its evidence. The
    pairing is the anti-shortcut device: when both halves fired the same rule
    at the same severity with the same title, nothing but the evidence can
    separate them.

``provenance``
    An item with no provenance block, or one that is neither marked
    ``is_synthetic`` nor carrying a licence from
    :data:`REDISTRIBUTABLE_LICENCES`. Version 1 of the corpus is entirely
    hand-authored and says so; this is what binds the day a sourced item
    arrives.

``documentation data only``
    A routable address, or an email or link outside the RFC 2606 reserved
    names. A corpus carrying a real address eventually gets somebody scanned,
    and this one ships in a public repository.

``counts``
    Header counts that disagree with the body. The README quotes those
    numbers, so a header that drifts takes the documentation with it.

``severity``
    Different severity distributions on the two halves. A corpus whose attacks
    are critical and whose noise is low is separable on severity alone and
    measures nothing. One-to-one pairing on a shared severity makes the two
    distributions identical, and this is the assertion that keeps it so.

Usage
-----
::

    python3 scripts/check_verdict_corpus.py
    python3 scripts/check_verdict_corpus.py --json
    python3 scripts/check_verdict_corpus.py --self-test

Exit codes: 0 clean, 1 findings, 2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

CORPUS_REL = Path("services") / "agents" / "tests" / "eval_data" / "verdict" / "verdict_corpus_v1.json"

#: The disposition that means "this was a real threat". Mirrors
#: ``aisoc_benchmark.replay.MALICIOUS``, spelled here rather than imported so
#: the gate runs on a bare interpreter with no package on the path.
MALICIOUS = "true_positive"

#: The four canonical dispositions. Mirrors ``GRADED_DISPOSITIONS``; the
#: cross-check against the real definition happens in
#: :func:`check_the_scorer_agrees`, which imports it when it can.
GRADED_DISPOSITIONS = (MALICIOUS, "benign_true_positive", "false_positive", "benign")

#: No class may hold more than this. Set by the plan: the largest class's
#: share is exactly what a constant answer of that class scores, so this is
#: the ceiling on a constant answer.
MAX_CLASS_SHARE = 0.60

#: Mirrors ``score_replay_set.MIN_MINORITY_SHARE``. Below this the scorer
#: refuses the corpus, and a corpus the scorer refuses is not a corpus.
MIN_MINORITY_SHARE = 0.05

#: At least half the items come from here. The plan's reason: this is where
#: the repository's labelled coverage was thinnest.
CLOUD_IDENTITY_SAAS = frozenset({"cloud", "identity", "saas"})
MIN_CLOUD_IDENTITY_SAAS_SHARE = 0.50

#: The ten sources the plan names by hand. Every one must appear.
REQUIRED_VENDORS = (
    "aws_cloudtrail",
    "gcp_audit",
    "azure_activity",
    "entra_id",
    "okta",
    "google_workspace",
    "m365",
    "github",
    "slack",
    "kubernetes_audit",
)

#: The benign shapes real queues are full of, per the plan. A benign class
#: that misses these is a class of obviously boring events, which measures
#: formatting rather than judgement.
REQUIRED_BENIGN_ARCHETYPES = (
    "admin_bulk_change",
    "scanner_or_security_tooling",
    "ci_service_account",
    "travel_sign_in",
    "break_glass_with_ticket",
    "backup_job",
)

#: Licences under which a third party's telemetry may be redistributed inside
#: this MIT repository. Deliberately short. CC BY-NC-SA is absent because the
#: non-commercial clause is incompatible and ShareAlike would relicense what it
#: is combined with; "research use only" is absent for the same reason.
REDISTRIBUTABLE_LICENCES = frozenset({"MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "CC0-1.0", "CC-BY-4.0", "ODbL-1.0"})

#: Fields every item must carry. ``labelled`` is here because ``score_replay``
#: grades only rows that declare it, and a corpus whose rows are silently
#: ungraded would report "0 labelled" rather than failing.
REQUIRED_FIELDS = (
    "id",
    "pair_id",
    "twin_of",
    "expected_disposition",
    "labelled",
    "is_synthetic",
    "family",
    "vendor",
    "rule_id",
    "title",
    "severity",
    "decisive_evidence",
    "evidence",
    "provenance",
)

#: What a twin pair must hold in common. Everything an alert carries that the
#: rule decided rather than the world — so the only thing left to separate the
#: two items on is the evidence.
TWIN_SHARED_FIELDS = ("pair_id", "vendor", "rule_id", "family", "severity", "title")

#: RFC 5737 documentation prefixes.
_DOCUMENTATION_PREFIXES = {(192, 0, 2), (198, 51, 100), (203, 0, 113)}

#: RFC 2606 / RFC 6761 reserved names. Nothing here can be registered, so
#: nothing here can be pointed at a real host.
_RESERVED_SUFFIXES = (
    ".example.com",
    ".example.net",
    ".example.org",
    ".example",
    ".test",
    ".invalid",
    ".localhost",
)
_RESERVED_EXACT = frozenset({"example.com", "example.net", "example.org", "localhost"})

#: The one real host the corpus is allowed to name, and why: every item's
#: provenance block points at this repository's own licence file, which is the
#: licence under which the hand-authored item is published. It is a statement
#: about the corpus, not data inside an event.
_ALLOWED_REAL_HOSTS = frozenset({"github.com"})

_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_URL_HOST = re.compile(r"https?://([A-Za-z0-9.\-]+)")


class CorpusUnreadable(RuntimeError):
    """The corpus is absent or malformed, so there is nothing to render a verdict about."""


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def load(root: Path) -> dict[str, Any]:
    """Read the corpus, refusing an absent or empty one rather than passing.

    A gate that walks zero items finds zero violations. "Found nothing" and
    "scanned nothing" print the same word unless the second one raises.
    """
    path = root / CORPUS_REL
    if not path.is_file():
        raise CorpusUnreadable(
            f"{CORPUS_REL} does not exist under {root}. There is no verdict corpus to check, "
            "which is the state depth plan 1.1 exists to end — not a clean result."
        )
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CorpusUnreadable(f"{CORPUS_REL} is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise CorpusUnreadable(f"{CORPUS_REL} must be an object carrying a `decisions` list, not a {type(doc).__name__}")
    items = doc.get("decisions")
    if not isinstance(items, list) or not items:
        raise CorpusUnreadable(f"{CORPUS_REL} carries no `decisions`. An empty corpus cannot measure anything.")
    return doc


# --------------------------------------------------------------------------
# The checks. Each takes the parsed document and returns findings.
# --------------------------------------------------------------------------


def check_fields(doc: dict[str, Any]) -> list[str]:
    """Every item carries the fields the scorer and the later checks read."""
    findings: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(doc["decisions"]):
        if not isinstance(item, dict):
            findings.append(f"decisions[{index}] is a {type(item).__name__}, not an object")
            continue
        where = item.get("id") or f"decisions[{index}]"
        missing = [field for field in REQUIRED_FIELDS if field not in item]
        if missing:
            findings.append(f"{where}: missing {', '.join(missing)}")
        if item.get("labelled") is not True:
            findings.append(f"{where}: `labelled` is not true, so score_replay would silently exclude it from accuracy")
        disposition = item.get("expected_disposition")
        if disposition not in GRADED_DISPOSITIONS:
            findings.append(f"{where}: expected_disposition {disposition!r} is not one of {list(GRADED_DISPOSITIONS)}")
        if where in seen:
            findings.append(f"{where}: duplicate id")
        seen.add(where)
    return findings


def check_balance(doc: dict[str, Any]) -> list[str]:
    """No class large enough that answering it to everything would score well."""
    items = doc["decisions"]
    counts = Counter(item.get("expected_disposition") for item in items)
    total = len(items)
    findings: list[str] = []

    if len(counts) < 2:
        return [f"the corpus holds one class ({next(iter(counts))!r}); a constant answer would score 100%"]

    largest, largest_n = counts.most_common(1)[0]
    if largest_n / total > MAX_CLASS_SHARE:
        findings.append(
            f"{largest!r} holds {largest_n} of {total} items ({largest_n / total:.1%}), over the "
            f"{MAX_CLASS_SHARE:.0%} ceiling. An agent answering {largest!r} to everything, without "
            f"reading anything, would score {largest_n / total:.1%} here."
        )

    smallest, smallest_n = counts.most_common()[-1]
    if smallest_n / total < MIN_MINORITY_SHARE:
        findings.append(
            f"{smallest!r} holds {smallest_n} of {total} items ({smallest_n / total:.1%}), under the "
            f"{MIN_MINORITY_SHARE:.0%} floor score_replay_set.assert_gradeable enforces. The scorer "
            "would refuse this corpus."
        )

    for required in ("benign", "benign_true_positive", MALICIOUS):
        if not counts.get(required):
            findings.append(f"no {required!r} item; the plan requires benign, benign-true-positive and malicious items")
    return findings


def check_source_mix(doc: dict[str, Any]) -> list[str]:
    """At least half from cloud, identity and SaaS, and all ten named sources present."""
    items = doc["decisions"]
    findings: list[str] = []
    in_scope = [item for item in items if item.get("family") in CLOUD_IDENTITY_SAAS]
    share = len(in_scope) / len(items)
    if share < MIN_CLOUD_IDENTITY_SAAS_SHARE:
        findings.append(
            f"{len(in_scope)} of {len(items)} items ({share:.1%}) come from cloud, identity or SaaS, "
            f"under the {MIN_CLOUD_IDENTITY_SAAS_SHARE:.0%} the plan requires. That is where this "
            "repository's labelled coverage is thinnest."
        )
    vendors = {item.get("vendor") for item in items}
    missing = [vendor for vendor in REQUIRED_VENDORS if vendor not in vendors]
    if missing:
        findings.append(f"no item from {', '.join(missing)}; the plan names all ten sources by hand")
    return findings


def check_twins(doc: dict[str, Any]) -> list[str]:
    """Every non-malicious item has a malicious twin differing only in evidence."""
    items = doc["decisions"]
    by_id = {item.get("id"): item for item in items if isinstance(item, dict)}
    findings: list[str] = []

    for item in items:
        where = item.get("id")
        twin_id = item.get("twin_of")
        twin = by_id.get(twin_id)
        if twin is None:
            findings.append(f"{where}: twin_of names {twin_id!r}, which is not in the corpus")
            continue
        if twin.get("twin_of") != where:
            findings.append(f"{where}: twin {twin_id} points at {twin.get('twin_of')!r} instead of back")

        malicious = item.get("expected_disposition") == MALICIOUS
        if malicious == (twin.get("expected_disposition") == MALICIOUS):
            findings.append(
                f"{where}: it and its twin {twin_id} are both "
                f"{'malicious' if malicious else 'non-malicious'}. A twin pair is one of each, or it "
                "demonstrates nothing."
            )
        for field in TWIN_SHARED_FIELDS:
            if item.get(field) != twin.get(field):
                findings.append(
                    f"{where}: differs from its twin {twin_id} in {field!r} "
                    f"({item.get(field)!r} against {twin.get(field)!r}). Twins differ in the decisive "
                    "evidence; anything else they differ in is a shortcut an agent can take instead of reading."
                )
        if item.get("evidence") == twin.get("evidence"):
            findings.append(f"{where}: identical evidence to its twin {twin_id}, so one of the two labels must be wrong")
        if item.get("decisive_evidence") == twin.get("decisive_evidence"):
            findings.append(f"{where}: identical decisive_evidence to its twin {twin_id}")
        if not str(item.get("decisive_evidence") or "").strip():
            findings.append(f"{where}: empty decisive_evidence — the label has no stated reason")

    archetypes = {item.get("benign_archetype") for item in items if item.get("expected_disposition") != MALICIOUS}
    missing = [name for name in REQUIRED_BENIGN_ARCHETYPES if name not in archetypes]
    if missing:
        findings.append(f"no benign item of type {', '.join(missing)}; the plan names the shapes real queues are full of")
    for item in items:
        if item.get("expected_disposition") != MALICIOUS and not item.get("benign_archetype"):
            findings.append(f"{item.get('id')}: non-malicious item with no benign_archetype")
    return findings


def check_provenance(doc: dict[str, Any]) -> list[str]:
    """Synthetic items say so; sourced items bring a licence that permits redistribution."""
    findings: list[str] = []
    for item in doc["decisions"]:
        where = item.get("id")
        block = item.get("provenance")
        if not isinstance(block, dict) or not block:
            findings.append(f"{where}: no provenance block. Every item records where it came from, the way detections/ does.")
            continue
        if not block.get("source"):
            findings.append(f"{where}: provenance names no source")
        licence = block.get("license")
        if not licence:
            findings.append(f"{where}: provenance records no licence. A source without a licence is refused, not assumed.")
        elif licence not in REDISTRIBUTABLE_LICENCES:
            findings.append(
                f"{where}: licence {licence!r} is not in the redistribution allow-list "
                f"({', '.join(sorted(REDISTRIBUTABLE_LICENCES))}). Redistributing it inside this "
                "repository is not covered."
            )
        if not block.get("license_url"):
            findings.append(f"{where}: provenance records no license_url, so the terms cannot be read")
        if item.get("is_synthetic") is not True and block.get("source") == "hand-authored":
            findings.append(f"{where}: provenance says hand-authored but is_synthetic is not true")
        if item.get("is_synthetic") is True and block.get("source") != "hand-authored":
            findings.append(
                f"{where}: is_synthetic is true but provenance names source {block.get('source')!r}. "
                "An invented item must not imply it came from somewhere."
            )
    return findings


def check_counts(doc: dict[str, Any]) -> list[str]:
    """The header counts match the body, so the README cannot quote a stale number."""
    items = doc["decisions"]
    synthetic = sum(1 for item in items if item.get("is_synthetic") is True)
    pairs = len({item.get("pair_id") for item in items})
    expected = {
        "items": len(items),
        "synthetic_items": synthetic,
        "sourced_items": len(items) - synthetic,
        "pairs": pairs,
    }
    return [f"header says {key}={doc.get(key)!r} and the body holds {value}" for key, value in expected.items() if doc.get(key) != value]


def check_severity_is_not_a_shortcut(doc: dict[str, Any]) -> list[str]:
    """Both halves carry the same severity distribution, so severity separates nothing."""
    malicious = Counter(i.get("severity") for i in doc["decisions"] if i.get("expected_disposition") == MALICIOUS)
    other = Counter(i.get("severity") for i in doc["decisions"] if i.get("expected_disposition") != MALICIOUS)
    if malicious == other:
        return []
    return [
        "the malicious and non-malicious halves carry different severity distributions "
        f"({dict(sorted(malicious.items()))} against {dict(sorted(other.items()))}). An agent can then "
        "separate them on severity without reading the evidence."
    ]


def _reserved(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host in _RESERVED_EXACT or host.endswith(_RESERVED_SUFFIXES)


def check_documentation_data_only(doc: dict[str, Any]) -> list[str]:
    """No routable address and no registrable name anywhere in the corpus."""
    text = json.dumps(doc, sort_keys=True)
    findings: list[str] = []

    for octets in sorted(set(_IPV4.findall(text))):
        a, b, c, _ = (int(part) for part in octets)
        documented = (
            (a, b, c) in _DOCUMENTATION_PREFIXES
            # 0.0.0.0 is "this network" (RFC 1122) and is how a firewall rule
            # spells "anywhere". It addresses no host, so it is safe to ship.
            or a in (0, 10, 127)
            or (a == 192 and b == 168)
            or (a == 172 and 16 <= b <= 31)
            or a >= 224
            or (a, b) == (169, 254)
            or (a, b) == (198, 18)
        )
        if not documented:
            findings.append(
                f"{'.'.join(octets)} is outside the RFC 5737 documentation and the private ranges. "
                "This corpus ships in a public repository; a real address in it eventually gets "
                "somebody scanned."
            )

    for domain in sorted(set(_EMAIL.findall(text))):
        if not _reserved(domain):
            findings.append(f"email domain {domain!r} is not an RFC 2606 reserved name")
    for host in sorted(set(_URL_HOST.findall(text))):
        if _IPV4.fullmatch(host):
            continue  # already judged above, as an address
        if host.lower() in _ALLOWED_REAL_HOSTS:
            continue
        if not _reserved(host):
            findings.append(f"link host {host!r} is not an RFC 2606 reserved name")
    return findings


def check_the_scorer_agrees(doc: dict[str, Any]) -> list[str]:
    """The corpus the gate accepts is the corpus the scorer accepts.

    Two independent implementations of "gradeable" would eventually disagree
    while both printing OK, so the real one is consulted. Imported here rather
    than at module scope: the empty-tree probe runs this gate inside a tree
    holding only ``scripts/``, where ``packages/`` does not exist, and the
    refusal it must produce is "there is no corpus" — not an import error from
    a check that never had anything to check.
    """
    try:
        from score_replay_set import CorpusNotGradeable, assert_gradeable
    except ImportError as exc:  # pragma: no cover - exercised only on a broken tree
        return [f"could not load score_replay_set to cross-check gradeability: {exc}"]
    try:
        assert_gradeable(doc["decisions"])
    except CorpusNotGradeable as exc:
        return [f"score_replay_set refuses this corpus: {exc}"]
    return []


CHECKS = (
    ("fields", check_fields),
    ("balance", check_balance),
    ("source mix", check_source_mix),
    ("twins", check_twins),
    ("provenance", check_provenance),
    ("counts", check_counts),
    ("severity is not a shortcut", check_severity_is_not_a_shortcut),
    ("documentation data only", check_documentation_data_only),
    ("the scorer agrees", check_the_scorer_agrees),
)


def run(doc: dict[str, Any]) -> dict[str, list[str]]:
    return {name: check(doc) for name, check in CHECKS}


def summarise(doc: dict[str, Any]) -> dict[str, Any]:
    """The numbers the README quotes, derived rather than copied."""
    items = doc["decisions"]
    counts = Counter(i.get("expected_disposition") for i in items)
    families = Counter(i.get("family") for i in items)
    in_scope = sum(count for family, count in families.items() if family in CLOUD_IDENTITY_SAAS)
    return {
        "items": len(items),
        "pairs": len({i.get("pair_id") for i in items}),
        "synthetic": sum(1 for i in items if i.get("is_synthetic") is True),
        "sourced": sum(1 for i in items if i.get("is_synthetic") is not True),
        "class_counts": dict(counts.most_common()),
        "class_shares": {k: round(v / len(items), 4) for k, v in counts.most_common()},
        "largest_class_share": round(max(counts.values()) / len(items), 4),
        "best_constant_answer_scores": round(max(counts.values()) / len(items), 4),
        "cloud_identity_saas": in_scope,
        "cloud_identity_saas_share": round(in_scope / len(items), 4),
        "families": dict(sorted(families.items())),
        "vendors": sorted({i.get("vendor") for i in items}),
    }


# --------------------------------------------------------------------------
# Self-test: one injected violation per rule, against a copy of the real corpus
# --------------------------------------------------------------------------


def _injections(doc: dict[str, Any]) -> list[tuple[str, str, Any]]:
    """(description, check name, mutation) for every rule this gate enforces.

    Each mutation is applied to a deep copy of the shipped corpus, so what is
    proved is that the gate catches the violation *in the real file's shape*
    rather than in a toy fixture the gate was written against.
    """

    def unbalance(d: dict[str, Any]) -> None:
        # Relabel enough non-malicious items to take malicious past 60%.
        need = int(len(d["decisions"]) * MAX_CLASS_SHARE) + 1 - sum(1 for i in d["decisions"] if i["expected_disposition"] == MALICIOUS)
        for item in d["decisions"]:
            if need <= 0:
                break
            if item["expected_disposition"] != MALICIOUS:
                item["expected_disposition"] = MALICIOUS
                need -= 1

    def starve_the_minority(d: dict[str, Any]) -> None:
        # Leave the class present but far under the floor, which is the shape
        # that matters: a class of zero is caught by the "one class" branch,
        # and a class of two in seventy-two reports the base rate while still
        # looking like a four-class corpus.
        survivors = 1
        for item in d["decisions"]:
            if item["expected_disposition"] != "false_positive":
                continue
            if survivors > 0:
                survivors -= 1
                continue
            item["expected_disposition"] = "benign"

    def drown_the_cloud(d: dict[str, Any]) -> None:
        for item in d["decisions"]:
            if item["family"] in CLOUD_IDENTITY_SAAS:
                item["family"] = "endpoint"

    def drop_a_named_vendor(d: dict[str, Any]) -> None:
        for item in d["decisions"]:
            if item["vendor"] == "okta":
                item["vendor"] = "some_other_product"

    def orphan_a_benign_item(d: dict[str, Any]) -> None:
        for item in d["decisions"]:
            if item["expected_disposition"] != MALICIOUS:
                item["twin_of"] = "VRD-NOT-A-REAL-ID"
                return

    def make_a_twin_separable_on_severity(d: dict[str, Any]) -> None:
        for item in d["decisions"]:
            if item["expected_disposition"] == MALICIOUS:
                item["severity"] = "critical"

    def strip_a_licence(d: dict[str, Any]) -> None:
        d["decisions"][0]["provenance"].pop("license", None)

    def claim_an_unredistributable_source(d: dict[str, Any]) -> None:
        d["decisions"][0]["is_synthetic"] = False
        d["decisions"][0]["provenance"].update({"source": "some-dataset", "license": "CC-BY-NC-SA-4.0"})

    def imply_real_provenance(d: dict[str, Any]) -> None:
        d["decisions"][0]["provenance"]["source"] = "a-real-customer-queue"

    def plant_a_routable_address(d: dict[str, Any]) -> None:
        d["decisions"][0]["evidence"]["sourceIPAddress"] = "8.8.8.8"

    def plant_a_registrable_name(d: dict[str, Any]) -> None:
        d["decisions"][0]["evidence"]["contact"] = "attacker@real-looking-domain.co"

    def drift_the_header(d: dict[str, Any]) -> None:
        d["synthetic_items"] = 999

    def unlabel_an_item(d: dict[str, Any]) -> None:
        d["decisions"][0]["labelled"] = False

    return [
        ("a class over 60% is caught", "balance", unbalance),
        ("a minority class under the scorer's floor is caught", "balance", starve_the_minority),
        ("under half from cloud, identity and SaaS is caught", "source mix", drown_the_cloud),
        ("one of the ten named sources going missing is caught", "source mix", drop_a_named_vendor),
        ("a benign item with no twin is caught", "twins", orphan_a_benign_item),
        ("a pair separable on severity is caught", "twins", make_a_twin_separable_on_severity),
        ("an item with no licence is caught", "provenance", strip_a_licence),
        ("a source whose licence forbids redistribution is caught", "provenance", claim_an_unredistributable_source),
        ("a synthetic item implying real provenance is caught", "provenance", imply_real_provenance),
        ("a routable address is caught", "documentation data only", plant_a_routable_address),
        ("a registrable domain name is caught", "documentation data only", plant_a_registrable_name),
        ("a header count drifting from the body is caught", "counts", drift_the_header),
        ("an item the scorer would silently skip is caught", "fields", unlabel_an_item),
    ]


def self_test(root: Path) -> int:
    try:
        clean = load(root)
    except CorpusUnreadable as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    extra: list[tuple[str, bool]] = []

    baseline = run(clean)
    extra.append(("the shipped corpus passes every rule", not any(baseline.values())))

    for description, expected_check, mutate in _injections(clean):
        broken = copy.deepcopy(clean)
        mutate(broken)
        findings = run(broken)
        # The named check must fire. Others may fire too — relabelling items to
        # unbalance the corpus also breaks their twins, and that is honest.
        extra.append((f"{description} (by `{expected_check}`)", bool(findings.get(expected_check))))

    return self_test_main(Path(__file__).name, [], extra=extra)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the verdict corpus stays balanced, paired and licensed.")
    parser.add_argument("--self-test", action="store_true", help="inject one violation of each rule and require it is caught")
    parser.add_argument("--json", action="store_true", help="print the derived summary as JSON")
    parser.add_argument("--repo-root", type=Path, default=None)
    args = parser.parse_args(argv)

    root = args.repo_root.resolve() if args.repo_root else repo_root()
    if args.self_test:
        return self_test(root)

    try:
        doc = load(root)
    except CorpusUnreadable as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    results = run(doc)
    stats = summarise(doc)

    if args.json:
        print(json.dumps({"summary": stats, "findings": results}, indent=2, sort_keys=True))
        return 1 if any(results.values()) else 0

    print(f"corpus    {CORPUS_REL} under {root}")
    print(f"items     {stats['items']} in {stats['pairs']} twin pairs; {stats['synthetic']} synthetic, {stats['sourced']} sourced")
    for label, count in stats["class_counts"].items():
        print(f"  {label:22} {count:4}  {stats['class_shares'][label]:.1%}")
    print(f"constant  a constant answer scores at most {stats['best_constant_answer_scores']:.1%} (ceiling {MAX_CLASS_SHARE:.0%})")
    in_scope = stats["cloud_identity_saas"]
    print(f"sources   {in_scope} of {stats['items']} from cloud, identity or SaaS ({stats['cloud_identity_saas_share']:.1%})")

    findings = [(name, problem) for name, problems in results.items() for problem in problems]
    if findings:
        print(f"\nverdict-corpus: {len(findings)} finding(s)", file=sys.stderr)
        for name, problem in findings:
            print(f"  [{name}] {problem}", file=sys.stderr)
        return 1
    print("verdict-corpus: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
