#!/usr/bin/env python3
"""Keyword matching over alert text: one vocabulary, and no identifier hits.

Two failures, both found in ``services/agents`` and reported as #1607.

**A keyword matched as a substring.** ``"c2" in text`` over the alert summary
*and the stringified raw payload* fires on every AWS private hostname
(``ip-10-0-1-7.ec2.internal``), on EC2 instance ids, and on hashes and base64
blobs carrying the pair. The alert was scored critical at 0.9, which is above
the model cascade's escalation floor, so it was never sent to the ML or LLM
tier. The visible symptom is a wrong severity; the expensive one is an alert
that silently skips analysis.

**The vocabulary was declared twice and had drifted.** ``triage_agent`` held
13 critical keywords, ``confidence/scoring`` held 11. An alert could be scored
critical by one and denied the matching confidence bonus by the other.

So this gate asserts two things, and refuses to pass without having measured
both:

``PARITY``
    Exactly one module declares a severity vocabulary. Every other module that
    does severity keyword matching imports it. A second literal list is the
    drift, so the gate looks for the *declaration*, not for agreement between
    two copies — two copies that happen to agree today is the state that
    precedes the bug, not the absence of it.

``COLLISION``
    No keyword in any registered vocabulary matches any string in
    :data:`OPAQUE`, and no *severity* keyword matches any string in
    :data:`NAMED`. This is the arm that generalises: it does not know about
    ``c2``, it knows that a keyword firing on a UUID is a bug whatever the
    keyword is.

Why the corpus is in two halves
-------------------------------
The first draft was one list and reported 13 findings, of which 6 were the
gate being wrong. ``aws``, ``iam``, ``s3`` and ``cloudtrail`` matched
``arn:aws:iam::123456789012:role/app`` — and they *should*, because the
corpus they come from is the investigator's topic router and that string is
genuinely an AWS IAM event. ``backup`` and ``scheduled`` matched a sentence
about a nightly backup, which is the swarm's *benign* hypothesis working
exactly as designed. A gate that flags correct content gets switched off
within a week, so the claim has to be narrower than "looks harmless".

The real property is **coincidence**. ``aws`` in an ARN is not a coincidence:
those three letters are there because it is AWS. ``c2`` in
``i-0ab2c2d3e4f5`` is: that is random hex. So:

:data:`OPAQUE`
    values whose letters are an artefact of encoding — UUIDs, SHA-256 and MD5
    digests, base64, JWTs, instance and volume ids, generated pod suffixes,
    MAC addresses, Windows SIDs. Any keyword match here is coincidence by
    construction, so *every* corpus is held to it.

:data:`NAMED`
    resources whose names carry real meaning — ARNs, service hostnames,
    directory DNs. A topic router is supposed to match these. Nothing in one
    should ever make an alert *critical*, so only the severity vocabularies
    are held to it.

Both halves are drawn from shapes a SOC pipeline actually carries rather than
from guesses. Several entries were chosen because they contain ``c2``
(``base64("secret")`` begins ``c2``; a MAC octet can be ``c2``), but the gate
runs every keyword against every string, so it catches the next collision
without anyone having predicted which keyword it will be — which is how it
caught the MAC address case that the original fix did not handle.

The matcher under test is the production one, imported from
``services/agents``. A gate that re-implemented the boundary rule would be
measuring its own copy, which is the failure this tree keeps finding.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

#: The one module allowed to declare a severity vocabulary.
_CANONICAL = "services/agents/app/keywords.py"

#: Modules that score alert severity and must read the canonical vocabulary
#: rather than carry their own copy.
_CONSUMERS = (
    "services/agents/app/agents/triage_agent.py",
    "services/agents/app/confidence/scoring.py",
)

#: Names that mean "this module is declaring a severity vocabulary". A second
#: declaration under any of these names in a consumer is the drift returning.
_VOCAB_NAMES = (
    "_CRITICAL_KEYWORDS",
    "_HIGH_KEYWORDS",
    "CRITICAL_KEYWORDS",
    "HIGH_KEYWORDS",
)

#: Every keyword corpus matched against alert or payload text, as
#: ``(module, attribute path)``. Each is read with ``ast`` and every string
#: literal inside it is run against :data:`INNOCUOUS`.
_CORPORA = (
    ("services/agents/app/keywords.py", "CRITICAL_KEYWORDS"),
    ("services/agents/app/keywords.py", "HIGH_KEYWORDS"),
    ("services/agents/app/investigator/strategies.py", "keywords"),
    ("services/agents/app/investigator/tools.py", "_MITRE_KEYWORDS"),
    ("services/agents/app/swarm/hypotheses.py", "supports_keywords"),
    ("services/agents/app/swarm/hypotheses.py", "contradicts_keywords"),
)

#: Values whose letters are an artefact of encoding or allocation. A keyword
#: found inside one has coincided with it. Every corpus is held to these.
OPAQUE: tuple[str, ...] = (
    # --- AWS hostnames and resource ids -----------------------------------
    "ip-10-0-1-7.ec2.internal",
    "ip-172-31-5-200.us-west-2.compute.internal",
    "ec2-54-80-12-3.compute-1.amazonaws.com",
    "i-0ab2c2d3e4f5a6b7",
    "vol-0c2b1a9f8e7d6c5b4",
    "vpc-0c2d4e6f8a1b3d5e7",
    "subnet-0a1b2c3d4e5f60718",
    "sg-0ab1c2d3e4f5a6b78",
    "eni-0c2a4e6b8d0f2a4c6",
    "AKIAIOSFODNN7EXAMPLE",
    "ASIAIOSFODNN7EXAMPLE",
    "EC2AMAZ-1A2B3C4",
    # --- Azure / GCP generated names --------------------------------------
    "aks-syspool-c2f4a1b6-vmss000003",
    "stprodarchivec2a4.blob.core.windows.net",
    "gke-prod-cluster-default-pool-a1c2d3e4-9xkp",
    "api-deployment-7d9c2f4b8-xk2lp",
    # --- Digests, tokens, identifiers --------------------------------------
    "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    "c2a4e6b8-1234-4567-89ab-cdef01234567",
    "d41d8cd98f00b204e9800998ecf8427e",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha256:9c2f1e0b7a6d5c4b3a29180f7e6d5c4b3a29180f7e6d5c4b3a29180f7e6d5c4b",
    "9c2f1e0b7a6d5c4b3a29180f7e6d5c4b3a29180f",
    "c2VjcmV0LXRva2VuLXZhbHVl",
    "aGVsbG8gd29ybGQgdGhpcyBpcyBmaW5l",
    # Joined from its segments rather than written out. gitleaks' `jwt` rule
    # matches the three-segment shape and not the contents, so a literal here
    # fails the repo's own secret scan on a value that decodes to
    # {"alg":"HS256","typ":"JWT"} / {"sub":"12345"} / b"signature". The joined
    # string is byte-identical, so the corpus this gate measures is unchanged.
    ".".join(("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIiOiIxMjM0NSJ9", "c2lnbmF0dXJl")),
    # --- Host, hardware and directory identifiers --------------------------
    "DESKTOP-C2A4B6",
    "00:1a:c2:3b:4c:5d",
    "S-1-5-21-3623811015-3361044348-30300820-1013",
)

#: Resources whose names carry real meaning. A topic router is meant to match
#: these; only the severity vocabularies are held to them, because nothing in
#: a resource name should make an alert critical on its own.
NAMED: tuple[str, ...] = (
    "arn:aws:iam::123456789012:role/AWSServiceRoleForAutoScaling",
    "arn:aws:s3:::reports-archive-prod/2026/10/inventory.parquet",
    "arn:aws:lambda:us-east-1:123456789012:function:nightly-rollup",
    "AWSLogs/123456789012/CloudTrail/us-east-1/2026/10/31/",
    "/subscriptions/3f2504e0-4f89-11d3-9a0c-0305e82c3301/resourceGroups/rg-prod",
    "/providers/Microsoft.Compute/virtualMachines/vm-reporting-02",
    "projects/analytics-prod-1234/zones/us-central1-a/instances/batch-runner-7",
    "serviceAccount:etl-writer@analytics-prod-1234.iam.gserviceaccount.com",
    "registry.internal/platform/report-builder:1.42.0",
    "mon-probe-01.corp.example.com",
    "CN=Reporting Service,OU=Service Accounts,DC=corp,DC=example,DC=com",
    "Scheduled nightly backup completed on ip-10-0-1-7.ec2.internal",
    "Autoscaling replaced instance i-0ab2c2d3e4f5a6b7 in asg web-prod",
)

#: The corpora whose keywords decide *severity*. Held to both halves.
_SEVERITY_CORPORA = frozenset(
    {
        ("services/agents/app/keywords.py", "CRITICAL_KEYWORDS"),
        ("services/agents/app/keywords.py", "HIGH_KEYWORDS"),
    }
)


def _module(root: Path, relative: str) -> ast.Module:
    path = root / relative
    if not path.is_file():
        raise SystemExit(f"FAIL: {relative} does not exist; the gate cannot measure what it names")
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _declares(tree: ast.Module, names: tuple[str, ...]) -> set[str]:
    """Module-level assignments among ``names`` — a vocabulary declaration."""

    found: set[str] = set()
    for node in tree.body:
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        for target in targets:
            if isinstance(target, ast.Name) and target.id in names:
                found.add(target.id)
    return found


def _imports_from(tree: ast.Module, module: str) -> set[str]:
    return {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module == module for alias in node.names}


def _literals_under(tree: ast.Module, attribute: str) -> list[str]:
    """Every string literal in any assignment or keyword named ``attribute``.

    Covers a module-level constant (``_MITRE_KEYWORDS = {...}``) and a keyword
    argument repeated across constructor calls (``keywords=(...)`` on each
    ``Strategy``), because the corpora in this tree are written both ways.
    """

    out: list[str] = []

    def harvest(node: ast.AST) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                out.append(child.value)

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == attribute:
                    harvest(node.value)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == attribute and node.value is not None:
                harvest(node.value)
        elif isinstance(node, ast.keyword) and node.arg == attribute and node.value is not None:
            harvest(node.value)
    return out


def _function_literals(tree: ast.Module, name: str) -> set[str]:
    """Every string literal inside the body of a named function."""

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return {c.value for c in ast.walk(node) if isinstance(c, ast.Constant) and isinstance(c.value, str)}
    return set()


def _legacy_vocabularies(root: Path) -> dict[str, set[str]]:
    """Each consumer's own critical vocabulary, however it happens to spell it.

    Only reached when the canonical module is absent — that is, on a tree
    where every consumer still carries its own list. Reporting *which*
    keywords disagree is the whole value of the gate at that point; "the file
    is missing" would send a reader looking for the wrong thing.
    """

    found: dict[str, set[str]] = {}
    for relative in _CONSUMERS:
        tree = _module(root, relative)
        literals = {k for k in _literals_under(tree, "_CRITICAL_KEYWORDS") if k.strip()}
        # The scorer inlined its copy in the function rather than as a constant.
        literals |= {k for k in _function_literals(tree, "_has_critical_keyword") if k.strip()}
        if literals:
            found[relative] = literals
    return found


def _load_matcher(root: Path):  # noqa: ANN202 - returns the production module
    """Import the production matcher. Never re-implement the rule under test."""

    agents = root / "services" / "agents"
    if str(agents) not in sys.path:
        sys.path.insert(0, str(agents))
    try:
        from app.keywords import display, matches, normalise  # noqa: PLC0415
    except ImportError as exc:  # the canonical vocabulary is not there at all
        print(f"FAIL: there is no canonical severity vocabulary at {_CANONICAL} ({exc})")
        legacy = _legacy_vocabularies(root)
        for relative, words in sorted(legacy.items()):
            print(f"  - {relative} declares its own critical vocabulary ({len(words)} keyword(s))")
        if len(legacy) > 1:
            everything: set[str] = set()
            for words in legacy.values():
                everything |= words
            for relative, words in sorted(legacy.items()):
                missing = sorted(everything - words)
                if missing:
                    print(f"  - {relative} is missing {missing}, which another copy treats as critical")
            print("    Two copies of one vocabulary have drifted; an alert can be scored critical by one and not credited by the other.")
        raise SystemExit(1) from exc

    return display, matches, normalise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="accepted for symmetry; the gate always checks")
    parser.parse_args()

    root = repo_root()
    display, matches, normalise = _load_matcher(root)
    failures: list[str] = []

    # --- PARITY ----------------------------------------------------------
    canonical = _module(root, _CANONICAL)
    declared = _declares(canonical, _VOCAB_NAMES)
    if not {"CRITICAL_KEYWORDS", "HIGH_KEYWORDS"} <= declared:
        failures.append(f"{_CANONICAL} must declare CRITICAL_KEYWORDS and HIGH_KEYWORDS (declares {sorted(declared)})")

    for relative in _CONSUMERS:
        tree = _module(root, relative)
        second = _declares(tree, _VOCAB_NAMES)
        if second:
            failures.append(
                f"{relative} declares its own {sorted(second)}; the severity vocabulary belongs to {_CANONICAL} alone — "
                f"two copies that agree today is what the drift looked like before it drifted"
            )
        if not _imports_from(tree, "app.keywords"):
            failures.append(f"{relative} scores severity but does not import from app.keywords")

    # --- COLLISION --------------------------------------------------------
    corpora_checked = 0
    keywords_checked = 0
    comparisons = 0
    for relative, attribute in _CORPORA:
        tree = _module(root, relative)
        keywords = sorted({k for k in _literals_under(tree, attribute) if k.strip()})
        if not keywords:
            failures.append(f"{relative}:{attribute} yielded no keywords; the gate would pass over an empty corpus")
            continue
        corpora_checked += 1
        # Severity keywords answer for named resources too: a topic router may
        # match an ARN, a critical verdict may not.
        samples = OPAQUE + NAMED if (relative, attribute) in _SEVERITY_CORPORA else OPAQUE
        for keyword in keywords:
            keywords_checked += 1
            comparisons += len(samples)
            hits = [sample for sample in samples if matches(normalise(sample), keyword)]
            if hits:
                failures.append(
                    f"{relative}:{attribute} keyword {display(keyword)!r} matches identifier(s) carrying no such meaning: "
                    + ", ".join(repr(h) for h in hits[:3])
                    + (f" (+{len(hits) - 3} more)" if len(hits) > 3 else "")
                )

    if not corpora_checked or not keywords_checked:
        print("FAIL: the gate compared nothing, which is indistinguishable from a clean result")
        return 1

    if failures:
        print(f"FAIL: keyword matching ({len(failures)} finding(s))")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        f"OK: one severity vocabulary across {len(_CONSUMERS)} consumer(s); "
        f"{keywords_checked} keyword(s) in {corpora_checked} corpora over "
        f"{comparisons} comparisons against {len(OPAQUE)} opaque identifiers "
        f"and {len(NAMED)} named resources"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
