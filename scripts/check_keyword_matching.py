#!/usr/bin/env python3
"""Keyword matching CI gate."""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

_CANONICAL = "services/agents/app/keywords.py"

_CONSUMERS = (
    "services/agents/app/agents/triage_agent.py",
    "services/agents/app/confidence/scoring.py",
)

_VOCAB_NAMES = (
    "_CRITICAL_KEYWORDS",
    "_HIGH_KEYWORDS",
    "CRITICAL_KEYWORDS",
    "HIGH_KEYWORDS",
)

_CORPORA = (
    ("services/agents/app/keywords.py", "CRITICAL_KEYWORDS"),
    ("services/agents/app/keywords.py", "HIGH_KEYWORDS"),
    ("services/agents/app/investigator/strategies.py", "keywords"),
    ("services/agents/app/investigator/tools.py", "_MITRE_KEYWORDS"),
    ("services/agents/app/swarm/hypotheses.py", "supports_keywords"),
    ("services/agents/app/swarm/hypotheses.py", "contradicts_keywords"),
)

OPAQUE: tuple[str, ...] = (
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
    "aks-syspool-c2f4a1b6-vmss000003",
    "stprodarchivec2a4.blob.core.windows.net",
    "gke-prod-cluster-default-pool-a1c2d3e4-9xkp",
    "api-deployment-7d9c2f4b8-xk2lp",
    "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    "c2a4e6b8-1234-4567-89ab-cdef01234567",
    "d41d8cd98f00b204e9800998ecf8427e",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha256:9c2f1e0b7a6d5c4b3a29180f7e6d5c4b3a29180f7e6d5c4b3a29180f7e6d5c4b",
    "9c2f1e0b7a6d5c4b3a29180f7e6d5c4b3a29180f",
    "c2VjcmV0LXRva2VuLXZhbHVl",
    "aGVsbG8gd29ybGQgdGhpcyBpcyBmaW5l",
    ".".join(("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIiOiIxMjM0NSJ9", "c2lnbmF0dXJl")),
    "DESKTOP-C2A4B6",
    "00:1a:c2:3b:4c:5d",
    "S-1-5-21-3623811015-3361044348-30300820-1013",
)

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
    except ImportError as exc:
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
