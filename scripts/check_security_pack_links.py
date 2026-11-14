#!/usr/bin/env python3
"""Every claim in the security pack still points at something real.

The pack (`docs/security/`) makes one promise: each statement names the file
or the CI job that makes it true. That promise decays silently. A module is
renamed, a workflow is deleted, a heading is reworded — and the pack goes on
reading like a document somebody verified, because a markdown link that
resolves to nothing looks exactly like one that resolves.

This project has shipped the failure that motivates it. Four security
documents described controls that did not exist in the tree: AES-256-GCM
backup encryption where the script only gzipped, envelope encryption cited as
the mitigation for a database dump while `EnvelopeCipher` had zero callers, an
unbroken distributed trace with neither end of the Kafka spine instrumented,
and per-tenant retention marked GATED by a test asserting only that the purge
SQL parses. A link checker would not have caught all four — a link can resolve
to a file whose contents do not support the sentence — but it catches the
cheapest half, which is the half that rots fastest.

What is checked
---------------
1. **Every relative link resolves.** A path to a module, a workflow, a
   migration or a sibling page must exist on disk.
2. **Every in-document and cross-document anchor resolves**, computed the way
   GitHub computes heading slugs. A section renamed in one file leaves a dead
   `#anchor` in the three pages that cited it, and nothing else notices.
3. **Every gate the pack names exists**, matched on `scripts/<name>.py` and
   `<workflow>.yml` wherever they appear in prose — including inside backticks,
   which is how they are usually written and where a plain link checker cannot
   see them.

What is deliberately not checked
--------------------------------
External URLs. Fetching them here would make a required check depend on the
network and on GitHub's rate limiter, which is how `fail: false` and
`--accept 403,429` ended up in the docs link job and why eight wrong-org 404s
survived it. The pack's external links are fetched by hand when they land;
this gate is the deterministic, offline half.

Usage::

    python3 scripts/check_security_pack_links.py
    python3 scripts/check_security_pack_links.py --self-test

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

PACK = "docs/security"

#: Also covered, because they are the pack's two closest neighbours and are
#: linked from it: the egress statement and the policy that points at it.
ALSO = ("docs/trust/data-flows.md", "SECURITY.md")

#: Gates the pack names **in order to say they do not exist**, each with the
#: reason. A questionnaire that lists its gaps has to be able to name them.
#:
#: Bidirectional, like the hostname allow-list and for the same reason: an
#: entry here is not a permanent licence. If the named script appears, this
#: gate fails and demands the entry go — because the pack's sentence saying
#: it is absent has just become false, and a document that understates a
#: control is a document a reviewer has to re-verify by hand.
KNOWN_ABSENT: dict[str, str] = {
    "scripts/audit_compliance_claims.py": (
        "docs/decisions/0002-compliance-claims.md asserts this gate exists and it never has. "
        "The pack names it to record that, and docs/audit/REALITY_REPORT.md lists the same "
        "finding. Delete this entry when the gate is built."
    ),
}

_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
_HEADING = re.compile(r"^#{1,6}\s+(.*)$")
#: A gate named in prose rather than linked. Both forms appear in the pack.
_SCRIPT = re.compile(r"`?(scripts/[a-z0-9_]+\.py)`?")
_WORKFLOW = re.compile(r"`([a-z0-9][a-z0-9-]*\.yml)`")


@dataclass
class Report:
    findings: list[str] = field(default_factory=list)
    files: int = 0
    links: int = 0
    anchors: int = 0
    gates: int = 0


def _slug(heading: str) -> str:
    """GitHub's heading-to-anchor rule, as far as this pack needs it."""
    text = re.sub(r"`([^`]*)`", r"\1", heading).strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"\s+", "-", text).strip("-")


def _anchors(path: pathlib.Path) -> set[str]:
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _HEADING.match(line)
        if match:
            out.add(_slug(match.group(1)))
    return out


def _exists_anywhere(root: pathlib.Path, name: str) -> bool:
    """Whether a bare filename matches any file in the tree.

    Cached per root because the pack names a handful of them and walking the
    tree once beats walking it per name. `node_modules` and `.git` are
    skipped: a name that only matches inside a dependency is not evidence
    that this repository ships it.
    """
    cache = _BASENAMES.setdefault(root, set())
    if not cache:
        skip = {".git", "node_modules", ".venv", "__pycache__"}
        for path in root.rglob("*"):
            if any(part in skip for part in path.parts):
                continue
            if path.is_file():
                cache.add(path.name)
    return name in cache


_BASENAMES: dict[pathlib.Path, set[str]] = {}


def _documents(root: pathlib.Path) -> list[pathlib.Path]:
    found = sorted((root / PACK).glob("*.md"))
    for extra in ALSO:
        candidate = root / extra
        if candidate.is_file():
            found.append(candidate)
    return found


def inspect(root: pathlib.Path) -> Report:
    report = Report()
    anchor_cache: dict[pathlib.Path, set[str]] = {}

    for doc in _documents(root):
        report.files += 1
        rel = doc.relative_to(root).as_posix()
        body = doc.read_text(encoding="utf-8", errors="replace")

        for target in _LINK.findall(body):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            report.links += 1
            path_part, _, fragment = target.partition("#")

            if path_part:
                resolved = (doc.parent / path_part).resolve()
                if not resolved.exists():
                    report.findings.append(f"{rel}: link to {target!r} resolves to nothing")
                    continue
            else:
                resolved = doc

            if not fragment:
                continue
            report.anchors += 1
            if resolved.suffix != ".md":
                continue
            if resolved not in anchor_cache:
                anchor_cache[resolved] = _anchors(resolved)
            if fragment not in anchor_cache[resolved]:
                report.findings.append(f"{rel}: anchor {target!r} names no heading in {resolved.name}")

        # Gates named in prose. A pack that cites a gate deleted last month
        # is the same lie as one that cites a module deleted last month, and
        # the citation is usually in backticks rather than in a link.
        for script in set(_SCRIPT.findall(body)):
            report.gates += 1
            if script in KNOWN_ABSENT:
                continue
            if not (root / script).is_file():
                report.findings.append(f"{rel}: names {script}, which does not exist")
        for name in set(_WORKFLOW.findall(body)):
            if (root / ".github" / "workflows" / name).is_file():
                report.gates += 1
                continue
            # Not every backticked `*.yml` is a workflow claim — the pack
            # names `docker-compose.yml` and several chart values files. A
            # name that exists as a file *somewhere* is one of those; a name
            # that exists nowhere is a workflow that has been renamed or
            # deleted, which is the case worth failing on.
            if _exists_anywhere(root, name):
                continue
            report.gates += 1
            report.findings.append(f"{rel}: names the workflow {name}, which exists nowhere in the tree")

    # The other direction. An exemption that has stopped being true is a
    # document now understating a control, which is the quieter half of the
    # same defect and the half nobody goes looking for.
    for script, reason in sorted(KNOWN_ABSENT.items()):
        if (root / script).is_file():
            report.findings.append(
                f"KNOWN_ABSENT lists {script} as not existing, and it now does. The pack says so in prose; "
                f"correct the prose and delete the entry. Recorded reason: {reason}"
            )

    return report


def _verdict(report: Report) -> int:
    # A gate that passes while inspecting nothing launders the claim it is
    # supposed to hold, so an empty scan is a hard error rather than a pass.
    if report.files == 0 or report.links == 0:
        print(
            f"check_security_pack_links: read {report.files} file(s) and {report.links} link(s) — "
            "refusing to report a pack with nothing in it as verified",
            file=sys.stderr,
        )
        return 2
    if report.findings:
        print("check_security_pack_links: FAIL", file=sys.stderr)
        for finding in report.findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(
        f"check_security_pack_links: OK — {report.files} document(s); "
        f"{report.links} relative link(s), {report.anchors} anchor(s) and "
        f"{report.gates} named gate(s) all resolve."
    )
    return 0


#: What a scratch copy needs for the pack's links to resolve. Not the whole
#: repository: `detections/` alone is thousands of files, and a self-test slow
#: enough to skip is a self-test nobody runs.
#:
#: The clean-copy case below is what keeps this list honest. If the pack grows
#: a link into a tree that is not here, that case fails — so the list cannot
#: silently fall behind and quietly turn every probe into a no-op.
_SCRATCH_TREES = ("docs", "scripts", ".github", "services", "infra", "apps", "tests", "packages")
_SCRATCH_FILES = ("SECURITY.md", "docker-compose.yml", "README.md", "CHANGELOG.md")
_SCRATCH_IGNORE = ("node_modules", "__pycache__", ".venv", "dist", ".next", "build")


def _scratch(root: pathlib.Path, base: pathlib.Path) -> None:
    import shutil

    ignore = shutil.ignore_patterns(*_SCRATCH_IGNORE)
    for tree in _SCRATCH_TREES:
        source = root / tree
        if source.is_dir():
            shutil.copytree(source, base / tree, ignore=ignore, symlinks=True, ignore_dangling_symlinks=True)
    for name in _SCRATCH_FILES:
        source = root / name
        if source.is_file():
            shutil.copy(source, base / name)


def self_test() -> int:
    import tempfile

    root = repo_root()
    extra: list[tuple[str, bool]] = [("the real pack passes", not inspect(root).findings)]

    def probe(description: str, mutate) -> None:  # noqa: ANN001
        with tempfile.TemporaryDirectory(prefix="aisoc-pack-links-") as tmp:
            base = pathlib.Path(tmp)
            _scratch(root, base)
            mutate(base)
            extra.append((description, bool(inspect(base).findings)))

    def break_link(base: pathlib.Path) -> None:
        target = base / PACK / "README.md"
        target.write_text(target.read_text() + "\n[dead](../../services/api/app/nope_does_not_exist.py)\n")

    def break_anchor(base: pathlib.Path) -> None:
        target = base / PACK / "README.md"
        target.write_text(target.read_text() + "\n[dead](questionnaire.md#no-such-heading)\n")

    def break_gate(base: pathlib.Path) -> None:
        target = base / PACK / "README.md"
        target.write_text(target.read_text() + "\nHeld by `scripts/check_not_a_real_gate.py`.\n")

    def break_workflow(base: pathlib.Path) -> None:
        target = base / PACK / "README.md"
        target.write_text(target.read_text() + "\nRun by `not-a-real-workflow.yml`.\n")

    def stale_exemption(base: pathlib.Path) -> None:
        """The other direction: an exemption that has stopped being true."""
        for script in KNOWN_ABSENT:
            created = base / script
            created.parent.mkdir(parents=True, exist_ok=True)
            created.write_text("# the gate the pack says does not exist, now existing\n")

    probe("detects a link to a file that does not exist", break_link)
    probe("detects an anchor that names no heading", break_anchor)
    probe("detects a named gate script that does not exist", break_gate)
    probe("detects a named workflow that does not exist", break_workflow)
    probe("detects a stale KNOWN_ABSENT entry whose script now exists", stale_exemption)

    # The direction it must not fire in. This case does double duty: it proves
    # the gate accepts a clean tree, and it proves `_SCRATCH_TREES` still
    # covers everything the pack links into — without which every probe above
    # would pass on a flood of unrelated findings and prove nothing.
    with tempfile.TemporaryDirectory(prefix="aisoc-pack-links-ok-") as tmp:
        base = pathlib.Path(tmp)
        _scratch(root, base)
        clean = inspect(base)
        if clean.findings:
            print("  the scratch copy is missing a tree the pack links into:", file=sys.stderr)
            for finding in clean.findings[:10]:
                print(f"    {finding}", file=sys.stderr)
        extra.append(("accepts an unmodified copy", not clean.findings))

    return self_test_main(pathlib.Path(__file__).name, [], extra)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="accepted for symmetry with the other gates")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", dest="self_test")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    return _verdict(inspect(repo_root()))


if __name__ == "__main__":
    raise SystemExit(main())
