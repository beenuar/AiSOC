#!/usr/bin/env python3
"""Ship the compiled detection corpus inside the API image, and keep it identical.

Why this exists
---------------
The fusion detection engine loads four things and runs 2,586 rules from them:

    services/fusion/app/data/detection_ruleset.json            741 stateless
    services/fusion/app/data/detection_ruleset_imported.json  1770 stateless
    services/fusion/app/data/windowed_ruleset.json              72 (70 windowed + 2 sequence)
    services/fusion/app/services/windowed_detection.py           3 windowed, declared in Python

The console's rule-management surface could see none of them (#1273). The
reason is not the handlers: it is that `docker-compose.yml` builds the API
with `context: ./services/api`, so its `COPY . .` has never been able to see
`services/fusion/`. "Read the compiled ruleset directly" works in a source
checkout and fails in every container — exactly how discussion #374 played
out for `marketplace/index.json` on this repository, and solved there by
committing a copy inside the build context with a gate holding the two
byte-identical.

Direction
---------
`services/fusion/app/data/` is the source of truth and the packaged copy is
derived. `--check` compares in **both** directions: a file added under the
packaged directory and not to the source fails too, because a one-directional
gate passes while drift accumulates in the direction things actually change.

The fourth artefact
-------------------
Three windowed rules (`wd-bruteforce-auth`, `wd-password-spray`,
`wd-port-scan`) are declared as a tuple literal in `windowed_detection.py`
rather than in any exported file, and `load_window_rules()` seeds from them
before reading the JSON — which is why the engine runs 73 windowed rules
against a file holding 72. Copying the three JSON files alone would leave the
catalogue three rules short of what fires, so they are exported here into
`windowed_builtin_rules.json`.

They are read out of the source with `ast`, not by importing fusion. Two
reasons: `windowed_detection` imports the fusion `app` package, which would
need fusion's full dependency set on a gate that must run on a bare
interpreter; and `services/api` and `services/fusion` both name their
top-level package `app`, so whichever is imported first in a process shadows
the other.

Why not add those three to `windowed_ruleset.json` instead
----------------------------------------------------------
It would be the tidier artefact, and it was not done deliberately: that file
is read by `generate_corpus_stats.py`, `detection_truth_table.py`,
`build_quarantine_index.py`, `check_content_packs.py`,
`check_windowed_translation.py`, `check_sigma_correlations.py` and
`check_detection_fields.py`, and its count is published. Changing it to carry
three rules that are not translations of anything would move a published
number and red six gates, for a change that belongs to the windowed engine
rather than to this fix.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

REPO = repo_root()
SOURCE = REPO / "services" / "fusion" / "app" / "data"
PACKAGED = REPO / "services" / "api" / "app" / "data" / "detections"
WINDOWED_SOURCE = REPO / "services" / "fusion" / "app" / "services" / "windowed_detection.py"

#: Copied verbatim. Named rather than globbed: a glob would silently stop
#: covering an artefact that was renamed, and print OK while doing it.
COPIED: tuple[str, ...] = (
    "detection_ruleset.json",
    "detection_ruleset_imported.json",
    "windowed_ruleset.json",
)

#: Generated from `_BUILTIN_RULES`.
GENERATED = "windowed_builtin_rules.json"

#: Everything this script writes. `--check` reads exactly this set, so it can
#: never verify fewer places than the writer writes.
WRITES: tuple[str, ...] = (*COPIED, GENERATED)


class SyncError(RuntimeError):
    """The sync could not run, which is not the same as a clean result."""


def python_resident_window_rules() -> list[dict[str, object]]:
    """`_BUILTIN_RULES`, as the same dict shape the JSON artefacts use."""
    if not WINDOWED_SOURCE.is_file():
        raise SyncError(f"{WINDOWED_SOURCE} is missing; there is nothing to export and nothing to compare")

    tree = ast.parse(WINDOWED_SOURCE.read_text(encoding="utf-8"))
    declaration = None
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "_BUILTIN_RULES":
            declaration = node.value
            break
    if declaration is None:
        raise SyncError("_BUILTIN_RULES is not declared in windowed_detection.py; the export has nothing to read")

    elements = getattr(declaration, "elts", None)
    if not elements:
        raise SyncError("_BUILTIN_RULES is no longer a tuple of WindowRule(...) literals; this exporter cannot read it")

    rules: list[dict[str, object]] = []
    for element in elements:
        if not isinstance(element, ast.Call):
            raise SyncError(f"_BUILTIN_RULES holds a {type(element).__name__}, not a WindowRule(...) call")
        rule: dict[str, object] = {}
        for keyword in element.keywords:
            if keyword.arg is None:
                raise SyncError("_BUILTIN_RULES uses **kwargs, which cannot be read statically")
            try:
                rule[keyword.arg] = ast.literal_eval(keyword.value)
            except ValueError as exc:
                raise SyncError(f"_BUILTIN_RULES passes a non-literal to {keyword.arg}: {exc}") from exc
        missing = {"id", "name", "severity", "category", "match_when", "group_by", "threshold", "window_seconds"} - set(rule)
        if missing:
            raise SyncError(f"{rule.get('id', '<unnamed>')} is missing {sorted(missing)}")
        rules.append(rule)

    if not rules:
        raise SyncError("_BUILTIN_RULES parsed to zero rules; finding nothing and reading nothing print the same word")
    return rules


def _serialise_generated(rules: list[dict[str, object]]) -> str:
    return (
        json.dumps(
            {
                "version": 1,
                "count": len(rules),
                "source": "services/fusion/app/services/windowed_detection.py::_BUILTIN_RULES",
                "rules": rules,
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    )


def _payloads() -> dict[str, bytes]:
    """What every destination must contain, keyed by file name."""
    out: dict[str, bytes] = {}
    for name in COPIED:
        path = SOURCE / name
        if not path.is_file():
            raise SyncError(f"{path.relative_to(REPO)} is missing; fusion's own engine reads it, so there is nothing to package")
        body = path.read_bytes()
        if not body.strip():
            raise SyncError(f"{path.relative_to(REPO)} is empty")
        out[name] = body
    out[GENERATED] = _serialise_generated(python_resident_window_rules()).encode("utf-8")
    # The writer and the check read this one function, and this is where the
    # two stay in step. A check that verifies fewer places than the writer
    # writes is one that certifies the case it cannot see — which is how the
    # marketplace index shipped missing from the API image for every release
    # after the endpoint was written.
    if tuple(out) != WRITES:
        raise SyncError(f"the artefact set drifted from WRITES: built {tuple(out)}, declared {WRITES}")
    return out


def write() -> int:
    payloads = _payloads()
    PACKAGED.mkdir(parents=True, exist_ok=True)
    for name, body in payloads.items():
        (PACKAGED / name).write_bytes(body)
    total = sum(len(json.loads(body.decode("utf-8"))["rules"]) for body in payloads.values())
    print(f"sync_packaged_detection_rulesets: wrote {len(payloads)} artefact(s) to {PACKAGED.relative_to(REPO)} — {total} rules")
    return 0


def check() -> int:
    payloads = _payloads()
    errors: list[str] = []

    for name, expected in payloads.items():
        destination = PACKAGED / name
        if not destination.is_file():
            errors.append(
                f"{destination.relative_to(REPO)} is missing. The API image is built from services/api, so the copy "
                "under services/fusion is outside its build context and the rule catalogue reads as empty in every "
                "container. Run `python3 scripts/sync_packaged_detection_rulesets.py`."
            )
            continue
        actual = destination.read_bytes()
        if actual != expected:
            errors.append(
                f"{name}: the packaged copy ({hashlib.sha256(actual).hexdigest()[:12]}) and what fusion runs "
                f"({hashlib.sha256(expected).hexdigest()[:12]}) describe different corpora. Run "
                "`python3 scripts/sync_packaged_detection_rulesets.py`."
            )

    # The other direction. A file that only exists on the packaged side is a
    # catalogue entry the engine never loads, which is the failure this whole
    # change exists to stop — listing rules that do not run is worse than
    # listing none.
    if PACKAGED.is_dir():
        for stray in sorted(PACKAGED.glob("*.json")):
            if stray.name not in payloads:
                errors.append(f"{stray.relative_to(REPO)} has no counterpart in {SOURCE.relative_to(REPO)}; the engine does not load it")

    if errors:
        print("PACKAGED DETECTION RULESET SYNC FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    counts = {name: len(json.loads(body.decode("utf-8"))["rules"]) for name, body in payloads.items()}
    print(f"sync_packaged_detection_rulesets: OK — {len(payloads)} identical artefact(s), {sum(counts.values())} rules ({counts})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the packaged copies are missing, stale or extra")
    args = parser.parse_args(argv)
    try:
        return check() if args.check else write()
    except SyncError as exc:
        print(f"sync_packaged_detection_rulesets: FAILED to run: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
