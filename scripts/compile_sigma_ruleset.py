#!/usr/bin/env python3
"""Compile imported Sigma rules and ship only the ones proven to fire.

Pipeline, in order, because each stage exists to stop the next one from
publishing something untrue:

1. :mod:`sigma_compiler` translates each imported Sigma rule into the
   matcher's ``match_when``, or refuses it with a reason.
2. :mod:`sigma_proof_event` builds a **vendor-shaped** event for each
   accepted rule.
3. That event is replayed through the **real connector** ``normalize()``
   (out of process — see :mod:`connector_normalize_worker`) and the **real**
   ``DetectionEngine``.
4. A rule ships only if it fires on its own event **and** stays silent on an
   empty event of the same shape. Everything else is refused and counted.

Step 4 is the whole point. ``scripts/check_detection_fields.py`` says so in its
own docstring: it over-approximates, every string literal in a connector counts
as an emitted field, and "a false pass is a rule this gate should have caught".
Passing it is not evidence a rule can fire. Replaying an event through the
pipeline that would carry it in production is.

The output is a second ruleset the engine loads beside the native one. Keeping
it separate keeps ``export_detection_ruleset.py`` — which drift-checks the
hand-authored specs — comparing like with like, while
``detection_truth_table.py`` reads both and so still derives "executable" from
what the engine loads rather than from a file path.

Usage:
    python3 scripts/compile_sigma_ruleset.py           # compile, prove, write
    python3 scripts/compile_sigma_ruleset.py --check   # fail on drift
    python3 scripts/compile_sigma_ruleset.py --report  # print the taxonomy
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()
sys.path.insert(0, str(ROOT / "scripts"))

from sigma_compiler import Refusal, compile_rule  # noqa: E402
from sigma_proof_event import build_null_event, build_vendor_event  # noqa: E402

SIGMA_DIR = ROOT / "detections" / "sigma-imports"
OUT = ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset_imported.json"
REPORT = ROOT / "docs" / "detections" / "sigma-compilation.md"
WORKER = ROOT / "scripts" / "connector_normalize_worker.py"

#: Upstream lifecycle states that disqualify a rule outright. SigmaHQ retires a
#: rule by marking it, and shipping something its authors withdrew is not a
#: judgement call.
WITHDRAWN_STATUSES = {"deprecated", "unsupported"}

R_WITHDRAWN = "upstream withdrew the rule (deprecated or unsupported)"
R_NO_PROOF_EVENT = "no proof event could be built from the rule body"
R_NORMALIZE_FAILED = "the connector rejected the proof event"
R_DID_NOT_FIRE = "compiled, but did not fire on its own proof event"
R_FIRES_ON_EMPTY = "fired on an empty event, so it would alert on everything"


def _load_docs() -> list[tuple[Path, dict[str, Any]]]:
    docs: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(SIGMA_DIR.rglob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if isinstance(doc, dict) and doc.get("id"):
            docs.append((path, doc))
    return docs


def _normalize_batch(requests: list[dict[str, Any]], *, no_lift: bool = False) -> list[dict[str, Any] | None]:
    """Run every raw payload through its real connector, in one worker pass."""
    if not requests:
        return []
    cmd = [sys.executable, str(WORKER)] + (["--no-lift"] if no_lift else [])
    payload = "\n".join(json.dumps(r, default=str) for r in requests)
    proc = subprocess.run(cmd, input=payload, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(f"connector worker failed:\n{proc.stderr}")
    out: list[dict[str, Any] | None] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        res = json.loads(line)
        out.append(res["normalized"] if res.get("ok") else None)
    if len(out) != len(requests):
        raise SystemExit(f"connector worker returned {len(out)} results for {len(requests)} inputs")
    return out


def _fired(engine: Any, normalized: dict[str, Any], rule_id: str) -> bool:
    message = {"ocsf_event": {"raw_data": json.dumps(normalized, default=str)}}
    return any(hit.rule_id == rule_id for hit in engine.evaluate(message))


def _category(doc: dict[str, Any], path: Path) -> str:
    cats = ((doc.get("tags") or {}).get("categories")) or []
    if cats:
        return str(cats[0])
    parts = path.relative_to(SIGMA_DIR).parts
    return parts[0] if parts and parts[0] != "_quarantine" else "endpoint"


def _mitre(doc: dict[str, Any]) -> list[str]:
    return [str(t).upper() for t in ((doc.get("tags") or {}).get("mitre") or [])]


def build() -> tuple[list[dict[str, Any]], Counter, dict[str, list[str]]]:
    """Compile, prove, and return (shipping rules, refusals, examples)."""
    refusals: Counter = Counter()
    examples: dict[str, list[str]] = {}

    def refuse(reason: str, detail: str) -> None:
        refusals[reason] += 1
        examples.setdefault(reason, []).append(detail)

    candidates: list[dict[str, Any]] = []
    for path, doc in _load_docs():
        status = _upstream_status(doc)
        if status in WITHDRAWN_STATUSES:
            refuse(R_WITHDRAWN, f"{path.name}: {status}")
            continue
        try:
            compiled = compile_rule(doc)
        except Refusal as r:
            refuse(r.reason, f"{path.name}: {r.detail}")
            continue
        except Exception as exc:  # noqa: BLE001 — a compiler bug must not be silent
            refuse(f"compiler error: {type(exc).__name__}", f"{path.name}: {exc}")
            continue

        logsource = doc.get("logsource") or doc.get("log_source") or {}
        candidates.append(
            {
                "rule": {
                    "id": str(doc["id"]),
                    "slug": path.stem,
                    "name": doc.get("name") or path.stem,
                    "severity": str(doc.get("severity") or "medium"),
                    "category": _category(doc, path),
                    "product": str(logsource.get("product") or ""),
                    "service": str(logsource.get("service") or ""),
                    "mitre": _mitre(doc),
                    "match_when": compiled.match_when,
                    "emitter": compiled.emitter,
                    "upstream_status": status,
                    "provenance": _provenance(doc),
                },
                "doc": doc,
                "path": path,
                "emitter": compiled.emitter,
            }
        )

    # --- prove ---------------------------------------------------------
    proof_reqs: list[dict[str, Any]] = []
    proof_owners: list[dict[str, Any]] = []
    for cand in candidates:
        raw = build_vendor_event(cand["doc"], cand["emitter"])
        if raw is None:
            refuse(R_NO_PROOF_EVENT, cand["path"].name)
            continue
        proof_reqs.append({"emitter": cand["emitter"], "raw": raw})
        proof_owners.append(cand)

    normalized = _normalize_batch(proof_reqs)

    sys.path.insert(0, str(ROOT / "services" / "fusion"))
    from app.services.detection_engine import DetectionEngine  # noqa: PLC0415

    emitters = sorted({c["emitter"] for c in proof_owners})
    null_norm = dict(
        zip(
            emitters,
            _normalize_batch([{"emitter": e, "raw": build_null_event(e)} for e in emitters]),
            strict=True,
        )
    )

    shipping: list[dict[str, Any]] = []
    for cand, norm in zip(proof_owners, normalized, strict=True):
        rule = cand["rule"]
        if norm is None:
            refuse(R_NORMALIZE_FAILED, cand["path"].name)
            continue
        engine = DetectionEngine(rules=[rule])
        if not _fired(engine, norm, rule["id"]):
            refuse(R_DID_NOT_FIRE, cand["path"].name)
            continue
        empty = null_norm.get(cand["emitter"])
        if empty is not None and _fired(engine, empty, rule["id"]):
            refuse(R_FIRES_ON_EMPTY, cand["path"].name)
            continue
        shipping.append(rule)

    shipping.sort(key=lambda r: r["id"])
    return shipping, refusals, examples


def _upstream_status(doc: dict[str, Any]) -> str:
    """The rule's SigmaHQ lifecycle state, as the importer recorded it.

    The importer wrote it into ``notes.quarantine_reason`` as the *reason for
    quarantine*, which is where the conflation this file undoes began: it made
    an upstream confidence signal look like a statement about whether the rule
    could execute here. They are different facts and only one of them is about
    this engine.
    """
    note = str((doc.get("notes") or {}).get("quarantine_reason") or "")
    prefix = "upstream status:"
    if note.lower().startswith(prefix):
        return note[len(prefix) :].strip().lower()
    return str(doc.get("status") or "").strip().lower()


def _provenance(doc: dict[str, Any]) -> dict[str, Any]:
    """Attribution carried onto the compiled rule.

    DRL-1.1 permits redistribution in modified form — a translation is exactly
    that — on condition that author identification, a link to the rule, and the
    licence itself travel with it. It further requires that *messages produced
    by matches* identify the author, which is why this block is attached to the
    rule the engine loads rather than only to the YAML on disk.
    """
    prov = dict(doc.get("provenance") or {})
    return {
        "source": prov.get("source", "SigmaHQ/sigma"),
        "source_id": prov.get("source_id", ""),
        "source_commit": prov.get("source_commit", ""),
        "license": prov.get("license", "DRL-1.1"),
        "license_url": prov.get("license_url", "https://github.com/SigmaHQ/Detection-Rule-License"),
        "upstream_path": prov.get("upstream_path", ""),
        "author": prov.get("author", ""),
        "translated_by": "aisoc sigma_compiler",
    }


def _serialise(rules: list[dict[str, Any]]) -> str:
    return json.dumps(
        {"version": 1, "count": len(rules), "rules": rules},
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )


def _render_report(rules: list[dict[str, Any]], refusals: Counter, examples: dict[str, list[str]]) -> str:
    total = len(rules) + sum(refusals.values())
    by_emitter = Counter(r["emitter"] for r in rules)
    lines = [
        "# Sigma compilation report",
        "",
        "<!-- Generated by scripts/compile_sigma_ruleset.py. Do not edit by hand. -->",
        "",
        "Imported Sigma rules are metadata until something translates them into the",
        "language the detection matcher evaluates. This is the result of that",
        "translation, and — more importantly — of replaying every translated rule",
        "through the real connector and the real engine to check it actually fires.",
        "",
        f"- **Imported Sigma rules considered:** {total:,}",
        f"- **Compiled and proven to fire:** {len(rules):,}",
        f"- **Refused:** {sum(refusals.values()):,}",
        "",
        "A rule ships only when a vendor-shaped event replayed through its",
        "connector's `normalize()` and the `DetectionEngine` produces a hit for that",
        "rule id, and an empty event of the same shape does not. The proof is that",
        "the rule is reachable and fires on a well-formed event of its own log",
        "source; it is not a claim that the rule detects an attack.",
        "",
        "## Shipping rules by emitting connector",
        "",
        "| Connector | Rules proven to fire |",
        "| --- | ---: |",
    ]
    for emitter, count in by_emitter.most_common():
        lines.append(f"| `{emitter}` | {count:,} |")
    lines += [
        "",
        "## Why the rest were refused",
        "",
        "Refusing is deliberate. A translation that is merely close changes what a",
        "rule means, and rules that fire on the wrong events are worse than rules",
        "that do not ship.",
        "",
        "| Reason | Rules | Example |",
        "| --- | ---: | --- |",
    ]
    for reason, count in refusals.most_common():
        # Several reasons *name a Sigma modifier*, and a Sigma modifier starts
        # with the pipe that also delimits a Markdown table cell — "|re is
        # case-sensitive upstream" opened an empty first column and shunted
        # every value one cell right. The sample was escaped and the reason
        # was not, so the rows that rendered wrong were exactly the ones
        # explaining the least obvious refusals.
        label = reason.replace("|", "\\|")
        sample = examples.get(reason, [""])[0].replace("|", "\\|")
        lines.append(f"| {label} | {count:,} | `{sample}` |")
    by_status = Counter(r.get("upstream_status") or "(none recorded)" for r in rules)
    lines += [
        "",
        "## Upstream lifecycle status",
        "",
        "The importer quarantined rules by their SigmaHQ status, which put 2,844",
        "`test` and 211 `experimental` rules behind a flag. That conflated two",
        "different facts: whether a rule *can execute* on this engine, and how",
        "confident its authors are in its content. Only the first is about AiSOC,",
        "and it was the actual blocker the whole time.",
        "",
        "So status no longer decides. Fireability does, and status is carried",
        "through to the rule and onto the alert so it can still be filtered:",
        "",
        "| Upstream status | Rules shipped | Treatment |",
        "| --- | ---: | --- |",
    ]
    for status, count in by_status.most_common():
        treatment = {
            "test": (
                "Shipped. In SigmaHQ this means reviewed and in community use — the normal state for most of the corpus, not a warning."
            ),
            "experimental": (
                "Shipped and labelled. Genuine false-positive risk, but that is a "
                "tuning problem, and hiding the rule does not help someone who wants the coverage."
            ),
        }.get(status, "Shipped. No upstream status was recorded on import.")
        lines.append(f"| `{status}` | {count:,} | {treatment} |")
    lines += [
        "",
        "`deprecated` and `unsupported` are refused outright: upstream withdrew",
        "those, which is not a judgement call for a downstream consumer to revisit.",
        "",
        "## Licence",
        "",
        "The imported corpus is licensed under the",
        "[Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License),",
        "which permits redistribution **in modified form** — a translation is exactly",
        "that — provided author identification, a link to the rule, and the licence",
        "travel with it. Every compiled rule therefore carries a `provenance` block,",
        "and the engine stamps that attribution onto each alert, because DRL-1.1 also",
        "requires messages produced by a match to identify the rule's author.",
        "",
        "### Known gap: the author is not the person",
        "",
        "What travels today is the upstream repository, the rule's upstream UUID,",
        "its path in that repository and the licence — enough to find the rule, not",
        "enough to name who wrote it. `provenance.author` is empty on all",
        f"{len(rules):,} compiled rules, because the Sigma importer never read the",
        "upstream `author:` field, and the compiler can only carry forward what the",
        "importer recorded. `_attribution()` in the detection engine is built from",
        "whatever the block actually holds, so the alert reads *Translated from",
        "SigmaHQ/sigma (rules/...), licensed under DRL-1.1* rather than naming an",
        'author called `""` — the sentence is short rather than false, which is the',
        "right behaviour for a gap but is not the same as closing it.",
        "",
        "Closing it needs a re-import: the field has to be captured at import time",
        "and the corpus recompiled. It is reported here rather than left implicit",
        "because a licence obligation that is partly met is not met, and a reader",
        "comparing this corpus against DRL-1.1 should not have to discover that by",
        "reading the JSON.",
        "",
    ]
    return "\n".join(lines) + "\n"


def prove_gate() -> int:
    """Show the fireability proof fails on the tree it was written for.

    A gate that has never been seen to fail is indistinguishable from one that
    cannot. This replays every shipped rule against a connector reverted to its
    pre-fix behaviour, where a Windows event's ``System`` and ``EventData``
    containers stayed nested one level below anything the engine flattened. Every
    rule whose fields came out of those containers must stop firing; if they do
    not, the proof is measuring something other than what it claims.
    """
    rules = json.loads(OUT.read_text(encoding="utf-8"))["rules"]
    docs = {str(doc["id"]): doc for _, doc in _load_docs()}
    windows = [r for r in rules if r.get("emitter") == "windows_event"]
    if not windows:
        print("ERROR: no windows_event rules shipped — nothing to prove against", file=sys.stderr)
        return 1

    reqs = []
    kept = []
    for rule in windows:
        doc = docs.get(rule["id"])
        raw = build_vendor_event(doc, "windows_event") if doc else None
        if raw is None:
            continue
        reqs.append({"emitter": "windows_event", "raw": raw})
        kept.append(rule)

    reverted = _normalize_batch(reqs, no_lift=True)

    sys.path.insert(0, str(ROOT / "services" / "fusion"))
    from app.services.detection_engine import DetectionEngine  # noqa: PLC0415

    still_firing = [
        rule["id"]
        for rule, norm in zip(kept, reverted, strict=True)
        if norm is not None and _fired(DetectionEngine(rules=[rule]), norm, rule["id"])
    ]
    print(f"replayed {len(kept)} windows_event rules against the pre-lift connector")
    if still_firing:
        print(
            f"ERROR: {len(still_firing)} rules fired without the container lift, so the proof "
            f"is not testing field reachability. First: {still_firing[:5]}",
            file=sys.stderr,
        )
        return 1
    print("OK: every one stopped firing, so the proof does depend on the connector propagating the field")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--report", action="store_true")
    parser.add_argument(
        "--prove-gate",
        action="store_true",
        help="verify the fireability proof fails against the pre-fix connector",
    )
    args = parser.parse_args()

    if args.prove_gate:
        return prove_gate()

    rules, refusals, examples = build()
    payload = _serialise(rules)
    report = _render_report(rules, refusals, examples)

    if args.report:
        print(report)
        return 0

    if args.check:
        stale = []
        if not OUT.exists() or OUT.read_text(encoding="utf-8").strip() != payload.strip():
            stale.append(str(OUT.relative_to(ROOT)))
        if not REPORT.exists() or REPORT.read_text(encoding="utf-8").strip() != report.strip():
            stale.append(str(REPORT.relative_to(ROOT)))
        if stale:
            print(
                "ERROR: stale — " + ", ".join(stale) + "\nRun: python3 scripts/compile_sigma_ruleset.py",
                file=sys.stderr,
            )
            return 1
        print(f"OK: compiled Sigma ruleset current ({len(rules)} rules proven to fire)")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(payload + "\n", encoding="utf-8")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(report, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} — {len(rules)} rules proven to fire")
    print(f"wrote {REPORT.relative_to(ROOT)}")
    for reason, count in refusals.most_common():
        print(f"  refused {count:5d}  {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
