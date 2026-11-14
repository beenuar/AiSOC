#!/usr/bin/env python3
"""CI entrypoint for the OSS detection contribution workflow.

This script is what ``.github/workflows/detections-validate.yml`` runs
on every PR. Local contributors invoke it the same way:

    python scripts/validate_detection.py app/detections/rules/

or, with an explicit subset (CI passes the list of changed files):

    python scripts/validate_detection.py \\
        app/detections/rules/endpoint/foo.yml \\
        app/detections/rules/cloud/bar.yml

Output:
    On success, prints a short JSON summary to stdout and exits 0.
    On failure, prints a per-issue table to stderr, the JSON summary
    to stdout, and exits 1.

The implementation deliberately delegates to
``app.detections.contrib.validate_pack_directory`` so the CI script,
the in-process API endpoint (``POST /detections/validate``), and the
DetectionAuthor agent's gate all share the same H1–H8 / S1–S3 logic.
There is one validator. Drift between CI and the live API is a bug.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Make ``app.*`` importable when this script is invoked from anywhere.
HERE = Path(__file__).resolve().parent
BACKEND = HERE.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def _format_issue(issue) -> str:  # noqa: ANN001 — duck typed
    return (
        f"  [{issue.severity:<7}] {issue.code:<5} "
        f"{issue.rule_id:<40} {issue.message}"
    )


def main(argv: list[str]) -> int:
    from app.detections.contrib import validate_pack_directory  # noqa: PLC0415

    if not argv:
        print(
            "usage: validate_detection.py <rules-dir-or-files>...",
            file=sys.stderr,
        )
        return 2

    rules_root = BACKEND / "app" / "detections" / "rules"
    if not rules_root.exists():
        print(f"error: rules dir not found: {rules_root}", file=sys.stderr)
        return 2

    # Resolve all argv entries.
    explicit_paths: list[Path] | None = None
    if len(argv) == 1 and Path(argv[0]).is_dir():
        # Bulk: validate everything under <dir>.
        rules_root = Path(argv[0]).resolve()
    else:
        explicit_paths = []
        for a in argv:
            p = Path(a).resolve()
            if not p.exists():
                # File was deleted in the PR — nothing to validate.
                continue
            if p.is_dir():
                explicit_paths.extend(sorted(p.rglob("*.y*ml")))
            else:
                explicit_paths.append(p)

    report = validate_pack_directory(rules_root, paths=explicit_paths)
    summary = report.to_dict()

    # Always print the summary JSON (CI artifact + tail-readable).
    print(json.dumps(summary, indent=2))

    if report.errors:
        print("", file=sys.stderr)
        print(
            f"Detection-content validation FAILED: "
            f"{len(report.errors)} error(s) across "
            f"{report.rules_checked} rule(s).",
            file=sys.stderr,
        )
        for issue in report.errors:
            print(_format_issue(issue), file=sys.stderr)
        if report.warnings:
            print("", file=sys.stderr)
            print(
                f"Plus {len(report.warnings)} warning(s) "
                "(non-blocking, but please review):",
                file=sys.stderr,
            )
            for w in report.warnings:
                print(_format_issue(w), file=sys.stderr)
        return 1

    if report.warnings:
        print("", file=sys.stderr)
        print(
            f"Detection-content validation passed with "
            f"{len(report.warnings)} warning(s):",
            file=sys.stderr,
        )
        for w in report.warnings:
            print(_format_issue(w), file=sys.stderr)
    else:
        print(
            f"Detection-content validation OK "
            f"({report.rules_checked} rules; {len(report.accepted)} accepted).",
            file=sys.stderr,
        )

    # Optional: write GitHub summary if running under Actions.
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write("## Detection content validation\n\n")
                fh.write(f"- Rules checked: **{report.rules_checked}**\n")
                fh.write(f"- Accepted: **{len(report.accepted)}**\n")
                fh.write(f"- Rejected: **{len(report.rejected)}**\n")
                fh.write(f"- Warnings: **{len(report.warnings)}**\n")
                if report.warnings:
                    fh.write("\n### Warnings\n\n")
                    for w in report.warnings:
                        fh.write(
                            f"- `{w.code}` `{w.rule_id}` — {w.message}\n"
                        )
        except OSError:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
