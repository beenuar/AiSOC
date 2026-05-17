#!/usr/bin/env python3
"""
Wet-eval preflight gate (T5.5).

This script is the first step of `.github/workflows/wet-eval.yml`. It exists
so the weekly wet-eval workflow can be a no-op on:

  * forks where ``WET_EVAL_OPENAI_KEY`` was never configured;
  * a freshly-cloned dev shell where someone runs the workflow manually;
  * any environment where the bench-bot token / API key haven't been
    rotated in yet.

Without this preflight, the workflow would shell into ``run_evals.py --wet``
which would in turn try to import the live agent stack and crash with a
stack trace instead of a clear "missing secret, skipping" message.

It is intentionally **stdlib-only** so it runs on a bare Python install
without ``pip install`` having been done first.

Behaviour
---------
* Inspects the environment for ``WET_EVAL_OPENAI_KEY`` (the key used to
  call the LLM provider) and ``AISOC_BENCH_BOT_TOKEN`` (the fine-grained
  GH PAT that opens the weekly PR).
* Exit code is **always 0** so the workflow can branch on the JSON
  status file rather than a non-zero exit. We never want a missing
  secret to look like a CI failure on a fork.
* Writes a small JSON status file (path passed via ``--status-out``)
  the workflow consumes:
      {
        "should_run": true | false,
        "missing_secrets": ["WET_EVAL_OPENAI_KEY", ...],
        "reason": "...",
        "checked_at": "2026-05-14T07:00:00Z"
      }
* Prints a clear human-readable line to stdout so workflow logs make
  sense without opening the JSON.

Usage
-----
::

    # CI dry-run (workflow uses this):
    python scripts/wet_eval_check.py --dry-run --status-out /tmp/wet-eval-check.json

    # Real preflight:
    python scripts/wet_eval_check.py --status-out /tmp/wet-eval-check.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

# Secrets the workflow needs. Names match what's documented in
# ``apps/docs/docs/operations/secrets.md`` so docs and code stay in step.
_REQUIRED_SECRETS_FOR_LIVE_RUN = (
    "WET_EVAL_OPENAI_KEY",  # LLM provider key used by the live agent.
    "AISOC_BENCH_BOT_TOKEN",  # Fine-grained PAT used to open the weekly PR.
)


def _missing_secrets() -> list[str]:
    """Return the names of secrets that aren't set in the environment."""
    return [name for name in _REQUIRED_SECRETS_FOR_LIVE_RUN if not os.environ.get(name)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Preflight gate for the weekly wet-eval CI job. Exits 0 always; "
            "the workflow consumes the JSON status file to decide whether "
            "to dispatch the live run."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Treat the run as a CI smoke test even when secrets are present. "
            "Used by the test suite and the workflow's PR-time validation "
            "step so we never accidentally call the live LLM provider on a "
            "non-cron trigger."
        ),
    )
    parser.add_argument(
        "--status-out",
        type=Path,
        default=None,
        help=(
            "Write a JSON status file to this path so the workflow can "
            "branch on ``should_run``. If omitted, only stdout is used."
        ),
    )
    args = parser.parse_args(argv)

    missing = _missing_secrets()
    has_all = not missing
    is_live = has_all and not args.dry_run

    if args.dry_run:
        reason = (
            "dry-run mode: status reported as no-op. The workflow will "
            "not dispatch the live wet eval."
        )
    elif missing:
        reason = (
            "Missing required secret(s): "
            + ", ".join(missing)
            + ". This is expected on forks and first-run CI; configure them "
              "in the repo settings to enable the weekly wet eval. See "
              "`apps/docs/docs/operations/secrets.md`."
        )
    else:
        reason = (
            "All required secrets are present. Proceeding to the live "
            "wet-eval run."
        )

    status = {
        "should_run": bool(is_live),
        "dry_run": bool(args.dry_run),
        "missing_secrets": missing,
        "reason": reason,
        # Each secret keyed by name so the workflow can render a checklist
        # without revealing values. Booleans only — never the secret itself.
        "secrets_present": {
            name: bool(os.environ.get(name))
            for name in _REQUIRED_SECRETS_FOR_LIVE_RUN
        },
        "checked_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if args.status_out is not None:
        args.status_out.parent.mkdir(parents=True, exist_ok=True)
        args.status_out.write_text(json.dumps(status, indent=2))

    if status["should_run"]:
        print("[wet-eval-check] OK — secrets present, live wet eval will run.")
    elif args.dry_run:
        print("[wet-eval-check] dry-run — no live API calls will be attempted.")
    else:
        # NOTE: We intentionally do **not** echo the raw ``reason`` string here,
        # nor the names of missing secrets, even though the names themselves
        # are not secret values. CodeQL (rule ``py/clear-text-logging-sensitive-data``)
        # treats any variable whose name contains ``secret``/``token``/``key`` as
        # tainted; piping ``reason`` (which is built from secret env-var names)
        # into ``print`` is flagged as clear-text logging of sensitive data.
        # The JSON status file already lists ``missing_secrets`` for the
        # workflow to consume, so the human log only needs a count.
        missing_count = len(status["missing_secrets"])
        print(
            "[wet-eval-check] SKIP — "
            f"{missing_count} required secret(s) not configured. "
            "Workflow will exit cleanly. See status JSON for the checklist."
        )

    # Always exit 0 — missing secrets is *expected* on forks. The workflow
    # branches on ``should_run`` from the JSON status, not on the exit code.
    return 0


if __name__ == "__main__":
    sys.exit(main())
