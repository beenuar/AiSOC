"""aisoc-sandbox — command-line entry point.

The two visible subcommands are ``demo`` and ``scenarios``:

  * ``aisoc-sandbox demo`` runs one full Detect → Triage → Hunt →
    Respond funnel against a bundled or user-supplied scenario and
    prints the Investigation Ledger to stdout. ``--json`` switches
    the output to a machine-readable form.

  * ``aisoc-sandbox scenarios`` lists the bundled scenarios so a user
    can pick one with ``--scenario <id>`` without reading the docs.

Exit codes follow UNIX convention:

  0  success — investigation ran and the ledger was emitted.
  2  invalid arguments (bad scenario id, missing file, etc).
  3  internal error during the run.

There is no networked path in this CLI. If you `strace` it you should
see exactly one ``read`` of the scenario file, zero ``connect`` syscalls.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Sequence

from . import __version__
from .investigation import run_investigation
from .ledger import Ledger
from .scenarios import available_scenarios, emit_scenario_index, load_scenario


_PROG = "aisoc-sandbox"
_DESCRIPTION = (
    "Run an AiSOC agent investigation offline in under 30 seconds. "
    "No Docker, no API key, no network."
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=_PROG,
        description=_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  aisoc-sandbox demo\n"
            "  aisoc-sandbox demo --scenario aws-credential-exfil\n"
            "  aisoc-sandbox demo --file my-alert.json --json\n"
            "  aisoc-sandbox scenarios\n"
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

    demo = sub.add_parser(
        "demo",
        help="Walk one scenario through the Detect → Triage → Hunt → Respond funnel.",
    )
    demo.add_argument(
        "--scenario",
        choices=available_scenarios(),
        default="lateral-movement",
        help="Bundled scenario id (default: %(default)s).",
    )
    demo.add_argument(
        "--file",
        metavar="PATH",
        help="Path to a custom scenario JSON. Overrides --scenario when set.",
    )
    demo.add_argument(
        "--json",
        action="store_true",
        help="Emit the ledger as a JSON document instead of the human view.",
    )

    sub.add_parser(
        "scenarios",
        help="List the bundled scenarios and exit.",
    )
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scenarios":
        emit_scenario_index()
        return 0

    if args.command == "demo":
        try:
            scenario = load_scenario(args.scenario, file=args.file)
        except (FileNotFoundError, ValueError) as exc:
            print(f"{_PROG}: error: {exc}", file=sys.stderr)
            return 2

        ledger = Ledger()
        started = time.perf_counter()
        try:
            run_investigation(scenario, ledger=ledger)
        except Exception as exc:  # noqa: BLE001 — surface to the user, exit 3.
            print(f"{_PROG}: investigation crashed: {exc}", file=sys.stderr)
            return 3
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        if args.json:
            payload = {
                "tool": _PROG,
                "version": __version__,
                "scenario": scenario.to_dict(),
                "ledger": ledger.to_dict(),
                "elapsed_ms": elapsed_ms,
            }
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return 0

        # Human view: brief preamble, then the rendered ledger.
        _print_preamble(scenario)
        ledger.render_human()
        print(
            f"Ran {len(ledger)} steps in {elapsed_ms} ms.\n"
            "Ready for the real stack? `pnpm aisoc:demo` from a fresh clone of\n"
            "  https://github.com/beenuar/AiSOC\n"
        )
        return 0

    # argparse refused to leave us here, but Pylance doesn't know that.
    parser.print_help()
    return 2


def _print_preamble(scenario: object) -> None:
    sc = scenario  # narrow for the type-checker
    # We don't depend on rich so the package stays zero-dep. The
    # output uses plain text + ANSI; piping to a file produces clean
    # text via Ledger.render_human's TTY-aware colour code.
    print(f"\nScenario: {sc.id}")
    print(f"Title:    {sc.title}")
    if sc.narrative:
        print(f"Narrative: {sc.narrative}")
    if sc.mitre_techniques:
        print(f"MITRE:    {', '.join(sc.mitre_techniques)}")
    print(f"Severity: {sc.severity}\n")


if __name__ == "__main__":  # pragma: no cover — covered by smoke test.
    sys.exit(main())
