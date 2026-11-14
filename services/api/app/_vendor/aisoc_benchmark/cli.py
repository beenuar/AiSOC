"""``aisoc-benchmark`` — grade any SOC agent on the same corpus.

    aisoc-benchmark run --agent-url https://your-agent/investigate \\
                        --corpus corpus/soc-agent-benchmark-v1.json

The point of the command is that it does not import AiSOC. A vendor points
it at their own endpoint and gets the same numbers computed by the same
code, which is what separates a benchmark from a self-report.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .adapter import HTTPAgent
from .runner import CorpusError, format_report, load_corpus, run_benchmark

DEFAULT_CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "soc-agent-benchmark-v1.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aisoc-benchmark", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Grade an agent over the corpus.")
    run.add_argument("--agent-url", required=True, help="POST endpoint taking an incident.")
    run.add_argument("--agent-name", default="http-agent")
    run.add_argument("--agent-version", default="unknown")
    run.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    run.add_argument("--header", action="append", default=[], metavar="K=V")
    run.add_argument("--concurrency", type=int, default=4)
    run.add_argument("--limit", type=int, default=None)
    run.add_argument("--json", action="store_true", help="Emit JSON instead of a report.")
    run.add_argument("--out", type=Path, help="Write the JSON result here as well.")

    describe = sub.add_parser("corpus", help="Describe the corpus without running anything.")
    describe.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)

    args = parser.parse_args(argv)

    if args.command == "corpus":
        try:
            incidents, _, provenance = load_corpus(args.corpus)
        except CorpusError as exc:
            print(f"aisoc-benchmark: {exc}", file=sys.stderr)
            return 1
        print(f"{len(incidents)} incidents in {args.corpus}")
        for source, count in sorted(provenance.items()):
            print(f"  {source:<20} {count}")
        return 0

    headers: dict[str, str] = {}
    for item in args.header:
        key, _, value = item.partition("=")
        if key and value:
            headers[key] = value

    agent = HTTPAgent(
        args.agent_url,
        name=args.agent_name,
        version=args.agent_version,
        headers=headers,
    )

    try:
        result = asyncio.run(run_benchmark(agent, args.corpus, concurrency=args.concurrency, limit=args.limit))
    except CorpusError as exc:
        print(f"aisoc-benchmark: {exc}", file=sys.stderr)
        return 1

    payload = result.as_dict()
    if args.out:
        args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(payload, indent=2) if args.json else format_report(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
