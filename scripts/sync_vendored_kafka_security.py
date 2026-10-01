#!/usr/bin/env python3
"""Keep every copy of ``app/core/kafka_security.py`` byte-identical.

Seven Python services construct Kafka clients, and each is built with its own
directory as the Docker build context — the same reason ``cors.py`` and
``tenant_scope.py`` are vendored rather than imported.

Drift is the hazard this prevents, and for a transport resolver it is a
particularly quiet one: a service whose copy still allows cleartext in
production does not fail, it connects, and the only symptom is that one
consumer out of seven is speaking plaintext to a broker the other six reach
over TLS. Nobody reads seven files side by side to find that.

Run modes
---------
* ``python scripts/sync_vendored_kafka_security.py``         — copy source → vendored.
* ``python scripts/sync_vendored_kafka_security.py --check`` — fail if any copy
  is missing or differs. CI uses this mode.

Dependency-free so it runs in any CI runner.

AiSOC — open-source AI Security Operations Center (MIT License).
"""

from __future__ import annotations

import argparse
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

#: The copy every other service is compared against.
SOURCE = REPO_ROOT / "services" / "fusion" / "app" / "core" / "kafka_security.py"

#: Every service that builds a Kafka client. Derived once by searching for
#: `AIOKafkaConsumer` and `AIOKafkaProducer`; `--check` re-derives it and
#: fails if a service has started using Kafka without taking a copy, so the
#: list cannot silently fall behind the tree.
VENDORED = (
    REPO_ROOT / "services" / "ueba" / "app" / "core" / "kafka_security.py",
    REPO_ROOT / "services" / "agents" / "app" / "core" / "kafka_security.py",
    REPO_ROOT / "services" / "threatintel" / "app" / "core" / "kafka_security.py",
    REPO_ROOT / "services" / "api" / "app" / "core" / "kafka_security.py",
)

#: Services that construct a client but are covered by another copy, or are
#: not Python. Named so the derivation below can tell "not using Kafka" from
#: "using Kafka and not covered".
NOT_PYTHON = ("ingest", "realtime")


def _services_using_kafka() -> set[str]:
    """Which services construct an aiokafka client, read from the tree."""
    found: set[str] = set()
    services = REPO_ROOT / "services"
    for path in services.rglob("*.py"):
        if "test" in path.parts or path.name.startswith("test_"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "AIOKafkaConsumer(" in text or "AIOKafkaProducer(" in text:
            found.add(path.relative_to(services).parts[0])
    return found


def _expected_copies() -> set[pathlib.Path]:
    return {SOURCE, *VENDORED}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify instead of writing")
    args = parser.parse_args()

    if not SOURCE.is_file():
        print(f"sync_vendored_kafka_security: canonical copy missing at {SOURCE}", file=sys.stderr)
        return 2

    expected = SOURCE.read_text(encoding="utf-8")
    problems: list[str] = []

    # Direction one: every declared copy matches.
    for target in VENDORED:
        if not target.is_file():
            problems.append(f"missing: {target.relative_to(REPO_ROOT)}")
            continue
        if target.read_text(encoding="utf-8") != expected:
            problems.append(f"differs: {target.relative_to(REPO_ROOT)}")

    # Direction two, which is the one that actually drifts: a service that
    # started using Kafka and never took a copy. Checking only the first
    # direction would pass a tree where an eighth service speaks plaintext.
    covered = {p.relative_to(REPO_ROOT / "services").parts[0] for p in _expected_copies()}
    for service in sorted(_services_using_kafka() - covered - set(NOT_PYTHON)):
        problems.append(
            f"uncovered: services/{service} constructs an aiokafka client and has no kafka_security.py — add it to VENDORED and re-run"
        )

    if args.check:
        if problems:
            print("sync_vendored_kafka_security: FAIL", file=sys.stderr)
            for problem in problems:
                print(f"  {problem}", file=sys.stderr)
            print("Run: python3 scripts/sync_vendored_kafka_security.py", file=sys.stderr)
            return 1
        print(
            f"sync_vendored_kafka_security: OK — {len(VENDORED)} vendored copy(ies) match, and every Python service using Kafka is covered."
        )
        return 0

    written = 0
    for target in VENDORED:
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.is_file() or target.read_text(encoding="utf-8") != expected:
            target.write_text(expected, encoding="utf-8")
            written += 1
    uncovered = [p for p in problems if p.startswith("uncovered:")]
    for problem in uncovered:
        print(f"  {problem}", file=sys.stderr)
    print(f"sync_vendored_kafka_security: wrote {written} copy(ies)")
    return 1 if uncovered else 0


if __name__ == "__main__":
    raise SystemExit(main())
