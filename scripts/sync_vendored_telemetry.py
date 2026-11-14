#!/usr/bin/env python3
"""Keep the guarded telemetry module byte-identical across its three services.

`services/ueba/app/core/telemetry.py` is canonical. `honeytokens` and
`purple-team` carry vendored copies, because each service image ships only
its own `app/` subtree and cannot import a sibling's module at runtime —
the same arrangement as `cors.py` and `tenant_scope.py`.

The module exists because all three services built an OTLP exporter inline
in `main.py` against a `settings.otel_endpoint` defaulting to
`http://localhost:4317` — inside a container, the service itself — so
tracing never reached the collector and the batch processor retried a
refused connection every few seconds (issue #1848). Three copies that can
drift silently are worse than one copy plus a gate, so this gate is a
digest comparison, like `sync_vendored_ip_class.py`.

The canonical copy carries no banner (it is itself a served module, not a
generated artifact), so the comparison is plain byte equality.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

CANONICAL = Path("services/ueba/app/core/telemetry.py")
VENDORED = (
    Path("services/honeytokens/app/core/telemetry.py"),
    Path("services/purple-team/app/core/telemetry.py"),
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail when a copy is stale")
    args = parser.parse_args()

    root = repo_root()
    source = root / CANONICAL
    if not source.is_file():
        print(f"FAIL {CANONICAL} is missing; refusing to report a vendored copy of nothing as current")
        return 1
    want = source.read_text(encoding="utf-8")

    failures = 0
    for rel in VENDORED:
        target = root / rel
        if args.check:
            have = target.read_text(encoding="utf-8") if target.is_file() else ""
            if have != want:
                print(f"FAIL {rel} is stale against {CANONICAL}")
                print(f"  canonical sha256 {hashlib.sha256(want.encode()).hexdigest()[:16]}")
                print(f"  vendored  sha256 {hashlib.sha256(have.encode()).hexdigest()[:16]}")
                print("  run: python3 scripts/sync_vendored_telemetry.py")
                failures += 1
            else:
                print(f"OK {rel} matches {CANONICAL}")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(want, encoding="utf-8")
        print(f"OK wrote {rel}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
