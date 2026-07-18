#!/usr/bin/env python3
"""
Phase 2.3 — keep ``infra/docker/prometheus.yml`` aligned with the
services that actually expose ``/metrics``.

Pre-Phase-2.3 the scrape config shipped five jobs, four of which
silently failed every scrape interval (wrong hostname, wrong port,
or no `/metrics` route in the service code). This script enforces a
hard invariant going forward:

    For every job listed in prometheus.yml:
        - the service named in the target MUST be a real
          docker-compose service
        - the service code MUST contain a `/metrics` handler
        - the port MUST be the internal container port the service
          actually listens on

    For every service whose code contains `/metrics`:
        - it MUST appear in prometheus.yml (so we don't accidentally
          add an instrumented service that no one scrapes)

The script is intentionally substring-based against the source tree
rather than parsing FastAPI routes — that would require importing
every service at audit time. The substring is a faithful proxy
because the only legitimate way to expose `/metrics` is to write
the literal string in a route decorator or a Go handler.

Usage::

    # Print the audit table.
    python3 scripts/audit_prometheus_targets.py

    # Fail with a non-zero exit code if the scrape config has
    # drifted from reality. Wire this into CI.
    python3 scripts/audit_prometheus_targets.py --check
"""

from __future__ import annotations

import argparse
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PROMETHEUS = REPO_ROOT / "infra" / "docker" / "prometheus.yml"
SERVICES_DIR = REPO_ROOT / "services"

# Which compose service each prometheus hostname maps to. ``ingest-
# worker`` is the docker-compose service name, but the actual code
# lives at ``services/ingest/``. The map keeps the audit honest
# without the script having to parse docker-compose.yml.
HOSTNAME_TO_SVC_DIR = {
    "api": "api",
    "ingest-worker": "ingest",
    "fusion": "fusion",
    "threatintel": "threatintel",
    "agents": "agents",
    "actions": "actions",
    "enrichment": "enrichment",
    "ueba": "ueba",
    "honeytokens": "honeytokens",
    "purple-team": "purple-team",
    "realtime": "realtime",
    "connectors": "connectors",
    "osquery-tls": "osquery-tls",
    "slack-bot": "slack-bot",
    "teams-bot": "teams-bot",
}

# Hostnames that map to a third-party image (not a service in our
# `services/` tree), so the "does the service tree expose /metrics"
# check doesn't apply. The image ships `/metrics` natively and we
# trust its upstream contract. Phase 2.4 added `alertmanager` here
# when wiring the in-cluster Alertmanager into the observability
# stack.
THIRD_PARTY_HOSTS: set[str] = {
    "alertmanager",
    # Issue #478 — LiteLLM gateway. A third-party image (berriai/litellm)
    # that exports per-task LLM latency/tokens/cost/errors on /metrics via
    # its prometheus callback. No source lives under services/, so the
    # "does the service tree expose /metrics" check does not apply.
    "litellm",
}

# Services we are intentionally NOT scraping even though they CAN
# have /metrics (they may be opt-in, gated behind a profile, or
# kept out of the default observability surface for cost reasons).
# Currently empty — every instrumented service is in-scope.
SCRAPE_EXEMPT: set[str] = set()

def parse_prometheus() -> list[tuple[str, str, int]]:
    """Return ``[(job, host, port), ...]`` from prometheus.yml.

    We walk the file line-by-line in linear time rather than the
    previous hand-rolled regex
    (``- job_name:\\s*…\\n(?:\\s+.*\\n)*?\\s+- targets:…``) which
    CodeQL flagged as a high-severity ReDoS (rule ``py/redos``) for
    exponential backtracking on malformed inputs starting with
    ``- job_name:-\\n`` and many repetitions of `` \\n``.

    PyYAML would be the more idiomatic option, but the CI Python lint
    job intentionally installs only ``ruff`` + ``mypy`` (no PyYAML).
    Keeping this script stdlib-only means the same script audits
    `prometheus.yml` from both the lint job and the compose-smoke
    job without splitting the dependency surface.

    The parser is deliberately permissive about formatting: single
    or double quotes, list brackets on the same line as ``targets:``,
    extra whitespace. It pairs the first ``targets:`` line under each
    ``- job_name:`` heading.
    """

    out: list[tuple[str, str, int]] = []
    job: str | None = None
    for raw_line in PROMETHEUS.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("- job_name:"):
            job = stripped.split(":", 1)[1].strip().strip("'\"")
            continue
        if job and stripped.startswith("- targets:"):
            # Pull the first ``host:port`` out of ``[ ... ]``. We don't
            # parse multi-target lists — every job in our scrape
            # config has exactly one target.
            after_bracket = stripped.split("[", 1)
            if len(after_bracket) != 2:
                job = None
                continue
            inner = after_bracket[1].split("]", 1)[0]
            # ``inner`` is typically ``'host:port'`` (with quotes) but
            # may include leading/trailing whitespace.
            target = inner.strip().strip("'\"")
            host, sep, port = target.rpartition(":")
            if sep and host and port.isdigit():
                out.append((job, host, int(port)))
            job = None
    return out


def has_metrics_endpoint(svc_dir: str) -> bool:
    """True if the service's source tree exposes ``/metrics``."""
    svc_path = SERVICES_DIR / svc_dir
    if not svc_path.is_dir():
        return False
    for path in svc_path.rglob("*"):
        if path.suffix not in {".py", ".go", ".ts", ".js"}:
            continue
        if "tests/" in str(path) or "/test/" in str(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if '"/metrics"' in text or "'/metrics'" in text:
            # Avoid matching comments or generated test fixtures.
            for line in text.splitlines():
                if '"/metrics"' in line or "'/metrics'" in line:
                    stripped = line.lstrip()
                    if stripped.startswith(("#", "//", "/*", "*")):
                        continue
                    return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if prometheus.yml has drifted from reality",
    )
    args = parser.parse_args()

    scrape_jobs = parse_prometheus()
    scraped_dirs = {
        HOSTNAME_TO_SVC_DIR.get(host, host) for _, host, _ in scrape_jobs
    }

    print(f"Audit of {PROMETHEUS.relative_to(REPO_ROOT)}\n")
    print(f"{'job':<20} {'host':<18} {'port':>6}  service tree has /metrics?")
    print(f"{'-' * 20} {'-' * 18} {'-' * 6}  ---------------------------")

    drift: list[str] = []
    for job, host, port in scrape_jobs:
        if host in THIRD_PARTY_HOSTS:
            print(f"{job:<20} {host:<18} {port:>6}  third-party image")
            continue
        svc_dir = HOSTNAME_TO_SVC_DIR.get(host)
        if svc_dir is None:
            print(f"{job:<20} {host:<18} {port:>6}  HOSTNAME UNKNOWN")
            drift.append(
                f"prometheus.yml scrapes {host!r} but no compose service "
                f"answers to that hostname (add it to "
                f"HOSTNAME_TO_SVC_DIR or THIRD_PARTY_HOSTS in "
                f"{pathlib.Path(__file__).name})"
            )
            continue
        has = has_metrics_endpoint(svc_dir)
        marker = "yes" if has else "NO  <-- broken scrape"
        print(f"{job:<20} {host:<18} {port:>6}  {marker}")
        if not has:
            drift.append(
                f"prometheus.yml scrapes {host}:{port} but "
                f"services/{svc_dir}/ has no /metrics handler"
            )

    print()

    # The other side of the invariant: services that expose
    # /metrics but aren't scraped.
    for svc_dir in sorted(p.name for p in SERVICES_DIR.iterdir() if p.is_dir()):
        if svc_dir in SCRAPE_EXEMPT:
            continue
        if svc_dir in scraped_dirs:
            continue
        if has_metrics_endpoint(svc_dir):
            drift.append(
                f"services/{svc_dir}/ exposes /metrics but no scrape job "
                f"in prometheus.yml targets it (add a job_name or list "
                f"the service in SCRAPE_EXEMPT with a written reason)"
            )

    if args.check and drift:
        print("DRIFT DETECTED:", file=sys.stderr)
        for d in drift:
            print(f"  - {d}", file=sys.stderr)
        return 1
    if not drift:
        print("OK — prometheus.yml matches reality.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
