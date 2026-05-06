#!/usr/bin/env python3
"""
generate_runbook.py — Generate operational runbooks from OpenTelemetry trace data.

For each configured alert scenario the script:
  1. Queries the OTLP / Tempo / Jaeger backend for recent traces matching the scenario.
  2. Extracts the service dependency graph and slowest operations from span data.
  3. Renders a structured Markdown runbook and writes it to --output.

Usage
-----
  python scripts/generate_runbook.py \\
    --output docs/operations/runbooks/ \\
    --lookback-hours 168 \\
    --otel-endpoint http://tempo:3100

Environment variables
---------------------
  OTEL_ENDPOINT   Grafana Tempo / Jaeger HTTP endpoint (default: http://localhost:3100)
  OTEL_BEARER     Bearer token for authenticated backends (optional)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None  # type: ignore  # noqa: N816

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Runbook definitions
# ---------------------------------------------------------------------------

@dataclass
class RunbookSpec:
    id: str                  # e.g. "RB-001"
    slug: str                # e.g. "api-high-latency"
    title: str
    trigger: str             # human-readable trigger condition
    service_filter: str      # service name to query traces for
    operation_filter: str    # span operation / route filter (substring match)
    impact: str
    escalation: str
    extra_steps: list[str] = field(default_factory=list)


RUNBOOK_SPECS: list[RunbookSpec] = [
    RunbookSpec(
        id="RB-001",
        slug="api-high-latency",
        title="API High Latency",
        trigger="http_request_duration_p99 > 500 ms for 3 minutes",
        service_filter="aisoc-api",
        operation_filter="GET /api",
        impact="End-user requests are slow; SLO breach imminent.",
        escalation="If not resolved in 30 min, page Engineering Lead.",
        extra_steps=[
            "Check recent deployments: `helm history aisoc --namespace aisoc`",
            "Inspect DB query latency in Grafana (dashboard: aisoc-postgres).",
            "Review `kubectl top pods -n aisoc` for CPU/memory saturation.",
        ],
    ),
    RunbookSpec(
        id="RB-002",
        slug="postgres-replica-lag",
        title="PostgreSQL Replica Lag",
        trigger="Streaming replication lag > 30 seconds",
        service_filter="aisoc-api",
        operation_filter="sqlalchemy",
        impact="Read queries may return stale data; failover risk.",
        escalation="If lag > 2 min page DBA on-call.",
        extra_steps=[
            "Check replication status: `SELECT * FROM pg_stat_replication;`",
            "Review network bandwidth between primary and replica regions.",
            "If needed, pause heavy batch jobs to reduce WAL volume.",
        ],
    ),
    RunbookSpec(
        id="RB-003",
        slug="region-failover",
        title="Region Failover",
        trigger="Regional health-check failure for > 3 consecutive checks (30 s)",
        service_filter="aisoc-api",
        operation_filter="GET /api/health",
        impact="All traffic in affected region is unavailable.",
        escalation="Immediate — follow CRIT escalation path.",
        extra_steps=[
            "Promote Postgres replica: `patronictl -c /etc/patroni.yml failover aisoc`",
            "Update DATABASE_URL secret: `kubectl create secret generic aisoc-db --from-literal=...`",
            "Restart API: `kubectl rollout restart deployment -n aisoc -l app=api`",
            "Confirm LB health-check passes before announcing recovery.",
        ],
    ),
    RunbookSpec(
        id="RB-004",
        slug="ingest-pipeline-stall",
        title="Ingest Pipeline Stall",
        trigger="Kafka consumer lag > 10 000 events or ingest_lag_p99 > 30 s",
        service_filter="aisoc-ingest",
        operation_filter="kafka.consume",
        impact="Security events are delayed; detection latency increases.",
        escalation="Page on-call if lag grows for > 10 min.",
        extra_steps=[
            "Check consumer group: `kafka-consumer-groups.sh --describe --group aisoc-ingest`",
            "Look for poison-pill messages: `kubectl logs -n aisoc -l app=ingest --tail=100`",
            "Scale ingest replicas: `kubectl scale deploy ingest -n aisoc --replicas=6`",
        ],
    ),
    RunbookSpec(
        id="RB-005",
        slug="agent-runner-oom",
        title="Agent Runner OOMKilled",
        trigger="OOMKilled exit code on `agents` pods",
        service_filter="aisoc-agents",
        operation_filter="agent.run",
        impact="AI-driven triage and enrichment is unavailable.",
        escalation="Notify product engineering if recurring.",
        extra_steps=[
            "Increase memory limit in values.yaml (`services.agents.resources.limits.memory`).",
            "Identify memory-heavy agent task in spans (look for large `llm.tokens` attributes).",
            "Enable request queuing to rate-limit concurrent agent executions.",
        ],
    ),
    RunbookSpec(
        id="RB-006",
        slug="cert-expiry",
        title="TLS Certificate Near Expiry",
        trigger="Certificate expires in < 14 days",
        service_filter="aisoc-api",
        operation_filter="tls",
        impact="HTTPS will fail after expiry; user access blocked.",
        escalation="Renew immediately; page if auto-renewal fails.",
        extra_steps=[
            "Check cert: `kubectl get cert -n aisoc`",
            "Force renewal: `kubectl delete secret aisoc-tls -n aisoc` (cert-manager will re-issue).",
            "Verify: `kubectl describe certificate aisoc-tls -n aisoc | grep -A5 Status`",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Trace fetching (Grafana Tempo HTTP API)
# ---------------------------------------------------------------------------

def _headers(bearer: str | None) -> dict[str, str]:
    h = {"Accept": "application/json"}
    if bearer:
        h["Authorization"] = f"Bearer {bearer}"
    return h


def fetch_traces(
    endpoint: str,
    service: str,
    operation: str,
    lookback_hours: int,
    bearer: str | None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Query Tempo TraceQL / search endpoint for recent error/slow traces."""
    if requests is None:
        LOG.warning("'requests' package not installed; skipping live trace fetch.")
        return []

    end_ns = int(datetime.now(timezone.utc).timestamp() * 1e9)
    start_ns = int((datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).timestamp() * 1e9)

    # Tempo search API
    url = f"{endpoint.rstrip('/')}/api/search"
    params: dict[str, Any] = {
        "service.name": service,
        "name": operation,
        "start": start_ns,
        "end": end_ns,
        "limit": limit,
        "tags": "error=true",
    }
    try:
        resp = requests.get(url, params=params, headers=_headers(bearer), timeout=15)
        resp.raise_for_status()
        return resp.json().get("traces", [])
    except Exception as exc:
        LOG.warning("Could not fetch traces from %s: %s", url, exc)
        return []


def extract_service_graph(traces: list[dict[str, Any]]) -> list[str]:
    """Pull unique service names from trace root spans."""
    services: set[str] = set()
    for trace in traces:
        for span in trace.get("spanSets", [{}])[0].get("spans", []):
            svc = span.get("attributes", {}).get("service.name", "")
            if svc:
                services.add(svc)
    return sorted(services)


def extract_slow_ops(traces: list[dict[str, Any]], top_n: int = 5) -> list[tuple[str, float]]:
    """Return top-N slowest operations (name, duration_ms)."""
    ops: list[tuple[str, float]] = []
    for trace in traces:
        for span_set in trace.get("spanSets", []):
            for span in span_set.get("spans", []):
                name = span.get("name", "unknown")
                duration_ns = span.get("durationNanos", 0)
                if isinstance(duration_ns, str):
                    try:
                        duration_ns = int(duration_ns)
                    except ValueError:
                        duration_ns = 0
                ops.append((name, duration_ns / 1e6))
    ops.sort(key=lambda x: x[1], reverse=True)
    return ops[:top_n]


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

_RUNBOOK_TEMPLATE = """\
# {id}: {title}

> **Auto-generated** by `scripts/generate_runbook.py` on {generated_at}
> Traces analysed: {trace_count} (last {lookback_hours} h)

---

## Trigger condition

{trigger}

## Impact

{impact}

## Diagnosis steps

{diagnosis}

## Remediation steps

{remediation}

## Verification steps

1. Confirm the triggering alert is resolved in Prometheus / AlertManager.
2. Check service status: `kubectl get pods -n aisoc -l app={service}`.
3. Run smoke test: `curl -sf https://<YOUR_HOST>/api/health | jq .`
4. Verify in the AiSOC SLA dashboard that MTTD/MTTR metrics are back within SLO.

## Escalation

{escalation}

---

*To regenerate this runbook: `python scripts/generate_runbook.py --output docs/operations/runbooks/`*
"""


def _build_diagnosis(
    spec: RunbookSpec,
    traces: list[dict[str, Any]],
    lookback_hours: int,
) -> str:
    services = extract_service_graph(traces)
    slow_ops = extract_slow_ops(traces)

    lines: list[str] = []

    if services:
        lines.append("### Services observed in recent error traces\n")
        for svc in services:
            lines.append(f"- `{svc}`")
        lines.append("")

    if slow_ops:
        lines.append("### Slowest operations in recent traces\n")
        lines.append("| Operation | Duration (ms) |")
        lines.append("|---|---|")
        for name, ms in slow_ops:
            lines.append(f"| `{name}` | {ms:.1f} |")
        lines.append("")
    else:
        lines.append(
            f"_No live traces fetched — run with `--otel-endpoint` pointing to Tempo/Jaeger "
            f"to populate this section from the last {lookback_hours} h of data._\n"
        )

    lines.append("### General diagnosis checklist\n")
    lines.append(f"1. Confirm the alert is genuine (not a monitoring flap).")
    lines.append(f"2. Check `kubectl get events -n aisoc --sort-by=lastTimestamp | tail -20`.")
    lines.append(f"3. Inspect pod logs: `kubectl logs -n aisoc -l app={spec.service_filter} --tail=100 --previous`.")
    lines.append(f"4. Review recent deploys: `helm history aisoc -n aisoc`.")

    return "\n".join(lines)


def _build_remediation(spec: RunbookSpec) -> str:
    steps: list[str] = []

    if spec.extra_steps:
        for i, step in enumerate(spec.extra_steps, 1):
            steps.append(f"{i}. {step}")
    else:
        steps.append("1. Follow standard incident response procedure.")

    return "\n".join(steps)


def render_runbook(
    spec: RunbookSpec,
    traces: list[dict[str, Any]],
    lookback_hours: int,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return _RUNBOOK_TEMPLATE.format(
        id=spec.id,
        title=spec.title,
        generated_at=now,
        trace_count=len(traces),
        lookback_hours=lookback_hours,
        trigger=spec.trigger,
        impact=spec.impact,
        service=spec.service_filter,
        diagnosis=_build_diagnosis(spec, traces, lookback_hours),
        remediation=_build_remediation(spec),
        escalation=spec.escalation,
    )


# ---------------------------------------------------------------------------
# TOC updater
# ---------------------------------------------------------------------------

def update_toc(output_dir: Path) -> None:
    """Rewrite the runbook index table in docs/operations/multi-region.md."""
    runbooks = sorted(output_dir.glob("RB-*.md"))
    if not runbooks:
        return

    toc_lines = ["| ID | Slug | Trigger |", "|---|---|---|"]
    for rb in runbooks:
        stem = rb.stem  # e.g. "RB-001-api-high-latency"
        parts = stem.split("-", 2)
        rb_id = f"{parts[0]}-{parts[1]}" if len(parts) >= 2 else stem
        slug = parts[2] if len(parts) >= 3 else ""
        spec = next((s for s in RUNBOOK_SPECS if s.id == rb_id), None)
        trigger = spec.trigger if spec else ""
        toc_lines.append(f"| {rb_id} | `{slug}` | {trigger} |")

    multi_region_md = output_dir.parent / "multi-region.md"
    if not multi_region_md.exists():
        LOG.info("multi-region.md not found; skipping TOC update.")
        return

    content = multi_region_md.read_text()
    marker_start = "### Available runbooks\n"
    marker_end = "\nTo regenerate all runbooks:"
    if marker_start in content and marker_end in content:
        before = content[: content.index(marker_start) + len(marker_start)]
        after = content[content.index(marker_end):]
        new_content = before + "\n" + "\n".join(toc_lines) + "\n" + after
        multi_region_md.write_text(new_content)
        LOG.info("Updated TOC in %s", multi_region_md)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--output", default="docs/operations/runbooks/", help="Output directory for runbook Markdown files.")
    p.add_argument("--lookback-hours", type=int, default=168, help="Hours of trace history to analyse (default: 168 = 1 week).")
    p.add_argument("--otel-endpoint", default=os.getenv("OTEL_ENDPOINT", "http://localhost:3100"), help="Grafana Tempo / Jaeger HTTP endpoint.")
    p.add_argument("--bearer", default=os.getenv("OTEL_BEARER", ""), help="Bearer token for authenticated backends.")
    p.add_argument("--runbook", help="Generate only this runbook ID (e.g. RB-001). Omit to generate all.")
    p.add_argument("--update-toc", action="store_true", help="Refresh the runbook table in docs/operations/multi-region.md and exit.")
    p.add_argument("--dry-run", action="store_true", help="Print rendered runbooks to stdout; do not write files.")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    output_dir = Path(args.output)

    if args.update_toc:
        update_toc(output_dir)
        return

    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    specs = RUNBOOK_SPECS
    if args.runbook:
        specs = [s for s in specs if s.id == args.runbook]
        if not specs:
            LOG.error("Unknown runbook ID: %s", args.runbook)
            sys.exit(1)

    bearer = args.bearer or None

    for spec in specs:
        LOG.info("Generating %s: %s …", spec.id, spec.title)

        traces = fetch_traces(
            endpoint=args.otel_endpoint,
            service=spec.service_filter,
            operation=spec.operation_filter,
            lookback_hours=args.lookback_hours,
            bearer=bearer,
        )
        LOG.info("  Fetched %d traces", len(traces))

        md = render_runbook(spec, traces, args.lookback_hours)
        filename = f"{spec.id}-{spec.slug}.md"

        if args.dry_run:
            print(f"\n{'='*60}\n{filename}\n{'='*60}\n")
            print(md)
        else:
            outfile = output_dir / filename
            outfile.write_text(md)
            LOG.info("  Written → %s", outfile)

    if not args.dry_run:
        update_toc(output_dir)
        LOG.info("Done. Runbooks written to %s", output_dir)


if __name__ == "__main__":
    main()
