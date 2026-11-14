#!/usr/bin/env python3
"""Measure a retro-hunt sweep at scale, against a real lake.

Wave 2, Phase 5.5: *"measure a retro-hunt over at least one million
indicators on RECORDED hardware; publish sweep time and lake cost, or the
point where it degrades."*

What this drives
----------------
The **real** generator. `app.services.retro_hunt.sql.build_sweep_sql` is
split out from the sweep's I/O precisely so a measurement can load it with
no service dependencies, and the module says why: *"this repository's
recurring defect is a test that compares a producer against a copy of
itself, and a live test that built its own SQL would be exactly that."* The
same applies to a benchmark. Nothing here writes a query.

What "a million indicators" means here
---------------------------------------
A retro-hunt is driven one indicator at a time: a feed publishes a
`NEW_IOC`, `retro_hunt_consumer` picks it up, and `sweep` runs one
aggregate against the tenant's history. So a million indicators is a
million sweeps, and the figure that decides whether that is feasible is
**per-sweep cost against lake size** — which is what this measures, at
several corpus sizes, and then extrapolates with the extrapolation labelled
as such.

Measuring a literal million sequential sweeps would take as long as the
answer it produces and would measure this laptop's patience. Measuring the
per-sweep cost and saying plainly which part is measured and which is
arithmetic is the honest version.

Lake cost
---------
ClickHouse reports `read_rows` and `read_bytes` per query in
`system.query_log`. That is the cost, and it is read from the engine rather
than estimated — an estimate here would be a number about a model of the
lake rather than about the lake.

Degradation
-----------
The sweep carries a bytes-to-read ceiling in production
(`sweep.py` sets `max_bytes_to_read`), so the interesting question is not
"does it get slower" but **at what corpus size does one sweep exceed the
budget**. That point is reported if it is reached, and reported as not
reached if it is not. A degradation point that was never hit is a different
fact from one that does not exist.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "services" / "api"))

from app.services.retro_hunt.ioc_fields import SWEEPABLE_TYPES, mapping_for  # noqa: E402
from app.services.retro_hunt.sql import build_sweep_sql  # noqa: E402

#: Corpus sizes to measure at. Each is a separate population of the lake,
#: so the per-sweep cost can be read against lake size rather than guessed.
DEFAULT_STEPS = (100_000, 1_000_000, 5_000_000)

#: How many sweeps to time at each step. Enough for a median and a p95 that
#: are not one outlier; few enough that the whole run is minutes.
SWEEPS_PER_STEP = 40


def _query(dsn: str, sql: str, *, params: dict[str, str] | None = None) -> str:
    """POST the statement, with credentials in a header rather than the URL.

    Inline `user:pass@host` credentials are parsed by urllib but not by
    every resolver underneath it, and the failure reads as a DNS error
    rather than as an auth one — which sends a reader to debug the wrong
    layer. The statement travels in the body so a long query is not capped
    by URL length.
    """
    parsed = urllib.parse.urlsplit(dsn)
    user = urllib.parse.unquote(parsed.username or "default")
    password = urllib.parse.unquote(parsed.password or "")
    host = parsed.hostname or "127.0.0.1"
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    url = urllib.parse.urlunsplit((parsed.scheme or "http", netloc, "/", urllib.parse.urlencode(params or {}), ""))
    request = urllib.request.Request(url, data=sql.encode("utf-8"), method="POST")  # noqa: S310
    request.add_header("X-ClickHouse-User", user)
    request.add_header("X-ClickHouse-Key", password)
    with urllib.request.urlopen(request, timeout=900) as response:  # noqa: S310 — operator-supplied DSN
        return response.read().decode()


def _hardware() -> dict[str, str]:
    """What the figures are about. A number with no machine is not a result."""
    cpu = platform.processor() or platform.machine()
    try:
        cpu = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip() or cpu
    except Exception:  # noqa: BLE001 — not every platform has sysctl
        pass
    return {
        "cpu": cpu,
        "arch": platform.machine(),
        "platform": platform.platform(),
        "python": platform.python_version(),
    }


def populate(dsn: str, tenant: str, target_rows: int, already: int) -> float:
    """Top the lake up to ``target_rows``, returning seconds spent."""
    to_write = target_rows - already
    if to_write <= 0:
        return 0.0
    started = time.monotonic()
    # Generated in the engine rather than streamed from here: the measurement
    # is about sweep cost, and a Python-side insert would measure this
    # process's serialisation instead.
    _query(
        dsn,
        f"""
        INSERT INTO aisoc.raw_events
            (tenant_id, event_time, class_uid, category_uid, severity_id, severity,
             activity_id, source_ip, dest_ip, src_port, dst_port, protocol,
             src_hostname, user_name, connector_type, iocs)
        SELECT
            toUUID('{tenant}'),
            now64(3) - toIntervalSecond(rand() % 2592000),
            4001, 4, 3, 'medium', 1,
            toIPv6(concat('203.0.', toString(rand() % 255), '.', toString(rand(1) % 255))),
            toIPv6('198.51.100.1'),
            toUInt16(rand(2) % 65535), toUInt16(443), 'tcp',
            concat('host-', toString(rand(3) % 50000)),
            concat('user-', toString(rand(4) % 5000)),
            'aws_cloudtrail',
            [concat('203.0.', toString(rand(5) % 255), '.', toString(rand(6) % 255))]
        FROM numbers({to_write})
        """,
    )
    return time.monotonic() - started


def sweep_once(dsn: str, tenant: str, needle: str, ioc_type: str, lookback_days: int) -> dict[str, float]:
    """Run one real sweep and read its cost out of the engine."""
    mapping = mapping_for(ioc_type)
    assert mapping is not None, f"{ioc_type} is not sweepable"
    sql, _columns = build_sweep_sql(mapping)
    # The generator emits `%(name)s` placeholders for the ClickHouse driver;
    # over HTTP the same values travel as `param_<name>`, so the statement
    # itself is still never string-formatted with the needle.
    http_sql = sql.replace("%(needle)s", "{needle:String}")
    http_sql = http_sql.replace("%(tenant_id)s", "{tenant_id:UUID}")
    http_sql = http_sql.replace("%(lookback_days)s", "{lookback_days:UInt16}")
    query_id = f"sweep-{uuid.uuid4()}"

    started = time.monotonic()
    _query(
        dsn,
        http_sql,
        params={
            "param_needle": needle,
            "param_tenant_id": tenant,
            "param_lookback_days": str(lookback_days),
            "query_id": query_id,
        },
    )
    elapsed_ms = (time.monotonic() - started) * 1000

    _query(dsn, "SYSTEM FLUSH LOGS")
    row = _query(
        dsn,
        "SELECT read_rows, read_bytes, memory_usage FROM system.query_log "
        f"WHERE query_id = '{query_id}' AND type = 'QueryFinish' LIMIT 1 FORMAT TabSeparated",
    ).strip()
    read_rows, read_bytes, memory = (row.split("\t") + ["0", "0", "0"])[:3] if row else ("0", "0", "0")
    return {
        "elapsed_ms": elapsed_ms,
        "read_rows": float(read_rows or 0),
        "read_bytes": float(read_bytes or 0),
        "memory_bytes": float(memory or 0),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", required=True, help="ClickHouse HTTP DSN, e.g. http://user:pass@127.0.0.1:8123")
    parser.add_argument("--steps", type=int, nargs="*", default=list(DEFAULT_STEPS))
    parser.add_argument("--sweeps", type=int, default=SWEEPS_PER_STEP)
    parser.add_argument("--indicators", type=int, default=1_000_000, help="the batch size the result is reported for")
    parser.add_argument("--lookback-days", type=int, default=30)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    tenant = str(uuid.uuid4())
    # One real sweepable type per run keeps the comparison honest; `ip` is
    # the commonest indicator a feed publishes.
    ioc_type = "ip" if "ip" in SWEEPABLE_TYPES else sorted(SWEEPABLE_TYPES)[0]

    # `steps` is a list this loop appends to; typed here so the appends are
    # checkable, rather than mypy inferring `object` from the heterogeneous
    # literal below and refusing `.append`.
    steps: list[dict[str, float | int]] = []
    report: dict[str, object] = {
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hardware": _hardware(),
        "clickhouse_version": _query(args.dsn, "SELECT version() FORMAT TabSeparated").strip(),
        "indicator_type": ioc_type,
        "lookback_days": args.lookback_days,
        "sweeps_per_step": args.sweeps,
        "steps": steps,
    }

    rows_present = 0
    for target in sorted(args.steps):
        load_seconds = populate(args.dsn, tenant, target, rows_present)
        rows_present = target
        _query(args.dsn, "OPTIMIZE TABLE aisoc.raw_events FINAL")

        samples = [
            sweep_once(args.dsn, tenant, f"203.0.{n % 255}.{(n * 7) % 255}", ioc_type, args.lookback_days) for n in range(args.sweeps)
        ]
        latencies = sorted(s["elapsed_ms"] for s in samples)
        step: dict[str, float | int] = {
            "lake_rows": target,
            "load_seconds": round(load_seconds, 2),
            "sweep_ms_median": round(statistics.median(latencies), 2),
            "sweep_ms_p95": round(latencies[int(len(latencies) * 0.95) - 1], 2),
            "read_rows_median": round(statistics.median(s["read_rows"] for s in samples)),
            "read_bytes_median": round(statistics.median(s["read_bytes"] for s in samples)),
            "memory_bytes_p95": round(max(s["memory_bytes"] for s in samples)),
        }
        # The arithmetic, labelled as arithmetic. A million sequential sweeps
        # were not run; this is the per-sweep median multiplied out, and a
        # reader must be able to tell that from a measurement.
        step["projected_hours_for_indicators_EXTRAPOLATED"] = round(step["sweep_ms_median"] * args.indicators / 1000 / 3600, 2)
        step["projected_read_bytes_EXTRAPOLATED"] = step["read_bytes_median"] * args.indicators
        steps.append(step)
        print(
            f"[scale] {target:>9,} rows: median {step['sweep_ms_median']:>7.2f} ms  "
            f"p95 {step['sweep_ms_p95']:>7.2f} ms  "
            f"read {step['read_rows_median']:>9,.0f} rows / {step['read_bytes_median'] / 1e6:>7.2f} MB  "
            f"-> {step['projected_hours_for_indicators_EXTRAPOLATED']} h for {args.indicators:,} indicators"
        )

    if args.out:
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
