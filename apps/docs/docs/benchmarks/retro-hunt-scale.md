---
title: Retro-hunt at scale
sidebar_label: Retro-hunt scale
---

# Retro-hunt at scale, and where it stops

Wave-2 Phase 5.5 asked for a retro-hunt measured over at least one million
indicators on recorded hardware, publishing sweep time and lake cost — *"or
the point where it degrades"*.

It degrades, the point is measurable, and the point is the result.

## What was measured

A retro-hunt is driven **one indicator at a time**: a feed publishes a new
indicator, `retro_hunt_consumer` picks it up, and `sweep` runs one aggregate
over the tenant's history. A million indicators is therefore a million
sweeps, and the figure that decides feasibility is per-sweep cost against
lake size.

`scripts/perf/retro_hunt_scale.py` drives the **real** generator —
`app.services.retro_hunt.sql.build_sweep_sql`, which is split out from the
sweep's I/O precisely so a measurement can load it without re-implementing
it. Lake cost is read from ClickHouse's own `system.query_log`, not
estimated.

### Hardware and software

| | |
|---|---|
| CPU | Apple M5 Max (18 cores) |
| Memory | 128 GiB |
| OS | macOS 26.5.1 (arm64) |
| ClickHouse | 24.8.14.39, single node in Docker |
| Indicator type | `ip` (the commonest a feed publishes) |
| Lookback | 30 days |
| Sweeps per step | 40 |
| Date | 2026-11-01 |

## Results

| Lake rows | Sweep median | Sweep p95 | Rows read | Bytes read | % of the 8 GiB budget |
|---:|---:|---:|---:|---:|---:|
| 100,000 | 6.97 ms | 7.64 ms | 100,000 | 9.24 MB | 0.11 % |
| 1,000,000 | 11.59 ms | 13.54 ms | 1,000,000 | 93.66 MB | 1.09 % |
| 5,000,000 | 38.74 ms | 46.27 ms | 5,000,000 | 469.17 MB | 5.46 % |
| 20,000,000 | 148.97 ms | 175.49 ms | 20,000,000 | 1,875.12 MB | 21.83 % |

**`read_rows` equals `lake_rows` at every step.** The sweep is a full scan.
That is the single most important number on this page, and it is what every
other figure here follows from.

Cost per row is stable at **93.8 bytes**, and per-sweep time is **7.45 ms
per million rows** once the fixed overhead is past.

## The degradation point

`sweep.py` declares its own ceiling — `MAX_BYTES_PER_SWEEP = 8 GiB`, passed
to ClickHouse as `max_bytes_to_read` so the server enforces it rather than
the client hoping. At 93.8 bytes per row scanned:

> **One sweep exceeds its declared budget at approximately 91.6 million rows
> of tenant history**, and is refused by the server from there on.

That is a real ceiling, not a slowdown. Past it the sweep reports *"could
not complete"* rather than returning fewer sightings — which is the correct
behaviour and the reason the limit is expressed in bytes rather than in a
client-side timeout.

There is a second, earlier ceiling: `SWEEP_TIMEOUT_SECONDS = 20.0`. On this
hardware a 20-second sweep is roughly 2.7 billion rows, so the byte budget
binds first by a wide margin. On slower storage the order could reverse, and
a deployment seeing timeouts before byte refusals is reading its own disk
rather than this table.

## A million indicators, extrapolated — and labelled as such

A literal million sequential sweeps were **not** run; that would take as
long as the answer. The rows below are the measured per-sweep median
multiplied out, and the distinction matters:

| Lake rows | 1M indicators, sequential | Lake bytes read |
|---:|---:|---:|
| 1,000,000 | 3.22 h | 93.7 TB |
| 5,000,000 | 10.76 h | 469 TB |
| 20,000,000 | 41.38 h | 1.88 PB |

### What that says

**A million indicators cannot be swept one at a time against a working
lake.** At 20 million rows — a small deployment — a single feed refresh of
that size would take over a day and read nearly two petabytes. The design
that would fix it is a batched sweep: one scan testing many needles, turning
*N* full scans into one. That is not built, and this page does not claim it
is.

Three honest limits on the figures above:

- **Single node, local disk, nothing else running.** A production ClickHouse
  under concurrent ingest will be slower; this is a floor, not a forecast.
- **One indicator type.** `ip` touches three columns including an array
  membership test. A `sha256` sweep touches fewer and should cost less; it
  was not measured.
- **A synthetic corpus.** 50,000 distinct hostnames and 5,000 users over 30
  days, generated in the engine. Real telemetry compresses differently, and
  the bytes-per-row figure is the one most likely to move.

## Reproducing it

```bash
docker run -d --name ch -p 8123:8123 \
  -e CLICKHOUSE_USER=aisoc -e CLICKHOUSE_PASSWORD=secret -e CLICKHOUSE_DB=aisoc \
  clickhouse/clickhouse-server:24.8-alpine
docker exec ch clickhouse-client --user aisoc --password secret \
  --multiquery --queries-file /path/to/services/api/clickhouse/001_init.sql

python3 scripts/perf/retro_hunt_scale.py \
  --dsn http://aisoc:secret@127.0.0.1:8123 \
  --steps 100000 1000000 5000000 20000000 \
  --sweeps 40 --out docs/perf/retro-hunt-scale.json
```

The raw output, including per-step memory and the extrapolation inputs, is
committed at `docs/perf/retro-hunt-scale.json` with the hardware and the
ClickHouse version inside it.
