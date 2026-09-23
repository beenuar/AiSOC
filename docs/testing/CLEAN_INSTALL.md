# Clean-machine install test

The acceptance question is narrow: **following only `README.md`, with no
tribal knowledge, does a fresh clone reach a running system that processes a
real event?**

This records an actual run, including what went wrong, because an install
document that only describes the happy path is the reason people say software
is hard to install.

---

## What was run

Date: 2026-09-23 · macOS 15 on Apple Silicon (arm64) · Docker 29.5.2 ·
8 CPUs / 16 GB allocated to Docker.

Only commands printed in `README.md` were used.

```bash
git clone https://github.com/beenuar/AiSOC && cd AiSOC
make up
make smoke
```

## Result

| Stage | Result |
|---|---|
| Clone | pass |
| `make up` — CORE profile, 10 services | pass |
| Postgres accepting connections, 92 tables | pass |
| Kafka broker answering admin requests | pass |
| `api`, `ingest-worker`, `fusion` healthy | pass |
| `make smoke` — 8 of 8 stages | pass |
| Alert visible via `GET /api/v1/alerts` | pass |
| `make doctor` — no failures | pass |

Observed `make smoke` output:

```
[PASS] ingest service is reachable
[PASS] api service is reachable
[PASS] raw telemetry accepted by ingest
[PASS] event traversed the spine and became an alert
[PASS] alert is retrievable by id from the API
[PASS] severity survived normalization
[PASS] source attribution is not duplicated
[PASS] description is prose, not a serialized payload

PASS: 8/8 stages
```

---

## What went wrong on the way, and what changed because of it

Every one of these was hit during the real run. They are listed because each
produced a fix, not to pad the document.

### 1. Port 5432 was already taken

Another project held Postgres. Compose failed with
`Bind for 0.0.0.0:5432 failed: port is already allocated`, which does not say
which service needs it or what to do.

**Changed:** `make doctor` checks all six host ports first, distinguishes "in
use by aisoc" from "held by something else", and prints the `lsof` command
that identifies the holder.

### 2. Docker ran out of disk, and Kafka reported healthy anyway

The Docker VM filled up. Kafka failed to write `meta.properties`
(`java.io.IOException: No space left on device`), then refused every request
— while its compose healthcheck continued to report **healthy**. Fusion
logged `Unable to update metadata` and ingest returned
`failed to publish events`. Nothing pointed at disk.

This is the most expensive failure in the list: three symptoms, none naming
the cause.

**Changed:**
- `make doctor` checks Docker's free disk **before anything else** and fails
  below 5 GB with the exact reason.
- The doctor probes Kafka with a real admin call (`kafka-topics --list`)
  rather than trusting the container healthcheck.
- The troubleshooting table in `README.md` names this symptom explicitly.
- The CI workflow reclaims runner disk before starting the stack.

Recovery is `docker system prune -af`, then `make clean && make up` — the
Kafka volume has to go, because the log dir is corrupted.

### 3. The first event failed to publish

Before the disk issue was resolved, the topic did not exist and could not be
created. The error — `Unknown Topic Or Partition` — reads like a
configuration problem and is not one.

**Changed:** `make smoke` prints the two commands that distinguish the cases
when this stage fails.

### 4. Alerts were labelled `"crowdstrike crowdstrike"`

Visible immediately in the first successful alert. Vendor and product were
joined without dedup, in two separate copies of the same helper — fixing one
left the other in place.

**Changed:** one shared implementation, and `make smoke` asserts the source
label contains no repeated word.

### 5. The alert description was a serialized payload

The console would have shown
`{"command_line": "powershell.exe -nop -w hidden -enc ...` where a sentence
belongs, discarding the vendor's own description.

**Changed:** the promoter prefers human text and returns empty rather than a
dict dump. `make smoke` asserts the description does not start with `{`.

---

## What a clean run does *not* include

Stated so the pass above is not read as broader than it is:

- **The `full` profile was not exercised** in this run. ClickHouse, Neo4j,
  Qdrant and the connectors service start under `make up-full`; that path was
  not part of the clean-machine test.
- **No live LLM.** No provider key was available, so agents ran their
  deterministic offline path. AI triage quality was not measured.
- **`install.sh` was not run end to end** on a machine without prerequisites.
  The `make up` path was. `install.sh` now runs the same golden pipeline
  before printing success, so the two agree.

---

## Re-running this test

```bash
make clean      # delete all volumes, so this is genuinely a fresh start
make up
make doctor
make smoke
```

`make smoke` exits non-zero if any stage fails, and names the boundary that
broke. CI runs the same sequence on every pull request
([`golden-pipeline.yml`](../../.github/workflows/golden-pipeline.yml)),
including a step that stops `fusion` and asserts the test then **fails** —
because a gate nobody has seen fail is a gate nobody knows works.
