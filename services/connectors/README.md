# AiSOC Connectors Service

A Python/FastAPI service that polls external security sources on a schedule,
normalises raw events into OCSF, and forwards them to the ingest pipeline.

---

## Highlights

- **Click-and-connect** — add a source via the UI wizard; credentials are
  encrypted at rest with Fernet (`CredentialVault`) before they leave the
  API service.
- **Registry-based discovery** — drop a `BaseConnector` subclass into
  `app/connectors/` and register it in `__init__.py`. No other wiring needed.
- **APScheduler polling** — one in-process job per enabled connector
  instance, 5-min default cadence, configurable per-instance.
- **Federated search** — translate a single query into SPL, KQL, and ES|QL
  and fan out to connected SIEMs.
- **Five-tier severity** — every connector's `normalize()` emits one of
  `info | low | medium | high | critical`. A vendor ladder that publishes a
  distinct `critical` must map to `critical` and must **not** be collapsed
  into `high`; 50 of the connector modules rely on that tier today.

---

## Supported connectors

84 connectors are registered in `_CONNECTOR_CLASSES`
(`app/connectors/__init__.py`), which is the only source of truth. The count
and its per-category breakdown are generated into
[`apps/web/src/data/connector-count.json`](../../apps/web/src/data/connector-count.json)
by `scripts/generate_connector_count.py`, and `--check` gates it in CI, so a
hand-written table here would go stale the day the next connector lands.

Per-connector setup walkthroughs live under
[`apps/docs/docs/connectors/`](../../apps/docs/docs/connectors/) and are
indexed in the docs sidebar.

---

## Quick start

```bash
# From the repo root
cp .env.example .env          # set AISOC_CREDENTIAL_KEY, DATABASE_URL, etc.
pnpm docker:dev               # bring up Postgres, Redis, Kafka, etc.

# Run the service
cd services/connectors
python -m uvicorn app.main:app --reload --port 8003
```

Disable the polling scheduler in tests:

```bash
AISOC_CONNECTORS_DISABLE_SCHEDULER=1 pytest
```

---

## Writing a new connector

1. Create `app/connectors/<name>.py` and subclass `BaseConnector`.
2. Implement `schema()`, `test_connection()`, `poll()`, and `normalize()`.
3. Add your class to `_CONNECTOR_CLASSES` in `app/connectors/__init__.py`.
4. Add a marketplace manifest at `plugins/<connector-id>/plugin.yaml`.
5. Add a docs walkthrough at `apps/docs/docs/connectors/<connector-id>.md`.
6. Run `pnpm marketplace:sync` and `pytest`.

See `CONTRIBUTING.md` in the repo root for the full checklist.

---

## Tests

```bash
cd services/connectors
python -m pytest tests/ -v
```

Current suite covers schema contracts, polling, normalisation,
federated query translation, and credential decryption.
