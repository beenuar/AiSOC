#!/usr/bin/env python3
"""End-to-end event-spine test against real containers (Phase 3.1).

Proves the product's central claim with zero mocks:

    raw vendor event
      → POST /v1/ingest/batch          (services/ingest, Go)
      → OCSF normalize                 (services/ingest)
      → Kafka `aisoc.raw_events`
      → promotion + dedup + correlate  (services/fusion)
      → Kafka `aisoc.alerts.fused`
      → WebSocket `alert.fused` frame  (services/realtime)
      → Postgres `alerts` row          (services/fusion AlertSink)
      → GET /api/v1/alerts             (services/api)

Also asserts duplicate suppression: re-submitting the same event must NOT
create a second alert row.

Run against a booted docker-compose stack (see .github/workflows/integration.yml):

    python3 scripts/integration/spine_test.py                # full spine test
    python3 scripts/integration/spine_test.py --post-event --title "chaos-1"
    python3 scripts/integration/spine_test.py --await-alert --title "chaos-1"

The --post-event / --await-alert modes are used by the chaos step (kill the
fusion consumer, produce, restart, assert recovery).

Dependencies: httpx, websockets (installed by the workflow).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import uuid

import httpx
import websockets

API = "http://localhost:8000"
INGEST = "http://localhost:8081"
FUSION = "http://localhost:8003"
REALTIME_HTTP = "http://localhost:8086"
REALTIME_WS = "ws://localhost:8086"
TENANT = "00000000-0000-0000-0000-000000000001"

HEALTH_BUDGET_S = 300
SPINE_BUDGET_S = 180
REPOST_INTERVAL_S = 20


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


async def wait_healthy(client: httpx.AsyncClient) -> None:
    """Block until every spine service answers its health probe."""
    probes = {
        "api": f"{API}/readyz",
        "ingest": f"{INGEST}/health",
        "fusion": f"{FUSION}/readyz",
        "realtime": f"{REALTIME_HTTP}/health",
    }
    deadline = time.monotonic() + HEALTH_BUDGET_S
    pending = dict(probes)
    while pending and time.monotonic() < deadline:
        for name, url in list(pending.items()):
            try:
                r = await client.get(url, timeout=5)
                if r.status_code == 200:
                    log(f"healthy: {name}")
                    del pending[name]
            except httpx.HTTPError:
                pass
        if pending:
            await asyncio.sleep(3)
    if pending:
        raise SystemExit(f"services never became healthy: {sorted(pending)}")


def event_payload(title: str) -> dict:
    """A CrowdStrike-shaped critical finding. `event_simpleName` maps to
    OCSF `activity_name`, which the fusion promoter uses as the alert title."""
    return {
        "connector_id": "spine-test",
        "connector_type": "crowdstrike_falcon",
        "source_format": "json",
        "events": [
            {
                "event_simpleName": title,
                "ComputerName": "SPINE-TEST-HOST",
                "UserName": "spine-test-user",
                "SHA256HashData": "f" * 64,
                "severity": "Critical",
                "technique_id": "T1003",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        ],
    }


async def post_event(client: httpx.AsyncClient, title: str) -> None:
    r = await client.post(
        f"{INGEST}/v1/ingest/batch",
        json=event_payload(title),
        headers={"X-Tenant-ID": TENANT},
        timeout=10,
    )
    r.raise_for_status()
    body = r.json()
    if body.get("accepted") != 1:
        raise SystemExit(f"ingest rejected the event: {body}")
    log(f"ingest accepted event title={title!r}")


async def count_alerts_titled(client: httpx.AsyncClient, title: str) -> int:
    r = await client.get(f"{API}/api/v1/alerts", params={"page_size": 200}, timeout=10)
    r.raise_for_status()
    items = r.json().get("items", [])
    return sum(1 for a in items if a.get("title") == title)


async def get_alert_titled(client: httpx.AsyncClient, title: str) -> dict | None:
    r = await client.get(f"{API}/api/v1/alerts", params={"page_size": 200}, timeout=10)
    r.raise_for_status()
    for a in r.json().get("items", []):
        if a.get("title") == title:
            return a
    return None


async def mint_ws_ticket(client: httpx.AsyncClient) -> str:
    r = await client.post(f"{API}/api/v1/realtime/ticket", timeout=10)
    r.raise_for_status()
    return r.json()["token"]


async def ws_listener(ticket: str, title: str, found: asyncio.Event) -> None:
    """Listen on the alerts channel until a fused frame carrying `title` arrives."""
    url = f"{REALTIME_WS}/ws/alerts?token={ticket}"
    async with websockets.connect(url, open_timeout=15) as ws:
        log("websocket connected")
        while not found.is_set():
            raw = await ws.recv()
            try:
                frame = json.loads(raw)
            except (TypeError, ValueError):
                continue
            if frame.get("type") != "alert.fused":
                continue
            payload = frame.get("payload") or {}
            alert = payload.get("alert") or {}
            if alert.get("title") == title:
                log("websocket frame received for spine event")
                found.set()


async def await_alert_row(client: httpx.AsyncClient, title: str, timeout_s: int, repost: bool) -> None:
    """Poll the API until the alert row exists. Optionally re-POST the event to
    ride out consumer-group assignment races (dedup keeps this idempotent).

    Transient HTTP errors are swallowed and retried rather than fatal: during
    the Postgres-outage chaos step the API and fusion are mid-reconnect, so a
    5xx blip must extend the poll window, not fail the whole test."""
    deadline = time.monotonic() + timeout_s
    last_post = time.monotonic()
    while time.monotonic() < deadline:
        try:
            if await count_alerts_titled(client, title) >= 1:
                log("alert row visible via GET /api/v1/alerts")
                return
            if repost and time.monotonic() - last_post > REPOST_INTERVAL_S:
                await post_event(client, title)
                last_post = time.monotonic()
        except httpx.HTTPError as exc:
            log(f"transient error while polling (will retry): {exc}")
        await asyncio.sleep(3)
    raise SystemExit(f"alert row for {title!r} never appeared within {timeout_s}s")


async def full_spine_test() -> None:
    title = f"SpineTest-{uuid.uuid4().hex[:12]}"
    async with httpx.AsyncClient() as client:
        await wait_healthy(client)

        # WS listener must be up before the event flows.
        ticket = await mint_ws_ticket(client)
        ws_found = asyncio.Event()
        ws_task = asyncio.create_task(ws_listener(ticket, title, ws_found))

        # Give the fusion + realtime consumer groups a moment to be assigned
        # partitions after boot; the repost loop below covers the rest.
        await asyncio.sleep(5)
        started = time.monotonic()
        await post_event(client, title)

        await await_alert_row(client, title, SPINE_BUDGET_S, repost=True)
        elapsed = time.monotonic() - started
        log(f"raw event → alert row in {elapsed:.1f}s")

        # WS frame: every fused alert (including dedup republish) is broadcast,
        # and the repost loop keeps producing until the row exists, so the
        # frame must arrive promptly if the realtime consumer is alive.
        try:
            await asyncio.wait_for(ws_found.wait(), timeout=60)
        except TimeoutError:
            raise SystemExit("no alert.fused WebSocket frame received within 60s") from None
        finally:
            ws_task.cancel()

        # Alert content assertions — the row must carry the fused pipeline's
        # fingerprint of the original telemetry, not a bare title.
        alert = await get_alert_titled(client, title)
        assert alert is not None
        for field, expected in [("severity", "critical"), ("status", "new")]:
            if alert.get(field) != expected:
                raise SystemExit(f"alert.{field}={alert.get(field)!r}, expected {expected!r}")
        techniques = alert.get("mitre_techniques") or []
        if "T1003" not in techniques:
            raise SystemExit(f"ATT&CK enrichment lost in transit: {techniques}")

        # Duplicate suppression: same event again must NOT create a second row.
        await post_event(client, title)
        await asyncio.sleep(15)
        n = await count_alerts_titled(client, title)
        if n != 1:
            raise SystemExit(f"duplicate suppression failed: {n} rows for {title!r}")
        log("duplicate suppression verified (1 row after re-submit)")

    log("SPINE TEST PASSED")


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--post-event", action="store_true", help="only POST an event")
    parser.add_argument("--await-alert", action="store_true", help="only await the alert row")
    parser.add_argument("--title", help="event title for --post-event / --await-alert")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()

    if args.post_event or args.await_alert:
        if not args.title:
            parser.error("--title is required with --post-event / --await-alert")
        async with httpx.AsyncClient() as client:
            if args.post_event:
                await post_event(client, args.title)
            if args.await_alert:
                await await_alert_row(client, args.title, args.timeout, repost=False)
        return

    await full_spine_test()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
