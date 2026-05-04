"""demo_seed — Reset and warm up the hosted demo at demo.aisoc.dev.

This is the canonical entrypoint for the hosted-demo refresh job. It runs
inside the api image (so it gets DATABASE_URL via Fly Postgres attach,
REDIS_URL via Upstash attach, and access to the rest of the API package),
and is invoked one of three ways:

* **Post-deploy** — `infra/fly/fly-demo-deploy.sh` runs it via
  `flyctl ssh console -a aisoc-demo-api -C "python -m app.scripts.demo_seed
  --reset --kickoff-investigation"` once the deploy completes, so visitors
  hitting `demo.aisoc.dev` immediately see a hot investigation.
* **Daily cron** — A Fly scheduled machine on the api app re-runs this
  every 24h at 00:00 UTC to scrub demo state and re-seed.
* **Local recovery** — Self-hosters can run
  `python scripts/demo_seed.py --reset` from the repo root if the demo
  data gets dirty during local development. (See ``scripts/demo_seed.py``
  shim, which just re-execs this module.)

Why three responsibilities in one entrypoint?
1. Drop demo-tenant data so each visitor sees the same canonical INC-001.
2. Re-seed canonical demo data via the existing ``seed_demo`` module —
   same data self-hosters get with ``pnpm seed:demo``.
3. Pre-warm an investigation so the deeplink ``/cases/INC-001?tab=ledger``
   already has agent events streaming when the browser arrives. This is
   the keystone of the sub-60s time-to-first-investigation target.

Idempotent. Safe to re-run. ``--dry-run`` prints actions without touching
any state.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from typing import Any

import httpx

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] demo-seed: %(message)s",
)
log = logging.getLogger("demo-seed")


# ── Demo configuration ───────────────────────────────────────────────────────
# On Fly the seed runs *inside* the api container, so CORE_API_URL points to
# localhost. The agents live in a sibling app reachable via Fly's internal
# 6PN DNS. Env vars override these for local docker-compose use.
CORE_API_URL = os.getenv("CORE_API_URL", "http://localhost:8000")
AGENTS_API_URL = os.getenv("AGENTS_API_URL", "http://aisoc-demo-agents.internal:8084")
DEMO_TENANT = os.getenv("AISOC_DEMO_TENANT", "demo")
DEMO_CASE_ID = os.getenv("AISOC_DEMO_CASE_ID", "INC-001")
HTTP_TIMEOUT = float(os.getenv("AISOC_DEMO_HTTP_TIMEOUT", "30"))


async def _wait_for_api(client: httpx.AsyncClient, url: str, timeout: int = 60) -> None:
    """Poll ``/health`` until the API answers 200 or the timeout elapses.

    Fly machines warm up while we run; without this the seed races api/agents
    finishing their first health check.
    """
    deadline = asyncio.get_event_loop().time() + timeout
    last_err: Exception | None = None
    while asyncio.get_event_loop().time() < deadline:
        try:
            r = await client.get(f"{url}/health")
            if r.status_code == 200:
                log.info("api healthy: %s", url)
                return
            last_err = RuntimeError(f"unexpected status {r.status_code}")
        except httpx.HTTPError as exc:
            last_err = exc
        await asyncio.sleep(2)
    raise RuntimeError(f"api never became healthy within {timeout}s ({url}): {last_err}")


def _run_local_seeder() -> None:
    """Invoke the existing ``seed_demo`` module in-process.

    The seeder writes to whatever Postgres ``DATABASE_URL`` points at — Fly
    managed Postgres on the demo, the docker-compose ``postgres`` service
    locally. Idempotent: drops + recreates demo-tenant data.
    """
    log.info("running canonical seed_demo (tenant=%s)…", DEMO_TENANT)
    try:
        from app.scripts.seed_demo import main as seed_main
    except Exception as exc:
        # If the in-process import fails (rare, but seed_demo imports a lot
        # of optional deps), fall back to a subprocess so we still re-seed
        # rather than silently leaving the demo stale.
        log.warning(
            "could not import in-process seeder (%s); falling back to subprocess",
            exc,
        )
        import subprocess

        subprocess.run(
            [sys.executable, "-m", "app.scripts.seed_demo"],
            check=True,
            env={**os.environ, "AISOC_DEMO_TENANT": DEMO_TENANT},
        )
        return

    if asyncio.iscoroutinefunction(seed_main):
        asyncio.run(seed_main())
    else:
        seed_main()


async def _kickoff_investigation(client: httpx.AsyncClient) -> str | None:
    """Start an agent run against ``INC-001`` so the demo lands hot.

    Returns the run_id on success, or None if the agent declined (e.g.,
    no model key + deterministic mode disabled). We never fail the deploy
    on a missed kickoff — the demo still works, the visitor just sees a
    cold case until they click "Investigate".
    """
    payload: dict[str, Any] = {
        "case_id": DEMO_CASE_ID,
        "mode": "deterministic",
        "tenant_id": DEMO_TENANT,
        "metadata": {"source": "demo_seed", "deeplink": True},
    }
    log.info("kicking off investigation against %s via %s…", DEMO_CASE_ID, AGENTS_API_URL)
    try:
        r = await client.post(f"{AGENTS_API_URL}/investigate", json=payload)
    except httpx.HTTPError as exc:
        log.warning("kickoff request failed: %s", exc)
        return None

    if r.status_code >= 400:
        log.warning("kickoff returned %s: %s", r.status_code, r.text[:200])
        return None

    try:
        body = r.json() if r.content else {}
    except ValueError:
        log.warning("kickoff response was not JSON: %s", r.text[:200])
        return None
    run_id = body.get("run_id") or body.get("id")
    log.info("investigation kicked off: run_id=%s", run_id)
    return run_id


async def main_async(args: argparse.Namespace) -> int:
    if args.dry_run:
        log.info(
            "DRY-RUN — would seed tenant=%s, kickoff=%s, core=%s, agents=%s",
            DEMO_TENANT,
            args.kickoff_investigation,
            CORE_API_URL,
            AGENTS_API_URL,
        )
        return 0

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        if args.wait_for_api:
            await _wait_for_api(client, CORE_API_URL, timeout=args.wait_timeout)
            # Agents health is best-effort: if it never comes up we still
            # seed Postgres so the visitor at least sees a populated UI.
            try:
                await _wait_for_api(client, AGENTS_API_URL, timeout=args.wait_timeout)
            except RuntimeError as exc:
                log.warning("agents never healthy (%s); continuing without kickoff", exc)
                args.kickoff_investigation = False

        # Reseed runs sync (uses sqlalchemy session, not httpx).
        _run_local_seeder()

        if args.kickoff_investigation:
            run_id = await _kickoff_investigation(client)
            if run_id is None:
                log.warning(
                    "could not kickoff investigation — demo will land on a cold case. "
                    "Set OPENAI_API_KEY or ensure deterministic mode is enabled on agents."
                )

    log.info("demo reset complete.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Reset and warm up the hosted AiSOC demo.")
    p.add_argument(
        "--reset",
        action="store_true",
        help="Drop and re-seed the demo tenant (default for cron use).",
    )
    p.add_argument(
        "--rotate-tenant",
        action="store_true",
        help="Rotate canonical data without dropping (less destructive).",
    )
    p.add_argument(
        "--kickoff-investigation",
        action="store_true",
        help="Start an agent run against INC-001 so the deeplink lands hot.",
    )
    p.add_argument(
        "--wait-for-api",
        action="store_true",
        default=True,
        help="Poll /health on api+agents before seeding.",
    )
    p.add_argument(
        "--wait-timeout",
        type=int,
        default=int(os.getenv("AISOC_DEMO_WAIT_TIMEOUT", "120")),
        help="Seconds to wait for api+agents health before giving up.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print actions without performing them.",
    )

    args = p.parse_args()
    if not (args.reset or args.rotate_tenant or args.kickoff_investigation):
        p.error("specify at least one of --reset / --rotate-tenant / --kickoff-investigation")

    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
