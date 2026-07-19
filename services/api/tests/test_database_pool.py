"""Pin the SQLAlchemy pool settings that keep Fly Postgres usable.

Without ``pool_pre_ping`` the pool hands out sockets the managed Postgres
already closed (autostop / idle teardown). The next query then raises
``asyncpg.exceptions.ConnectionDoesNotExistError``, which is what was
500ing every demo endpoint on tryaisoc.com while ``/health`` still looked
fine. These tests are import-free (parse the source) so they run in the
same lightweight CI job as the schema-drift guards — no full API dep set
required.
"""

from __future__ import annotations

import re
from pathlib import Path

_API_ROOT = Path(__file__).resolve().parents[1]
_DATABASE_PY = _API_ROOT / "app" / "db" / "database.py"
_CONFIG_PY = _API_ROOT / "app" / "core" / "config.py"
_MAIN_PY = _API_ROOT / "app" / "main.py"


def test_engine_enables_pool_pre_ping():
    src = _DATABASE_PY.read_text(encoding="utf-8")
    assert "pool_pre_ping=True" in src, (
        "create_async_engine must set pool_pre_ping=True — without it Fly "
        "Postgres autostop produces ConnectionDoesNotExistError 500s on every "
        "demo endpoint"
    )


def test_engine_recycles_pooled_connections():
    src = _DATABASE_PY.read_text(encoding="utf-8")
    assert "pool_recycle=" in src, "create_async_engine must set pool_recycle"
    assert "DATABASE_POOL_RECYCLE_SECONDS" in src


def test_pool_recycle_setting_defaults_to_five_minutes():
    src = _CONFIG_PY.read_text(encoding="utf-8")
    match = re.search(
        r"DATABASE_POOL_RECYCLE_SECONDS:\s*int\s*=\s*(\d+)",
        src,
    )
    assert match, "DATABASE_POOL_RECYCLE_SECONDS must be declared on Settings"
    assert int(match.group(1)) == 300


def test_demo_bootstrap_disposes_pool_on_connection_errors():
    """The self-heal loop must invalidate the pool after a disconnect.

    Otherwise every retry reuses the same dead socket and the hosted demo
    stays 500ing for the full ~30 min budget (what /health.demo_bootstrap
    showed on 2026-07-19: 22 attempts, all ConnectionDoesNotExistError).
    """
    src = _MAIN_PY.read_text(encoding="utf-8")
    assert "async def _invalidate_stale_db_pool" in src
    assert "await engine.dispose()" in src
    # Every failure path in the bootstrap must call the invalidator.
    for stage in ("probe:", "create_all:", "migrate:", "seed:"):
        assert stage in src, f"bootstrap must tag failures as {stage!r}"
    assert src.count("await _invalidate_stale_db_pool(") >= 3
