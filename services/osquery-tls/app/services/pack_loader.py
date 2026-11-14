"""Pack loader: reads AiSOC osquery pack YAML files from disk.

Packs live under ``<repo_root>/packs/`` in YAML format documented at
``packs/README.md``.  This module handles discovery, parsing, validation,
and in-memory caching of all pack definitions.

The loader is imported by:
- ``pack_resolver`` (to build per-tenant config responses)
- The pack catalog API (to serve ``GET /v1/packs``)
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Locate the packs directory
# ---------------------------------------------------------------------------
# Walk up from this file until we find the repo root (indicated by the
# presence of a ``packs/`` directory).  This avoids hard-coding absolute paths
# and works whether the service is run from source or inside a container with
# the repo mounted.


def _find_packs_dir() -> Path:
    """Return the absolute path to the ``packs/`` directory."""
    env_override = os.environ.get("AISOC_PACKS_DIR")
    if env_override:
        p = Path(env_override)
        if p.is_dir():
            return p

    # Walk up from the module location
    candidate = Path(__file__).resolve()
    for _ in range(10):  # Safety limit
        candidate = candidate.parent
        packs = candidate / "packs"
        if packs.is_dir():
            return packs

    # Fallback: relative to cwd
    return Path("packs")


PACKS_DIR: Path = _find_packs_dir()


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class PackQuery:
    name: str
    sql: str
    interval: int
    severity: str = "info"
    description: str = ""
    mitre: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class OsqueryPack:
    id: str
    name: str
    version: str
    platforms: list[str]
    description: str
    queries: list[PackQuery] = field(default_factory=list)
    discovery: list[str] = field(default_factory=list)
    file_paths: dict[str, list[str]] = field(default_factory=dict)

    # --- Rendering helpers ---------------------------------------------------

    def to_osquery_json(self) -> dict[str, Any]:
        """Compile to canonical osquery pack JSON format."""
        queries: dict[str, Any] = {}
        for q in self.queries:
            queries[q.name] = {
                "query": q.sql.strip(),
                "interval": q.interval,
                "description": q.description,
            }
            if q.mitre:
                queries[q.name]["tags"] = q.mitre

        payload: dict[str, Any] = {"queries": queries}
        if self.discovery:
            payload["discovery"] = self.discovery
        return payload

    def to_osctrl_format(self) -> dict[str, Any]:
        """Render as osctrl schedule block (subset of full osquery JSON).

        osctrl accepts the standard osquery pack JSON format via its
        ``/conf/:env`` endpoint.  We add an outer wrapper with platform and
        version metadata for documentation purposes.
        """
        return {
            "pack_id": self.id,
            "pack_version": self.version,
            "platforms": self.platforms,
            **self.to_osquery_json(),
        }

    def to_fleetdm_format(self) -> dict[str, Any]:
        """Render as FleetDM pack YAML structure (converted to dict).

        FleetDM uses a slightly different pack format where queries have
        additional fields like ``platform``, ``min_osquery_version``, and
        ``automations_enabled``.
        """
        queries: dict[str, Any] = {}
        for q in self.queries:
            queries[q.name] = {
                "query": q.sql.strip(),
                "interval": q.interval,
                "description": q.description,
                "platform": ",".join(self.platforms),
                "automations_enabled": True,
                "tags": q.mitre if q.mitre else [],
            }

        return {
            "name": self.id,
            "description": self.description.strip(),
            "queries": queries,
        }

    def to_schedule_dict(self) -> dict[str, Any]:
        """Return queries as a flat schedule dict for osquery TLS config.

        Used by pack_resolver to build the ``schedule`` section of the
        config response.  Query names are prefixed with the pack id to
        avoid collisions when merging multiple packs.
        """
        schedule: dict[str, Any] = {}
        for q in self.queries:
            key = f"{self.id}__{q.name}"
            schedule[key] = {
                "query": q.sql.strip(),
                "interval": q.interval,
                "description": q.description,
            }
        return schedule


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _parse_pack(path: Path) -> OsqueryPack:
    """Parse a single pack YAML file into an OsqueryPack instance."""
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    queries: list[PackQuery] = []
    for qname, qdata in (raw.get("queries") or {}).items():
        queries.append(
            PackQuery(
                name=qname,
                sql=qdata["sql"],
                interval=int(qdata.get("interval", 300)),
                severity=qdata.get("severity", "info"),
                description=qdata.get("description", ""),
                mitre=qdata.get("mitre") or [],
                references=qdata.get("references") or [],
            )
        )

    return OsqueryPack(
        id=raw["id"],
        name=raw["name"],
        version=raw.get("version", "1.0.0"),
        platforms=raw.get("platforms") or ["linux", "darwin", "windows"],
        description=raw.get("description", ""),
        queries=queries,
        discovery=raw.get("discovery") or [],
        file_paths=raw.get("file_paths") or {},
    )


# ---------------------------------------------------------------------------
# Registry (in-memory cache with TTL)
# ---------------------------------------------------------------------------

_CACHE_TTL: int = int(os.environ.get("AISOC_PACKS_CACHE_TTL", "300"))  # seconds
# Use a mutable container so all mutations are visible to CodeQL static analysis
_cache_state: dict[str, object] = {"packs": {}, "ts": 0.0}


def _load_all() -> dict[str, OsqueryPack]:
    """Load (or return cached) all packs from PACKS_DIR."""
    now = time.monotonic()
    cached_packs = _cache_state["packs"]
    cached_ts = _cache_state["ts"]
    if cached_packs and (now - cached_ts) < _CACHE_TTL:  # type: ignore[operator]
        return cached_packs  # type: ignore[return-value]

    packs: dict[str, OsqueryPack] = {}
    if PACKS_DIR.is_dir():
        for yaml_file in sorted(PACKS_DIR.glob("*.yaml")):
            if yaml_file.name == "README.md":
                continue
            try:
                pack = _parse_pack(yaml_file)
                packs[pack.id] = pack
            except Exception as exc:
                # Log parsing errors but continue loading other packs.
                # In production structlog would be used; a plain print avoids
                # a circular import with the service's log config here.
                print(f"[pack_loader] Failed to parse {yaml_file}: {exc}")

    _cache_state["packs"] = packs
    _cache_state["ts"] = now
    return packs


def get_all_packs() -> list[OsqueryPack]:
    """Return all loaded packs."""
    return list(_load_all().values())


def get_pack(pack_id: str) -> OsqueryPack | None:
    """Return a single pack by id, or None if not found."""
    return _load_all().get(pack_id)


def invalidate_cache() -> None:
    """Force a reload on the next call (useful for tests)."""
    _cache_state["packs"] = {}
    _cache_state["ts"] = 0.0
