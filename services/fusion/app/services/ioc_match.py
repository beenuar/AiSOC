"""Match a fused alert's indicators against the tenant's own IOC store.

Parity plan 3.1: "Match the indicators on fused alerts against the tenant's
IOC store inside fusion, with IOC expiry and decay."

Why inside fusion
-----------------
`AlertEnricher` already extracts indicators and asks the **enrichment
service** about them. That service runs in the `full` profile, so on a CORE
install `enrich()` catches a connection error, logs at `debug` and returns
`{}`. The investigation agent then receives "could not check" for every
indicator on every alert, which is the first thing the capability review
found: the default install gives the agent almost nothing to reason with.

The tenant's own IOC store is different. `threat_intel_iocs` lives in the
same Postgres every CORE service already connects to, and CORE ships a real
CISA KEV feed, so there is genuinely something to match against on a first
run. Reading it directly needs no extra service.

Expiry and decay
----------------
An indicator is not true forever, and treating a two-year-old commodity
hash with the weight of a fresh one is how a stale feed produces confident
nonsense.

* **Expiry** is a hard gate: past `expires_at`, or `is_active = false`, or
  `false_positive = true`, the row does not match at all.
* **Decay** is a multiplier on confidence derived from `last_seen`, with a
  per-type half-life. An IP changes hands in weeks; a malware hash does
  not. Decayed confidence below the floor is reported as a match with low
  confidence rather than dropped, because "we have seen this, weakly" is
  different information from "we have never seen this".

Both are reported alongside the match, so a reader can tell a strong hit
from a faded one rather than seeing one number.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger()

#: Half-life in days, per indicator type. An indicator's confidence halves
#: over this period since `last_seen`.
#:
#: These are judgement, not measurement, and are stated as such: an IP
#: reassigns in weeks, a domain can be re-registered, and a file hash
#: identifies the same bytes forever even if the campaign using it stops.
HALF_LIFE_DAYS: dict[str, float] = {
    "ip": 30.0,
    "ipv4": 30.0,
    "ipv6": 30.0,
    "domain": 90.0,
    "url": 60.0,
    "hash": 3650.0,
    "md5": 3650.0,
    "sha1": 3650.0,
    "sha256": 3650.0,
    "email": 180.0,
    "filename": 365.0,
}
DEFAULT_HALF_LIFE_DAYS = 90.0

#: Decayed confidence below this is still a match, reported weakly.
WEAK_CONFIDENCE_FLOOR = 10.0


@dataclass(frozen=True)
class IocMatch:
    ioc_type: str
    value: str
    #: As stored.
    confidence: int
    #: After decay. This is the one a scorer should use.
    effective_confidence: float
    severity: str
    source: str
    age_days: float
    half_life_days: float
    threat_actor: str | None = None
    malware_family: str | None = None

    @property
    def is_weak(self) -> bool:
        return self.effective_confidence < WEAK_CONFIDENCE_FLOOR

    def as_dict(self) -> dict[str, Any]:
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "confidence": self.confidence,
            "effective_confidence": round(self.effective_confidence, 1),
            "severity": self.severity,
            "source": self.source,
            "age_days": round(self.age_days, 1),
            "half_life_days": self.half_life_days,
            "weak": self.is_weak,
            "threat_actor": self.threat_actor,
            "malware_family": self.malware_family,
            # Why this number is not the stored one, so a reader does not
            # have to re-derive the decay to trust it.
            "decay_note": (
                f"confidence {self.confidence} decayed to "
                f"{self.effective_confidence:.1f} over {self.age_days:.0f} days "
                f"(half-life {self.half_life_days:.0f} days)"
            ),
        }


def decay_factor(age_days: float, half_life_days: float) -> float:
    """Exponential decay. 1.0 at zero age, 0.5 at one half-life."""
    if age_days <= 0 or half_life_days <= 0:
        return 1.0
    return float(math.pow(0.5, age_days / half_life_days))


def effective_confidence(
    *, confidence: int, last_seen: datetime | None, ioc_type: str, now: datetime | None = None
) -> tuple[float, float, float]:
    """`(effective, age_days, half_life_days)` for one indicator."""
    half_life = HALF_LIFE_DAYS.get(ioc_type.lower(), DEFAULT_HALF_LIFE_DAYS)
    if last_seen is None:
        return float(confidence), 0.0, half_life
    reference = now or datetime.now(UTC)
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    age_days = max(0.0, (reference - last_seen).total_seconds() / 86400.0)
    return float(confidence) * decay_factor(age_days, half_life), age_days, half_life


#: `(ioc_type, value)` pairs are read from these alert fields. Mirrors
#: `AlertEnricher._IOC_FIELDS` so the two see the same indicators; a
#: divergence would mean the enrichment service and the local store
#: disagree about what the alert contains.
_SELECT = """
    SELECT ioc_type, value, confidence, severity, source, last_seen,
           threat_actor, malware_family
      FROM threat_intel_iocs
     WHERE tenant_id = $1::uuid
       AND is_active = TRUE
       AND false_positive = FALSE
       AND (expires_at IS NULL OR expires_at > NOW())
       AND (ioc_type, value) = ANY($2::record[])
"""


class TenantIocMatcher:
    """Reads `threat_intel_iocs` directly. No enrichment service required.

    Owns a small lazy pool rather than borrowing the alert sink's, so its
    construction does not depend on the order things are built in
    `main.py`. Two connections: this runs once per fused alert and the
    query is a single indexed lookup.
    """

    def __init__(self, dsn_or_pool: Any) -> None:
        if isinstance(dsn_or_pool, str):
            self._dsn: str | None = dsn_or_pool
            self._pool: Any = None
        else:
            self._dsn = None
            self._pool = dsn_or_pool

    @property
    def available(self) -> bool:
        return self._pool is not None or bool(self._dsn)

    async def _ensure_pool(self) -> Any:
        if self._pool is not None or not self._dsn:
            return self._pool
        try:
            import asyncpg

            dsn = self._dsn
            # SQLAlchemy spelling to the one asyncpg accepts.
            for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
                if dsn.startswith(prefix):
                    dsn = "postgresql://" + dsn[len(prefix) :]
                    break
            self._pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ioc_match.pool_unavailable", error=str(exc))
            self._dsn = None
        return self._pool

    async def match(self, *, tenant_id: str, indicators: list[dict[str, str]], now: datetime | None = None) -> list[IocMatch]:
        """Indicators that are in this tenant's store and not expired."""
        if not indicators:
            return []
        pool = await self._ensure_pool()
        if pool is None:
            return []

        # `= ANY(record[])` is awkward across drivers; a pair of arrays and
        # an explicit join is portable and uses the (tenant, type, value)
        # index the migration already creates.
        types = [str(i.get("ioc_type") or "").lower() for i in indicators]
        values = [str(i.get("value") or "") for i in indicators]
        query = """
            SELECT ioc_type, value, confidence, severity, source, last_seen,
                   threat_actor, malware_family
              FROM threat_intel_iocs
             WHERE tenant_id = $1::uuid
               AND is_active = TRUE
               AND false_positive = FALSE
               AND (expires_at IS NULL OR expires_at > NOW())
               AND lower(ioc_type) = ANY($2::text[])
               AND value = ANY($3::text[])
        """
        try:
            async with pool.acquire() as conn:
                rows = await conn.fetch(query, tenant_id, types, values)
        except Exception as exc:  # noqa: BLE001
            # Loud, not debug. A matcher that silently stops matching looks
            # exactly like a tenant with no indicators, and the agent would
            # report "no known indicators" as a finding.
            logger.warning("ioc_match.query_failed", tenant_id=tenant_id, error=str(exc))
            return []

        wanted = {(t, v) for t, v in zip(types, values, strict=False)}
        out: list[IocMatch] = []
        for row in rows:
            pair = (str(row["ioc_type"]).lower(), str(row["value"]))
            if pair not in wanted:
                continue
            effective, age, half_life = effective_confidence(
                confidence=int(row["confidence"]),
                last_seen=row["last_seen"],
                ioc_type=pair[0],
                now=now,
            )
            out.append(
                IocMatch(
                    ioc_type=pair[0],
                    value=pair[1],
                    confidence=int(row["confidence"]),
                    effective_confidence=effective,
                    severity=str(row["severity"]),
                    source=str(row["source"]),
                    age_days=age,
                    half_life_days=half_life,
                    threat_actor=row["threat_actor"],
                    malware_family=row["malware_family"],
                )
            )
        return out

    def to_enrichments(self, matches: list[IocMatch]) -> dict[str, Any]:
        """The shape the confidence scorer and the agent prompt already read."""
        if not matches:
            return {}
        strong = [m for m in matches if not m.is_weak]
        return {
            "ti_hits": [m.as_dict() for m in matches],
            "ti_source": "tenant_ioc_store",
            "ti_max_confidence": round(max(m.effective_confidence for m in matches), 1),
            "ti_strong_hits": len(strong),
            "ti_weak_hits": len(matches) - len(strong),
            # Stated so the agent does not read a local-only match as a
            # full-spectrum intelligence verdict.
            "ti_scope": ("matched against this tenant's own indicator store only; external enrichment runs in the `full` profile"),
        }


def enabled() -> bool:
    """On by default. The store is in the same database fusion already uses."""
    return os.getenv("AISOC_TENANT_IOC_MATCH", "1").strip().lower() not in ("0", "false", "no")
