"""Attack-chain timeline endpoint (T3.3 — v8.0 parallel team).

Exposes the ranked timeline computed by
``services/api/app/services/attack_chain.py`` to the case-detail UI.

``GET /v1/cases/{case_id}/attack-chain?window=24h``
    Returns a ranked chain of alerts that share entities with the
    seed alert anchored to this case, plus the side-by-side entity
    graph the right column renders.

The endpoint is tenant-scoped via the existing RLS dependency stack
(``AuthUser`` + ``DBSession``). The seed alert is resolved as the
*earliest* alert linked to the case so the timeline reads
chronologically — first → last — by default.
"""

from __future__ import annotations

import logging
import uuid
from datetime import timedelta
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select, text

from app.api.v1.deps import AuthUser, DBSession
from app.models.alert import Alert
from app.models.case import Case
from app.services.attack_chain import (
    AttackChain,
    PostgresAttackChainLoader,
    compute_attack_chain,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cases", tags=["cases"])


WindowLiteral = Literal["1h", "6h", "24h", "72h", "7d", "30d"]

_WINDOW_TO_TIMEDELTA: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "72h": timedelta(hours=72),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


@router.get("/{case_id}/attack-chain")
async def get_attack_chain(
    case_id: uuid.UUID,
    db: DBSession,
    user: AuthUser,
    window: WindowLiteral = Query(default="24h"),
) -> dict[str, Any]:
    """Return the ranked attack-chain timeline for the case's seed alert.

    The seed alert is the earliest ``alert.event_time`` linked to the
    case. If the case has no linked alerts the response is an empty
    chain — never a 500.
    """
    if window not in _WINDOW_TO_TIMEDELTA:
        # Belt + suspenders: FastAPI's Literal already rejects unknowns
        # but a future schema change could relax that — fail closed.
        raise HTTPException(status_code=400, detail=f"unknown window: {window}")

    case_row = (await db.execute(select(Case).where(Case.id == case_id, Case.tenant_id == user.tenant_id))).scalar_one_or_none()
    if case_row is None:
        raise HTTPException(status_code=404, detail="case_not_found")

    # Pick the seed alert: earliest event_time linked to the case. We
    # prefer ``case.alert_ids`` (denormalised) but fall back to a probe
    # on ``alerts.case_id`` if that list is empty so a freshly-linked
    # case still resolves.
    seed_alert_id: uuid.UUID | None = None
    if case_row.alert_ids:
        candidate_ids = [uuid.UUID(str(a)) if not isinstance(a, uuid.UUID) else a for a in case_row.alert_ids]
        seed_row = (
            await db.execute(
                select(Alert)
                .where(
                    Alert.id.in_(candidate_ids),
                    Alert.tenant_id == user.tenant_id,
                )
                .order_by(Alert.event_time.asc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if seed_row is not None:
            seed_alert_id = seed_row.id

    if seed_alert_id is None:
        seed_row = (
            await db.execute(
                select(Alert)
                .where(
                    Alert.case_id == case_id,
                    Alert.tenant_id == user.tenant_id,
                )
                .order_by(Alert.event_time.asc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if seed_row is not None:
            seed_alert_id = seed_row.id

    if seed_alert_id is None:
        return {
            "case_id": str(case_id),
            "tenant_id": str(user.tenant_id),
            "window": window,
            "seed_alert_id": None,
            "chain": [],
            "entity_graph": {"nodes": [], "edges": []},
            "chain_signature": None,
            "confidence": 0.0,
            "reason": "case_has_no_linked_alerts",
        }

    loader = PostgresAttackChainLoader(db)
    chain: AttackChain | None = await compute_attack_chain(
        seed_alert_id=seed_alert_id,
        tenant_id=user.tenant_id,
        loader=loader,
        window=_WINDOW_TO_TIMEDELTA[window],
        window_label=window,
    )
    if chain is None:
        raise HTTPException(status_code=404, detail="seed_alert_not_found")

    # Persist the materialised chain so subsequent navigations skip the
    # BFS. The unique constraint on (tenant, seed, window, signature)
    # makes this an atomic upsert when the chain hasn't changed.
    try:
        await db.execute(
            text(
                """
                INSERT INTO aisoc_attack_chains (
                    tenant_id, seed_alert_id, case_id, "window",
                    chain, entity_graph, chain_signature, confidence,
                    updated_at
                ) VALUES (
                    :tenant_id, :seed_alert_id, :case_id, :window,
                    CAST(:chain AS JSONB), CAST(:entity_graph AS JSONB),
                    :signature, :confidence, NOW()
                )
                ON CONFLICT (tenant_id, seed_alert_id, "window", chain_signature)
                DO UPDATE SET
                    case_id      = EXCLUDED.case_id,
                    chain        = EXCLUDED.chain,
                    entity_graph = EXCLUDED.entity_graph,
                    confidence   = EXCLUDED.confidence,
                    updated_at   = NOW()
                """
            ),
            {
                "tenant_id": str(user.tenant_id),
                "seed_alert_id": str(chain.seed_alert_id),
                "case_id": str(case_id),
                "window": window,
                "chain": _json_dumps([link.to_dict() for link in chain.chain]),
                "entity_graph": _json_dumps(chain.entity_graph),
                "signature": chain.chain_signature,
                "confidence": chain.confidence,
            },
        )
        await db.commit()
    except Exception as exc:  # noqa: BLE001 — table may not exist in tests
        # The migration is the source of truth; if it hasn't been
        # applied yet (e.g. dev branch, fresh test harness) we still
        # serve the response — caching is a nice-to-have, not a gate.
        logger.debug("attack_chain cache write skipped: %s", exc)

    payload = chain.to_dict()
    payload["case_id"] = str(case_id)
    return payload


def _json_dumps(value: Any) -> str:
    """Stable JSON encoder (sorted keys, UTF-8 default) for cache writes."""
    import json

    return json.dumps(value, default=str, sort_keys=True)
