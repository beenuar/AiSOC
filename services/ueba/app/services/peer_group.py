"""Peer-group analysis service.

Entities are grouped by an externally-supplied ``peer_group_id`` (e.g. derived
from HR department, role, or subnet).  The service maintains aggregate statistics
for each group and computes how far an individual event deviates from group norms.
"""

from __future__ import annotations

import math
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.ueba import PeerGroup
from app.services.baseline import _welford_update, compute_z_score


class PeerGroupService:
    def __init__(self, session: AsyncSession) -> None:
        self._db = session

    async def get_or_create(
        self,
        tenant_id: uuid.UUID,
        peer_group_id: str,
        entity_type: str,
        label: str | None = None,
    ) -> PeerGroup:
        result = await self._db.execute(
            select(PeerGroup).where(
                PeerGroup.id == peer_group_id,
                PeerGroup.tenant_id == tenant_id,
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            row = PeerGroup(
                id=peer_group_id,
                tenant_id=tenant_id,
                entity_type=entity_type,
                label=label or peer_group_id,
                member_count=0,
                feature_stats={},
            )
            self._db.add(row)
            await self._db.flush()
        return row

    async def update(
        self,
        tenant_id: uuid.UUID,
        peer_group_id: str,
        entity_type: str,
        features: dict[str, float],
    ) -> PeerGroup:
        """Add a member's observations to the peer-group aggregate stats."""
        group = await self.get_or_create(tenant_id, peer_group_id, entity_type)
        stats = dict(group.feature_stats)

        for feature, value in features.items():
            stats = _welford_update(stats, feature, value)

        group.feature_stats = stats
        group.member_count = stats.get(next(iter(stats), ""), {}).get("count", group.member_count)
        await self._db.flush()
        return group

    async def deviation_score(
        self,
        tenant_id: uuid.UUID,
        peer_group_id: str,
        features: dict[str, float],
    ) -> float | None:
        """Return a composite deviation score (0–10) vs. the peer group.

        Returns ``None`` if the group has fewer than ``peer_group_min_size`` observations.
        """
        result = await self._db.execute(
            select(PeerGroup).where(
                PeerGroup.id == peer_group_id,
                PeerGroup.tenant_id == tenant_id,
            )
        )
        group = result.scalar_one_or_none()
        if group is None:
            return None

        stats = group.feature_stats
        if not stats:
            return None

        # Check minimum sample size
        first_feat_count = next(iter(stats.values()), {}).get("count", 0)
        if first_feat_count < settings.peer_group_min_size:
            return None

        z_scores = [compute_z_score(stats, f, v) for f, v in features.items() if f in stats]
        if not z_scores:
            return None

        rss = math.sqrt(sum(z**2 for z in z_scores))
        return min(rss, 10.0)
