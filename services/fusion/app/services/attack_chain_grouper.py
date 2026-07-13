"""Attack-chain auto-grouping at fuse time (Phase C4).

Correlation groups alerts into incidents by shared entity, and the API can
compute an attack chain *per case* on demand. But nothing formed or extended a
chain **at fuse time**, so related alerts didn't auto-collapse into one ordered
incident narrative as they arrived — the analyst saw N separate alerts instead
of "stage 3 of an intrusion on host X that began with initial-access 20m ago".

This grouper closes that. For each entity an alert touches (host / user / ip),
it looks up (or mints) a stable ``chain_id`` in Redis with a rolling TTL, so a
follow-on alert on the same entity within the window joins the same chain. It
appends a compact member record, orders members by MITRE kill-chain stage, and
returns a :class:`ChainAssignment` the fusion engine attaches to the fused
alert (``enrichments["attack_chain"]``) — giving the UI and the triage agent an
at-a-glance "this is step K of an unfolding attack" view.

Fail-soft: a Redis miss/outage degrades to "no chain assignment", never an
error into the fusion pipeline.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any

import structlog

logger = structlog.get_logger()

# MITRE ATT&CK tactic → kill-chain ordinal. Lower = earlier in an intrusion.
# Names are matched case-insensitively against both dashed and spaced forms.
_TACTIC_ORDER = {
    "reconnaissance": 0,
    "resource-development": 1,
    "initial-access": 2,
    "execution": 3,
    "persistence": 4,
    "privilege-escalation": 5,
    "defense-evasion": 6,
    "credential-access": 7,
    "discovery": 8,
    "lateral-movement": 9,
    "collection": 10,
    "command-and-control": 11,
    "exfiltration": 12,
    "impact": 13,
}
_MAX_MEMBERS = 50


def _stage_ordinal(tactics: list[str]) -> int:
    best = -1
    for t in tactics or []:
        key = str(t).strip().lower().replace(" ", "-")
        if key in _TACTIC_ORDER and _TACTIC_ORDER[key] > best:
            best = _TACTIC_ORDER[key]
    return best


def _stage_name(ordinal: int) -> str:
    if ordinal < 0:
        return "unknown"
    for name, ord_ in _TACTIC_ORDER.items():
        if ord_ == ordinal:
            return name
    return "unknown"


@dataclass
class ChainMember:
    alert_id: str
    title: str
    severity: str
    stage_ordinal: int
    stage: str
    ts: float


@dataclass
class ChainAssignment:
    chain_id: str
    is_new_chain: bool
    position: int  # 1-based position of this alert in the chain
    stage: str  # this alert's kill-chain stage
    entity: str  # the entity the chain is keyed on ("host:WIN-DC01")
    prior_alert_ids: list[str]
    member_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _entities(alert: Any) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if getattr(alert, "hostname", None):
        out.append(("host", str(alert.hostname)))
    if getattr(alert, "username", None):
        out.append(("user", str(alert.username)))
    if getattr(alert, "src_ip", None):
        out.append(("ip", str(alert.src_ip)))
    return out


class AttackChainGrouper:
    """Redis-backed fuse-time chain former/extender. Fail-soft on every op."""

    def __init__(self, redis_client: Any, *, window_seconds: int = 3600) -> None:
        self._redis = redis_client
        self._window = window_seconds

    def _chain_key(self, tenant_id: str, entity_type: str, entity_id: str) -> str:
        return f"chain:idx:{tenant_id}:{entity_type.lower()}:{entity_id.lower()}"

    def _members_key(self, chain_id: str) -> str:
        return f"chain:members:{chain_id}"

    async def assign(self, alert: Any) -> ChainAssignment | None:
        """Form or extend the attack chain for ``alert``. Returns the
        assignment, or ``None`` when the alert has no entity or Redis is down."""
        entities = _entities(alert)
        if not entities:
            return None
        tenant_id = str(getattr(alert, "tenant_id", ""))
        try:
            # Reuse the first entity that already has an active chain; otherwise
            # start a new chain keyed on the alert's primary entity.
            chain_id: str | None = None
            chosen_entity = entities[0]
            for etype, eid in entities:
                existing = await self._redis.get(self._chain_key(tenant_id, etype, eid))
                if existing:
                    chain_id = existing.decode() if isinstance(existing, bytes) else str(existing)
                    chosen_entity = (etype, eid)
                    break

            is_new = chain_id is None
            if chain_id is None:
                chain_id = str(uuid.uuid4())

            # Point every entity of this alert at the chain (rolling TTL) so a
            # later alert on any of them joins the same chain.
            for etype, eid in entities:
                await self._redis.set(self._chain_key(tenant_id, etype, eid), chain_id, ex=self._window)

            stage_ord = _stage_ordinal(list(getattr(alert, "mitre_tactics", []) or []))
            member = ChainMember(
                alert_id=str(getattr(alert, "id", "")),
                title=str(getattr(alert, "title", ""))[:200],
                severity=str(getattr(getattr(alert, "severity", None), "value", getattr(alert, "severity", ""))),
                stage_ordinal=stage_ord,
                stage=_stage_name(stage_ord),
                ts=time.time(),
            )

            members = await self._load_members(chain_id)
            prior_ids = [m.alert_id for m in members]
            members.append(member)
            members = members[-_MAX_MEMBERS:]
            await self._save_members(chain_id, members)

            # Position = kill-chain-ordered rank of this alert among members.
            ordered = sorted(members, key=lambda m: (m.stage_ordinal, m.ts))
            position = next((i + 1 for i, m in enumerate(ordered) if m.alert_id == member.alert_id), len(members))

            return ChainAssignment(
                chain_id=chain_id,
                is_new_chain=is_new,
                position=position,
                stage=member.stage,
                entity=f"{chosen_entity[0]}:{chosen_entity[1]}",
                prior_alert_ids=prior_ids,
                member_count=len(members),
            )
        except Exception as exc:  # noqa: BLE001 — chaining is additive; never break fusion
            logger.warning("attack_chain.assign_failed", error=str(exc))
            return None

    async def _load_members(self, chain_id: str) -> list[ChainMember]:
        raw = await self._redis.get(self._members_key(chain_id))
        if not raw:
            return []
        try:
            data = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
            return [ChainMember(**m) for m in data]
        except (ValueError, TypeError):
            return []

    async def _save_members(self, chain_id: str, members: list[ChainMember]) -> None:
        payload = json.dumps([asdict(m) for m in members])
        await self._redis.set(self._members_key(chain_id), payload.encode("utf-8"), ex=self._window)
