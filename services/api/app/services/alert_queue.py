"""Investigation queue workbench backend.

This module powers the ``/queue`` workbench in the AiSOC console — a
fixed-priority list of alerts an analyst should be working *right
now*. The ordering rule is deliberately opinionated and mirrors what
shift-leads on a live SOC floor would draw on the whiteboard:

1. Alerts assigned to the current user first, oldest SLA first.
2. Unassigned alerts at severity ``critical`` or ``high``, oldest SLA
   first.

Unassigned ``low`` / ``medium`` / ``info`` alerts are deliberately
omitted from the queue. Those are triaged in bulk on ``/alerts``;
paging through them one-by-one on the queue is a documented
anti-pattern of legacy SOC tools we are deliberately *not* reproducing.

The queue is computed against a *virtual* ``sla_due_at`` column —
``Alert.first_seen + mttd_target`` for the alert's severity. We avoid
materialising the column on every row because the SLA target is a
tenant-configurable knob (see ``tenant_sla_config``); computing it
at query time keeps the alerts schema invariant when targets are
re-tuned. The expression we generate is plain SQL ``CASE`` on
severity, so PostgreSQL can index-walk over ``alerts.first_seen``
and apply the offset cheaply.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, Field
from sqlalchemy import and_, case, func, literal, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.sla import TenantSLAConfig
from app.services.sla import DEFAULT_SLA_TARGETS

# Severities that show up in the *unassigned* bucket of the queue.
# Low-priority alerts should be triaged in bulk on ``/alerts``; we
# don't want analysts paging through low-noise findings one-by-one.
QUEUE_UNASSIGNED_SEVERITIES: tuple[str, ...] = ("critical", "high")

# Alert statuses that *exit* the queue. Anything in this set is
# considered done — claim/snooze/assign must not return it to the
# queue, and the queue endpoint hides it.
QUEUE_CLOSED_STATUSES: tuple[str, ...] = (
    "resolved",
    "closed",
    "false_positive",
    "fp",
)

# Maximum page size for the queue endpoint. The workbench paginates
# locally; this cap exists to keep one bad client from yanking
# tens of thousands of rows at once.
QUEUE_MAX_PAGE_SIZE: int = 200


# ─── Type aliases for query params ──────────────────────────────────────


Owner = Literal["me", "unassigned", "all"]
Period = Literal["24h", "7d", "30d", "all"]

PERIOD_TO_TIMEDELTA: dict[str, timedelta | None] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "all": None,
}


# ─── Pydantic response shapes ───────────────────────────────────────────


class QueueAsset(BaseModel):
    """Lightweight asset descriptor for a queue row.

    The queue surfaces *one* representative entity per alert so the
    row is informative at a glance ("VPN brute force on `web-01`")
    without enumerating every entity. The full pivotable list lives
    on the Investigation Rail when the analyst opens the alert.
    """

    kind: str = Field(description="host | user | ip | asset")
    value: str
    label: str | None = None


class QueueAction(BaseModel):
    """Top suggested next action for a queue row.

    Sourced from ``Alert.ai_recommendations``. The lowest-priority
    integer wins (1 = most urgent). String-only legacy values are
    accepted and mapped to ``risk="low"`` with the array index as a
    fallback priority.
    """

    priority: int
    action: str
    risk: str = "low"


class QueueItem(BaseModel):
    """One row in the Investigation Queue workbench.

    Intentionally slimmer than ``AlertResponse``. The queue exists to
    answer "what should I work on next?" — clicking a row navigates
    to ``/alerts/{id}`` which loads full detail via the existing
    detail endpoint (``GET /alerts/{id}``). Keeping this payload
    small means a busy SOC with thousands of open alerts can refresh
    the queue cheaply (the badge on the topbar polls it).
    """

    id: uuid.UUID
    tenant_id: uuid.UUID
    title: str
    severity: str
    status: str
    priority: int
    category: str | None = None
    connector_type: str | None = None

    assigned_to_id: uuid.UUID | None = None
    case_id: uuid.UUID | None = None

    first_seen: datetime
    sla_due_at: datetime
    # Seconds until ``sla_due_at``. Negative once the SLA is breached;
    # the frontend uses the sign to flip the timer to red.
    sla_remaining_seconds: int
    sla_breached: bool

    # Seconds since ``first_seen``. Cheaper for the UI to render
    # than a relative-time library re-parsing dates on every tick.
    age_seconds: int

    asset: QueueAsset | None = None
    suggested_action: QueueAction | None = None

    bucket: Literal["mine", "unassigned"]


class QueueResponse(BaseModel):
    """Paginated queue response.

    ``counts`` always reports both buckets so the workbench can
    render the "mine / unassigned / all" tabs without re-fetching.
    ``generated_at`` is the server-side ``now`` we used to compute
    SLA remaining — the frontend can drift its own clock from this
    so multiple analysts on different boxes see the same countdowns.
    """

    items: list[QueueItem]
    total: int
    counts: dict[str, int]
    period: str
    owner: str
    page: int
    page_size: int
    pages: int
    generated_at: datetime


# ─── Errors ─────────────────────────────────────────────────────────────


class AlertNotFoundError(LookupError):
    """The requested alert does not exist for this tenant."""


class AlertAlreadyClaimedError(RuntimeError):
    """Another analyst already owns this alert."""

    def __init__(self, alert_id: uuid.UUID, owner_id: uuid.UUID) -> None:
        super().__init__(f"alert {alert_id} already claimed by {owner_id}")
        self.alert_id = alert_id
        self.owner_id = owner_id


# ─── SLA target resolution ──────────────────────────────────────────────


async def load_sla_targets(
    db: AsyncSession,
    tenant_id: uuid.UUID,
) -> dict[str, int]:
    """Return a ``{severity → mttd_target_minutes}`` mapping for the tenant.

    Per-tenant overrides in ``tenant_sla_config`` win; severities not
    overridden fall back to ``DEFAULT_SLA_TARGETS``. We only need
    ``mttd_target`` here because the queue's SLA timer is MTTD
    (time-to-acknowledge). MTTR and MTTC live on cases / SLA reports.
    """
    result: dict[str, int] = {sev: cfg["mttd_target"] for sev, cfg in DEFAULT_SLA_TARGETS.items()}
    rows = await db.execute(select(TenantSLAConfig).where(TenantSLAConfig.tenant_id == tenant_id))
    for cfg in rows.scalars().all():
        if cfg.severity in result:
            result[cfg.severity] = cfg.mttd_target
    return result


def sla_due_at_expression(targets: dict[str, int]):
    """SQL expression for the virtual ``sla_due_at`` column.

    Materialises ``Alert.first_seen + mttd_target`` as a ``CASE`` on
    severity. Returns a SQLAlchemy ``ColumnElement`` suitable for
    use in both ``select`` and ``order_by``. The fallback uses the
    ``info`` target so brand-new or unknown severities still produce
    a sortable value rather than ``NULL``.
    """
    branches = [(Alert.severity == sev, Alert.first_seen + literal(timedelta(minutes=mins))) for sev, mins in targets.items()]
    fallback = Alert.first_seen + literal(timedelta(minutes=DEFAULT_SLA_TARGETS["info"]["mttd_target"]))
    return case(*branches, else_=fallback)


# ─── Asset / action projection ──────────────────────────────────────────


def first_asset(alert: Alert) -> QueueAsset | None:
    """Pick the single most useful pivot for a queue row.

    Priority order: ``host → user → asset → ip``. This isn't the
    place to enumerate every entity — that's what the Investigation
    Rail (W6) is for. We surface one anchor so the row is meaningful
    at a glance.
    """
    hosts = [h for h in (alert.affected_hosts or []) if isinstance(h, str) and h.strip()]
    if hosts:
        return QueueAsset(kind="host", value=hosts[0].strip())
    users = [u for u in (alert.affected_users or []) if isinstance(u, str) and u.strip()]
    if users:
        return QueueAsset(kind="user", value=users[0].strip())
    assets = [a for a in (alert.affected_assets or []) if isinstance(a, str) and a.strip()]
    if assets:
        return QueueAsset(kind="asset", value=assets[0].strip())
    ips = [i for i in (alert.affected_ips or []) if isinstance(i, str) and i.strip()]
    if ips:
        return QueueAsset(kind="ip", value=ips[0].strip())
    return None


def first_action(alert: Alert) -> QueueAction | None:
    """Pick the top suggested next action.

    ``Alert.ai_recommendations`` is written by the ResponderAgent at
    investigation close. Older rows wrote bare strings; modern rows
    write structured dicts. We accept both shapes. The action with
    the lowest ``priority`` wins (1 = most urgent); ties break by
    array order.
    """
    raw = alert.ai_recommendations
    if not isinstance(raw, list) or not raw:
        return None

    candidates: list[QueueAction] = []
    for idx, item in enumerate(raw):
        if isinstance(item, str):
            text = item.strip()
            if not text:
                continue
            candidates.append(QueueAction(priority=idx + 1, action=text))
        elif isinstance(item, dict):
            action = str(item.get("action") or "").strip()
            if not action:
                continue
            try:
                priority = max(1, int(item.get("priority", idx + 1)))
            except (TypeError, ValueError):
                priority = idx + 1
            risk = str(item.get("risk") or "low").lower()
            if risk not in {"low", "medium", "high"}:
                risk = "low"
            candidates.append(QueueAction(priority=priority, action=action, risk=risk))

    if not candidates:
        return None
    candidates.sort(key=lambda c: c.priority)
    return candidates[0]


# ─── Queue assembly ─────────────────────────────────────────────────────


async def build_queue(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    owner: Owner = "all",
    period: Period = "all",
    page: int = 1,
    page_size: int = 50,
) -> QueueResponse:
    """Assemble queue rows for the given owner / period.

    The returned ``items`` are always pre-sorted:
      * bucket 0 (assigned to me) before bucket 1 (unassigned),
      * within each bucket: ``sla_due_at`` ascending,
      * tiebreaker: severity descending (critical > high > …).

    ``counts`` is always populated for *all* buckets regardless of
    the ``owner`` filter, so the workbench tabs render correctly.
    """
    page_size = max(1, min(page_size, QUEUE_MAX_PAGE_SIZE))
    page = max(1, page)

    now = datetime.now(UTC)
    period_delta = PERIOD_TO_TIMEDELTA.get(period)

    targets = await load_sla_targets(db, tenant_id)
    sla_expr = sla_due_at_expression(targets)

    base_filters = [
        Alert.tenant_id == tenant_id,
        Alert.status.notin_(QUEUE_CLOSED_STATUSES),
        or_(Alert.snoozed_until.is_(None), Alert.snoozed_until <= now),
    ]
    if period_delta is not None:
        base_filters.append(Alert.first_seen >= (now - period_delta))

    mine_filter = and_(*base_filters, Alert.assigned_to_id == user_id)
    unassigned_filter = and_(
        *base_filters,
        Alert.assigned_to_id.is_(None),
        Alert.severity.in_(QUEUE_UNASSIGNED_SEVERITIES),
    )

    # Counts: always report both buckets so the topbar badge + tabs
    # work without re-fetching.
    mine_count = (await db.execute(select(func.count()).select_from(Alert).where(mine_filter))).scalar_one()
    unassigned_count = (await db.execute(select(func.count()).select_from(Alert).where(unassigned_filter))).scalar_one()

    # Bucket label: mine (0) sorts before unassigned (1).
    bucket_expr = case(
        (Alert.assigned_to_id == user_id, literal(0)),
        else_=literal(1),
    )

    # Severity rank for the tiebreaker: critical > high > medium > …
    severity_rank = case(
        (Alert.severity == "critical", literal(0)),
        (Alert.severity == "high", literal(1)),
        (Alert.severity == "medium", literal(2)),
        (Alert.severity == "low", literal(3)),
        else_=literal(4),
    )

    if owner == "me":
        where_clause = mine_filter
        total = mine_count
    elif owner == "unassigned":
        where_clause = unassigned_filter
        total = unassigned_count
    else:  # all
        where_clause = or_(mine_filter, unassigned_filter)
        total = mine_count + unassigned_count

    offset = (page - 1) * page_size
    rows = (
        await db.execute(
            select(Alert, bucket_expr.label("_bucket"), sla_expr.label("_sla_due"))
            .where(where_clause)
            .order_by(bucket_expr.asc(), sla_expr.asc(), severity_rank.asc())
            .offset(offset)
            .limit(page_size)
        )
    ).all()

    items: list[QueueItem] = []
    for row in rows:
        alert: Alert = row[0]
        bucket_idx: int = int(row[1])
        sla_due_at: datetime = row[2]
        if sla_due_at.tzinfo is None:
            sla_due_at = sla_due_at.replace(tzinfo=UTC)
        remaining = int((sla_due_at - now).total_seconds())

        first_seen = alert.first_seen
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=UTC)
        age = int((now - first_seen).total_seconds())

        items.append(
            QueueItem(
                id=alert.id,
                tenant_id=alert.tenant_id,
                title=alert.title,
                severity=alert.severity,
                status=alert.status,
                priority=alert.priority,
                category=alert.category,
                connector_type=alert.connector_type,
                assigned_to_id=alert.assigned_to_id,
                case_id=alert.case_id,
                first_seen=first_seen,
                sla_due_at=sla_due_at,
                sla_remaining_seconds=remaining,
                sla_breached=remaining < 0,
                age_seconds=max(0, age),
                asset=first_asset(alert),
                suggested_action=first_action(alert),
                bucket="mine" if bucket_idx == 0 else "unassigned",
            )
        )

    pages = (total + page_size - 1) // page_size if total else 0
    return QueueResponse(
        items=items,
        total=total,
        counts={
            "mine": mine_count,
            "unassigned": unassigned_count,
            "all": mine_count + unassigned_count,
        },
        period=period,
        owner=owner,
        page=page,
        page_size=page_size,
        pages=pages,
        generated_at=now,
    )


# ─── Claim ──────────────────────────────────────────────────────────────


async def claim_alert(
    db: AsyncSession,
    *,
    alert_id: uuid.UUID,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
) -> Alert:
    """Atomically claim an unassigned alert for the current user.

    Behaviour:
      * Unassigned                  → assign to me.
      * Already assigned to me      → no-op (idempotent — refreshing
                                       the queue and re-clicking claim
                                       must not 409).
      * Assigned to someone else    → ``AlertAlreadyClaimedError``.

    The update is guarded with a ``WHERE assigned_to_id IS NULL``
    clause so two analysts racing for the same row can't both win —
    the second update is a no-op and we surface 409 to the loser.
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise AlertNotFoundError(str(alert_id))

    if alert.assigned_to_id == user_id:
        return alert  # idempotent

    if alert.assigned_to_id is not None:
        raise AlertAlreadyClaimedError(
            alert_id=alert_id,
            owner_id=alert.assigned_to_id,
        )

    now = datetime.now(UTC)
    update_result = await db.execute(
        update(Alert)
        .where(Alert.id == alert_id, Alert.assigned_to_id.is_(None))
        .values(assigned_to_id=user_id, assigned_at=now, updated_at=now)
        .returning(Alert.assigned_to_id)
    )
    winner = update_result.scalar_one_or_none()
    if winner is None or winner != user_id:
        # Someone else grabbed it between our SELECT and UPDATE.
        # Re-read so the error carries the actual owner.
        refresh = await db.execute(select(Alert.assigned_to_id).where(Alert.id == alert_id))
        actual_owner = refresh.scalar_one_or_none()
        if actual_owner is None:
            raise AlertNotFoundError(str(alert_id))
        if actual_owner == user_id:
            await db.commit()
            await db.refresh(alert)
            return alert
        raise AlertAlreadyClaimedError(alert_id=alert_id, owner_id=actual_owner)

    await db.commit()
    await db.refresh(alert)
    return alert
