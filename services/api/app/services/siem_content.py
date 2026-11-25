"""The SIEM content inventory and rule health from outcomes.

Two halves over migration 180:

**Inventory** — ``sweep_tenant`` asks each of the tenant's content-capable
SIEM connectors (Splunk, Elastic — the Sentinel and QRadar legs plug into
the same ``/content`` seam and are recorded follow-ups) for its detection
content through the connectors microservice, the same decrypt-and-forward
transport federated search uses. One row per vendor rule with a SHA-256
over the fields that define behaviour; an unchanged hash advances
``last_seen``, a changed one bumps ``version`` and keeps ``previous_hash``
— drift is a fact, not a diff nobody ran.

**Health** — ``rule_health`` reads outcomes from the alerts this platform
already attributed: alerts carry ``rule_id``/``rule_name`` provenance, and
dispositions are analyst verdicts plus polled-back closures. The rules the
recorded metric defects taught bind here hardest:

* **every rate travels with its denominator** — a false-positive rate is
  ``(fp_count, disposed_count)``, and ``disposed_count == 0`` renders
  ``not measured``, never ``0.0``;
* vendor-reported execution state is listed only where the vendor's API
  exposed it (the inventory's ``enabled``); where it did not, the field
  says ``could_not_check``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.connectors_auth import connectors_headers
from app.models.connector import Connector
from app.security.credential_vault import CredentialVaultError, get_vault

logger = logging.getLogger("aisoc.siem_content")

#: Connector types whose /content leg exists today. Sentinel and QRadar
#: plug into the same seam; recorded follow-ups, named in the PR.
CONTENT_SOURCES = ("splunk", "elastic")

_UPSERT_SQL = text(
    """
    INSERT INTO siem_content_rules
      (tenant_id, connector_id, connector_type, vendor_rule_id, name, kind,
       enabled, severity, attack, content_sha256, raw)
    VALUES
      (:tenant_id, :connector_id, :connector_type, :vendor_rule_id, :name, :kind,
       :enabled, :severity, CAST(:attack AS jsonb), :content_sha256, CAST(:raw AS jsonb))
    ON CONFLICT ON CONSTRAINT siem_content_rules_identity DO UPDATE SET
      name = EXCLUDED.name,
      kind = EXCLUDED.kind,
      enabled = EXCLUDED.enabled,
      severity = EXCLUDED.severity,
      attack = EXCLUDED.attack,
      last_seen = NOW(),
      -- Drift bumps the version and keeps the prior hash; sameness only
      -- advances last_seen.
      previous_hash = CASE WHEN siem_content_rules.content_sha256 != EXCLUDED.content_sha256
                           THEN siem_content_rules.content_sha256
                           ELSE siem_content_rules.previous_hash END,
      version = CASE WHEN siem_content_rules.content_sha256 != EXCLUDED.content_sha256
                     THEN siem_content_rules.version + 1
                     ELSE siem_content_rules.version END,
      content_sha256 = EXCLUDED.content_sha256,
      raw = EXCLUDED.raw
    RETURNING (xmax = 0) AS inserted
    """
)


async def content_capable_connectors(db: AsyncSession, *, tenant_id: uuid.UUID) -> list[Connector]:
    """The tenant's enabled connectors whose type has a /content leg.

    The model's flag is ``is_enabled``; the refresh endpoint once queried a
    non-existent ``Connector.enabled`` and 500'd on every call before it could
    report "no connector". Centralised here so the selection is tested once
    through the real ORM.
    """
    result = await db.execute(
        select(Connector).where(
            Connector.tenant_id == tenant_id,
            Connector.is_enabled.is_(True),
            Connector.connector_type.in_(CONTENT_SOURCES),
        )
    )
    return list(result.scalars().all())


def content_hash(rule: dict[str, Any]) -> str:
    """SHA-256 over the fields that define the rule's behaviour."""
    basis = {
        "query": rule.get("query") or "",
        "kind": rule.get("kind") or "",
        "severity": rule.get("severity") or "",
        "enabled": bool(rule.get("enabled")),
    }
    return hashlib.sha256(json.dumps(basis, sort_keys=True).encode()).hexdigest()


async def sweep_tenant(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    connectors: list[Any],
    http_post: Any | None = None,
) -> dict[str, Any]:
    """Refresh the inventory from each content-capable connector.

    One SIEM's failure is a per-source verdict, never the sweep's. Returns
    per-connector outcomes the endpoint and the worker both render.
    """
    outcomes: list[dict[str, Any]] = []
    for connector in connectors:
        ctype = str(connector.connector_type)
        if ctype not in CONTENT_SOURCES:
            continue
        started = datetime.now(UTC)
        try:
            decrypted = get_vault().decrypt_dict(connector.auth_config or {})
        except CredentialVaultError as exc:
            outcomes.append(
                {
                    "connector_id": str(connector.id),
                    "connector_type": ctype,
                    "status": "error",
                    "error": f"credential decryption failed: {exc}",
                }
            )
            continue
        url = f"{settings.CONNECTORS_SERVICE_URL.rstrip('/')}/api/v1/connectors/{ctype}/content"
        payload = {"auth_config": decrypted, "connector_config": connector.connector_config or {}}
        try:
            if http_post is not None:
                body = await http_post(url, payload, connector.tenant_id)
            else:
                async with httpx.AsyncClient(timeout=httpx.Timeout(60.0)) as client:
                    resp = await client.post(url, json=payload, headers=connectors_headers(connector.tenant_id))
                    if resp.status_code == 501:
                        outcomes.append(
                            {"connector_id": str(connector.id), "connector_type": ctype, "status": "unsupported", "error": resp.text[:200]}
                        )
                        continue
                    resp.raise_for_status()
                    body = resp.json()
        except Exception as exc:  # noqa: BLE001 — one SIEM down is a verdict
            outcomes.append(
                {
                    "connector_id": str(connector.id),
                    "connector_type": ctype,
                    "status": "error",
                    "error": f"{type(exc).__name__}: {exc}"[:300],
                }
            )
            continue

        rules = body.get("rules") or []
        upserted = 0
        changed = 0
        for rule in rules:
            digest = content_hash(rule)
            inserted = (
                await db.execute(
                    _UPSERT_SQL,
                    {
                        "tenant_id": str(tenant_id),
                        "connector_id": str(connector.id),
                        "connector_type": ctype,
                        "vendor_rule_id": str(rule.get("vendor_rule_id") or ""),
                        "name": str(rule.get("name") or "")[:500],
                        "kind": str(rule.get("kind") or ""),
                        "enabled": rule.get("enabled"),
                        "severity": str(rule.get("severity") or ""),
                        "attack": json.dumps(rule.get("attack") or []),
                        "content_sha256": digest,
                        "raw": json.dumps(rule, default=str),
                    },
                )
            ).scalar_one_or_none()
            upserted += 1
            if inserted is False:
                changed += 0  # version bumps are visible in the table itself
        outcomes.append(
            {
                "connector_id": str(connector.id),
                "connector_type": ctype,
                "status": "ok",
                "rules": upserted,
                "duration_ms": int((datetime.now(UTC) - started).total_seconds() * 1000),
            }
        )
    return {"tenant_id": str(tenant_id), "sources": outcomes}


_HEALTH_SQL = text(
    """
    SELECT
      r.vendor_rule_id,
      r.name,
      r.connector_type,
      r.enabled,
      r.attack,
      r.version,
      r.last_seen,
      count(a.id) AS alerts_attributed,
      count(a.id) FILTER (WHERE a.disposition IS NOT NULL) AS disposed,
      count(a.id) FILTER (WHERE a.disposition IN ('false_positive', 'benign')) AS fp,
      max(a.created_at) AS last_fired
    FROM siem_content_rules r
    LEFT JOIN alerts a
      ON a.tenant_id = r.tenant_id
     AND a.connector_type = r.connector_type
     AND (a.rule_id = r.vendor_rule_id OR a.rule_name = r.name)
    WHERE r.tenant_id = :tenant_id
    GROUP BY r.id, r.vendor_rule_id, r.name, r.connector_type, r.enabled, r.attack, r.version, r.last_seen
    ORDER BY alerts_attributed DESC, r.name
    LIMIT :limit
    """
)


async def rule_health(db: AsyncSession, *, tenant_id: uuid.UUID, limit: int = 200) -> list[dict[str, Any]]:
    """Per SIEM rule: outcomes with denominators, or 'not measured'."""
    rows = (await db.execute(_HEALTH_SQL, {"tenant_id": str(tenant_id), "limit": limit})).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        (vendor_rule_id, name, connector_type, enabled, attack, version, last_seen, attributed, disposed, fp, last_fired) = row
        fp_rate: dict[str, Any]
        if int(disposed) > 0:
            fp_rate = {"rate": round(int(fp) / int(disposed), 4), "denominator": int(disposed)}
        else:
            fp_rate = {"rate": None, "denominator": 0, "note": "not measured — no disposed alerts attribute to this rule"}
        out.append(
            {
                "vendor_rule_id": vendor_rule_id,
                "name": name,
                "connector_type": connector_type,
                "vendor_execution_state": (
                    {"enabled": bool(enabled)}
                    if enabled is not None
                    else {"could_not_check": "the vendor listing did not expose an enabled state"}
                ),
                "attack": attack if isinstance(attack, list) else json.loads(attack or "[]"),
                "content_version": int(version),
                "inventory_last_seen": last_seen.isoformat() if last_seen else None,
                "alerts_attributed": int(attributed),
                "dispositions": int(disposed),
                "false_positive": fp_rate,
                "last_fired": last_fired.isoformat() if last_fired else None,
            }
        )
    return out


_TUNING_LANGUAGE = {"splunk": "spl", "elastic": "eql", "sentinel": "kql", "qradar": "aql"}


async def record_tuning_proposal(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    author_id: uuid.UUID,
    connector_type: str,
    vendor_rule_id: str,
    change: str,
    rationale: str,
    target_name: str,
    proposed_content: str,
) -> uuid.UUID:
    """Record a SIEM-rule change as a DRAFT on the governed proposal path.

    ``proposed_by_id`` is written so the promote path's author-is-not-approver
    rule actually applies: that check is guarded by ``proposed_by_id IS NOT
    NULL``, so a proposal created without an author silently skips it and a
    reviewer could approve their own change to the SIEM. The caller commits.
    """
    scaffold = "\n".join(
        [
            f"# SIEM tuning proposal ({change}) for {connector_type} rule {vendor_rule_id!r}.",
            f"# Target: {target_name}",
            f"# Rationale: {rationale}",
            "# Apply path: the governed sync_detection_rule verb (content read-back verified,",
            "#   rollback from prior content). Nothing applies without review; the reviewer",
            "#   cannot be this proposal's author.",
            "",
            proposed_content or "# (no proposed content supplied — the reviewer drafts it)",
        ]
    )
    proposal_id = uuid.uuid4()
    await db.execute(
        text(
            """
            INSERT INTO detection_rule_proposals
              (id, tenant_id, proposed_by_id, base_rule_id, name, description,
               rule_language, rule_body, category, severity, confidence,
               status, source, created_at, updated_at)
            VALUES
              (:id, :tid, :author, NULL, :name, :desc,
               :lang, :body, 'siem-tuning', 'medium', 60,
               'draft', 'siem-tuning', :now, :now)
            """
        ).bindparams(
            id=proposal_id,
            tid=tenant_id,
            author=author_id,
            name=f"tune({change}): {target_name}"[:200],
            desc=rationale[:2000],
            lang=_TUNING_LANGUAGE[connector_type],
            body=scaffold,
            now=datetime.now(UTC),
        )
    )
    return proposal_id
