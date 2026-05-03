"""First-touch alerting for honeytoken triggers."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime, timezone

import httpx

from app.core.config import settings

LOG = logging.getLogger(__name__)


def _sign_payload(payload: bytes, secret: str) -> str:
    """Return HMAC-SHA256 hex digest for webhook payload verification."""
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


async def send_alert(
    honeytoken_id: uuid.UUID,
    tenant_id: uuid.UUID,
    token_type: str,
    token_name: str,
    trigger_id: uuid.UUID,
    source_ip: str | None,
    triggered_at: datetime,
) -> bool:
    """
    POST a JSON alert to the configured webhook URL.

    Returns True on success, False otherwise.
    """
    if not settings.alert_webhook_url:
        LOG.info("No alert_webhook_url configured; skipping outbound alert.")
        return False

    payload_dict = {
        "event": "honeytoken.triggered",
        "honeytoken_id": str(honeytoken_id),
        "tenant_id": str(tenant_id),
        "token_type": token_type,
        "token_name": token_name,
        "trigger_id": str(trigger_id),
        "source_ip": source_ip,
        "triggered_at": triggered_at.isoformat(),
    }
    payload_bytes = json.dumps(payload_dict).encode()
    signature = _sign_payload(payload_bytes, settings.alert_webhook_secret)

    headers = {
        "Content-Type": "application/json",
        "X-AiSOC-Signature": f"sha256={signature}",
        "X-AiSOC-Event": "honeytoken.triggered",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                settings.alert_webhook_url,
                content=payload_bytes,
                headers=headers,
            )
            resp.raise_for_status()
            LOG.info(
                "Alert sent: token=%s trigger=%s status=%s",
                honeytoken_id,
                trigger_id,
                resp.status_code,
            )
            return True
    except Exception as exc:
        LOG.error("Alert delivery failed: %s", exc)
        return False
