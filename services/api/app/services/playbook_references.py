"""Resolve the names a playbook step addresses into something it can use.

Two callers, one table:

* ``POST /api/v1/playbook-steps/references`` — the agents engine asking what
  ``${IDP_BASE_URL}`` and ``IDP_BEARER_HEADERS`` are, so it can render an
  ``http`` step and put the result through its SSRF guard.
* ``playbook_step_dispatch`` — resolving the destination a ``notify`` step
  names into the executor params that channel's arm reads.

Three rules this module keeps, each of which has an opposite that shipped
somewhere in this repository before:

**A disabled or missing reference is absent, and says which.** Not an empty
string. Substituting empty into ``${IDP_BASE_URL}/sessions`` hands httpx a
scheme-relative path, which it resolves against whatever base it has — a
request to somewhere nobody chose.

**A secret is decrypted on the way to one step and never stored in a run
record.** The caller is told the header *names*; the values go to httpx and
nowhere else.

**A value that will not decrypt is reported, never downgraded.** A step that
quietly became a preview because a key would not decrypt is the failure the
whole governed-dispatch path exists to remove.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.connector import Connector
from app.models.playbook_reference import PlaybookReference
from app.security.credential_vault import CredentialVaultError, get_vault

logger = structlog.get_logger(__name__)

#: Executor parameter names each notify kind produces. Kept here rather than
#: in the dispatcher so the three notify arms and this resolver agree in one
#: place — a webhook reference that produced ``url`` instead of
#: ``webhook_url`` would make every arm report "no destination configured"
#: while a destination sat right there, configured.
_WEBHOOK_PARAM = "webhook_url"
_ROUTING_KEY_PARAM = "pd_routing_key"


class ReferenceError(RuntimeError):
    """A reference exists and could not be read. Distinct from absent."""


def _decrypt(reference: PlaybookReference) -> dict[str, Any]:
    """The secret half of a reference, as a dict.

    Stored as a vault-encrypted JSON object for every kind, so one code path
    covers a single webhook URL and a whole SMTP configuration. A blank
    secret is an empty dict, not an error: a ``url`` reference has no secret.
    """
    if not reference.secret_value:
        return {}
    try:
        decrypted = get_vault().decrypt_dict({"payload": reference.secret_value})
    except CredentialVaultError as exc:
        raise ReferenceError(f"the stored secret for {reference.name!r} could not be decrypted: {exc}") from exc
    raw = decrypted.get("payload")
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else {}
    except json.JSONDecodeError as exc:
        raise ReferenceError(f"the stored secret for {reference.name!r} is not a JSON object") from exc
    return parsed if isinstance(parsed, dict) else {}


async def _rows(db: AsyncSession, *, tenant_id: uuid.UUID, names: list[str]) -> dict[str, PlaybookReference]:
    if not names:
        return {}
    result = await db.execute(
        select(PlaybookReference)
        .where(PlaybookReference.tenant_id == tenant_id)
        .where(PlaybookReference.name.in_(sorted(set(names))))
        .where(PlaybookReference.enabled.is_(True))
    )
    return {row.name: row for row in result.scalars().all()}


async def _connector_base_url(db: AsyncSession, *, tenant_id: uuid.UUID, connector_id: uuid.UUID) -> str:
    """A bound connector's base URL, scoped to the tenant that asked.

    Tenant-scoped in the WHERE clause rather than trusting the foreign key:
    the reference row carries a caller-editable id, and a row that named
    another tenant's connector would otherwise read its hostname.
    """
    connector = (
        await db.execute(
            select(Connector)
            .where(Connector.id == connector_id)
            .where(Connector.tenant_id == tenant_id)
            .where(Connector.is_enabled.is_(True))
        )
    ).scalar_one_or_none()
    if connector is None:
        return ""
    config = connector.connector_config or {}
    return str(config.get("base_url") or config.get("instance_url") or "")


async def resolve(db: AsyncSession, *, tenant_id: uuid.UUID, names: list[str]) -> dict[str, dict[str, Any]]:
    """``{name: {...}}`` for the references this tenant has enabled.

    A name that is absent, disabled, or bound to a connector that no longer
    has a base URL is simply not in the result. The caller reports which
    names it needed and did not get, because "you have not configured this"
    is a different sentence from "the lookup failed".
    """
    resolved: dict[str, dict[str, Any]] = {}
    for name, row in (await _rows(db, tenant_id=tenant_id, names=names)).items():
        secret = _decrypt(row)
        if row.kind == "url":
            value = row.value
            if row.connector_id is not None:
                value = await _connector_base_url(db, tenant_id=tenant_id, connector_id=row.connector_id) or value
            if not value:
                continue
            resolved[name] = {"kind": "url", "value": value.rstrip("/"), "secret": False}
        elif row.kind == "headers":
            headers = {str(k): str(v) for k, v in secret.items()}
            if not headers:
                continue
            resolved[name] = {"kind": "headers", "headers": headers, "secret": True}
        elif row.kind == "webhook":
            url = str(secret.get("webhook_url") or row.value or "")
            if not url:
                continue
            resolved[name] = {"kind": "webhook", "channel": row.channel, _WEBHOOK_PARAM: url, "secret": True}
        elif row.kind == "routing_key":
            key = str(secret.get("routing_key") or secret.get(_ROUTING_KEY_PARAM) or "")
            if not key:
                continue
            resolved[name] = {"kind": "routing_key", "channel": row.channel or "pagerduty", _ROUTING_KEY_PARAM: key, "secret": True}
        elif row.kind == "smtp":
            if not secret.get("smtp_host"):
                continue
            resolved[name] = {"kind": "smtp", "channel": row.channel or "email", "secret": True, **{str(k): v for k, v in secret.items()}}
    return resolved


#: Where a `notify` step names its destination, in the order the packs use.
#: `destination` is the spelling the console writes; the two `_env` keys are
#: what the 62 shipped packs carry and are read verbatim rather than
#: rewritten, because rewriting content to match code is how a pack stops
#: matching the schema it validates against.
NOTIFY_DESTINATION_KEYS: tuple[str, ...] = ("destination", "webhook_env", "service_key_env")


def destination_name(params: dict[str, Any]) -> str:
    for key in NOTIFY_DESTINATION_KEYS:
        value = params.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


async def notify_destination(db: AsyncSession, *, tenant_id: uuid.UUID, params: dict[str, Any]) -> tuple[str, dict[str, Any], str]:
    """Resolve a ``notify`` step's destination into executor params.

    Returns ``(channel, executor_params, reason_it_did_not_resolve)``. The
    channel comes from the stored destination rather than from the step, so
    a reference configured as Teams cannot be paged as PagerDuty because a
    playbook said so — the credential and the transport have to agree or the
    message goes somewhere that cannot read it.
    """
    name = destination_name(params)
    if not name:
        return "", {}, "the step names no destination (set `destination`, `webhook_env` or `service_key_env`)"

    resolved = await resolve(db, tenant_id=tenant_id, names=[name])
    reference = resolved.get(name)
    if reference is None:
        return "", {}, f"this tenant has no enabled playbook reference named {name!r}"

    channel = str(reference.get("channel") or "")
    executor_params = {k: v for k, v in reference.items() if k not in {"kind", "channel", "secret"}}
    if not channel:
        return "", {}, f"the playbook reference {name!r} does not say which channel it serves"
    return channel, {**executor_params, "destination": name}, ""
