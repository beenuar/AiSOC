"""Auto-refresh worker for OAuth-provisioned connector instances.

Workstream 5 of the AI Stack & Data Integration plan calls for the
platform to keep ``oauth_provisioned`` connectors healthy without
operator intervention. The hosted ``/oauth/start`` flow stores
``access_token`` + (optional) ``refresh_token`` in ``connector.auth_config``
under the credential vault, plus an absolute ``expires_at`` timestamp.

This worker scans for instances whose access token is about to expire
(``LEAD_TIME`` seconds before ``expires_at``) and exchanges the refresh
token for a fresh access_token using the same per-tenant
``OAuthAppCredential`` that powered the original authorize call.

Failure model:

* Network / 5xx — increment ``oauth_refresh_failures``, leave the row
  alone otherwise; the next tick will retry.
* 4xx with ``invalid_grant`` (refresh token revoked) — same counter,
  but now the operator has to re-consent. The catalog UI shows
  ``health_status='unhealthy'`` once the counter crosses
  :pyattr:`Settings.OAUTH_REFRESH_ALARM_THRESHOLD`.

The worker runs as a single ``asyncio.Task`` started from the API's
``lifespan`` hook. It owns its own DB session (``AsyncSessionLocal``)
and is safe to run as a singleton — providers tolerate concurrent
refresh attempts but every extra exchange burns a refresh-token rotation
on providers that rotate (e.g. Salesforce, Auth0).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.database import AsyncSessionLocal
from app.models.connector import Connector
from app.models.oauth import OAuthAppCredential
from app.security.credential_vault import CredentialVaultError, get_vault

logger = logging.getLogger(__name__)


# Status string mirrored from the connectors API. Kept here as a private
# constant so the worker doesn't import the API endpoint module (which
# would be a layering violation — workers are below API routers).
_HEALTH_UNHEALTHY = "unhealthy"


class _CatalogResolver:
    """Resolves OAuth ``token_url`` + scopes from the connector catalog.

    The hosted-OAuth callback uses ``_fetch_catalog_entry`` which talks
    to the connectors microservice. We reuse the same import path here
    so the worker and the wizard agree on hints. Importing lazily inside
    methods keeps the worker module loadable even when the catalog
    helpers aren't on the path (tests, alembic, etc.).
    """

    @staticmethod
    async def hints_for(connector_type: str) -> dict[str, Any]:
        """Return the ``oauth`` hints block for ``connector_type``.

        Empty dict when the catalog is unreachable or the entry doesn't
        ship hints — the caller falls back to the per-tenant
        ``OAuthAppCredential.token_url`` override.
        """
        from app.api.v1.endpoints.connectors import _fetch_catalog

        try:
            catalog = await _fetch_catalog()
        except Exception as exc:  # pragma: no cover - logged + bubbled to fallback
            logger.warning(
                "oauth_refresh.catalog_unreachable connector_type=%s err=%s",
                connector_type,
                type(exc).__name__,
            )
            return {}
        for entry in catalog:
            if not isinstance(entry, dict):
                continue
            if entry.get("name") == connector_type:
                hints = entry.get("oauth") or {}
                return hints if isinstance(hints, dict) else {}
        return {}


def _resolve_token_url(app_credential: OAuthAppCredential, hints: Mapping[str, Any]) -> str | None:
    """Mirror of :func:`oauth._resolve_token_url` for non-HTTP context.

    Returns ``None`` instead of raising — the worker logs and skips so
    one mis-configured tenant can't poison the loop for everyone else.
    """
    url = (app_credential.token_url or hints.get("token_url") or "").strip()
    return url or None


def _parse_expires_at(value: Any) -> datetime | None:
    """Best-effort parse of an ``expires_at`` field stored in auth_config.

    The hosted callback writes ISO-8601 with ``+00:00``; older rows
    (pre-WS5) might be missing or malformed. Anything we can't parse is
    treated as "expired" so the worker attempts a refresh on next tick.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        # ``fromisoformat`` accepts the ``+00:00`` tail emitted by our
        # callback; ``Z`` is patched in to be safe in case a future
        # provider response slips through with the trailing ``Z``.
        normalised = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalised)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


async def _select_due_connectors(db: AsyncSession, *, lead_time_s: int) -> list[Connector]:
    """Find every OAuth-provisioned connector that needs a refresh.

    "Due" means one of:

    * ``auth_config`` is empty / unparseable (e.g. legacy row, or vault
      key rotation in flight) — we'll attempt a no-op refresh and let
      the failure path mark it.
    * ``expires_at`` exists and is within ``LEAD_TIME`` seconds of now.

    Connectors with no refresh token are skipped at the row-evaluation
    step so the SELECT stays cheap.
    """
    cutoff = datetime.now(UTC) + timedelta(seconds=lead_time_s)

    # ``auth_config`` is JSONB encrypted at the application layer, so we
    # can't push expires_at filtering into the DB. We pull all
    # OAuth-provisioned rows and filter in Python — the working set is
    # tiny (one row per tenant connector instance).
    stmt = select(Connector).where(Connector.oauth_provisioned.is_(True)).where(Connector.is_enabled.is_(True))
    result = await db.execute(stmt)
    candidates: list[Connector] = list(result.scalars().all())

    due: list[Connector] = []
    vault = get_vault()
    for conn in candidates:
        try:
            decrypted = vault.decrypt_dict(conn.auth_config or {})
        except CredentialVaultError as exc:
            logger.warning(
                "oauth_refresh.decrypt_failed connector_id=%s tenant=%s err=%s",
                conn.id,
                conn.tenant_id,
                type(exc).__name__,
            )
            # We can't decrypt → can't refresh. Surface as a refresh
            # failure so the operator sees the row going unhealthy.
            due.append(conn)
            continue

        refresh_token = decrypted.get("refresh_token")
        if not refresh_token:
            # No refresh token means we can't rotate even if we wanted
            # to. Skip silently — the original token will keep working
            # until its natural expiry, at which point the connector
            # poll will fail and the scheduler's health bookkeeping
            # marks it degraded.
            continue

        expires_at = _parse_expires_at(decrypted.get("expires_at"))
        if expires_at is None:
            # No / malformed expires_at — refresh defensively. We don't
            # want a connector silently running on an expired token.
            due.append(conn)
            continue

        if expires_at <= cutoff:
            due.append(conn)

    return due


async def _refresh_one(
    db: AsyncSession,
    *,
    connector: Connector,
    timeout_s: float,
    alarm_threshold: int,
) -> bool:
    """Attempt to refresh ``connector``'s access token. Returns success."""
    vault = get_vault()
    tenant_id = connector.tenant_id
    connector_type = connector.connector_type

    # 1. Decrypt the connector's auth_config to get the refresh_token.
    try:
        decrypted = vault.decrypt_dict(connector.auth_config or {})
    except CredentialVaultError as exc:
        logger.warning(
            "oauth_refresh.decrypt_failed connector_id=%s tenant=%s err=%s",
            connector.id,
            tenant_id,
            type(exc).__name__,
        )
        await _record_failure(
            db,
            connector=connector,
            alarm_threshold=alarm_threshold,
            reason="decrypt_failed",
        )
        return False

    refresh_token = decrypted.get("refresh_token")
    if not refresh_token:
        # Race with selection (tenant rotated config between SELECT and
        # this step). Treat as a soft skip, not a failure.
        return False

    # 2. Resolve the per-tenant OAuthAppCredential for client_id /
    # client_secret. Without this we can't talk to the provider.
    app_stmt = select(OAuthAppCredential).where(
        OAuthAppCredential.tenant_id == tenant_id,
        OAuthAppCredential.connector_type == connector_type,
    )
    app_credential: OAuthAppCredential | None = (await db.execute(app_stmt)).scalar_one_or_none()
    if app_credential is None:
        logger.warning(
            "oauth_refresh.app_credential_missing connector_id=%s tenant=%s connector_type=%s",
            connector.id,
            tenant_id,
            connector_type,
        )
        await _record_failure(
            db,
            connector=connector,
            alarm_threshold=alarm_threshold,
            reason="app_credential_missing",
        )
        return False

    try:
        client_secret = vault.decrypt(app_credential.client_secret_vault)
    except CredentialVaultError as exc:
        logger.warning(
            "oauth_refresh.client_secret_decrypt_failed connector_id=%s tenant=%s err=%s",
            connector.id,
            tenant_id,
            type(exc).__name__,
        )
        await _record_failure(
            db,
            connector=connector,
            alarm_threshold=alarm_threshold,
            reason="client_secret_decrypt_failed",
        )
        return False

    # 3. Resolve token_url from the per-tenant override or catalog hints.
    hints = await _CatalogResolver.hints_for(connector_type)
    token_url = _resolve_token_url(app_credential, hints)
    if not token_url:
        logger.warning(
            "oauth_refresh.token_url_missing connector_id=%s tenant=%s connector_type=%s",
            connector.id,
            tenant_id,
            connector_type,
        )
        await _record_failure(
            db,
            connector=connector,
            alarm_threshold=alarm_threshold,
            reason="token_url_missing",
        )
        return False

    # 4. POST to the token endpoint with grant_type=refresh_token.
    body: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": str(refresh_token),
        "client_id": app_credential.client_id,
        "client_secret": client_secret,
    }
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.post(
                token_url,
                data=body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        detail = ""
        try:
            detail = exc.response.text[:256]
        except Exception:  # pragma: no cover
            pass
        logger.warning(
            "oauth_refresh.token_exchange_failed connector_id=%s tenant=%s status=%s body=%s",
            connector.id,
            tenant_id,
            exc.response.status_code,
            detail,
        )
        await _record_failure(
            db,
            connector=connector,
            alarm_threshold=alarm_threshold,
            reason=f"http_{exc.response.status_code}",
        )
        return False
    except httpx.HTTPError as exc:
        logger.warning(
            "oauth_refresh.token_exchange_unreachable connector_id=%s tenant=%s err=%s",
            connector.id,
            tenant_id,
            type(exc).__name__,
        )
        await _record_failure(
            db,
            connector=connector,
            alarm_threshold=alarm_threshold,
            reason="unreachable",
        )
        return False

    try:
        token_payload = resp.json()
    except ValueError:
        logger.warning(
            "oauth_refresh.token_response_malformed connector_id=%s tenant=%s",
            connector.id,
            tenant_id,
        )
        await _record_failure(
            db,
            connector=connector,
            alarm_threshold=alarm_threshold,
            reason="malformed_response",
        )
        return False

    new_access_token = token_payload.get("access_token")
    if not new_access_token:
        logger.warning(
            "oauth_refresh.no_access_token connector_id=%s tenant=%s",
            connector.id,
            tenant_id,
        )
        await _record_failure(
            db,
            connector=connector,
            alarm_threshold=alarm_threshold,
            reason="no_access_token",
        )
        return False

    # 5. Build a fresh auth_payload — keep the existing refresh_token
    # when the provider rotates only access_token (Auth0 default), and
    # promote the rotated one when present (Salesforce, GitHub Apps).
    auth_payload: dict[str, Any] = dict(decrypted)
    auth_payload["access_token"] = new_access_token
    if "refresh_token" in token_payload and token_payload["refresh_token"]:
        auth_payload["refresh_token"] = token_payload["refresh_token"]
    if "id_token" in token_payload:
        auth_payload["id_token"] = token_payload["id_token"]
    if "token_type" in token_payload:
        auth_payload["token_type"] = token_payload["token_type"]

    expires_in = token_payload.get("expires_in")
    if isinstance(expires_in, (int, float)) and expires_in > 0:
        auth_payload["expires_at"] = (datetime.now(UTC) + timedelta(seconds=int(expires_in))).isoformat()
    else:
        # Provider didn't tell us — drop the stale value so we refresh
        # again on the very next tick rather than running on a token of
        # unknown lifetime.
        auth_payload.pop("expires_at", None)

    encrypted = vault.encrypt_dict(auth_payload)

    now = datetime.now(UTC)
    # Reset failure counter + bookkeeping. Restore healthy status only
    # if we were the ones who flipped it to ``unhealthy`` — leave other
    # health states (e.g. "degraded" from the connectors scheduler)
    # alone. The connectors poll will reconcile on the next tick.
    new_status = "healthy" if connector.health_status == _HEALTH_UNHEALTHY else connector.health_status
    await db.execute(
        update(Connector)
        .where(Connector.id == connector.id)
        .values(
            auth_config=encrypted,
            oauth_refresh_failures=0,
            oauth_last_refresh_at=now,
            health_status=new_status,
            updated_at=now,
        )
    )
    await db.commit()

    logger.info(
        "oauth_refresh.success connector_id=%s tenant=%s connector_type=%s",
        connector.id,
        tenant_id,
        connector_type,
    )
    return True


async def _record_failure(
    db: AsyncSession,
    *,
    connector: Connector,
    alarm_threshold: int,
    reason: str,
) -> None:
    """Bump ``oauth_refresh_failures`` and trip the alarm at threshold.

    The threshold is **inclusive** — at ``alarm_threshold`` consecutive
    failures we flip ``health_status`` to ``unhealthy`` so the
    connectors UI surfaces the red badge and the catalog API can route
    the operator to the re-consent flow.
    """
    new_count = (connector.oauth_refresh_failures or 0) + 1
    values: dict[str, Any] = {
        "oauth_refresh_failures": new_count,
        "updated_at": datetime.now(UTC),
    }
    if new_count >= alarm_threshold:
        values["health_status"] = _HEALTH_UNHEALTHY
        logger.error(
            "oauth_refresh.alarm connector_id=%s tenant=%s connector_type=%s failures=%d reason=%s — flipping health_status=unhealthy",
            connector.id,
            connector.tenant_id,
            connector.connector_type,
            new_count,
            reason,
        )

    await db.execute(update(Connector).where(Connector.id == connector.id).values(**values))
    await db.commit()


async def run_once() -> dict[str, int]:
    """Execute a single pass of the refresh worker.

    Returns a stats dict useful for tests and observability:
    ``{"checked": N, "refreshed": M, "failed": K}``.
    """
    stats = {"checked": 0, "refreshed": 0, "failed": 0}
    async with AsyncSessionLocal() as db:
        due = await _select_due_connectors(db, lead_time_s=settings.OAUTH_REFRESH_LEAD_TIME_SECONDS)
        stats["checked"] = len(due)
        for conn in due:
            ok = await _refresh_one(
                db,
                connector=conn,
                timeout_s=settings.OAUTH_REFRESH_HTTP_TIMEOUT_SECONDS,
                alarm_threshold=settings.OAUTH_REFRESH_ALARM_THRESHOLD,
            )
            if ok:
                stats["refreshed"] += 1
            else:
                stats["failed"] += 1
    return stats


async def run_forever(*, stop_event: asyncio.Event | None = None) -> None:
    """Run the refresh loop until ``stop_event`` is set.

    The loop cadence is :pyattr:`Settings.OAUTH_REFRESH_INTERVAL_SECONDS`.
    Cancellation (ASGI shutdown) is the canonical exit path; the
    optional ``stop_event`` is provided so tests can stop the loop
    deterministically without raising ``CancelledError``.
    """
    interval = max(5, settings.OAUTH_REFRESH_INTERVAL_SECONDS)
    logger.info(
        "oauth_refresh.started interval=%ds lead=%ds threshold=%d",
        interval,
        settings.OAUTH_REFRESH_LEAD_TIME_SECONDS,
        settings.OAUTH_REFRESH_ALARM_THRESHOLD,
    )
    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                break
            try:
                stats = await run_once()
                if stats["checked"]:
                    logger.info(
                        "oauth_refresh.tick checked=%d refreshed=%d failed=%d",
                        stats["checked"],
                        stats["refreshed"],
                        stats["failed"],
                    )
            except Exception as exc:  # noqa: BLE001
                # Never let a transient failure kill the loop — the
                # whole point of this worker is durability. The next
                # tick gets a fresh DB session.
                logger.exception("oauth_refresh.tick_failed err=%s", type(exc).__name__)
            try:
                if stop_event is not None:
                    await asyncio.wait_for(stop_event.wait(), timeout=interval)
                else:
                    await asyncio.sleep(interval)
            except TimeoutError:
                continue
    except asyncio.CancelledError:
        logger.info("oauth_refresh.cancelled — shutting down cleanly")
        raise
    finally:
        logger.info("oauth_refresh.stopped")


__all__ = [
    "run_once",
    "run_forever",
]
