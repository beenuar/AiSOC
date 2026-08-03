"""Bounded, read-only Splunk evidence tool for the investigation graph (#570).

The auto-investigation used to reason only over enrichment already present on
the alert — it never pulled the surrounding events from the SIEM that raised
it. This tool closes that gap for Splunk-originated alerts:

* resolve the originating connector instance from the alert's provenance
  (``connector_id`` — issue #568), never from the LLM;
* obtain credentials from the CredentialVault, never from a prompt/log/ledger;
* build a TIME-BOUNDED, allow-listed SPL pivot around the alert's user / host /
  IP / hash (values are quote-escaped; the query shape is fixed);
* enforce a maximum time range, execution timeout, and result/field caps;
* cite the (redacted) results + a content hash in the investigation findings
  and the ledger;
* treat any failure/timeout as *missing evidence* so the caller escalates to
  needs_review instead of dismissing the alert as a false positive.

Everything is best-effort and self-contained (a minimal Splunk REST client) so
it runs in the agents service without importing the actions service.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import httpx
import structlog

from app.investigator import ledger as ledger_module
from app.models.state import InvestigationState
from app.security.credential_vault import get_vault

logger = structlog.get_logger()

_MAX_RESULTS = int(os.getenv("AISOC_SPLUNK_EVIDENCE_MAX_RESULTS", "50"))
_MAX_WINDOW_HOURS = float(os.getenv("AISOC_SPLUNK_EVIDENCE_MAX_WINDOW_HOURS", "24"))
_WINDOW_HOURS = min(float(os.getenv("AISOC_SPLUNK_EVIDENCE_WINDOW_HOURS", "6")), _MAX_WINDOW_HOURS)
_TIMEOUT_S = float(os.getenv("AISOC_SPLUNK_EVIDENCE_TIMEOUT_S", "20"))
_MAX_FIELD_LEN = 500  # per-field redaction cap (byte-ish bound on cited evidence)


@dataclass(frozen=True)
class SplunkCreds:
    base_url: str
    token: str
    ssl_verify: bool = True
    index: str = "main"


@dataclass
class SplunkEvidenceResult:
    """Outcome of an evidence attempt.

    ``applicable`` is True only when a Splunk connector was actually resolved
    for the alert, so a *missing evidence* escalation (issue #570) is never
    triggered for non-Splunk alerts. ``queried`` is True only on a successful
    bounded query.
    """

    applicable: bool
    queried: bool
    result_count: int = 0
    error: str | None = None
    query: str | None = None
    findings: list[str] = field(default_factory=list)


def _spl_quote(value: str) -> str:
    """Quote-escape a value for safe insertion into an SPL double-quoted string."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _safe_index(index: str) -> str:
    """Allow-list the index token (letters/digits/_-* only)."""
    cleaned = "".join(ch for ch in (index or "") if ch.isalnum() or ch in "_-*")
    return cleaned or "main"


def build_evidence_spl(raw_alert: dict[str, Any], *, index: str = "main", max_results: int = _MAX_RESULTS) -> str | None:
    """Build a bounded, allow-listed SPL pivot around the alert's entities.

    Returns ``None`` when the alert has no pivotable entity (so we never run an
    unbounded ``search index=*`` fishing query).
    """
    filters: list[str] = []
    username = _first_str(raw_alert, "username", "user")
    if username:
        filters.append(f'user="{_spl_quote(username)}"')
    host = _first_str(raw_alert, "hostname", "host")
    if host:
        filters.append(f'host="{_spl_quote(host)}"')
    ip = _first_str(raw_alert, "src_ip", "dst_ip")
    if ip:
        q = _spl_quote(ip)
        filters.append(f'(src_ip="{q}" OR dest_ip="{q}" OR src="{q}" OR dest="{q}")')
    file_hash = _first_str(raw_alert, "file_hash")
    if file_hash:
        q = _spl_quote(file_hash)
        filters.append(f'(file_hash="{q}" OR hash="{q}")')

    if not filters:
        return None
    where = " OR ".join(filters)
    return f"search index={_safe_index(index)} ({where}) | head {int(max_results)}"


def _first_str(obj: dict[str, Any], *keys: str) -> str | None:
    for k in keys:
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _time_window(raw_alert: dict[str, Any]) -> tuple[str, str]:
    """Return (earliest, latest) Splunk time tokens, bounded to ±_WINDOW_HOURS."""
    et = raw_alert.get("event_time")
    if not et:
        raw_event = raw_alert.get("raw_event")
        if isinstance(raw_event, dict):
            et = raw_event.get("time")
    if isinstance(et, str) and et:
        try:
            dt = datetime.fromisoformat(et.replace("Z", "+00:00"))
            start = dt - timedelta(hours=_WINDOW_HOURS)
            end = dt + timedelta(hours=_WINDOW_HOURS)
            return (str(int(start.timestamp())), str(int(end.timestamp())))
        except ValueError:
            pass
    return (f"-{int(_WINDOW_HOURS)}h", "now")


def _redact_samples(results: list[dict[str, Any]]) -> list[str]:
    """Compact, length-capped one-liners for a few results (bounded citation)."""
    out: list[str] = []
    for row in results:
        if not isinstance(row, dict):
            continue
        parts = []
        for k in ("_time", "host", "source", "sourcetype", "user", "action"):
            v = row.get(k)
            if v:
                parts.append(f"{k}={str(v)[:80]}")
        line = " ".join(parts) or json.dumps(row, default=str)
        out.append(line[:_MAX_FIELD_LEN])
    return out


class SplunkEvidenceClient:
    """Minimal, bounded, read-only Splunk oneshot-search client."""

    def __init__(self, creds: SplunkCreds, *, timeout_s: float = _TIMEOUT_S, max_results: int = _MAX_RESULTS) -> None:
        self._base = creds.base_url.rstrip("/")
        self._token = creds.token
        self._verify = creds.ssl_verify
        self._timeout = timeout_s
        self._max_results = max_results

    async def search(self, spl: str, *, earliest: str, latest: str) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self._timeout, verify=self._verify) as client:
            resp = await client.post(
                f"{self._base}/services/search/jobs",
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data={
                    "search": spl,
                    "output_mode": "json",
                    "exec_mode": "oneshot",
                    "earliest_time": earliest,
                    "latest_time": latest,
                    "count": str(self._max_results),
                },
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", []) if isinstance(data, dict) else []
            return results[: self._max_results]


async def resolve_splunk_credentials(state: InvestigationState) -> SplunkCreds | None:
    """Resolve + decrypt the originating Splunk connector's credentials.

    Keyed on the alert's ``connector_id`` provenance (issue #568) scoped to the
    tenant, and only for a connector whose ``connector_type`` is ``splunk``.
    Returns ``None`` (not raise) when the alert isn't Splunk-originated, no DB
    is configured, or the vault can't decrypt — the caller then simply skips
    the evidence step. Credentials are never logged.
    """
    raw = state.raw_alert or {}
    connector_id = raw.get("connector_id")
    if not connector_id:
        return None
    pool = await ledger_module.get_pool()
    if pool is None:
        return None
    try:
        cid = uuid.UUID(str(connector_id))
    except (ValueError, TypeError):
        return None
    try:
        async with pool.acquire() as conn:
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", str(state.tenant_id))
            row = await conn.fetchrow(
                """
                SELECT auth_config, connector_config
                  FROM connectors
                 WHERE id = $1 AND tenant_id = $2 AND connector_type = 'splunk'
                """,
                cid,
                state.tenant_id,
            )
        if row is None:
            return None
        auth = _as_dict(row["auth_config"])
        cfg = _as_dict(row["connector_config"])
        vault = get_vault()
        if vault is not None:
            auth = vault.decrypt_dict(auth)
        merged = {**cfg, **auth}
        base_url = str(merged.get("base_url") or "").strip()
        token = str(merged.get("token") or "").strip()
        if not base_url or not token:
            return None
        return SplunkCreds(
            base_url=base_url,
            token=token,
            ssl_verify=bool(merged.get("ssl_verify", True)),
            index=str(merged.get("saved_search") or "main") if str(merged.get("saved_search") or "").startswith("index=") else "main",
        )
    except Exception as exc:  # noqa: BLE001 — best-effort; never leak creds in the log
        logger.debug("splunk_evidence.resolve_failed", error=type(exc).__name__)
        return None


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            return {}
    return {}


def _make_client(creds: SplunkCreds) -> SplunkEvidenceClient:
    return SplunkEvidenceClient(creds)


async def collect_splunk_evidence(state: InvestigationState) -> SplunkEvidenceResult:
    """Run one bounded Splunk evidence query for a Splunk-originated alert.

    Adds redacted, hashed evidence to the investigation findings (cited in the
    verdict rationale) and records it to the ledger. On any failure/timeout it
    returns ``queried=False`` with ``applicable=True`` so the caller escalates
    to needs_review rather than dismissing the alert.
    """
    creds = await resolve_splunk_credentials(state)
    if creds is None:
        return SplunkEvidenceResult(applicable=False, queried=False)

    raw = state.raw_alert or {}
    spl = build_evidence_spl(raw, index=creds.index, max_results=_MAX_RESULTS)
    if spl is None:
        state.add_finding("Splunk evidence: no pivotable entity (user/host/ip/hash) on the alert — skipped.")
        return SplunkEvidenceResult(applicable=True, queried=False, error="no_pivot")

    earliest, latest = _time_window(raw)
    try:
        results = await _make_client(creds).search(spl, earliest=earliest, latest=latest)
    except Exception as exc:  # noqa: BLE001 — treat as missing evidence, escalate safely
        logger.warning("splunk_evidence.query_failed", error=type(exc).__name__)
        state.add_finding(f"Splunk evidence query failed ({type(exc).__name__}) — treating as missing evidence, escalating.")
        return SplunkEvidenceResult(applicable=True, queried=False, error=str(exc), query=spl)

    count = len(results)
    digest = hashlib.sha256(json.dumps(results, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
    samples = _redact_samples(results[:3])

    findings = [
        f"Splunk evidence: {count} surrounding event(s) via bounded query "
        f"[head {_MAX_RESULTS}, window ±{int(_WINDOW_HOURS)}h] digest={digest}.",
    ]
    findings.extend(f"Splunk sample: {s}" for s in samples)
    for f in findings:
        state.add_finding(f)
    state.confidence_basis.append(f"splunk_evidence_count={count} digest={digest}")

    await _record_evidence_ledger(state, query=spl, count=count, digest=digest)

    return SplunkEvidenceResult(
        applicable=True,
        queried=True,
        result_count=count,
        query=spl,
        findings=findings,
    )


async def _record_evidence_ledger(state: InvestigationState, *, query: str, count: int, digest: str) -> None:
    """Best-effort ledger event citing the query + result count + digest.

    Records ONLY the query, count, and content hash — never credentials.
    """
    try:
        await ledger_module.record_event(
            run_id=state.run_id,
            tenant_id=state.tenant_id,
            seq=900,  # high seq bucket for tool evidence; ON CONFLICT dedups replays
            kind="splunk_evidence",
            agent="splunk_evidence_tool",
            summary=f"Splunk evidence: {count} events (digest {digest})",
            payload={"query": query, "result_count": count, "digest": digest},
        )
    except Exception as exc:  # noqa: BLE001 — audit is best-effort
        logger.debug("splunk_evidence.ledger_noop", error=type(exc).__name__)
