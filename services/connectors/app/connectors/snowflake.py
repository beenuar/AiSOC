"""
Snowflake account_usage / login-history audit connector.

Snowflake's audit data lives in two places:

  * ``snowflake.account_usage.login_history`` — every authentication
    attempt, with reported_client_type, error_code, is_success, role.
    Latency: 45min .. 2h. Useful for credential-stuffing / impossible-
    travel detection.
  * ``snowflake.account_usage.query_history`` and
    ``snowflake.account_usage.access_history`` — query-level audit with
    role, warehouse, DB, schema, object touched. Latency: 45min.

We poll via the Snowflake SQL API (``POST /api/v2/statements``) using
key-pair JWT auth. The connector schema captures the account locator,
warehouse, role, and the *private key* in PKCS#8 PEM form (encrypted
at rest by ``CredentialVault``); RSA signing is done at runtime to mint
short-lived JWTs.

Severity collapse:
  * Failed login (is_success=NO) with error_code in known suspicious
    set → medium; bursty failures → high (computed downstream)
  * GRANT / REVOKE / CREATE_USER / DROP_USER → high
  * SHOW / SELECT / CALL / USE → info
  * COPY INTO / UNLOAD to external stage → medium (data exfil signal)
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class SnowflakeConnector(BaseConnector):
    """Snowflake account_usage audit."""

    connector_id = "snowflake"
    connector_name = "Snowflake Audit"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Snowflake account_usage audit. Polls login_history "
                "and query_history for authentication failures, role "
                "grants, and data-exfil-shaped query patterns via the "
                "SQL API with key-pair JWT authentication."
            ),
            docs_url="/docs/connectors/snowflake",
            fields=[
                Field(
                    "account",
                    "string",
                    "Account locator",
                    placeholder="abc12345.us-east-1",
                    help_text="Account locator from your Snowflake URL.",
                ),
                Field(
                    "user",
                    "string",
                    "Service user",
                    placeholder="AISOC_SVC",
                    help_text="Snowflake user the JWT identifies.",
                ),
                Field(
                    "role",
                    "string",
                    "Role",
                    placeholder="ACCOUNTADMIN",
                    required=False,
                ),
                Field(
                    "warehouse",
                    "string",
                    "Warehouse",
                    placeholder="AUDIT_WH",
                    required=False,
                ),
                Field(
                    "private_key_pem",
                    "secret",
                    "RSA private key (PKCS#8 PEM)",
                    help_text=(
                        "PKCS#8 PEM-encoded RSA private key paired "
                        "with the public key registered on the "
                        "service user. Encrypted at rest by "
                        "CredentialVault."
                    ),
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_AUDIT,
            Capability.QUERY_LOGS,
            Capability.READ_AUDIT_TRAIL,
            Capability.PIVOT_USER,
        )

    def __init__(
        self,
        account: str,
        user: str,
        private_key_pem: str,
        role: str | None = None,
        warehouse: str | None = None,
    ):
        self._account = account
        self._user = user
        self._role = role
        self._warehouse = warehouse
        self._private_key_pem = private_key_pem
        self._base = f"https://{account}.snowflakecomputing.com"

    # ----------------------- jwt + auth ---------------------------

    def _public_key_fingerprint(self) -> str:
        """SHA-256 of the public key DER, base64-encoded — Snowflake's
        canonical fingerprint format. Computed lazily so unit tests can
        run without a real key."""
        try:
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
                load_pem_private_key,
            )

            priv = load_pem_private_key(self._private_key_pem.encode(), password=None)
            der = priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            digest = hashlib.sha256(der).digest()
            return "SHA256:" + base64.b64encode(digest).decode("ascii")
        except Exception as exc:
            logger.debug("snowflake.fp_fallback", error=str(exc))
            return "SHA256:" + hashlib.sha256(self._private_key_pem.encode()).hexdigest()

    def _build_jwt(self) -> str:
        """Sign a 1-hour JWT for the SQL API. RS256 + SHA-256 fingerprint."""
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        now = int(time.time())
        sub = f"{self._account.upper()}.{self._user.upper()}"
        iss = f"{sub}.{self._public_key_fingerprint()}"
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iss": iss,
            "sub": sub,
            "iat": now,
            "exp": now + 3600,
        }
        signing_input = (
            _b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + _b64url(json.dumps(payload, separators=(",", ":")).encode())
        ).encode()
        priv = serialization.load_pem_private_key(self._private_key_pem.encode(), password=None)
        signature = priv.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return signing_input.decode() + "." + _b64url(signature)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._build_jwt()}",
            "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def _exec(self, sql: str) -> list[dict[str, Any]]:
        body: dict[str, Any] = {"statement": sql, "timeout": 60}
        if self._warehouse:
            body["warehouse"] = self._warehouse
        if self._role:
            body["role"] = self._role
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{self._base}/api/v2/statements",
                headers=self._headers(),
                json=body,
            )
            if resp.status_code not in (200, 201, 202):
                logger.warning("snowflake.exec_failed", status=resp.status_code, body=resp.text[:300])
                return []
            payload = resp.json() or {}
            cols = [c.get("name") for c in payload.get("resultSetMetaData", {}).get("rowType") or []]
            rows = payload.get("data") or []
            return [dict(zip(cols, row, strict=False)) for row in rows]

    async def test_connection(self) -> dict[str, Any]:
        try:
            rows = await self._exec("SELECT CURRENT_VERSION() AS V, CURRENT_ACCOUNT() AS A")
            if rows:
                return {
                    "success": True,
                    "connector": self.connector_id,
                    "version": rows[0].get("V"),
                    "account": rows[0].get("A") or self._account,
                }
            return {"success": False, "connector": self.connector_id, "error": "no rows from CURRENT_VERSION"}
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 3600) -> list[dict[str, Any]]:
        # account_usage has 45min..2h latency, so we shift the window back
        # by an hour and widen it. Caller can still set a small since_seconds
        # if they're polling frequently — we union the two streams.
        since = (datetime.now(UTC) - timedelta(seconds=max(since_seconds, 3600))).strftime("%Y-%m-%d %H:%M:%S")
        login_sql = (
            "SELECT EVENT_ID, EVENT_TIMESTAMP, USER_NAME, CLIENT_IP, "
            "REPORTED_CLIENT_TYPE, FIRST_AUTHENTICATION_FACTOR, "
            "IS_SUCCESS, ERROR_CODE, ERROR_MESSAGE "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY "
            f"WHERE EVENT_TIMESTAMP >= '{since}' "
            "ORDER BY EVENT_TIMESTAMP DESC LIMIT 500"
        )
        query_sql = (
            "SELECT QUERY_ID, START_TIME, USER_NAME, ROLE_NAME, "
            "WAREHOUSE_NAME, DATABASE_NAME, SCHEMA_NAME, QUERY_TYPE, "
            "EXECUTION_STATUS, BYTES_SCANNED "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY "
            f"WHERE START_TIME >= '{since}' "
            "AND QUERY_TYPE IN ("
            "'GRANT', 'REVOKE', 'CREATE_USER', 'DROP_USER', "
            "'ALTER_USER', 'COPY', 'UNLOAD', 'CREATE_ROLE', "
            "'DROP_ROLE', 'ALTER_ROLE', 'CREATE_NETWORK_POLICY') "
            "ORDER BY START_TIME DESC LIMIT 500"
        )
        login_rows = await self._exec(login_sql)
        query_rows = await self._exec(query_sql)
        out: list[dict[str, Any]] = []
        for row in login_rows:
            out.append(self.normalize({"_kind": "login", **row}))
        for row in query_rows:
            out.append(self.normalize({"_kind": "query", **row}))
        return out

    # ----------------------- normalize --------------------------

    _PRIV_QUERY_TYPES = (
        "GRANT",
        "REVOKE",
        "CREATE_USER",
        "DROP_USER",
        "ALTER_USER",
        "CREATE_ROLE",
        "DROP_ROLE",
        "ALTER_ROLE",
        "CREATE_NETWORK_POLICY",
    )
    _DATA_MOVE_QUERIES = ("COPY", "UNLOAD")

    # Snowflake login error codes worth flagging. The full enumeration is
    # documented at docs.snowflake.com/en/user-guide/authenticator-error-codes
    _SUSPICIOUS_LOGIN_ERRORS = {
        "390100",  # incorrect username/password
        "390101",  # locked
        "390114",  # MFA required
        "390195",  # network policy violation
        "390302",  # IP not allowed
    }

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        kind = raw.get("_kind")
        if kind == "login":
            return self._normalize_login(raw)
        if kind == "query":
            return self._normalize_query(raw)
        # Unknown shape — surface as info, retain payload.
        return {
            "source": self.connector_id,
            "external_id": raw.get("EVENT_ID") or raw.get("QUERY_ID") or "",
            "title": "Snowflake audit event",
            "description": "unknown account_usage shape",
            "severity": "info",
            "raw_event": raw,
            "created_at": raw.get("EVENT_TIMESTAMP") or raw.get("START_TIME"),
        }

    def _normalize_login(self, raw: dict[str, Any]) -> dict[str, Any]:
        is_success = (raw.get("IS_SUCCESS") or "").upper() == "YES"
        err = str(raw.get("ERROR_CODE") or "")
        severity = "info"
        if not is_success:
            severity = "low"
            if err in self._SUSPICIOUS_LOGIN_ERRORS:
                severity = "medium"
        return {
            "source": self.connector_id,
            "stream": "login_history",
            "external_id": raw.get("EVENT_ID") or "",
            "title": (f"Snowflake login {'success' if is_success else 'failure'} " f"({raw.get('USER_NAME')})"),
            "description": raw.get("ERROR_MESSAGE") or raw.get("REPORTED_CLIENT_TYPE"),
            "severity": severity,
            "actor": raw.get("USER_NAME"),
            "src_ip": raw.get("CLIENT_IP"),
            "event_type": "snowflake.login",
            "raw_event": raw,
            "created_at": raw.get("EVENT_TIMESTAMP"),
        }

    def _normalize_query(self, raw: dict[str, Any]) -> dict[str, Any]:
        qtype = (raw.get("QUERY_TYPE") or "").upper()
        severity = "info"
        if qtype in self._PRIV_QUERY_TYPES:
            severity = "high"
        elif qtype in self._DATA_MOVE_QUERIES:
            severity = "medium"
        return {
            "source": self.connector_id,
            "stream": "query_history",
            "external_id": raw.get("QUERY_ID") or "",
            "title": f"Snowflake {qtype}",
            "description": (
                f"user={raw.get('USER_NAME')}; role={raw.get('ROLE_NAME')}; "
                f"warehouse={raw.get('WAREHOUSE_NAME')}; "
                f"db={raw.get('DATABASE_NAME')}.{raw.get('SCHEMA_NAME')}"
            ),
            "severity": severity,
            "actor": raw.get("USER_NAME"),
            "event_type": f"snowflake.query.{qtype.lower()}",
            "raw_event": raw,
            "created_at": raw.get("START_TIME"),
        }
