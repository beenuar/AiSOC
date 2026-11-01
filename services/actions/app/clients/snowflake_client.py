"""Snowflake client for user and session containment over the SQL API.

Depth 5.5 names "Snowflake … deactivate or freeze a user and revoke their
tokens". Snowflake has no REST admin surface for this; containment is SQL,
run through the SQL API, which is the documented programmatic path.

References, each fetched before this module was written:

* submitting requests to the SQL API — https://docs.snowflake.com/en/developer-guide/sql-api/submitting-requests
* SQL API reference — https://docs.snowflake.com/en/developer-guide/sql-api/reference
* ``ALTER USER`` — https://docs.snowflake.com/en/sql-reference/sql/alter-user
* ``SYSTEM$ABORT_SESSION`` — https://docs.snowflake.com/en/sql-reference/functions/system_abort_session

The injection boundary, which is the whole design of this module
----------------------------------------------------------------
Every statement here interpolates an identifier, because SQL identifiers
cannot be bind parameters in any dialect. A denylist of dangerous
characters is the wrong control and adding the one you missed repeats the
mistake — this repository has already shipped that bug once, in the osquery
renderer, where six templates were injectable behind a denylist that
blocked ``--``, ``/*`` and ``;`` and never ``'``.

So the value is made unrepresentable instead: ``_identifier`` accepts the
character set Snowflake allows in an unquoted identifier and **refuses**
anything else. It does not escape. An escaped identifier that reaches
Snowflake and matches no user reports a clean result from a statement that
did nothing, which on a containment action is the worst possible outcome.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

#: Snowflake unquoted identifiers: letters, digits, underscore and dollar,
#: not starting with a digit. Deliberately narrower than what Snowflake
#: would accept inside double quotes — a containment path is not the place
#: to support exotic names, and a refusal names the problem.
_IDENTIFIER = re.compile(r"\A[A-Za-z_][A-Za-z0-9_$]{0,254}\Z")
_SESSION_ID = re.compile(r"\A[0-9]{1,20}\Z")


class SnowflakeAPIError(RuntimeError):
    """Snowflake answered and declined, or the statement failed."""


class SnowflakeClient:
    """Async client over the Snowflake SQL API v2."""

    def __init__(
        self,
        account_url: str,
        token: str,
        *,
        token_type: str = "OAUTH",
        warehouse: str | None = None,
        role: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self._base = account_url.rstrip("/")
        self._token = token
        self._token_type = token_type
        self._warehouse = warehouse
        self._role = role
        self._timeout = timeout

    @staticmethod
    def _identifier(value: str, *, kind: str = "identifier") -> str:
        if not _IDENTIFIER.match(value or ""):
            raise ValueError(
                f"{value!r} is not a valid Snowflake {kind}. Refusing rather than "
                f"escaping: an escaped name that matches nothing would report a "
                f"successful containment that changed nothing."
            )
        return value.upper()

    async def execute(self, statement: str) -> dict[str, Any]:
        """``POST /api/v2/statements``. Raises on anything but success."""
        headers = {
            "Authorization": f"Bearer {self._token}",
            "X-Snowflake-Authorization-Token-Type": self._token_type,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        payload: dict[str, Any] = {"statement": statement, "timeout": int(self._timeout)}
        if self._warehouse:
            payload["warehouse"] = self._warehouse
        if self._role:
            payload["role"] = self._role

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(f"{self._base}/api/v2/statements", headers=headers, json=payload)
        if response.status_code >= 400:
            raise SnowflakeAPIError(f"Snowflake statement failed with HTTP {response.status_code}: {response.text[:300]}")
        try:
            body = response.json()
        except ValueError as exc:
            raise SnowflakeAPIError("Snowflake returned a non-JSON body") from exc
        # 202 means the statement is still running. Containment that may or
        # may not have finished is not containment, so this is a failure
        # rather than a success with a caveat nobody reads.
        if response.status_code == 202:
            raise SnowflakeAPIError(f"Snowflake accepted the statement asynchronously (handle {body.get('statementHandle')}); this client needs a completed result to report an effect")
        return body

    async def set_user_disabled(self, user: str, *, disabled: bool) -> dict[str, Any]:
        """``ALTER USER <name> SET DISABLED = TRUE|FALSE``."""
        name = self._identifier(user, kind="user name")
        await self.execute(f"ALTER USER {name} SET DISABLED = {'TRUE' if disabled else 'FALSE'}")
        logger.info("snowflake.set_user_disabled", user=name, disabled=disabled)
        return {"user": name, "disabled": disabled}

    async def disable_user(self, user: str) -> dict[str, Any]:
        return await self.set_user_disabled(user, disabled=True)

    async def enable_user(self, user: str) -> dict[str, Any]:
        return await self.set_user_disabled(user, disabled=False)

    async def describe_user(self, user: str) -> dict[str, Any]:
        """``DESCRIBE USER``: the read behind the disable probe.

        The SQL API returns rows as positional arrays with a separate
        column description, so the property name and its value are read out
        of the ``property``/``value`` columns rather than assumed to be at
        fixed offsets.
        """
        name = self._identifier(user, kind="user name")
        body = await self.execute(f"DESCRIBE USER {name}")
        columns = [col.get("name", "").upper() for col in (body.get("resultSetMetaData") or {}).get("rowType") or []]
        try:
            property_index = columns.index("PROPERTY")
            value_index = columns.index("VALUE")
        except ValueError as exc:
            raise SnowflakeAPIError(f"DESCRIBE USER returned columns {columns}, which do not include PROPERTY and VALUE") from exc

        properties = {str(row[property_index]).upper(): row[value_index] for row in (body.get("data") or []) if len(row) > max(property_index, value_index)}
        disabled_raw = str(properties.get("DISABLED", "")).strip().lower()
        return {
            "user": name,
            "disabled": disabled_raw in ("true", "t", "yes"),
            "login_name": properties.get("LOGIN_NAME"),
            "default_role": properties.get("DEFAULT_ROLE"),
        }

    async def abort_session(self, session_id: str) -> dict[str, Any]:
        """``SYSTEM$ABORT_SESSION``: end one live session by id.

        Session-level rather than user-level on purpose: an analyst who has
        the session id from the alert should be able to cut that session
        without disabling the account, which is the narrower action and the
        one that does not stop a team's pipelines.
        """
        if not _SESSION_ID.match(str(session_id or "")):
            raise ValueError(f"{session_id!r} is not a Snowflake session id (digits only)")
        body = await self.execute(f"SELECT SYSTEM$ABORT_SESSION({session_id})")
        rows = body.get("data") or []
        return {
            "session_id": str(session_id),
            "aborted": True,
            "result": rows[0][0] if rows and rows[0] else None,
        }
