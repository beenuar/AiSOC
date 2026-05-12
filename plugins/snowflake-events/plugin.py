"""Snowflake events connector plugin for AiSOC.

Pulls login_history and query_history from SNOWFLAKE.ACCOUNT_USAGE.

Required config:
  - account, user, password, warehouse
  - role (default ACCOUNTADMIN)
  - poll_interval_seconds (default 300)

Payload shape:
  {
    "action": "test_connection" | "fetch_logins" | "fetch_queries",
    "since": "ISO-8601 timestamp",
    "limit": 500
  }

The official `snowflake-connector-python` package is required.
This plugin gracefully degrades if the dependency is missing.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

try:
    import snowflake.connector  # type: ignore[import-not-found]

    _SF = True
except ImportError:
    _SF = False


class Plugin:
    """Snowflake events connector plugin."""

    def _connect(self, context: dict[str, Any]):
        config = context.get("config") or {}
        for k in ("account", "user", "password", "warehouse"):
            if not config.get(k):
                raise ValueError(f"{k} is required in plugin config")
        return snowflake.connector.connect(
            account=config["account"],
            user=config["user"],
            password=config["password"],
            warehouse=config["warehouse"],
            role=config.get("role") or "ACCOUNTADMIN",
        )

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        if not _SF:
            return {
                "error": (
                    "snowflake-connector-python not installed; "
                    "run `pip install snowflake-connector-python`"
                )
            }

        action = payload.get("action", "fetch_logins")
        since = payload.get("since") or (
            datetime.now(UTC) - timedelta(minutes=15)
        ).isoformat()
        limit = int(payload.get("limit", 500))

        try:
            conn = self._connect(context)
        except Exception as exc:
            return {"error": f"snowflake connect failed: {exc}"}

        try:
            cursor = conn.cursor()
            try:
                if action == "test_connection":
                    cursor.execute("SELECT CURRENT_VERSION()")
                    row = cursor.fetchone()
                    return {"connected": True, "version": row[0] if row else None}
                if action == "fetch_logins":
                    cursor.execute(
                        f"""
                        SELECT EVENT_TIMESTAMP, USER_NAME, CLIENT_IP,
                               REPORTED_CLIENT_TYPE, FIRST_AUTHENTICATION_FACTOR,
                               IS_SUCCESS, ERROR_MESSAGE
                          FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
                         WHERE EVENT_TIMESTAMP >= TO_TIMESTAMP_TZ(%s)
                         ORDER BY EVENT_TIMESTAMP DESC
                         LIMIT {limit}
                        """,
                        (since,),
                    )
                    rows = [
                        {desc[0].lower(): val for desc, val in zip(cursor.description, row)}
                        for row in cursor.fetchall()
                    ]
                    return {"action": action, "since": since, "events": rows}
                if action == "fetch_queries":
                    cursor.execute(
                        f"""
                        SELECT START_TIME, USER_NAME, ROLE_NAME, WAREHOUSE_NAME,
                               QUERY_TYPE, EXECUTION_STATUS, ROWS_PRODUCED,
                               BYTES_SCANNED, QUERY_TEXT
                          FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                         WHERE START_TIME >= TO_TIMESTAMP_TZ(%s)
                         ORDER BY START_TIME DESC
                         LIMIT {limit}
                        """,
                        (since,),
                    )
                    rows = [
                        {desc[0].lower(): val for desc, val in zip(cursor.description, row)}
                        for row in cursor.fetchall()
                    ]
                    return {"action": action, "since": since, "events": rows}
                return {"error": f"Unknown action: {action}"}
            finally:
                cursor.close()
        finally:
            conn.close()
