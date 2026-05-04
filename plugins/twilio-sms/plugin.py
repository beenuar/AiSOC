"""Twilio SMS notifier action plugin for AiSOC."""
from __future__ import annotations

from typing import Any

import httpx


class Plugin:
    """Twilio SMS plugin."""

    def _api_url(self, account_sid: str) -> str:
        return f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"

    async def _send(
        self,
        account_sid: str,
        auth_token: str,
        from_number: str,
        to_number: str,
        body: str,
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                self._api_url(account_sid),
                auth=(account_sid, auth_token),
                data={"From": from_number, "To": to_number, "Body": body},
            )
            resp.raise_for_status()
            return resp.json()

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        config = context.get("config") or {}
        for k in ("account_sid", "auth_token", "from_number"):
            if not config.get(k):
                return {"error": f"{k} is required in plugin config"}

        account_sid = config["account_sid"]
        auth_token = config["auth_token"]
        from_number = config["from_number"]

        action = payload.get("action", "send_sms")
        body = payload.get("body") or payload.get("message") or "AiSOC alert"

        try:
            if action == "send_sms":
                to_number = payload.get("to") or (
                    config.get("default_recipients") or [None]
                )[0]
                if not to_number:
                    return {"error": "`to` recipient is required"}
                result = await self._send(
                    account_sid, auth_token, from_number, to_number, body
                )
                return {"action": action, "ok": True, "sid": result.get("sid")}

            if action == "bulk_send":
                recipients = payload.get("recipients") or config.get(
                    "default_recipients"
                )
                if not recipients:
                    return {"error": "no recipients configured"}
                results = []
                for to_number in recipients:
                    try:
                        r = await self._send(
                            account_sid, auth_token, from_number, to_number, body
                        )
                        results.append({"to": to_number, "sid": r.get("sid")})
                    except httpx.HTTPError as exc:
                        results.append({"to": to_number, "error": str(exc)})
                return {"action": action, "results": results}

            return {"error": f"Unknown action: {action}"}
        except httpx.HTTPStatusError as exc:
            return {
                "error": f"twilio error: {exc.response.status_code}",
                "body": exc.response.text[:512],
            }
        except httpx.HTTPError as exc:
            return {"error": f"twilio request failed: {exc}"}
