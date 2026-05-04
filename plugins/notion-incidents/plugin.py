"""Notion incidents sync action plugin for AiSOC."""
from __future__ import annotations

from typing import Any

import httpx

API_BASE = "https://api.notion.com/v1"


class Plugin:
    """Notion incidents sync plugin."""

    def _headers(self, context: dict[str, Any]) -> dict[str, str]:
        config = context.get("config") or {}
        if not config.get("api_token"):
            raise ValueError("api_token is required")
        return {
            "Authorization": f"Bearer {config['api_token']}",
            "Notion-Version": config.get("notion_version") or "2022-06-28",
            "Content-Type": "application/json",
        }

    def _props(self, payload: dict[str, Any]) -> dict[str, Any]:
        title = payload.get("title") or "AiSOC Incident"
        severity = payload.get("severity") or "medium"
        status = payload.get("status") or "open"
        case_url = payload.get("case_url")
        techniques = payload.get("mitre_techniques") or []

        properties: dict[str, Any] = {
            "Name": {"title": [{"text": {"content": title}}]},
            "Severity": {"select": {"name": severity}},
            "Status": {"select": {"name": status}},
        }
        if case_url:
            properties["AiSOC Case"] = {"url": case_url}
        if techniques:
            properties["MITRE"] = {
                "multi_select": [{"name": t} for t in techniques[:10]]
            }
        return properties

    def _children(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        summary = payload.get("summary") or ""
        if not summary:
            return []
        return [
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [{"type": "text", "text": {"content": summary[:1900]}}]
                },
            }
        ]

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        try:
            headers = self._headers(context)
        except ValueError as exc:
            return {"error": str(exc)}

        config = context.get("config") or {}
        database_id = config.get("database_id")
        if not database_id:
            return {"error": "database_id is required"}

        action = payload.get("action", "create_incident_page")

        try:
            async with httpx.AsyncClient(
                timeout=30.0, base_url=API_BASE, headers=headers
            ) as client:
                if action == "create_incident_page":
                    body = {
                        "parent": {"database_id": database_id},
                        "properties": self._props(payload),
                        "children": self._children(payload),
                    }
                    resp = await client.post("/pages", json=body)
                    resp.raise_for_status()
                    data = resp.json()
                    return {
                        "action": action,
                        "page_id": data.get("id"),
                        "url": data.get("url"),
                    }

                if action == "update_incident_page":
                    page_id = payload.get("page_id")
                    if not page_id:
                        return {"error": "page_id is required"}
                    body = {"properties": self._props(payload)}
                    resp = await client.patch(f"/pages/{page_id}", json=body)
                    resp.raise_for_status()
                    return {"action": action, "ok": True, "page_id": page_id}

                if action == "append_post_mortem":
                    page_id = payload.get("page_id")
                    text = payload.get("post_mortem") or payload.get("summary") or ""
                    if not page_id or not text:
                        return {"error": "page_id and post_mortem text required"}
                    body = {
                        "children": [
                            {
                                "object": "block",
                                "type": "heading_2",
                                "heading_2": {
                                    "rich_text": [
                                        {"type": "text", "text": {"content": "Post-mortem"}}
                                    ]
                                },
                            },
                            {
                                "object": "block",
                                "type": "paragraph",
                                "paragraph": {
                                    "rich_text": [
                                        {
                                            "type": "text",
                                            "text": {"content": text[:1900]},
                                        }
                                    ]
                                },
                            },
                        ]
                    }
                    resp = await client.patch(f"/blocks/{page_id}/children", json=body)
                    resp.raise_for_status()
                    return {"action": action, "ok": True, "page_id": page_id}

                return {"error": f"Unknown action: {action}"}
        except httpx.HTTPStatusError as exc:
            return {
                "error": f"notion error: {exc.response.status_code}",
                "body": exc.response.text[:512],
            }
        except httpx.HTTPError as exc:
            return {"error": f"notion request failed: {exc}"}
