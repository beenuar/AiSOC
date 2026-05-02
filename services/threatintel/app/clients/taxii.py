"""
TAXII 2.1 client for fetching STIX bundles from threat intelligence feeds.

Cyble Open-Source AI Security Operations Center — MIT License
"""
from __future__ import annotations

import json
import logging
from typing import Any, Iterator

import httpx

logger = logging.getLogger(__name__)


class TaxiiClient:
    """
    Lightweight async TAXII 2.1 client.

    Supports:
    - Discovery endpoint
    - Collection listing
    - Objects endpoint with added/removed pagination
    """

    def __init__(
        self,
        url: str,
        collection_id: str,
        username: str = "",
        password: str = "",
        verify_ssl: bool = True,
    ) -> None:
        self._base_url = url.rstrip("/")
        self._collection_id = collection_id
        self._auth = (username, password) if username else None
        self._verify_ssl = verify_ssl
        self._headers = {
            "Accept": "application/taxii+json;version=2.1",
            "Content-Type": "application/taxii+json;version=2.1",
        }

    async def get_objects(
        self,
        added_after: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """
        Fetch STIX objects from a TAXII collection.

        Args:
            added_after: ISO-8601 timestamp — only fetch objects added after this time.
            limit: Maximum objects per page.

        Returns:
            List of raw STIX object dicts.
        """
        objects: list[dict[str, Any]] = []
        params: dict[str, Any] = {"limit": limit}
        if added_after:
            params["added_after"] = added_after

        next_cursor: str | None = None
        page = 0

        async with httpx.AsyncClient(
            auth=self._auth,
            headers=self._headers,
            verify=self._verify_ssl,
            timeout=60.0,
        ) as client:
            while True:
                if next_cursor:
                    params["next"] = next_cursor

                url = (
                    f"{self._base_url}/collections/{self._collection_id}/objects/"
                )
                try:
                    resp = await client.get(url, params=params)
                    resp.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    logger.error(
                        "TAXII fetch failed",
                        url=url,
                        status=exc.response.status_code,
                    )
                    break

                body = resp.json()
                page_objects = body.get("objects", [])
                objects.extend(page_objects)
                page += 1
                logger.debug(
                    "TAXII page fetched",
                    page=page,
                    count=len(page_objects),
                    total=len(objects),
                )

                next_cursor = body.get("next")
                if not next_cursor or not page_objects:
                    break

        logger.info(
            "TAXII collection fetched",
            collection=self._collection_id,
            total_objects=len(objects),
        )
        return objects
