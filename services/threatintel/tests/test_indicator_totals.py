"""`total` must be the catalogue, not the page and not the scan window.

The route scrolls a bounded window over Qdrant and returns one page from it.
It published ``len(indicators)`` after post-filtering as ``total``, so with
1,725 CISA KEV entries collected the store held 1,725, the API answered 400
(the scan bound) and the console's headline card read 100 (its page) — three
answers to one question, two of them published, both wrong, and the page
presenting the smallest of them as the size of the corpus.

These tests drive `list_indicators` directly against a stub client rather than
a live Qdrant: the thing under test is which number ends up in which field,
and a container cannot make that clearer.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import pytest
from app.api.indicators import list_indicators
from app.security.tenant_scope import TenantPrincipal

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")


@dataclass
class _Point:
    payload: dict[str, Any]


@dataclass
class _CountResult:
    count: int


class _StubQdrant:
    """Answers `scroll` with a fixed window and `count` with a fixed total."""

    def __init__(self, *, points: list[_Point], count: int | None, count_raises: bool = False) -> None:
        self._points = points
        self._count = count
        self._count_raises = count_raises
        self.scroll_limits: list[int] = []

    async def scroll(self, *, collection_name: str, scroll_filter: Any, limit: int, **_: Any):
        self.scroll_limits.append(limit)
        return self._points[:limit], None

    async def count(self, *, collection_name: str, count_filter: Any, exact: bool):
        if self._count_raises:
            raise RuntimeError("qdrant said no")
        return _CountResult(count=self._count or 0)


class _Request:
    def __init__(self, client: _StubQdrant) -> None:
        self.app = type("_App", (), {"state": type("_State", (), {"qdrant_client": client})()})()


def _points(n: int, *, ioc_type: str = "ip") -> list[_Point]:
    return [
        _Point(
            payload={
                "type": ioc_type,
                "value": f"CVE-2024-{i:05d}",
                "description": f"indicator {i}",
                "sources": ["cisa-kev"],
                "tags": ["kev"],
            }
        )
        for i in range(n)
    ]


def _principal() -> TenantPrincipal:
    return TenantPrincipal(tenant_ids=frozenset({TENANT}), subject="test")


async def _call(client: _StubQdrant, **kwargs: Any):
    return await list_indicators(
        request=_Request(client),  # type: ignore[arg-type]
        principal=_principal(),
        ioc_type=kwargs.get("ioc_type"),
        tag=kwargs.get("tag"),
        q=kwargs.get("q"),
        limit=kwargs.get("limit", 100),
    )


@pytest.mark.asyncio
async def test_total_is_the_store_count_not_the_page() -> None:
    """The regression this file exists for, in the shape it was observed."""
    client = _StubQdrant(points=_points(400), count=1725)

    response = await _call(client, limit=100)

    assert response.total == 1725, "total must be the catalogue"
    assert response.shown == 100, "shown must be the page"
    assert len(response.indicators) == 100
    assert response.bounded is False


@pytest.mark.asyncio
async def test_total_survives_a_filtered_query_and_marks_it_bounded() -> None:
    """A post-filter narrows the page; it does not shrink the catalogue."""
    client = _StubQdrant(points=_points(40, ioc_type="ip"), count=1725)

    response = await _call(client, ioc_type="domain", limit=100)

    assert response.total == 1725
    assert response.shown == 0
    assert response.bounded is True, "the caller must be told the match was made in a bounded window"


@pytest.mark.asyncio
async def test_count_failure_degrades_to_the_window_rather_than_losing_the_page() -> None:
    """Losing the list over a secondary count would be the worse failure."""
    client = _StubQdrant(points=_points(12), count=None, count_raises=True)

    response = await _call(client, limit=100)

    assert response.total == 12
    assert response.shown == 12
    assert len(response.indicators) == 12


@pytest.mark.asyncio
async def test_empty_store_reports_zero_rather_than_a_page_length() -> None:
    client = _StubQdrant(points=[], count=0)

    response = await _call(client, limit=100)

    assert response.total == 0
    assert response.shown == 0
    assert response.indicators == []
