"""Follow a vendor's "here is the next page" link to the end of a collection.

Why this is a shared helper rather than a convention each connector restates
-----------------------------------------------------------------------------
A poll window here is derived from the clock — ``[now - since_seconds, now]``
— and the scheduler passes the instance's poll interval as ``since_seconds``,
so consecutive windows abut exactly. Nothing re-reads an earlier window: the
checkpoint on :class:`~app.connectors.base.BaseConnector` de-duplicates rows
that were already *seen*, it does not widen the next request to recover rows
that were never *returned*.

So a connector that asks for a capped page and reads only the first response
does not merely lag behind a busy window — it drops whatever did not fit, and
those rows fall below the next window's lower bound and are never requested
again. Three connectors had that shape against vendors whose own
documentation requires the link to be followed, which is why the loop lives
in one place with one set of properties instead of being rewritten per
vendor.

The properties, each of which is a defect someone has shipped:

* **A partial read is kept, never discarded.** A later page failing leaves the
  earlier pages' rows in hand; throwing them away would turn a transient
  vendor error into the data loss this module exists to prevent.
* **The bound is announced when it binds.** A page cap that is silent when it
  is reached is the same defect one layer up: the operator sees a plausible
  number of events and nothing says it was cut.
* **The link is requested verbatim.** Microsoft Graph states it outright —
  "Don't try to extract the ``$skiptoken`` or ``$skip`` value and use it in a
  different request" — and the same holds for every vendor here, because the
  link already carries the filter and ordering the first request established.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

#: Pages one feed may read in a single poll. At the page sizes the callers
#: request this is tens of thousands of rows, far above a normal window; it
#: exists so a misbehaving vendor cursor cannot spin a poll forever, not as a
#: volume limit anyone should reach. Reaching it is logged.
DEFAULT_MAX_PAGES = 25


def _page_rows(body: Any, items_field: str) -> list[dict[str, Any]]:
    if not isinstance(body, dict):
        return []
    rows = body.get(items_field)
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _next_link(body: Any, link_field: str) -> str | None:
    if not isinstance(body, dict):
        return None
    link = body.get(link_field)
    return link if isinstance(link, str) and link else None


async def read_linked_pages(
    client: httpx.AsyncClient,
    first: httpx.Response,
    *,
    link_field: str,
    items_field: str,
    headers: dict[str, str],
    feed: str,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> list[dict[str, Any]]:
    """Every row of a collection, starting from an already-fetched first page.

    ``first`` is the caller's own 200 response, so the caller keeps ownership
    of authentication, retry-on-401 and failure reporting for the request that
    opens the collection. This helper only continues one that already
    succeeded.
    """
    try:
        body = first.json()
    except ValueError:
        logger.warning("connector.paging.first_page_unparseable", feed=feed)
        return []

    rows = _page_rows(body, items_field)
    for _ in range(max_pages - 1):
        link = _next_link(body, link_field)
        if not link:
            return rows
        try:
            resp = await client.get(link, headers=headers)
        except httpx.HTTPError as exc:
            # Keep what was read. A network failure on page four is not a
            # reason to discard pages one to three.
            logger.warning("connector.paging.next_page_error", feed=feed, rows=len(rows), error=str(exc))
            return rows
        if resp.status_code != 200:
            logger.warning(
                "connector.paging.next_page_failed",
                feed=feed,
                status=resp.status_code,
                rows=len(rows),
                body=resp.text[:300],
            )
            return rows
        try:
            body = resp.json()
        except ValueError:
            logger.warning("connector.paging.next_page_unparseable", feed=feed, rows=len(rows))
            return rows
        rows.extend(_page_rows(body, items_field))

    if _next_link(body, link_field):
        logger.warning(
            "connector.paging.page_cap_reached",
            feed=feed,
            pages=max_pages,
            rows=len(rows),
            detail="the window was not read to the end; rows beyond this point are not re-requested by a later poll",
        )
    return rows
