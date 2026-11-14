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

from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

#: Pages one feed may read in a single poll. At the page sizes the callers
#: request this is tens of thousands of rows, far above a normal window; it
#: exists so a misbehaving vendor cursor cannot spin a poll forever, not as a
#: volume limit anyone should reach. Reaching it is logged.
DEFAULT_MAX_PAGES = 25


def _at(body: Any, path: str) -> Any:
    """The value at a dotted ``path``, or None if any segment is missing.

    A bare key is a one-segment path, so a vendor that returns its rows at
    the top level and one that nests them under a GraphQL connection are read
    by the same function rather than by two that can drift apart.
    """
    node = body
    for key in path.split("."):
        node = node.get(key) if isinstance(node, dict) else None
    return node


def _rows_at(body: Any, path: str) -> list[dict[str, Any]]:
    rows = _at(body, path)
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _token_at(body: Any, path: str) -> str | None:
    """The continuation token at a dotted ``path``, or None when the collection has ended."""
    node = _at(body, path)
    return node if isinstance(node, str) and node else None


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

    rows = _rows_at(body, items_field)
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
        rows.extend(_rows_at(body, items_field))

    if _next_link(body, link_field):
        logger.warning(
            "connector.paging.page_cap_reached",
            feed=feed,
            pages=max_pages,
            rows=len(rows),
            detail="the window was not read to the end; rows beyond this point are not re-requested by a later poll",
        )
    return rows


async def read_token_pages(
    *,
    request: Callable[[str | None], Awaitable[httpx.Response]],
    items_field: str,
    feed: str,
    token_field: str = "nextPageToken",
    stop_when: Callable[[list[dict[str, Any]]], bool] | None = None,
    empty_page_ends: bool = False,
    more_field: str | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> list[dict[str, Any]]:
    """Every row of a collection paged by an opaque continuation token.

    The other half of :func:`read_linked_pages`. Where Microsoft hands back a
    complete URL, Google hands back a token that the client puts back into the
    *same* request — into the query string for a GET, into the body for a
    POST. ``request`` is the caller's own closure so it keeps ownership of
    authentication, the retry-on-401 and where the token belongs; it is called
    with ``None`` for the opening page and with the token thereafter.
    ``token_field`` and ``items_field`` are dotted paths, for a vendor that
    nests either — a GraphQL connection puts its rows at
    ``data.<field>.nodes`` and its cursor at ``data.<field>.pageInfo.endCursor``.
    A bare key is a one-segment path, so existing callers are unchanged.

    ``stop_when`` receives each **non-empty** page and ends the read when it
    answers True, as in :func:`read_link_header_pages`. It is how a
    newest-first collection with no server-side time filter stops once a page
    has passed the start of the window, instead of walking back to the oldest
    row the vendor holds.

    One rule here is not shared with the link-following version, and getting
    it wrong is worse than the truncation this exists to fix. **An empty page
    does not end the collection.** Cloud Logging's reference states:

        If a value for nextPageToken appears and the entries field is empty,
        it means that the search found no log entries so far but it did not
        have time to search all the possible log entries. Retry the method
        with this value for pageToken to continue the search.

    So the loop ends on the *token*, never on an empty page. A connector that
    stops at the first empty response can return nothing at all from a window
    that was full of events, which reads downstream as a quiet estate rather
    than as a failed read. GitLab's GraphQL connections behave the same way —
    a request this reviewer sent to the live endpoint came back with
    ``nodes: []`` beside ``hasNextPage: true``, because authorization filters
    rows out of a page without shortening the connection.

    ``empty_page_ends`` is the exception, for a vendor whose own client ends
    the read there. Datadog's generated API clients stop a cursor-paged read
    on an empty page as well as on an absent cursor, so a Datadog cursor beside
    an empty page is not a promise of more rows, and following it would spend
    the page cap on a quiet window. Pass it only on that kind of evidence.

    ``more_field`` is for a vendor whose token is never absent. Sophos
    Central's SIEM API returns ``next_cursor`` on every page, the last one
    included, because the same value is how a client resumes on its next
    poll; whether there is anything after this page is said separately, by
    ``has_more``. Ending on the token alone would re-request the final page
    until the page cap, so when ``more_field`` names a dotted path the read
    ends as soon as the value there is not ``True`` — an absent or malformed
    flag included, because a flag that does not say "more" is not a promise
    of more rows.
    """
    rows: list[dict[str, Any]] = []
    token: str | None = None

    for page in range(max_pages):
        try:
            resp = await request(token)
        except httpx.HTTPError as exc:
            # Keep what was read; a failure part-way is not a reason to
            # discard the pages that succeeded.
            logger.warning("connector.paging.token_page_error", feed=feed, page=page, rows=len(rows), error=str(exc))
            return rows
        if resp.status_code != 200:
            logger.warning(
                "connector.paging.token_page_failed",
                feed=feed,
                page=page,
                status=resp.status_code,
                rows=len(rows),
                body=resp.text[:300],
            )
            return rows
        try:
            body = resp.json()
        except ValueError:
            logger.warning("connector.paging.token_page_unparseable", feed=feed, page=page, rows=len(rows))
            return rows

        page_rows = _rows_at(body, items_field)
        rows.extend(page_rows)

        token = _token_at(body, token_field)
        if token is None or (empty_page_ends and not page_rows):
            return rows
        if more_field is not None and _at(body, more_field) is not True:
            return rows
        if page_rows and stop_when is not None and stop_when(page_rows):
            return rows

    logger.warning(
        "connector.paging.page_cap_reached",
        feed=feed,
        pages=max_pages,
        rows=len(rows),
        detail="the window was not read to the end; rows beyond this point are not re-requested by a later poll",
    )
    return rows


async def read_offset_pages(
    first: httpx.Response,
    *,
    request: Callable[[int], Awaitable[httpx.Response]],
    items_field: str,
    page_size: int,
    feed: str,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> list[dict[str, Any]]:
    """Every row of a collection paged by a numeric offset, from an already-fetched first page.

    For a vendor that hands back neither a link nor a token: the client asks
    again for the rows from ``page_size`` onward, then from ``2 * page_size``,
    and so on. ``first`` is the caller's own 200 response for offset 0, as in
    :func:`read_linked_pages`, so the caller keeps ownership of authentication
    and of how a refused opening request is reported. ``request`` is called
    with each following offset and owns where that offset goes in the request;
    ``items_field`` is a dotted path, as in :func:`read_token_pages`.

    **A page shorter than** ``page_size`` **ends the collection.** There is no
    continuation to read the end from, and an offset-paged list fills every
    page but its last. That makes the rule only as good as ``page_size``: it
    must be the number of rows the request actually asks for, or a full page
    reads as the last one.
    """
    try:
        page = _rows_at(first.json(), items_field)
    except ValueError:
        logger.warning("connector.paging.first_page_unparseable", feed=feed)
        return []

    rows = list(page)
    for page_number in range(1, max_pages):
        if len(page) < page_size:
            return rows
        try:
            resp = await request(page_number * page_size)
        except httpx.HTTPError as exc:
            # Keep what was read, as in the other readers.
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
            page = _rows_at(resp.json(), items_field)
        except ValueError:
            logger.warning("connector.paging.next_page_unparseable", feed=feed, rows=len(rows))
            return rows
        rows.extend(page)

    if len(page) >= page_size:
        logger.warning(
            "connector.paging.page_cap_reached",
            feed=feed,
            pages=max_pages,
            rows=len(rows),
            detail="the window was not read to the end; rows beyond this point are not re-requested by a later poll",
        )
    return rows


def created_before(row: dict[str, Any], cutoff_ms: int) -> bool:
    """Is this row's ``created_at`` older than ``cutoff_ms``? An absent or unparseable stamp is not."""
    value = row.get("created_at")
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000 < cutoff_ms
    except ValueError:
        return False


def _array_rows(body: Any) -> list[dict[str, Any]]:
    return [row for row in body if isinstance(row, dict)] if isinstance(body, list) else []


def _same_origin_target(origin: httpx.URL, link: str) -> httpx.URL | None:
    """``link`` resolved against ``origin``, or None if it leaves that origin."""
    try:
        target = origin.join(link)
    except httpx.InvalidURL:
        return None
    return target if (target.scheme, target.host, target.port) == (origin.scheme, origin.host, origin.port) else None


async def read_link_header_pages(
    client: httpx.AsyncClient,
    first: httpx.Response,
    *,
    headers: dict[str, str],
    feed: str,
    stop_when: Callable[[list[dict[str, Any]]], bool] | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> list[dict[str, Any]]:
    """Every row of a JSON-array collection paged by an RFC 8288 ``Link`` header.

    The sibling of :func:`read_linked_pages` for vendors that put the link in
    the response headers and the rows at the top level of the body. ``first``
    is the caller's own 200 response, for the same reason as there.
    ``stop_when`` receives each non-empty page and ends the read when it answers
    True, which is how a newest-first collection with no server-side time filter
    stops once a page has passed the start of the window.

    Two rules are specific to this shape:

    * **An empty page ends the collection, even when it carries a next link.**
      This is the opposite of :func:`read_token_pages`, and it is what the
      vendor requires. Okta documents that a System Log request with no
      ``until`` has "an infinite number of pages" whose next link is "always
      present, even if there are no new events", and says to "continue this
      process until no events are returned".
    * **The link may not leave the origin of the opening request.** The egress
      guard in ``app/security/egress.py`` validates the URLs a tenant configures,
      not the ones a server answers with, and ``domain`` and ``gitlab_url`` are
      tenant-controlled. A server at a permitted address could otherwise answer
      ``Link: <http://169.254.169.254/...>; rel="next"`` and have this loop fetch
      it, with the vendor credential attached. A refused link is logged and ends
      the read with the rows already in hand.
    """

    def finished(page: list[dict[str, Any]]) -> bool:
        return not page or (stop_when is not None and stop_when(page))

    try:
        page = _array_rows(first.json())
    except ValueError:
        logger.warning("connector.paging.first_page_unparseable", feed=feed)
        return []

    rows = list(page)
    resp = first
    for _ in range(max_pages - 1):
        if finished(page):
            return rows
        link = resp.links.get("next", {}).get("url")
        if not link:
            return rows
        target = _same_origin_target(first.url, link)
        if target is None:
            logger.warning("connector.paging.next_link_refused", feed=feed, origin=first.url.host, rows=len(rows))
            return rows
        try:
            resp = await client.get(target, headers=headers)
        except httpx.HTTPError as exc:
            # Keep what was read, as in the other two readers.
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
            page = _array_rows(resp.json())
        except ValueError:
            logger.warning("connector.paging.next_page_unparseable", feed=feed, rows=len(rows))
            return rows
        rows.extend(page)

    if not finished(page) and resp.links.get("next"):
        logger.warning(
            "connector.paging.page_cap_reached",
            feed=feed,
            pages=max_pages,
            rows=len(rows),
            detail="the window was not read to the end; rows beyond this point are not re-requested by a later poll",
        )
    return rows
