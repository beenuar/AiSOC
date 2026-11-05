#!/usr/bin/env python3
"""Every connector that polls a capped vendor collection must read it to the end.

Why this gate exists
--------------------
Five connectors shipped the same defect inside two days: ask a vendor for a
capped page, read the first response, and stop. On its own that is a
performance bug. Here it is data loss, because of how the poll window is
built:

``fetch_alerts`` derives its window from the clock as
``[now - since_seconds, now]``, and the scheduler passes the instance's poll
interval as ``since_seconds``. Consecutive windows therefore abut exactly,
and nothing re-reads an earlier one. ``BaseConnector.apply_checkpoint()``
de-duplicates rows that were *already returned*; it never widens a later
request, so it cannot recover a row the vendor never handed over. Whatever
did not fit in the page falls below the next window's lower bound and is
never requested again.

Worse, most of these connectors order newest-first, so the rows discarded are
the *oldest* in the window — the beginning of whatever burst overflowed it,
which is the part an investigation needs.

What this gate asserts
----------------------
For every connector with a ``fetch_alerts`` that makes an HTTP request, one
of the following must be true:

1. the code reachable from ``fetch_alerts`` follows a continuation — either
   through the shared helpers in ``app/connectors/_paging.py`` or through its
   own loop over a vendor cursor; or
2. the connector is **declared** in ``_REVIEWED`` with a reason, because a
   human established against the vendor's documentation that it does not need
   one.

Anything else is unclassified and is counted against ``MAX_UNCLASSIFIED``.

On the unknown bucket
---------------------
The temptation when writing this was to let "no page cap found" mean "fine".
That is the defect this repository keeps finding in its own gates: a checker
whose *unknown* answer is a pass reports OK over exactly the cases it could
not analyse. "I could not find a cap" and "this vendor returns everything"
are different statements, and only the second is a reason.

So there is no silent third state. A connector that neither pages nor carries
a reviewed reason is **named in the output on every run** and counted.
``MAX_UNCLASSIFIED`` is not a target, it is a debt balance: it may only be
lowered, and lowering it means someone read the vendor's documentation and
wrote down what they found. A new connector in that state reds the build,
which is the property that matters.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import BARE, SKELETON, refuses_an_empty_tree, repo_root  # noqa: E402

CONNECTOR_REL = "services/connectors/app/connectors"

#: Below this, the gate is not looking at this repository. The connector set
#: has been in the high eighties for months and only grows, so a scan that
#: finds a handful has been pointed at a scratch tree, a partial checkout or
#: a moved directory. Reporting OK there would be the exact defect this gate
#: is about one level up: "found nothing" and "scanned nothing" must not
#: print the same word.
MIN_CONNECTORS = 50

#: Request parameters that cap how much of a window one response may carry.
_CAP_KEYS = {
    "$top",
    "count",
    "first",
    "limit",
    "max_count",
    "max_results",
    "maxrecords",
    "maxresults",
    "page[limit]",
    "page_size",
    "pagesize",
    "per_page",
    "rows",
    "search_to",
    "size",
    "sysparm_limit",
    "top",
}

#: Names a response uses to say "there is more". Matched as substrings because
#: vendors spell the same idea a dozen ways and a new spelling must not read
#: as "this connector does not page".
_CONTINUATION = (
    "nextlink",
    "nextpagetoken",
    "next_page_token",
    "nexttoken",
    "next_token",
    "nextcursor",
    "next_cursor",
    "next_page",
    "nextpagenumber",
    "next_stream_position",
    "skiptoken",
    "pagetoken",
    "continuation",
    "cursor",
    "has_more",
    "hasnextpage",
    "endcursor",
    "paging",
    "result_info",
    "offset",
    "stream_position",
    "search_after",
    "scroll_id",
)

#: The shared helpers. Calling one of these *is* following the contract.
_PAGING_HELPERS = {"read_linked_pages", "read_token_pages"}

#: Connectors established, against the vendor's own documentation, not to need
#: a continuation on their alert-polling path. Each entry is a reason someone
#: can check, not a silencer — "could not determine" is not a reason and does
#: not belong here.
_REVIEWED: dict[str, str] = {
    "auditd": "reads a local file by byte cursor; `since_seconds` is explicitly unused, so there is no vendor window to truncate.",
    "kubernetes_audit": "file_tail mode reads by byte cursor and webhook mode is pushed to; neither asks a vendor for a page.",
    "azure_event_hubs": (
        "deliberate exception, pinned by test. It re-lists a never-drained blob container from the start on every poll and "
        "de-duplicates by identity; a bounded identity set would make it re-emit forever. Do not 'fix' by symmetry."
    ),
}


def _module_functions(tree: ast.Module) -> dict[str, ast.AST]:
    out: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[node.name] = node
    return out


def _called_names(node: ast.AST) -> set[str]:
    """Function names this node calls, by bare name and by ``self.name``."""
    names: set[str] = set()
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        func = sub.func
        if isinstance(func, ast.Name):
            names.add(func.id)
        elif isinstance(func, ast.Attribute):
            names.add(func.attr)
    return names


def _reachable(entry: str, funcs: dict[str, ast.AST]) -> list[ast.AST]:
    """``entry`` plus everything in this module it can reach."""
    seen: set[str] = set()
    stack = [entry]
    out: list[ast.AST] = []
    while stack:
        name = stack.pop()
        if name in seen or name not in funcs:
            continue
        seen.add(name)
        node = funcs[name]
        out.append(node)
        stack.extend(n for n in _called_names(node) if n in funcs and n not in seen)
    return out


def _makes_http_request(nodes: list[ast.AST]) -> bool:
    for node in nodes:
        for sub in ast.walk(node):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Attribute)
                and sub.func.attr in {"get", "post", "put", "request"}
                and isinstance(sub.func.value, ast.Name | ast.Attribute)
            ):
                # `client.get(...)` with a url-ish first argument.
                if sub.args or any(k.arg in {"params", "json", "headers", "data"} for k in sub.keywords):
                    return True
    return False


def _requests_a_cap(nodes: list[ast.AST]) -> bool:
    for node in nodes:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Dict):
                for key in sub.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, str) and key.value.lower() in _CAP_KEYS:
                        return True
            if isinstance(sub, ast.keyword) and sub.arg and sub.arg.lower() in _CAP_KEYS:
                return True
    return False


_Loop = ast.For | ast.AsyncFor | ast.While


def _is_page_shaped_loop(node: _Loop) -> bool:
    """A loop that re-requests, as opposed to one that iterates feeds.

    This is the discriminator the first version of this gate got wrong, in the
    direction that matters. Matching a vocabulary of cursor names missed every
    connector that pages by page number or offset — Auth0, CrowdStrike, Cisco
    Umbrella and a dozen others page correctly and carry no token at all — and
    a gate that flags correct code is switched off within a week.

    Loop *shape* separates the two cleanly. ``while`` and ``for _ in
    range(...)`` bound a number of attempts, which is what paging looks like.
    ``for app_name in _DEFAULT_APPS`` walks a fixed set of feeds and issues one
    request per feed, which is not paging — and that distinction is load
    bearing, because the Google Workspace connector had exactly that shape
    while reading one page per application.
    """
    if isinstance(node, ast.While):
        return True
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Name) and node.iter.func.id == "range"
    return False


def _follows_a_continuation(nodes: list[ast.AST], source: str) -> bool:
    """True when the reachable code reads past the first page."""
    for node in nodes:
        if _PAGING_HELPERS & _called_names(node):
            return True
        for sub in ast.walk(node):
            # The isinstance is what narrows `sub` from `ast.AST` for the type
            # checker; `_is_page_shaped_loop` then answers the question this
            # gate actually cares about, which is whether the loop re-requests.
            if not isinstance(sub, (ast.For, ast.AsyncFor, ast.While)) or not _is_page_shaped_loop(sub):
                continue
            body_nodes: list[ast.AST] = list(sub.body)
            if _makes_http_request(body_nodes):
                return True
            body = "\n".join(ast.unparse(stmt) for stmt in body_nodes).lower()
            if any(token in body for token in _CONTINUATION):
                return True
    # A boto3 paginator is the vendor SDK doing the same job — but only when
    # it is allowed to run to the end. `MaxItems` stops the paginator early
    # and is as silent as reading one page, so it is not credited here.
    return "get_paginator" in source and "MaxItems" not in source


class EmptyRead(RuntimeError):
    """The gate could not find a corpus, so it has no verdict to give."""


def audit(root: Path | None = None) -> tuple[list[tuple[str, str]], list[str], list[str]]:
    """Returns (unclassified, paging, reviewed). Raises on an empty read."""
    connector_dir = (root or repo_root()) / CONNECTOR_REL
    if not connector_dir.is_dir():
        raise EmptyRead(f"no connector directory at {CONNECTOR_REL}")

    unclassified: list[tuple[str, str]] = []
    paging: list[str] = []
    reviewed: list[str] = []
    scanned = 0

    for path in sorted(connector_dir.glob("*.py")):
        name = path.stem
        if name.startswith("__") or name == "_paging":
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        scanned += 1
        funcs = _module_functions(tree)
        if "fetch_alerts" not in funcs:
            continue
        nodes = _reachable("fetch_alerts", funcs)
        if not _makes_http_request(nodes):
            # Not an HTTP poller. Still must be accounted for, never assumed.
            if name in _REVIEWED:
                reviewed.append(name)
            else:
                unclassified.append((name, "fetch_alerts makes no recognised HTTP request and carries no reviewed reason"))
            continue
        if _follows_a_continuation(nodes, source):
            paging.append(name)
            continue
        if name in _REVIEWED:
            reviewed.append(name)
            continue
        detail = (
            "requests a capped page and never follows a continuation"
            if _requests_a_cap(nodes)
            else "polls a vendor collection without following a continuation, and no reviewed reason says the vendor returns all of it"
        )
        unclassified.append((name, detail))

    if scanned < MIN_CONNECTORS:
        raise EmptyRead(f"only {scanned} connector module(s) under {CONNECTOR_REL}; expected at least {MIN_CONNECTORS}")

    return unclassified, paging, reviewed


#: Not a target, a debt balance. Lower it by establishing what a connector's
#: vendor actually does and recording that in `_REVIEWED`, or by making the
#: connector follow the continuation. It must never be raised: a new connector
#: that polls a vendor collection without reading it to the end is the defect
#: this gate exists to stop.
MAX_UNCLASSIFIED = 59


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-unclassified", type=int, default=MAX_UNCLASSIFIED)
    parser.add_argument("--self-test", action="store_true", help="prove the detector in both directions and exit")
    args = parser.parse_args()

    if args.self_test:
        return _self_test()

    try:
        unclassified, paging, reviewed = audit()
    except EmptyRead as exc:
        # Fail closed. An exit status of 0 here would credit a tree this gate
        # never opened, which is indistinguishable from a clean one.
        print(f"check_connector_paging: FAIL — nothing to check: {exc}")
        return 1
    print(f"check_connector_paging: {len(paging)} follow a continuation, {len(reviewed)} reviewed, {len(unclassified)} unclassified")
    for name, why in unclassified:
        print(f"  UNCLASSIFIED  {name}: {why}")

    if len(unclassified) > args.max_unclassified:
        print(
            f"\nFAIL — {len(unclassified)} unclassified, ceiling is {args.max_unclassified}.\n"
            "A connector's poll window is contiguous, so a page it does not read is a page nothing reads later.\n"
            "Either follow the vendor's continuation, or add the connector to _REVIEWED with the vendor\n"
            "documentation that says it returns the whole window. 'Could not determine' is not a reason."
        )
        return 1
    print("OK")
    return 0


_VIOLATION = """
import httpx
class X:
    async def fetch_alerts(self, since_seconds: int = 300):
        async with httpx.AsyncClient() as client:
            resp = await client.get("https://v/api", params={"limit": 100, "since": "x"})
            return resp.json().get("data", [])
"""

_CLEAN_OWN_LOOP = """
import httpx
class X:
    async def fetch_alerts(self, since_seconds: int = 300):
        out, cursor = [], None
        async with httpx.AsyncClient() as client:
            for _ in range(25):
                params = {"limit": 100}
                if cursor:
                    params["cursor"] = cursor
                resp = await client.get("https://v/api", params=params)
                body = resp.json()
                out.extend(body.get("data") or [])
                cursor = body.get("next_cursor")
                if not cursor:
                    break
        return out
"""

_CLEAN_HELPER = """
import httpx
from app.connectors._paging import read_token_pages
class X:
    async def fetch_alerts(self, since_seconds: int = 300):
        async with httpx.AsyncClient() as client:
            async def page(token):
                return await client.get("https://v/api", params={"limit": 100, "pageToken": token})
            return await read_token_pages(request=page, items_field="data", feed="f")
"""

_CLEAN_INDIRECT = """
import httpx
class X:
    async def fetch_alerts(self, since_seconds: int = 300):
        return await self._paginate()

    async def _paginate(self):
        out, page = [], 1
        async with httpx.AsyncClient() as client:
            for _ in range(25):
                resp = await client.get("https://v/api", params={"per_page": 100, "page": page})
                body = resp.json()
                out.extend(body.get("data") or [])
                nxt = (body.get("meta") or {}).get("next_page")
                if not nxt:
                    break
                page = nxt
        return out
"""


def _classify_source(src: str) -> str:
    tree = ast.parse(src)
    funcs = _module_functions(tree)
    nodes = _reachable("fetch_alerts", funcs)
    if not _makes_http_request(nodes):
        return "no-http"
    return "pages" if _follows_a_continuation(nodes, src) else "unclassified"


def _self_test() -> int:
    """Both directions: the detector must fire, and must not over-fire."""
    cases = [
        ("a capped single-page read", _VIOLATION, "unclassified"),
        ("its own cursor loop", _CLEAN_OWN_LOOP, "pages"),
        ("the shared token helper", _CLEAN_HELPER, "pages"),
        ("a loop one call away from fetch_alerts", _CLEAN_INDIRECT, "pages"),
    ]
    failures = []
    for label, src, expected in cases:
        got = _classify_source(src)
        status = "ok" if got == expected else "FAIL"
        print(f"  [{status}] {label}: expected {expected}, got {got}")
        if got != expected:
            failures.append(label)

    # The ratchet must be able to fail, not merely be able to pass.
    unclassified, paging, reviewed = audit()
    corpus = len(unclassified) + len(paging) + len(reviewed)
    print(f"  [{'ok' if corpus >= MIN_CONNECTORS else 'FAIL'}] it counts what it scanned ({corpus} connectors classified)")
    if corpus < MIN_CONNECTORS:
        failures.append("corpus too small")

    # And it must refuse a tree with no connectors rather than calling it
    # clean — the same defect this gate detects, one level up. Proven with
    # the shared helper so it is the same question CI asks, against both of
    # the empty shapes CI builds.
    for shape in (BARE, SKELETON):
        refused, detail = refuses_an_empty_tree("check_connector_paging.py", shape=shape)
        print(f"  [{'ok' if refused else 'FAIL'}] a {shape} tree is refused, not reported clean: {detail.splitlines()[0]}")
        if not refused:
            failures.append(f"{shape} tree not refused")

    if failures:
        print(f"self-test FAILED: {failures}")
        return 1
    print("self-test OK — the detector fires on the defect and stays quiet on all three correct shapes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
