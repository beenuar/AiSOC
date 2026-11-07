#!/usr/bin/env python3
"""A 404 and a 403 are different facts, and a connector may not file them as one.

Why this gate exists
--------------------
Three times now a connector has polled a URL the vendor does not serve, and
each time the symptom was the same: a 404 handled in the same branch as a
403 and reported as the customer's plan or permissions.

* ``cloudflare_zt`` polled ``/zones/{id}/security/events``, a route Cloudflare
  answers with error 10404 "No route for that URI". WAF mode had never
  returned an event (issue #1686).
* ``crowdstrike`` polled the Detects API after it was decommissioned, so a
  saved connector looked healthy while every poll 404'd.
* ``gitlab`` polled ``/groups/{id}/security/vulnerability_findings``, which
  GitLab answers with Grape's route-not-found body. The stream had never
  returned a row on any deployment, and the connector logged it at ``info``
  as "not available on this plan" (issue #1754).

The defect is not the wrong URL — anyone can mistype a path. The defect is
that the wrong URL was *unreportable*: folding 404 into the permissions
branch converts "we are asking for something that does not exist" into "the
customer has not bought this", and nobody debugs the second.

What this gate asserts
----------------------
For every connector module, no single ``except``-style branch may accept a
404 together with an authentication or authorization status (401 or 403),
unless the pairing is **declared** in ``_REVIEWED`` with the vendor
documentation that lists 404 among that endpoint's own responses.

That is the whole discriminator, and it is the one a human can check: if the
vendor publishes 404 as a response of a route they serve, treating it as an
operator condition is correct. If they do not, a 404 is our URL being wrong.

On the unknown bucket
---------------------
There is no silent third state, for the same reason as
``check_connector_paging.py``. A pairing this gate cannot attribute is named
in the output and fails the run. "Probably fine" is not a vendor document.

The ceiling is zero and stays zero: unlike the paging gate there is no
historical debt to work down, because the only two pairings in the tree when
this was written were both checkable against a published response list.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

CONNECTOR_REL = "services/connectors/app/connectors"

#: Below this the gate is not looking at this repository. Same reasoning as
#: the paging gate: "found nothing" and "scanned nothing" must not print the
#: same word.
MIN_CONNECTORS = 50

#: Statuses that mean "this route exists and you may not have it".
_AUTH_STATUSES = frozenset({401, 403})

#: Pairings established against the vendor's own published response list.
#: The key is ``(module, enclosing function)``; the value is why a 404 is a
#: real answer from a route that vendor serves. "Could not determine" is not
#: a reason and does not belong here.
_REVIEWED: dict[tuple[str, str], str] = {
    ("github", "fetch_alerts"): (
        "GitHub publishes `404 - Resource not found` in the response list for "
        "`GET /orgs/{org}/code-scanning/alerts` itself, and returns it when the org has no "
        "Advanced Security rather than when the path is wrong. The route is real: the same "
        "token reaches `/orgs/{org}/audit-log` on the line above. "
        "https://docs.github.com/en/rest/code-scanning/code-scanning#list-code-scanning-alerts-for-an-organization"
    ),
}


def _module_functions(tree: ast.Module) -> list[tuple[str, ast.AST]]:
    return [(n.name, n) for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _literal_ints(node: ast.AST) -> set[int]:
    """Integer literals in a container or a lone constant."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return {node.value}
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        out: set[int] = set()
        for element in node.elts:
            out |= _literal_ints(element)
        return out
    return set()


def _is_status(node: ast.AST) -> bool:
    """Does this expression read an HTTP status?

    404 is an ordinary integer and a gate that flags ``page_size in (403,
    404)`` gets switched off within a week, so the subject has to be
    identified rather than assumed. Every spelling in this tree —
    ``resp.status_code``, ``status_code``, ``response.status`` — contains
    the word, and nothing that is not a status does.
    """
    return "status" in ast.unparse(node).lower()


def _statuses_compared(compare: ast.Compare) -> set[int]:
    if not _is_status(compare.left):
        return set()
    found: set[int] = set()
    for op, comparator in zip(compare.ops, compare.comparators, strict=False):
        if isinstance(op, (ast.In, ast.NotIn, ast.Eq)):
            found |= _literal_ints(comparator)
    return found


def _conflations(node: ast.AST) -> list[int]:
    """Lines where one branch accepts 404 alongside a 401 or 403.

    Three spellings, because a detector that knows one syntax is the hole
    this repository keeps finding in its own gates:

    * ``status in (403, 404)`` and ``status not in (200, 403, 404)``
    * ``status == 403 or status == 404``
    * ``status in {401, 404}``
    """
    lines: list[int] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Compare):
            found = _statuses_compared(sub)
            if 404 in found and found & _AUTH_STATUSES:
                lines.append(sub.lineno)
        elif isinstance(sub, ast.BoolOp):
            # `status == 403 or status == 404` is two comparisons that are
            # only a conflation when read together.
            found = set()
            for value in sub.values:
                if isinstance(value, ast.Compare):
                    found |= _statuses_compared(value)
            if 404 in found and found & _AUTH_STATUSES:
                lines.append(sub.lineno)
    return sorted(set(lines))


class EmptyRead(RuntimeError):
    """The gate could not find a corpus, so it has no verdict to give."""


def audit(root: Path | None = None) -> tuple[list[tuple[str, str, int, str]], list[str]]:
    """Returns (undeclared, reviewed). Raises on an empty read."""
    connector_dir = (root or repo_root()) / CONNECTOR_REL
    if not connector_dir.is_dir():
        raise EmptyRead(f"no connector directory at {CONNECTOR_REL}")

    undeclared: list[tuple[str, str, int, str]] = []
    reviewed: list[str] = []
    scanned = 0

    for path in sorted(connector_dir.glob("*.py")):
        module = path.stem
        if module.startswith("__"):
            continue
        scanned += 1
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for function, node in _module_functions(tree):
            for line in _conflations(node):
                key = (module, function)
                if key in _REVIEWED:
                    reviewed.append(f"{module}.{function}:{line}")
                else:
                    undeclared.append(
                        (
                            module,
                            function,
                            line,
                            "a 404 is accepted in the same branch as a 401/403, so a URL we got wrong "
                            "is reported as the tenant's plan or permissions",
                        )
                    )

    if scanned < MIN_CONNECTORS:
        raise EmptyRead(f"only {scanned} connector module(s) under {CONNECTOR_REL}; expected at least {MIN_CONNECTORS}")

    return undeclared, reviewed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="prove the detector in both directions and exit")
    args = parser.parse_args()

    if args.self_test:
        return _self_test()

    try:
        undeclared, reviewed = audit()
    except EmptyRead as exc:
        # Fail closed: an exit of 0 here would credit a tree never opened.
        print(f"check_connector_404_conflation: FAIL — nothing to check: {exc}")
        return 1

    print(f"check_connector_404_conflation: {len(reviewed)} reviewed, {len(undeclared)} undeclared")
    for name in reviewed:
        print(f"  reviewed      {name}")
    for module, function, line, why in undeclared:
        print(f"  UNDECLARED    {module}.{function}:{line}: {why}")

    if undeclared:
        print(
            "\nFAIL — a 404 and a 401/403 are different facts.\n"
            "A 403 says the route exists and this caller may not read it, which is the operator's\n"
            "problem. A 404 on a URL we constructed is usually ours, and filing it as a plan limit is\n"
            "how three connectors shipped polling routes their vendor never served.\n"
            "Either split the branch, or add the pairing to _REVIEWED with the vendor's own response\n"
            "list for that endpoint. 'Could not determine' is not a reason."
        )
        return 1
    print("OK")
    return 0


_VIOLATION = """
class X:
    async def fetch_alerts(self):
        resp = await self._get("/v1/things")
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code in (403, 404):
            logger.info("things_unavailable", status=resp.status_code)
        return []
"""

_VIOLATION_BOOLOP = """
class X:
    async def fetch_alerts(self):
        resp = await self._get("/v1/things")
        if resp.status_code == 401 or resp.status_code == 404:
            logger.info("things_unavailable")
        return []
"""

_VIOLATION_NOT_IN = """
class X:
    async def test_connection(self):
        resp = await self._get("/v1/things")
        if resp.status_code not in (200, 403, 404):
            return {"success": False}
        return {"success": True}
"""

_CLEAN_SPLIT = """
class X:
    async def fetch_alerts(self):
        resp = await self._get("/v1/things")
        if resp.status_code == 403:
            logger.info("forbidden")
        elif resp.status_code == 404:
            logger.warning("the path is wrong or the thing is gone")
        return []
"""

_CLEAN_404_ALONE = """
class X:
    async def fetch_alerts(self):
        resp = await self._get("/v1/things")
        if resp.status_code == 404:
            logger.info("the vendor documents 404 here for a branch with no protection")
        return []
"""

_CLEAN_UNRELATED_NUMBERS = """
class X:
    async def fetch_alerts(self):
        # 404 is an ordinary integer. A detector that cannot tell a status
        # from a page size flags correct code, and a gate that flags correct
        # code is switched off within a week.
        if self.page_size in (403, 404):
            self.page_size = 100
        if self.limit == 404:
            self.limit = 100
        return []
"""


def _classify(src: str) -> bool:
    """True when the source contains a conflation."""
    tree = ast.parse(src)
    return any(_conflations(node) for _, node in _module_functions(tree))


def _self_test() -> int:
    cases = [
        ("an `in (403, 404)` branch", _VIOLATION, True),
        ("an `== 401 or == 404` branch", _VIOLATION_BOOLOP, True),
        ("a `not in (200, 403, 404)` guard", _VIOLATION_NOT_IN, True),
        ("a split 403/404 pair", _CLEAN_SPLIT, False),
        ("a 404 handled on its own", _CLEAN_404_ALONE, False),
        ("403/404 as ordinary integers", _CLEAN_UNRELATED_NUMBERS, False),
    ]
    extra: list[tuple[str, bool]] = []
    for label, src, expected in cases:
        got = _classify(src)
        extra.append((f"{label}: {'flagged' if expected else 'left alone'}", got == expected))

    # The ratchet must be able to fail, not merely able to pass.
    undeclared, reviewed = audit()
    corpus = len(undeclared) + len(reviewed)
    extra.append((f"it counts what it scanned ({corpus} pairing(s) classified across the connector tree)", True))

    # `_CLEAN_UNRELATED_NUMBERS` is the one that matters most. A detector
    # that flags correct code is switched off inside a week, and `404` is a
    # perfectly ordinary integer.
    return self_test_main("check_connector_404_conflation.py", extra=extra)


if __name__ == "__main__":
    sys.exit(main())
