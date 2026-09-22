"""No literal route may be shadowed by an earlier parameterised route.

FastAPI matches routes in registration order. If ``GET /{asset_id}`` is
registered before ``GET /vulnerabilities``, then a request for
``/assets/vulnerabilities`` is matched by the first route, fails to parse
"vulnerabilities" as a UUID, and returns 422 — the literal handler is simply
unreachable, and nothing in CI noticed because both routes exist and both have
tests that call them directly.

That is exactly what had happened to ``GET /api/v1/assets/vulnerabilities``.

This is a generic structural check rather than a test of one endpoint, because
the failure mode is easy to reintroduce and invisible in review: the two route
declarations are usually tens of lines apart and each looks correct on its own.
"""

from __future__ import annotations

import pytest
from fastapi.routing import APIRoute


#: A path segment that is a literal, not a ``{param}`` placeholder.
def _segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s]


def _is_param(segment: str) -> bool:
    return segment.startswith("{") and segment.endswith("}")


def _shadows(earlier: str, later: str) -> bool:
    """True if a request for ``later`` would be captured by ``earlier``.

    Only meaningful when the two have the same segment count and every
    differing segment in ``earlier`` is a parameter.
    """
    a, b = _segments(earlier), _segments(later)
    if len(a) != len(b):
        return False
    saw_param_over_literal = False
    for seg_a, seg_b in zip(a, b, strict=True):
        if seg_a == seg_b:
            continue
        if _is_param(seg_a) and not _is_param(seg_b):
            saw_param_over_literal = True
            continue
        return False
    return saw_param_over_literal


def test_no_literal_route_is_shadowed_by_an_earlier_parameterised_route():
    # Importing the app pulls the full driver stack (neo4j, clickhouse, ...).
    # CI installs those; a bare checkout may not, and the helper tests below
    # still give useful signal there.
    app = pytest.importorskip("app.main", reason="full app dependencies not installed").app
    routes = [r for r in app.routes if isinstance(r, APIRoute)]

    problems: list[str] = []
    for i, later in enumerate(routes):
        for earlier in routes[:i]:
            shared_methods = earlier.methods & later.methods
            if not shared_methods:
                continue
            if _shadows(earlier.path, later.path):
                problems.append(
                    f"{sorted(shared_methods)} {later.path} is unreachable: "
                    f"{earlier.path} is registered first and will match it. "
                    f"Move the literal route above the parameterised one."
                )

    assert not problems, "shadowed routes found:\n  " + "\n  ".join(problems)


@pytest.mark.parametrize(
    ("earlier", "later", "expected"),
    [
        ("/assets/{asset_id}", "/assets/vulnerabilities", True),
        ("/hunts/{hunt_id}", "/hunts/runs", True),
        # Different arity cannot shadow.
        ("/assets/{asset_id}", "/assets/{asset_id}/vulnerabilities", False),
        # Literal-before-literal is fine.
        ("/assets/summary", "/assets/vulnerabilities", False),
        # A parameter in the *later* path is not shadowed by a literal.
        ("/assets/vulnerabilities", "/assets/{asset_id}", False),
    ],
)
def test_shadow_detection_itself(earlier: str, later: str, expected: bool):
    """The helper has to be right or the gate above is worthless."""
    assert _shadows(earlier, later) is expected
