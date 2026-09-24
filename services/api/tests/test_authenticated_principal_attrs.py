"""No route may read an attribute the authenticated principal does not have.

`get_current_user` returns :class:`app.api.v1.deps.CurrentUser`, whose
identifier is ``user_id``. Sixteen handlers across seven modules read
``current_user.id`` instead, so every mutating route that stamps "who did
this" answered ``500 Internal Server Error``: creating a report template,
creating an operator organisation, granting a tenant, watchlisting a profile,
acknowledging an indicator, publishing a replay, suppressing a finding. The
MSSP portfolio surface was unreachable in both directions — the aggregate
500'd, and so did the only route that can create the organisation it
aggregates over.

Two things let that ship:

* **The annotation lied.** Thirty-plus handlers declared
  ``current_user: User`` while the dependency returns ``CurrentUser``, so a
  type checker was told the attribute existed.
* **The tests used the other type.** `resolve_portfolio_scope` was exercised
  with an ORM ``User`` fetched from the test database, which really does have
  ``.id``. A passing test on the wrong object is indistinguishable from a
  working feature.

A gate is cheaper than remembering. This one reads the endpoint sources and
fails on any attribute access against a name bound to the authenticated
principal that ``CurrentUser`` does not define, which catches the next
instance whether or not it is annotated honestly.
"""

from __future__ import annotations

import ast
import pathlib

from app.api.v1.deps import CurrentUser

ENDPOINTS = pathlib.Path(__file__).resolve().parents[1] / "app" / "api" / "v1" / "endpoints"

# Names the codebase binds to the resolved principal.
PRINCIPAL_NAMES = {"current_user", "_user", "user", "principal"}

# The dependency callables that produce a `CurrentUser`.
PRINCIPAL_DEPS = {"get_current_user", "require_permission", "AuthUser"}


def _principal_attributes() -> set[str]:
    """Everything a `CurrentUser` actually exposes, read off the class."""
    probe = CurrentUser(
        user_id=__import__("uuid").uuid4(),
        tenant_id=__import__("uuid").uuid4(),
        role="admin",
        email="probe@example.com",
    )
    return {a for a in dir(probe) if not a.startswith("__")}


def _principal_locals(fn: ast.AST) -> set[str]:
    """Parameter names in ``fn`` bound to the authenticated principal."""
    bound: set[str] = set()
    args = getattr(fn, "args", None)
    if args is None:
        return bound
    every = list(args.args) + list(args.kwonlyargs)
    defaults = list(args.defaults) + [d for d in args.kw_defaults if d is not None]
    rendered_defaults = " ".join(ast.unparse(d) for d in defaults)
    for arg in every:
        if arg.arg not in PRINCIPAL_NAMES:
            continue
        annotation = ast.unparse(arg.annotation) if arg.annotation else ""
        blob = f"{annotation} {rendered_defaults}"
        if any(dep in blob for dep in PRINCIPAL_DEPS):
            bound.add(arg.arg)
    return bound


def test_no_handler_reads_an_attribute_the_principal_lacks() -> None:
    allowed = _principal_attributes()
    assert "user_id" in allowed and "id" not in allowed, "premise changed; revisit this gate"

    offenders: list[str] = []
    for path in sorted(ENDPOINTS.glob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            bound = _principal_locals(fn)
            if not bound:
                continue
            for node in ast.walk(fn):
                if (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id in bound
                    and node.attr not in allowed
                ):
                    offenders.append(f"{path.name}:{node.lineno} {node.value.id}.{node.attr}")

    assert not offenders, "authenticated principal has no such attribute:\n  " + "\n  ".join(offenders)


def test_the_gate_would_catch_the_defect_it_was_written_for() -> None:
    """A gate that cannot fail is decorative. Feed it the original shape."""
    source = (
        "async def create_template(\n"
        "    current_user: CurrentUser = Depends(get_current_user),\n"
        "):\n"
        "    return ReportTemplate(created_by=current_user.id)\n"
    )
    tree = ast.parse(source)
    fn = tree.body[0]
    bound = _principal_locals(fn)
    assert bound == {"current_user"}
    bad = [
        n.attr
        for n in ast.walk(fn)
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id in bound and n.attr not in _principal_attributes()
    ]
    assert bad == ["id"]
