"""Every tenant-scoped route carries an auth dependency (GHSA-grv9-vcqp-f37v).

The advisory's own framework-level method, kept as the regression gate: walk
the dependency table FastAPI builds and refuse any route that names a tenant
in its path or parameters while carrying zero dependencies. The two region
reads were exactly that — their sibling PUT carried ``require_tenant``, the
reads carried nothing, and an unauthenticated caller could read any tenant's
home region and migration audit trail.

FastAPI versions that defer router flattening expose ``_IncludedRouter``
wrappers on ``app.routes``; the walk unwraps them, and the test refuses to
report a clean verdict over a table it could not actually enumerate.
"""

from __future__ import annotations


def _walk(routes):
    for route in routes:
        if type(route).__name__ == "_IncludedRouter":
            yield from _walk(route.original_router.routes)
        else:
            yield route


def main() -> int:
    from app.main import app

    flagged: list[str] = []
    walked = 0
    for route in _walk(app.routes):
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        walked += 1
        path = getattr(route, "path", "")
        tenant_scoped = (
            "{tenant_id}" in path
            or any(p.name == "tenant_id" for p in dependant.path_params)
            or any(q.name == "tenant_id" for q in dependant.query_params)
        )
        if tenant_scoped and not dependant.dependencies:
            methods = ",".join(sorted(m for m in (getattr(route, "methods", []) or []) if m != "HEAD"))
            flagged.append(f"{methods} {path}")

    if walked < 100:
        print(f"FAIL: only {walked} API routes enumerated — the walk no longer sees the app's routers, so a clean verdict would be vacuous.")
        return 1
    if flagged:
        print(f"FAIL: {len(flagged)} tenant-scoped route(s) carry no auth dependency (GHSA-grv9-vcqp-f37v class):")
        for line in flagged:
            print(f"  {line}")
        return 1
    print(f"OK: {walked} API routes walked; every tenant-scoped route carries at least one dependency.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
