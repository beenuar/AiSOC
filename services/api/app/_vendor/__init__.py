"""Vendored third-party / cross-service modules used by the API service.

This namespace exists so that modules owned by *other* services can be shipped
inside the ``aisoc-api`` Docker image without depending on the rest of the
monorepo being copied in. The build context for ``services/api/Dockerfile`` is
``./services/api``, which means anything under ``services/agents`` is **not**
available at runtime — vendoring the bits we actually consume is the simplest,
most auditable way to keep the container self-contained.

Current vendored modules:

* ``nl_query`` — natural-language → ES|QL/SPL/KQL translator owned by
  ``services/agents/app/nl_query/``. Kept in lockstep via
  ``scripts/sync_vendored_nl_query.py``; CI fails the build if the two trees
  drift.

Do **not** import from this namespace directly outside of
``services/api/app/api/v1/endpoints/nl_query.py``. The dynamic loader in that
endpoint resolves the module at runtime under a collision-free name so it does
not interfere with the rest of the ``app`` package.
"""
