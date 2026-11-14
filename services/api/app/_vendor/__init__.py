"""Vendored third-party / cross-service modules used by the API service.

This namespace exists so that modules owned by *other* services can be shipped
inside the ``aisoc-api`` Docker image without depending on the rest of the
monorepo being copied in. The build context for ``services/api/Dockerfile`` is
``./services/api``, which means anything under ``services/agents`` or
``services/fusion`` is **not** available at runtime — vendoring the bits we
actually consume is the simplest, most auditable way to keep the container
self-contained.

Current vendored modules:

* ``nl_query`` — natural-language → ES|QL/SPL/KQL translator owned by
  ``services/agents/app/nl_query/``. Kept in lockstep via
  ``scripts/sync_vendored_nl_query.py``; CI fails the build if the two trees
  drift.

* ``narrative`` — deterministic correlation-narrative builder owned by
  ``services/fusion/app/services/narrative.py``. Used by the API to lazily
  compute the narrative on first read for alerts whose ``narrative`` column
  is still ``NULL`` (e.g. legacy rows fused before the column existed). Kept
  in lockstep via ``scripts/sync_vendored_narrative.py``; CI fails the build
  if the two copies drift.

Do **not** import from this namespace directly outside of the dynamic loaders
in ``services/api/app/api/v1/endpoints/nl_query.py`` and
``services/api/app/services/narrative_loader.py``. The loaders resolve the
modules at runtime under collision-free names so they do not interfere with
the rest of the ``app`` package.
"""
