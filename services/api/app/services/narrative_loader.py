"""Dynamic loader for the correlation-narrative builder.

The narrative builder lives canonically in
``services/fusion/app/services/narrative.py`` and is consumed by both:

* the **fusion service**, at fusion time, to populate
  ``FusedAlert.narrative`` deterministically before publishing the alert to
  Kafka; and
* the **API service**, lazily, when ``GET /alerts/{id}`` is asked for an
  alert whose ``narrative`` column is still ``NULL`` (e.g. legacy rows that
  were fused before the column existed).

Because the ``aisoc-api`` Docker image is built with ``services/api`` as its
build context, anything under ``services/fusion`` is **not** available at
runtime. ``scripts/sync_vendored_narrative.py`` byte-mirrors the source file
into ``services/api/app/_vendor/narrative.py``; CI fails the build if the two
files drift.

This module loads that vendored file under a collision-free name
(``aisoc_fusion_narrative``) so it does not interfere with anything else in
the ``app`` package. It also falls back to the source-of-truth file at
``services/fusion/app/services/narrative.py`` for local development where
the API runs outside of Docker against a checked-out monorepo.

Public re-exports (one-to-one with ``narrative.py``):

* :data:`build_narrative` — pure function ``(NarrativeInputs) -> str``.
* :class:`NarrativeInputs` — dataclass of all builder inputs.
* :class:`NarrativeFactor` — single confidence-factor entry inside
  ``NarrativeInputs.confidence_factors``.

Determinism guarantee
---------------------
``build_narrative`` is a pure, deterministic function. Calling it twice with
the same ``NarrativeInputs`` returns the same byte-for-byte string. The
caller (the alerts endpoint) safely persists the result on the row so we
only pay the build cost once per alert.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Static-only re-export so type checkers can see the dataclass fields and
    # function signature. At runtime we load the module dynamically (see
    # ``_load_narrative_module`` below) to avoid colliding with any other
    # ``narrative`` module in the API service.
    from services.fusion.app.services.narrative import (  # noqa: F401
        NarrativeFactor,
        NarrativeInputs,
        build_narrative,
    )


_MODULE_NAME = "aisoc_fusion_narrative"


def _candidate_narrative_files() -> list[Path]:
    """Return ordered list of files that may contain the narrative module.

    The first entry is the in-tree vendored copy under
    ``services/api/app/_vendor/narrative.py`` — this is what ships inside
    the ``aisoc-api`` Docker image. The second entry is the source-of-truth
    file at ``services/fusion/app/services/narrative.py``, used during local
    development when the API runs outside of Docker.
    """
    here = Path(__file__).resolve()
    candidates: list[Path] = []

    # 1) Vendored copy — lives at ``<api-app-root>/_vendor/narrative.py``.
    #    parents[2] resolves to the ``app`` directory: services → app.
    try:
        api_app_root = here.parents[1]
        vendored = api_app_root / "_vendor" / "narrative.py"
        if vendored.is_file():
            candidates.append(vendored)
    except IndexError:  # pragma: no cover - defensive
        pass

    # 2) Source-of-truth file — walk up the repo until we find it.
    for ancestor in here.parents:
        source = ancestor / "services" / "fusion" / "app" / "services" / "narrative.py"
        if source.is_file():
            candidates.append(source)
            break

    return candidates


def _load_narrative_module() -> ModuleType:
    """Load the narrative builder under a collision-free module name.

    Prefers the in-tree vendored copy (so the module is available inside the
    Dockerized ``aisoc-api`` service whose build context excludes
    ``services/fusion``) and falls back to the source-of-truth file at
    ``services/fusion/app/services/narrative.py`` for local non-Docker
    development.
    """
    if _MODULE_NAME in sys.modules:
        return sys.modules[_MODULE_NAME]

    candidates = _candidate_narrative_files()
    if not candidates:
        raise ImportError(
            "Correlation-narrative module not found — expected either "
            "services/api/app/_vendor/narrative.py (vendored) or "
            "services/fusion/app/services/narrative.py (source). Run "
            "`python scripts/sync_vendored_narrative.py` to regenerate the "
            "vendored copy."
        )

    narrative_file = candidates[0]
    spec = importlib.util.spec_from_file_location(_MODULE_NAME, narrative_file)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"Could not build spec for {narrative_file}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


_narrative = _load_narrative_module()

# Re-export the public API at module scope so callers can write
# ``from app.services.narrative_loader import build_narrative`` instead of
# fishing through the dynamically loaded module.
if not TYPE_CHECKING:
    build_narrative = _narrative.build_narrative
    NarrativeInputs = _narrative.NarrativeInputs
    NarrativeFactor = _narrative.NarrativeFactor


__all__ = ["NarrativeFactor", "NarrativeInputs", "build_narrative"]
