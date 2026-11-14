"""The copilot router must mount without the full tool-validation stack.

``tests/isolation/test_route_auth_default_deny.py`` imports this router to
prove default-deny auth. A module-level import of ``app.tools.copilot`` drags
in ``jsonschema`` before any handler runs, which the isolation job does not
install, so the gate errors at setup instead of testing auth.
"""

from __future__ import annotations

import importlib.abc
import sys
from collections.abc import Sequence
from types import ModuleType

import pytest


def test_copilot_router_import_does_not_require_jsonschema(monkeypatch: pytest.MonkeyPatch) -> None:
    sys.modules.pop("jsonschema", None)

    # Subclassing MetaPathFinder is what makes the object a valid member of
    # `sys.meta_path` to the type checker, not just at runtime — and the
    # override must carry the ABC's own signature.
    class BlockJsonschema(importlib.abc.MetaPathFinder):
        def find_spec(
            self,
            fullname: str,
            path: Sequence[str] | None = None,
            target: ModuleType | None = None,
        ) -> None:
            if fullname == "jsonschema" or fullname.startswith("jsonschema."):
                raise ModuleNotFoundError("jsonschema blocked for import-boundary test")
            return None

    finder = BlockJsonschema()
    sys.meta_path.insert(0, finder)
    try:
        from app.api import copilot as mod  # noqa: PLC0415

        assert mod.router.dependencies, "copilot router must default-deny before handlers run"
    finally:
        sys.meta_path.remove(finder)
