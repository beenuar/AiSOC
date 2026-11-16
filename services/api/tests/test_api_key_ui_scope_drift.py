"""The console's hardcoded API-key scopes must exist server-side (#1934).

`SettingsView.tsx` creates keys with a literal scope list, and
`_validate_scopes` refuses unknown scopes with a 422 — the right failure
direction, but it means the two lists drifting apart bricks key creation in
the UI entirely: the shipped `detection:read` never existed (`rules:read`
does), so every Generate click 422'd.

A scope the UI names must be in ``VALID_SCOPES``. The reverse is not
asserted: the server may offer more scopes than the UI's default pair.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from app.api.v1.endpoints.api_keys import VALID_SCOPES

_SETTINGS_VIEW = Path(__file__).parents[3] / "apps" / "web" / "src" / "components" / "settings" / "SettingsView.tsx"

#: String-literal arrays assigned to a `scopes:` key, e.g.
#: ``scopes: ['cases:read', 'alerts:read']``. Dynamic values
#: (``scopes: record.scopes``) deliberately do not match.
_SCOPES_LITERAL = re.compile(r"scopes:\s*\[([^\]]+)\]")
_STRING_ITEM = re.compile(r"""['"]([^'"]+)['"]""")


def _ui_scope_literals() -> list[list[str]]:
    text = _SETTINGS_VIEW.read_text(encoding="utf-8")
    literals: list[list[str]] = []
    for match in _SCOPES_LITERAL.finditer(text):
        items = _STRING_ITEM.findall(match.group(1))
        if items:
            literals.append(items)
    return literals


@pytest.mark.skipif(not _SETTINGS_VIEW.exists(), reason="web console not present in this checkout")
def test_every_ui_scope_literal_is_a_valid_server_scope() -> None:
    literals = _ui_scope_literals()
    assert literals, (
        "no literal scope arrays found in SettingsView.tsx — if key creation "
        "moved or became a picker, point this gate at the new source of the "
        "scopes the console sends"
    )
    for scopes in literals:
        unknown = [s for s in scopes if s not in VALID_SCOPES]
        assert not unknown, f"SettingsView.tsx names scope(s) the server will 422: {unknown}. Valid scopes: {sorted(VALID_SCOPES)}"


def test_the_shipped_defect_is_recognised_by_this_gate() -> None:
    """Self-test: the exact pre-fix literal must trip the gate's logic."""
    pre_fix = ["cases:read", "detection:read"]
    unknown = [s for s in pre_fix if s not in VALID_SCOPES]
    assert unknown == ["detection:read"]
