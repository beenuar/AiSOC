"""Pin `_mdx_safe` in scripts/generate_connector_docs.py.

Docusaurus parses the generated connector pages under MDX, where a bare
angle-bracket placeholder in prose is an unclosed JSX tag that fails the
whole docs build. `_mdx_safe` is the escape hatch — and it shipped with a
single-token pattern (`<account>`, `<your-tenant>`) that let a placeholder
with a space straight through: `<your subdomain>` parses in MDX as a `your`
tag carrying a boolean `subdomain` attribute, and the Huntress page's help
text broke every "Deploy Docs to GitHub Pages" run from 2026-11-12 until it
was found (the build only runs on push to main, so no pull request saw it).

The function had no test at all; this file is the pin, loaded by path the
way the other gate tests load their gate, so a future edit that narrows the
pattern fails here rather than in the live docs deploy.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "generate_connector_docs.py"


def _load_mdx_safe():
    spec = importlib.util.spec_from_file_location("generate_connector_docs", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._mdx_safe


def test_single_token_placeholder_is_escaped():
    """The original behaviour: `<account>` becomes a code span."""
    mdx_safe = _load_mdx_safe()
    assert mdx_safe("the key at <account> under Settings") == "the key at `<account>` under Settings"


def test_spaced_placeholder_is_escaped():
    """The shape that shipped the outage: a placeholder containing a space.

    MDX reads `<your subdomain>` as JSX (`your` tag, `subdomain` boolean
    attribute), so leaving it unescaped fails the docs build. This is the
    Huntress help text verbatim.
    """
    mdx_safe = _load_mdx_safe()
    assert (
        mdx_safe("Generated with the API key at <your subdomain>.huntress.io under API Credentials.")
        == "Generated with the API key at `<your subdomain>`.huntress.io under API Credentials."
    )


def test_existing_code_spans_are_left_alone():
    """Text already inside backticks is not double-wrapped."""
    mdx_safe = _load_mdx_safe()
    assert mdx_safe("sign in at `<your subdomain>.huntress.io` first") == ("sign in at `<your subdomain>.huntress.io` first")


def test_prose_comparisons_are_not_mangled():
    """`x < y` is arithmetic, not a tag: `<` followed by a space never matches."""
    mdx_safe = _load_mdx_safe()
    assert mdx_safe("alerts where severity < 5 and count > 2") == "alerts where severity < 5 and count > 2"
