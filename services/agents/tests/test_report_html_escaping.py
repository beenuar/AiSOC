"""The incident report's fallback renderer must not emit untrusted HTML.

`_md_to_html` uses the `markdown` package when it is importable and wraps the
source in `<pre>` when it is not. The fallback interpolated the Markdown raw,
and the title interpolated the case id raw.

Found while fixing GHSA-w754-prh8-m56j, by looking for the same shape
elsewhere. What makes it worth a test rather than a quiet fix is that the
sibling renderer in `app/orchestrator/report.py` already escapes here, and its
comment says why in as many words: "a raw `<pre>` wrap would leak HTML through
unchanged". One copy of the lesson was written down and the other copy did the
thing it warns about.

The content is not trustworthy: the Markdown is model output and the report
embeds connector-supplied entity names, so a hostname or filename carried in
from an alert reaches an analyst's browser.
"""

from __future__ import annotations

import builtins
import re

import pytest

from app.investigator.report_writer_agent import _md_to_html

SCRIPT = "<script>alert('xss')</script>"
IMG = "<img src=x onerror=alert(1)>"


@pytest.fixture
def without_markdown(monkeypatch: pytest.MonkeyPatch):
    """Force the `<pre>` fallback.

    The defect is only reachable when `markdown` is absent, which is the
    branch a slim image takes — so a test that did not force it would
    exercise the safe path and pass against the vulnerable code.
    """
    real_import = builtins.__import__

    def _refuse_markdown(name: str, *args, **kwargs):
        if name == "markdown":
            raise ImportError("forced for this test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _refuse_markdown)


def _title_of(document: str) -> str:
    found = re.search(r"<title>(.*?)</title>", document, re.S)
    assert found, "the report has no title element"
    return found.group(1)


class TestTheFallbackRendererEscapes:
    def test_markdown_body_cannot_carry_an_element(self, without_markdown) -> None:
        document = _md_to_html(SCRIPT, "case-1")
        assert "<script>alert" not in document
        assert "&lt;script&gt;" in document

    def test_the_case_id_cannot_carry_an_element(self, without_markdown) -> None:
        """The title took the case id raw.

        Asserted structurally rather than by substring: `html.escape` encodes
        the angle brackets but leaves `onerror=alert(1)` as literal text, so a
        substring check passes on escaped output and proves nothing.
        """
        title = _title_of(_md_to_html("# ok", IMG))
        assert not re.search(r"<(img|script)", title)

    def test_the_document_stays_a_single_document(self, without_markdown) -> None:
        """A payload closing `</html>` and opening another would not show up
        in either assertion above."""
        document = _md_to_html("</body></html><html><body>grafted", "</title></head><body>grafted")
        assert document.count("<html") == 1
        assert document.count("</html>") == 1


class TestTheMarkdownPathIsUnchanged:
    def test_ordinary_markdown_still_renders(self) -> None:
        """The fix must not reach the `markdown` path, which handles its own
        escaping — double-escaping there would corrupt every real report."""
        document = _md_to_html("# Heading\n\nSome **bold** text.", "case-1")
        assert "Heading" in document
        assert "&amp;lt;" not in document
