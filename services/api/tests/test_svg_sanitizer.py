"""An uploaded SVG is a script-carrying document, and this is what stops it.

Gap-closure Phase 13.2 gate.

A logo is uploaded by a customer administrator and rendered inside the
console and inside PDF reports other people open. That makes it a stored
cross-site scripting vector with a distribution mechanism attached, so the
tests below are written as attacks rather than as round trips.

The allowlist is asserted from both sides. A denylist test ("no <script>
survives") passes against a sanitiser that lets `<foreignObject>` through,
which is the failure this design exists to prevent, so there is a case here
for every construct the allowlist excludes and a case proving a legitimate
logo still renders.
"""

from __future__ import annotations

import pytest
from app.services.branding.svg_sanitizer import (
    MAX_SVG_BYTES,
    SvgRejected,
    looks_like_svg,
    sanitize_svg,
)

#: A logo of the kind a graphics program produces. Must survive intact.
BENIGN = b"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 40" width="120" height="40">
  <title>Acme Security</title>
  <defs>
    <linearGradient id="g1" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#2563EB"/>
      <stop offset="100%" stop-color="#7C3AED"/>
    </linearGradient>
  </defs>
  <rect x="0" y="0" width="40" height="40" rx="6" fill="url(#g1)"/>
  <path d="M8 20 L18 30 L32 10" stroke="#ffffff" stroke-width="4" fill="none"/>
  <text x="48" y="26" font-family="Arial" font-size="16" fill="#0f172a">Acme</text>
</svg>"""


class TestActiveContentIsRemoved:
    @pytest.mark.parametrize(
        ("payload", "must_not_contain"),
        [
            (b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "alert"),
            (b'<svg xmlns="http://www.w3.org/2000/svg"><script/><circle r="1"/></svg>', "script"),
            # The classic: an event handler on a legitimate element.
            (b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><circle r="1"/></svg>', "onload"),
            (b'<svg xmlns="http://www.w3.org/2000/svg"><circle r="1" onmouseover="alert(1)"/></svg>', "onmouseover"),
            # Arbitrary HTML, which a denylist of <script> misses entirely.
            (
                # Well-formed XML on purpose: a malformed payload would be
                # refused by the parser, which would let this case pass
                # against a sanitiser with no allowlist at all.
                b'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body xmlns="http://www.w3.org/1999/xhtml">'
                b'<img src="x" onerror="alert(1)"/></body></foreignObject></svg>',
                "foreignObject",
            ),
            # Animation that writes an attribute, reaching the same place.
            (
                b'<svg xmlns="http://www.w3.org/2000/svg"><animate attributeName="href" values="javascript:alert(1)"/></svg>',
                "animate",
            ),
            (b'<svg xmlns="http://www.w3.org/2000/svg"><set attributeName="onload" to="alert(1)"/></svg>', "set"),
            # An external document reference.
            (
                b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
                b'<use xlink:href="https://attacker.example/evil.svg#x"/></svg>',
                "attacker.example",
            ),
            (b'<svg xmlns="http://www.w3.org/2000/svg"><image href="https://attacker.example/p.png"/></svg>', "attacker"),
            # Inline CSS, which can fetch and can carry expressions.
            (b'<svg xmlns="http://www.w3.org/2000/svg"><style>@import url(https://attacker.example/x.css);</style></svg>', "import"),
            (b'<svg xmlns="http://www.w3.org/2000/svg"><circle r="1" style="behavior:url(#x)"/></svg>', "behavior"),
            # A paint server pointing off-document: an outbound request from
            # wherever this renders, which for a PDF is the server.
            (b'<svg xmlns="http://www.w3.org/2000/svg"><rect fill="url(https://attacker.example/x)"/></svg>', "attacker"),
            (b'<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><circle r="1"/></a></svg>', "javascript"),
        ],
    )
    def test_the_dangerous_construct_does_not_survive(self, payload: bytes, must_not_contain: str) -> None:
        cleaned = sanitize_svg(payload)
        assert must_not_contain.lower() not in cleaned.svg.lower()
        assert cleaned.modified, "nothing was reported removed, so the sanitiser did not notice this payload"

    def test_a_namespaced_script_tag_does_not_slip_past_a_name_comparison(self) -> None:
        """``{http://www.w3.org/2000/svg}script`` is not the string ``script``.

        A sanitiser comparing ElementTree's tag against a bare name lets this
        through while passing every unqualified test above.
        """
        payload = b'<svg xmlns="http://www.w3.org/2000/svg"><svg:script xmlns:svg="http://www.w3.org/2000/svg">alert(1)</svg:script></svg>'
        cleaned = sanitize_svg(payload)
        assert "alert" not in cleaned.svg
        assert "script" not in cleaned.svg.lower()

    def test_a_disallowed_elements_children_are_not_promoted(self) -> None:
        """``<script><circle/></script>`` is not a circle somebody wanted."""
        payload = b'<svg xmlns="http://www.w3.org/2000/svg"><script><circle r="5"/></script></svg>'
        cleaned = sanitize_svg(payload)
        assert "circle" not in cleaned.svg


class TestEntityExpansionIsRefusedNotBounded:
    def test_a_billion_laughs_document_is_refused_before_parsing(self) -> None:
        """Refused on a byte scan, so the expansion never runs.

        A size cap alone does not help: the expansion is what turns a small
        upload into gigabytes, so the input passes the cap.
        """
        payload = (
            b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
            b'<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
            b'<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>'
            b'<svg xmlns="http://www.w3.org/2000/svg"><title>&lol3;</title></svg>'
        )
        with pytest.raises(SvgRejected, match="DTD or an entity"):
            sanitize_svg(payload)

    def test_an_external_entity_is_refused(self) -> None:
        payload = (
            b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            b'<svg xmlns="http://www.w3.org/2000/svg"><title>&xxe;</title></svg>'
        )
        with pytest.raises(SvgRejected, match="DTD or an entity"):
            sanitize_svg(payload)

    def test_a_bare_doctype_is_refused_even_without_entities(self) -> None:
        """Refused rather than repaired.

        A document declaring a DTD is not a logo somebody drew, and repairing
        it would mean guessing what an untrusted author meant.
        """
        payload = b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" ""><svg xmlns="http://www.w3.org/2000/svg"/>'
        with pytest.raises(SvgRejected):
            sanitize_svg(payload)


class TestStructuralRefusals:
    def test_an_oversized_upload_is_refused(self) -> None:
        with pytest.raises(SvgRejected, match="limit is"):
            sanitize_svg(b"<svg xmlns='http://www.w3.org/2000/svg'>" + b"<!-- x -->" * MAX_SVG_BYTES + b"</svg>")

    def test_an_empty_upload_is_refused(self) -> None:
        with pytest.raises(SvgRejected, match="empty"):
            sanitize_svg(b"")

    def test_malformed_xml_is_refused(self) -> None:
        with pytest.raises(SvgRejected, match="well-formed"):
            sanitize_svg(b"<svg><unclosed>")

    def test_a_non_svg_root_is_refused(self) -> None:
        with pytest.raises(SvgRejected, match="not <svg>"):
            sanitize_svg(b'<html xmlns="http://www.w3.org/2000/svg"><body/></html>')


class TestLegitimateLogosSurvive:
    def test_a_real_logo_keeps_its_geometry_and_palette(self) -> None:
        """A sanitiser that removes everything is safe and useless."""
        cleaned = sanitize_svg(BENIGN)
        assert not cleaned.modified, f"removed {cleaned.removed_elements} / {cleaned.removed_attributes}"
        for fragment in ("<path", "<rect", "<text", "linearGradient", "#2563EB", "M8 20 L18 30 L32 10", "Acme"):
            assert fragment in cleaned.svg

    def test_a_same_document_paint_reference_survives(self) -> None:
        """``url(#id)`` is how a gradient is applied, and must still work."""
        assert 'fill="url(#g1)"' in sanitize_svg(BENIGN).svg

    def test_the_output_declares_its_namespace_so_it_renders_standalone(self) -> None:
        assert "http://www.w3.org/2000/svg" in sanitize_svg(BENIGN).svg


class TestDetection:
    @pytest.mark.parametrize(
        ("content_type", "raw", "expected"),
        [
            ("image/svg+xml", b"<svg/>", True),
            # Declared as a raster, actually XML. This is the case that makes
            # detection-by-header alone a hole: a caller controls the header,
            # and skipping the sanitiser is the whole attack.
            ("image/png", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', True),
            ("image/png", b"\x89PNG\r\n\x1a\n\x00\x00", False),
            ("image/jpeg", b"\xff\xd8\xff\xe0", False),
        ],
    )
    def test_an_svg_is_recognised_from_its_bytes_not_only_its_header(self, content_type, raw, expected) -> None:
        assert looks_like_svg(content_type, raw) is expected
