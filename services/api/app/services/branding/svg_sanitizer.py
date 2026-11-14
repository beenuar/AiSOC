"""Sanitising an uploaded SVG, which is a script-carrying format.

Why this is a security boundary and not a theming detail
---------------------------------------------------------
PNG and JPEG are pixels. SVG is XML with a scripting model: it can carry
``<script>``, ``onload`` and every other event attribute, ``<foreignObject>``
containing arbitrary HTML, CSS that fetches remote resources, and references
to external documents. An operator logo is uploaded by a customer
administrator and then rendered inside the console and inside PDF reports
that other people open. That makes an uploaded SVG a stored cross-site
scripting vector with a distribution mechanism attached.

Allowlist, never denylist
--------------------------
A denylist of ``<script>`` misses ``<foreignObject>``, ``<use href="...">``,
``<animate attributeName="href">``, ``<set>``, ``<handler>``, and whatever the
next revision of the specification adds. The list of dangerous constructs
grows; the list of things a logo needs does not. So only the elements and
attributes below survive, and everything else is dropped.

Entity expansion is refused before parsing, not handled after
--------------------------------------------------------------
``xml.etree.ElementTree`` does not fetch external entities, but it does
expand internal ones, which is enough for a billion-laughs expansion out of a
very small upload. Both that and the quadratic-blowup variant need entity
definitions, and entity definitions need a DTD. So a document declaring a
DOCTYPE or an ENTITY at all is refused on a byte scan **before** the parser
sees it, which removes the class rather than bounding it.

This module deliberately uses only the standard library. The alternative was
a new XML dependency on a path that parses untrusted input, which is a larger
surface than the one being defended.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET  # noqa: N817
from dataclasses import dataclass, field
from typing import Final

SVG_NAMESPACE: Final[str] = "http://www.w3.org/2000/svg"
XLINK_NAMESPACE: Final[str] = "http://www.w3.org/1999/xlink"

#: Largest SVG this accepts, before parsing. A logo does not need more, and
#: an unbounded parse of attacker-supplied XML is a denial of service on the
#: request path whatever the sanitiser does afterwards.
MAX_SVG_BYTES: Final[int] = 256 * 1024

#: Elements a logo can be drawn with. Everything absent is dropped with its
#: subtree. `foreignObject` is absent on purpose: it embeds arbitrary HTML.
#: `use` is absent because its whole purpose is to reference another document
#: fragment, and the safe subset of that is not worth the parsing.
ALLOWED_ELEMENTS: Final[frozenset[str]] = frozenset(
    {
        "svg",
        "g",
        "defs",
        "title",
        "desc",
        "path",
        "rect",
        "circle",
        "ellipse",
        "line",
        "polyline",
        "polygon",
        "text",
        "tspan",
        "linearGradient",
        "radialGradient",
        "stop",
        "clipPath",
        "mask",
        "pattern",
        "symbol",
        "marker",
    }
)

#: Attributes those elements may carry. Presentation and geometry only.
#: Nothing here can name a URL except `fill`, `stroke` and `clip-path`, whose
#: values are checked separately so only same-document `url(#id)` references
#: survive.
ALLOWED_ATTRIBUTES: Final[frozenset[str]] = frozenset(
    {
        "id",
        "class",
        "d",
        "cx",
        "cy",
        "r",
        "rx",
        "ry",
        "x",
        "y",
        "x1",
        "y1",
        "x2",
        "y2",
        "dx",
        "dy",
        "width",
        "height",
        "points",
        "transform",
        "viewBox",
        "preserveAspectRatio",
        "fill",
        "fill-opacity",
        "fill-rule",
        "stroke",
        "stroke-width",
        "stroke-linecap",
        "stroke-linejoin",
        "stroke-dasharray",
        "stroke-dashoffset",
        "stroke-opacity",
        "stroke-miterlimit",
        "opacity",
        "offset",
        "stop-color",
        "stop-opacity",
        "gradientUnits",
        "gradientTransform",
        "spreadMethod",
        "clip-path",
        "clip-rule",
        "mask",
        "fr",
        "fx",
        "fy",
        "font-family",
        "font-size",
        "font-weight",
        "font-style",
        "text-anchor",
        "dominant-baseline",
        "letter-spacing",
        "xmlns",
        "version",
    }
)

#: A `url(...)` that points inside this document. Anything else in a paint
#: attribute is dropped: `fill="url(https://attacker.example/x)"` is an
#: outbound request from wherever the logo is rendered, which for a PDF
#: report is the server.
_LOCAL_URL_REF = re.compile(r"^url\(\s*['\"]?#[A-Za-z_][\w.:-]*['\"]?\s*\)$")

#: Byte-level refusals, applied before the parser runs.
_DOCTYPE = re.compile(rb"<!\s*DOCTYPE", re.IGNORECASE)
_ENTITY = re.compile(rb"<!\s*ENTITY", re.IGNORECASE)

#: A value that executes rather than describes. Checked on every surviving
#: attribute value, because `style` is not on the allowlist but a future
#: addition to it would otherwise inherit this hole silently.
_ACTIVE_VALUE = re.compile(r"(javascript|vbscript|data)\s*:", re.IGNORECASE)


class SvgRejected(ValueError):
    """An upload that cannot be made safe, with the reason.

    Refused rather than repaired. A document declaring a DTD is not a logo
    somebody drew in a graphics program; repairing it would mean guessing
    what the author meant, and the author here is untrusted.
    """


@dataclass
class SanitizeResult:
    """The cleaned document and what was taken out of it.

    The removals are reported rather than discarded so an administrator whose
    logo renders wrong can be told why, and so a test can assert on the
    specific construct rather than on the absence of a string.
    """

    svg: str
    removed_elements: list[str] = field(default_factory=list)
    removed_attributes: list[str] = field(default_factory=list)

    @property
    def modified(self) -> bool:
        return bool(self.removed_elements or self.removed_attributes)


def _localname(tag: str) -> str:
    """Strip a namespace from an ElementTree tag.

    Namespace-qualified names are how a hostile document smuggles a
    disallowed element past a comparison against a bare name:
    ``{http://www.w3.org/2000/svg}script`` is not the string ``script``.
    """
    return tag.rpartition("}")[2] if "}" in tag else tag


def _attribute_allowed(name: str, value: str) -> bool:
    local = _localname(name)

    # Any xlink attribute at all. `xlink:href` is the classic external
    # reference and there is no member of that namespace a logo needs.
    if name.startswith(f"{{{XLINK_NAMESPACE}}}") or local.startswith("xlink"):
        return False

    # Every event handler, by shape rather than by enumeration. `onload`,
    # `onbegin`, `onmouseover` and whatever is added next all start `on`.
    if local.lower().startswith("on"):
        return False

    if local not in ALLOWED_ATTRIBUTES:
        return False

    if _ACTIVE_VALUE.search(value):
        return False

    # A paint or clip value may name a reference. Only a same-document one.
    if "url(" in value.lower() and not _LOCAL_URL_REF.match(value.strip()):
        return False

    return True


def sanitize_svg(raw: bytes) -> SanitizeResult:
    """Return a safe rendering of ``raw``, or raise :class:`SvgRejected`.

    The output is re-serialised from the parsed tree rather than produced by
    editing the input, so anything the parser did not understand cannot
    survive into the result. A sanitiser that returns a modified copy of the
    original leaves whatever it failed to recognise in place.
    """
    if not raw:
        raise SvgRejected("the uploaded file is empty")
    if len(raw) > MAX_SVG_BYTES:
        raise SvgRejected(f"SVG is {len(raw)} bytes; the limit is {MAX_SVG_BYTES}")

    if _DOCTYPE.search(raw) or _ENTITY.search(raw):
        raise SvgRejected(
            "SVG declares a DTD or an entity. Both are refused: internal entity expansion is a "
            "denial of service out of a small upload, and a logo has no use for either."
        )

    parser = ET.XMLParser()
    try:
        root = ET.fromstring(raw, parser=parser)  # noqa: S314 - DTD and entities refused above
    except ET.ParseError as exc:
        raise SvgRejected(f"not well-formed XML: {exc}") from exc

    if _localname(root.tag) != "svg":
        raise SvgRejected(f"root element is <{_localname(root.tag)}>, not <svg>")

    result = SanitizeResult(svg="")
    _scrub(root, result)

    # Namespace declared once on the root, so the serialised document is a
    # standalone SVG a browser and WeasyPrint both render.
    root.set("xmlns", SVG_NAMESPACE)

    ET.register_namespace("", SVG_NAMESPACE)
    body = ET.tostring(root, encoding="unicode")
    # ElementTree re-emits the namespace as a prefix in some configurations;
    # collapse the redundant declaration so the output is one canonical shape
    # rather than two that differ by Python version.
    body = body.replace(f'xmlns:ns0="{SVG_NAMESPACE}"', "").replace("ns0:", "")
    result.svg = body.strip()
    return result


def _scrub(element: ET.Element, result: SanitizeResult) -> None:
    """Drop disallowed children and attributes, depth first."""
    for attribute in list(element.attrib):
        if not _attribute_allowed(attribute, element.attrib[attribute]):
            result.removed_attributes.append(_localname(attribute))
            del element.attrib[attribute]

    for child in list(element):
        name = _localname(child.tag)
        if name not in ALLOWED_ELEMENTS:
            # The whole subtree goes. A disallowed element's children are not
            # promoted into its parent: `<script><circle/></script>` is not a
            # circle somebody wanted.
            result.removed_elements.append(name)
            element.remove(child)
            continue
        _scrub(child, result)


def looks_like_svg(content_type: str | None, raw: bytes) -> bool:
    """Whether this upload should go through the sanitiser.

    Decided on the bytes as well as the declared type. A caller controls the
    ``Content-Type`` header, so an SVG announced as ``image/png`` would
    otherwise skip sanitising entirely, which is the shape of the bug this
    check exists to prevent.
    """
    if content_type and "svg" in content_type.lower():
        return True
    head = raw[:1024].lstrip()
    return head.startswith(b"<?xml") or head.startswith(b"<svg") or b"<svg" in head[:512].lower()
