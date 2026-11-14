"""Per-organisation white-label branding.

``svg_sanitizer``
    Turns an untrusted uploaded SVG into one that is safe to render in a
    console and inside a PDF, or refuses it.
``resolver``
    Answers "what does this tenant's product look like", falling back to the
    platform default field by field.
"""

from app.services.branding.resolver import (
    DEFAULT_BRANDING,
    Branding,
    branding_for_org,
    resolve_branding,
)
from app.services.branding.svg_sanitizer import (
    MAX_SVG_BYTES,
    SanitizeResult,
    SvgRejected,
    looks_like_svg,
    sanitize_svg,
)

__all__ = [
    "DEFAULT_BRANDING",
    "MAX_SVG_BYTES",
    "Branding",
    "SanitizeResult",
    "SvgRejected",
    "branding_for_org",
    "looks_like_svg",
    "resolve_branding",
    "sanitize_svg",
]
