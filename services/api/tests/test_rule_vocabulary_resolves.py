"""Every field the rule builder suggests must exist on the fused alert.

The builder's previous list prefixed everything with ``alert.`` and invented
a ``target``/``time`` structure; both rule engines resolve plain dotted paths
against the fused ``RawAlert`` dict, so every suggested clause resolved to
``None`` — a builder-authored rule could never match anything, in preview or
live, while the preview endpoint *manufactured* a nested shape that made the
broken paths look like they worked.

The list below is duplicated in
``apps/web/src/app/(app)/settings/business-context/RuleBuilder.tsx``
(``FIELD_SUGGESTIONS``) and pinned there by ``RuleBuilder.test.tsx`` naming
these same literals. Two copies, one assertion each: drift reds one of them.

``RawAlert`` lives in ``services/fusion``, which is not importable from the
api suite (both services name their top-level package ``app``), so the field
set is asserted against the api's own alerts sample shape — the one
``_fetch_sample_alerts`` builds — plus the engine's resolver semantics.
"""

from __future__ import annotations

from app.services.business_context.engine import _resolve_field

# Keep in lockstep with RuleBuilder.tsx FIELD_SUGGESTIONS (see module docstring).
FIELD_SUGGESTIONS = [
    "severity",
    "source",
    "hostname",
    "username",
    "src_ip",
    "dst_ip",
    "domain",
    "tags",
    "risk_score",
    "raw_event.env",
]

# The shape the worker evaluates: fusion's RawAlert.model_dump(). Keys listed
# explicitly (not imported — see docstring) and cross-checked against
# services/fusion/app/models/alert.py by the fusion suite's own schema tests.
FUSED_ALERT_SAMPLE = {
    "id": "a1",
    "tenant_id": "t1",
    "source": "edr",
    "title": "t",
    "description": "",
    "severity": "high",
    "status": "new",
    "src_ip": "203.0.113.9",
    "dst_ip": "198.51.100.7",
    "hostname": "prod-web-01",
    "username": "svc_backup",
    "file_hash": None,
    "domain": "example.net",
    "url": None,
    "mitre_tactics": [],
    "mitre_techniques": [],
    "raw_event": {"env": "production"},
    "tags": ["prod"],
    "risk_score": 0.7,
}


def test_every_suggested_field_resolves_on_the_fused_alert() -> None:
    for path in FIELD_SUGGESTIONS:
        value = _resolve_field(FUSED_ALERT_SAMPLE, path)
        assert value is not None and not _is_missing(value), (
            f"builder suggests '{path}' but it resolves to nothing on the fused alert shape — "
            "a rule written from the suggestion list could never match"
        )


def test_the_old_alert_prefixed_paths_do_not_resolve() -> None:
    """The regression direction: if someone reintroduces the `alert.` prefix,
    this documents that such paths resolve to nothing on the real shape."""
    for path in ("alert.target.tag", "alert.severity", "alert.time.is_business_hours"):
        assert _is_missing(_resolve_field(FUSED_ALERT_SAMPLE, path))


def _is_missing(value: object) -> bool:
    # engine._resolve_field returns a _Missing sentinel for absent paths.
    return type(value).__name__ == "_Missing" or value is None
