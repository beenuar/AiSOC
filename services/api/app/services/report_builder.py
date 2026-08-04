"""Customizable dashboard / report builder (Wave 7, W7.1).

A report is a declarative list of widgets — each a whitelisted ``type`` bound to
a whitelisted data ``source`` — that the builder validates and then renders by
resolving each widget's data through injected resolvers. Keeping the assembly
pure (resolvers are passed in) makes the layout + validation logic unit-testable
without a database, and lets the same definition drive both the live dashboard
and an exported PDF/HTML report.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

WIDGET_TYPES = frozenset({"metric", "table", "timeseries", "bar", "pie", "text"})
# Whitelisted data sources a widget may bind to. Extend as new resolvers land.
DATA_SOURCES = frozenset(
    {
        "alerts_by_severity",
        "alerts_over_time",
        "mttr",
        "funnel",
        "top_detections",
        "cost_by_model",
        "posture_summary",
        "static",  # widget carries its own literal data (text/markdown tiles)
    }
)
MAX_WIDGETS = 40


class ReportError(Exception):
    """A report definition is structurally invalid."""


@dataclass(frozen=True)
class ReportWidget:
    id: str
    type: str
    title: str
    source: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReportDefinition:
    name: str
    widgets: list[ReportWidget]


def parse_definition(payload: dict[str, Any]) -> ReportDefinition:
    """Build + validate a ReportDefinition from a raw dict (API body / stored)."""
    name = str(payload.get("name", "")).strip()
    if not name:
        raise ReportError("report name is required")
    raw_widgets = payload.get("widgets", [])
    if not isinstance(raw_widgets, list):
        raise ReportError("widgets must be a list")
    if len(raw_widgets) > MAX_WIDGETS:
        raise ReportError(f"too many widgets ({len(raw_widgets)} > {MAX_WIDGETS})")

    widgets: list[ReportWidget] = []
    seen_ids: set[str] = set()
    for i, raw in enumerate(raw_widgets):
        if not isinstance(raw, dict):
            raise ReportError(f"widget[{i}] must be an object")
        wtype = str(raw.get("type", ""))
        source = str(raw.get("source", ""))
        wid = str(raw.get("id") or f"w{i}")
        if wtype not in WIDGET_TYPES:
            raise ReportError(f"widget[{i}] unknown type '{wtype}'")
        if source not in DATA_SOURCES:
            raise ReportError(f"widget[{i}] unknown source '{source}'")
        if wid in seen_ids:
            raise ReportError(f"widget[{i}] duplicate id '{wid}'")
        seen_ids.add(wid)
        widgets.append(ReportWidget(id=wid, type=wtype, title=str(raw.get("title", "")), source=source, params=dict(raw.get("params", {}))))
    return ReportDefinition(name=name, widgets=widgets)


# A resolver takes a widget's params and returns its rendered data payload.
Resolver = Callable[[dict[str, Any]], Any]


def render_report(definition: ReportDefinition, resolvers: dict[str, Resolver]) -> dict[str, Any]:
    """Assemble a report by resolving each widget's data. A widget whose source
    has no resolver (or whose resolver raises) renders an ``error`` field rather
    than failing the whole report."""
    rendered: list[dict[str, Any]] = []
    for widget in definition.widgets:
        entry: dict[str, Any] = {"id": widget.id, "type": widget.type, "title": widget.title, "source": widget.source}
        if widget.source == "static":
            entry["data"] = widget.params.get("data")
        else:
            resolver = resolvers.get(widget.source)
            if resolver is None:
                entry["error"] = f"no resolver for source '{widget.source}'"
            else:
                try:
                    entry["data"] = resolver(widget.params)
                except Exception:  # noqa: BLE001 — one bad widget shouldn't break the report
                    # Log the detail server-side but never expose the raw
                    # exception (it may carry stack/internal detail) to the API
                    # caller — the widget just carries a generic error.
                    logger.warning("report widget %r resolver failed", widget.id, exc_info=True)
                    entry["error"] = "resolver failed"
        rendered.append(entry)
    return {"name": definition.name, "widgets": rendered}
