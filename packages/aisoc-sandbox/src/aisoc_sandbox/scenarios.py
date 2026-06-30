"""Scenarios — alert fixtures the sandbox can investigate.

A :class:`Scenario` is the input to one investigation run. The
sandbox ships five built-ins under ``src/aisoc_sandbox/scenarios/``
that mirror the (deliberately broader) production fixture set under
[`examples/`](https://github.com/beenuar/AiSOC/tree/main/examples). A
user can also supply an arbitrary JSON file from disk via
``aisoc-sandbox demo --file <path>`` if they want to walk their own
alert through the funnel.

The schema is intentionally minimal — just enough for the funnel to
have something to talk about. Every field is optional except
``id`` / ``title`` / ``mitre_techniques`` / ``events``; missing
optionals are filled in from defaults by :func:`load_scenario`.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any


@dataclass
class Scenario:
    """An alert fixture the sandbox can investigate.

    Attributes:
        id: Stable scenario identifier (e.g. ``lateral-movement``).
        title: Human-readable headline (e.g. "Lateral movement —
            impossible-travel Okta sign-in").
        narrative: One-paragraph synopsis the sandbox prints before it
            walks the funnel.
        severity: ``info | low | medium | high | critical``.
        mitre_techniques: List of ATT&CK technique IDs.
        entities: Optional dict of entity-type → identifier (e.g.
            ``{"user": "alice@example.com", "asset_a": "host-12"}``).
            Used to populate evidence chips in the rendered ledger.
        events: List of raw events the alert was synthesised from.
            Treated as opaque blobs by the simulator.
        recommended_actions: Pre-baked actions the RespondAgent
            "would" propose. Each is ``{"name": ..., "args": {...}}``.
    """

    id: str
    title: str
    narrative: str = ""
    severity: str = "medium"
    mitre_techniques: list[str] = field(default_factory=list)
    entities: dict[str, str] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    recommended_actions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_SEVERITY_TIERS = {"info", "low", "medium", "high", "critical"}


def _validate(payload: dict[str, Any], *, source: str) -> Scenario:
    missing = [k for k in ("id", "title") if k not in payload]
    if missing:
        raise ValueError(
            f"Scenario {source!r} is missing required keys: {', '.join(missing)}"
        )
    sev = payload.get("severity", "medium")
    if sev not in _SEVERITY_TIERS:
        raise ValueError(
            f"Scenario {source!r} severity={sev!r} must be one of "
            f"{sorted(_SEVERITY_TIERS)}"
        )
    return Scenario(
        id=str(payload["id"]),
        title=str(payload["title"]),
        narrative=str(payload.get("narrative", "")),
        severity=sev,
        mitre_techniques=list(payload.get("mitre_techniques", [])),
        entities=dict(payload.get("entities", {})),
        events=list(payload.get("events", [])),
        recommended_actions=list(payload.get("recommended_actions", [])),
    )


def available_scenarios() -> list[str]:
    """Return the IDs of every bundled scenario, sorted."""

    pkg = resources.files("aisoc_sandbox").joinpath("scenarios")
    return sorted(
        p.name.removesuffix(".json")
        for p in pkg.iterdir()
        if p.name.endswith(".json")
    )


def load_scenario(scenario_id: str | None = None, *, file: str | None = None) -> Scenario:
    """Load a bundled scenario by ID, or an arbitrary scenario from disk.

    Args:
        scenario_id: One of :func:`available_scenarios`. Ignored if
            ``file`` is set.
        file: Path to a user-supplied scenario JSON. Takes precedence
            over ``scenario_id``.

    Returns:
        The loaded :class:`Scenario`.
    """

    if file is not None:
        path = Path(file).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"Scenario file not found: {path}")
        with path.open("r", encoding="utf-8") as fp:
            return _validate(json.load(fp), source=str(path))

    sid = scenario_id or "lateral-movement"
    if sid not in available_scenarios():
        raise ValueError(
            f"Unknown scenario {sid!r}. Available: {', '.join(available_scenarios())}"
        )
    pkg = resources.files("aisoc_sandbox").joinpath("scenarios", f"{sid}.json")
    with pkg.open("r", encoding="utf-8") as fp:
        return _validate(json.load(fp), source=f"<bundled:{sid}>")


def emit_scenario_index(*, out: Any = None) -> None:
    """Print the bundled scenarios in a copy-pasteable form."""

    if out is None:
        out = sys.stdout
    out.write("Bundled scenarios (use --scenario <id>):\n")
    for sid in available_scenarios():
        sc = load_scenario(sid)
        out.write(f"  {sid:<35}  {sc.title}\n")
