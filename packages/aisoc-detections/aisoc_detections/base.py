"""Load + evaluate Python detection modules."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

_VALID_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})


class DetectionError(Exception):
    """A detection module is malformed (missing rule(), bad metadata, ...)."""


@dataclass(frozen=True)
class Detection:
    """A loaded, validated Python detection."""

    id: str
    title: str
    severity: str
    description: str
    mitre: list[str]
    rule: Callable[[dict[str, Any]], bool]
    tests: list[dict[str, Any]] = field(default_factory=list)
    _title_fn: Callable[[dict[str, Any]], str] | None = None
    _dedup_fn: Callable[[dict[str, Any]], str] | None = None
    source_path: str | None = None

    def title_for(self, event: dict[str, Any]) -> str:
        if self._title_fn is not None:
            return str(self._title_fn(event))
        return self.title

    def dedup_for(self, event: dict[str, Any]) -> str | None:
        if self._dedup_fn is not None:
            return str(self._dedup_fn(event))
        return None


def evaluate(detection: Detection, event: dict[str, Any]) -> bool:
    """Run a detection's rule against one event. Fail-closed (a raising rule
    returns False rather than firing) so a buggy rule can't storm the queue."""
    try:
        return bool(detection.rule(event))
    except Exception:  # noqa: BLE001 — a broken rule must not fire or crash the batch
        return False


def _require(module: Any, name: str, path: Path) -> Any:
    value = getattr(module, name, None)
    if value is None:
        raise DetectionError(f"{path.name}: detection is missing required '{name}'")
    return value


def load_detection(path: str | Path) -> Detection:
    """Import + validate one detection module from a .py file."""
    path = Path(path)
    spec = importlib.util.spec_from_file_location(f"aisoc_detection_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise DetectionError(f"{path}: cannot import module")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        raise DetectionError(f"{path.name}: import failed: {exc}") from exc

    rule = _require(module, "rule", path)
    if not callable(rule):
        raise DetectionError(f"{path.name}: 'rule' must be callable")
    severity = str(getattr(module, "SEVERITY", "medium")).lower()
    if severity not in _VALID_SEVERITIES:
        raise DetectionError(f"{path.name}: SEVERITY '{severity}' not in {sorted(_VALID_SEVERITIES)}")

    tests = getattr(module, "TESTS", [])
    if not isinstance(tests, list):
        raise DetectionError(f"{path.name}: TESTS must be a list")

    return Detection(
        id=str(_require(module, "ID", path)),
        title=str(getattr(module, "TITLE", path.stem)),
        severity=severity,
        description=str(getattr(module, "DESCRIPTION", "")),
        mitre=list(getattr(module, "MITRE", []) or []),
        rule=rule,
        tests=tests,
        _title_fn=getattr(module, "title", None) if callable(getattr(module, "title", None)) else None,
        _dedup_fn=getattr(module, "dedup", None) if callable(getattr(module, "dedup", None)) else None,
        source_path=str(path),
    )


def load_detections(directory: str | Path) -> list[Detection]:
    """Load every ``*.py`` detection in ``directory`` (non-recursive, skips
    ``_``-prefixed files). Raises on the first malformed module."""
    directory = Path(directory)
    detections: list[Detection] = []
    for path in sorted(directory.glob("*.py")):
        if path.name.startswith("_"):
            continue
        detections.append(load_detection(path))
    return detections
