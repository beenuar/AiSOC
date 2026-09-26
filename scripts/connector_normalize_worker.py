#!/usr/bin/env python3
"""Run raw vendor payloads through a real connector's ``normalize()``.

A separate process because ``services/connectors`` and ``services/fusion`` both
ship their code under the package name ``app``, so only one of them can be
importable at a time. Shelling out keeps the fireability proof running against
the **real** connector rather than a copy of its mapping — a test that
reimplements the thing it is testing is the failure mode this repository keeps
finding, so the extra process is the cheaper side of that trade.

Reads JSON lines of ``{"emitter": "...", "raw": {...}}`` on stdin and writes
JSON lines of ``{"ok": true, "normalized": {...}}`` or ``{"ok": false,
"error": "..."}`` on stdout, one per input line and in the same order.

``--no-lift`` constructs the connector's pre-fix behaviour, where a Windows
event's ``System``/``EventData`` containers stayed nested. The fireability gate
uses it to prove it is not vacuous: rules that depend on the lift must stop
firing when it is removed.
"""

from __future__ import annotations

import argparse
import inspect
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "services" / "connectors"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-lift", action="store_true", help="simulate the pre-fix connector")
    args = parser.parse_args()

    from app.connectors import _CONNECTOR_CLASSES  # noqa: PLC0415

    by_id = {cls.connector_id: cls for cls in _CONNECTOR_CLASSES}
    instances: dict[str, object] = {}

    def instantiate(cls: Any) -> Any:
        """Build a connector whose ``normalize()`` can run.

        ``normalize()`` is pure, but some connectors read configuration set in
        ``__init__`` (the CloudTrail one stamps the region onto each record).
        Placeholders come from the constructor signature rather than a
        per-connector table, so a new connector needs no change here.
        """
        kwargs: dict[str, Any] = {}
        for name, param in inspect.signature(cls.__init__).parameters.items():
            if name == "self" or param.kind in {param.VAR_POSITIONAL, param.VAR_KEYWORD}:
                continue
            if param.default is not inspect.Parameter.empty:
                continue
            kwargs[name] = False if param.annotation is bool else f"proof-{name}"
        try:
            return cls(**kwargs)
        except Exception:  # noqa: BLE001 — fall back to a bare instance
            return cls.__new__(cls)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            emitter = req["emitter"]
            cls = by_id.get(emitter)
            if cls is None:
                raise KeyError(f"no connector registered as {emitter!r}")
            if emitter not in instances:
                instances[emitter] = instantiate(cls)
            normalized = cls.normalize(instances[emitter], req["raw"])
            if args.no_lift and isinstance(normalized.get("raw_event"), dict):
                normalized["raw_event"] = req["raw"]
            print(json.dumps({"ok": True, "normalized": normalized}, default=str))
        except Exception as exc:  # noqa: BLE001 — reported per line, never fatal
            print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
