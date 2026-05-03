"""
MTTR Dashboard Widget — AiSOC Reference Plugin
================================================
Computes MTTR / MTTD from the AiSOC case database and returns structured
time-series and summary data for the dashboard widget renderer.

Payload keys (all optional):
  lookback_days   (int)  : Override config; default 30.
  severity_filter (list) : e.g. ["high", "critical"]
  playbook_filter (str)  : Filter to a specific playbook ID.

Config keys:
  lookback_days  — Days of history to analyse (default: 30).
  percentiles    — List of integer percentiles (default: [50, 75, 95]).

Returns:
  {
    "mttr_seconds": {"mean": 3600, "p50": 2400, "p75": 5400, "p95": 14400},
    "mttd_seconds": {"mean": 900, "p50": 600, "p75": 1500, "p95": 3600},
    "by_severity": {
      "critical": {"mean_mttr": 1800, "count": 12},
      ...
    },
    "trend": [{"date": "2026-04-03", "mean_mttr": 3200}, ...],
    "sample_size": 142,
  }

Notes:
  This plugin queries the AiSOC internal REST API via the `api_url` key in
  context["config"] (defaults to http://api:8000). In a real deployment the
  plugin runner injects a pre-authenticated client; here we use httpx with a
  service-account API key from context["api_key"].
"""
from __future__ import annotations

import os
import statistics
from datetime import datetime, timezone, timedelta
from typing import Any

try:
    import httpx
    _HTTPX = True
except ModuleNotFoundError:
    _HTTPX = False


def _percentile(data: list[float], pct: int) -> float:
    if not data:
        return 0.0
    data = sorted(data)
    k = (len(data) - 1) * pct / 100
    f, c = int(k), min(int(k) + 1, len(data) - 1)
    return data[f] + (data[c] - data[f]) * (k - f)


class Plugin:
    """MTTR Dashboard Widget plugin."""

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        if not _HTTPX:
            return {"error": "httpx not installed; run `pip install httpx`"}

        cfg = context.get("config", {})
        lookback = int(payload.get("lookback_days") or cfg.get("lookback_days", 30))
        pcts = list(cfg.get("percentiles", [50, 75, 95]))
        severity_filter = payload.get("severity_filter") or []
        playbook_filter = payload.get("playbook_filter")

        api_url = cfg.get("api_url") or os.getenv("AISOC_API_URL", "http://api:8000")
        api_key = context.get("api_key") or os.getenv("AISOC_API_KEY", "")

        headers: dict[str, str] = {}
        if api_key:
            headers["X-API-Key"] = api_key

        # Query closed cases in the lookback window
        since = (datetime.now(timezone.utc) - timedelta(days=lookback)).isoformat()
        params: dict[str, Any] = {"status": "closed", "created_after": since, "limit": 1000}
        if severity_filter:
            params["severity"] = ",".join(severity_filter)
        if playbook_filter:
            params["playbook_id"] = playbook_filter

        async with httpx.AsyncClient(base_url=api_url, headers=headers, timeout=30) as client:
            r = await client.get("/api/v1/cases", params=params)
            r.raise_for_status()
            cases: list[dict] = r.json().get("items", [])

        if not cases:
            return {"sample_size": 0, "mttr_seconds": {}, "mttd_seconds": {}, "by_severity": {}, "trend": []}

        mttr_vals: list[float] = []
        mttd_vals: list[float] = []
        by_sev: dict[str, list[float]] = {}
        daily: dict[str, list[float]] = {}

        for c in cases:
            created_at = c.get("created_at")
            detected_at = c.get("detected_at") or created_at
            resolved_at = c.get("resolved_at")
            sev = c.get("severity", "unknown").lower()

            if not resolved_at:
                continue

            try:
                t_created = datetime.fromisoformat(created_at)
                t_detected = datetime.fromisoformat(detected_at)
                t_resolved = datetime.fromisoformat(resolved_at)
            except (TypeError, ValueError):
                continue

            mttr = (t_resolved - t_created).total_seconds()
            mttd = (t_created - t_detected).total_seconds()

            if mttr < 0 or mttd < 0:
                continue

            mttr_vals.append(mttr)
            mttd_vals.append(max(mttd, 0))

            by_sev.setdefault(sev, []).append(mttr)
            day_key = t_resolved.strftime("%Y-%m-%d")
            daily.setdefault(day_key, []).append(mttr)

        def _summary(vals: list[float]) -> dict:
            if not vals:
                return {}
            result = {"mean": round(statistics.mean(vals), 1)}
            for p in pcts:
                result[f"p{p}"] = round(_percentile(vals, p), 1)
            return result

        trend = sorted(
            [{"date": d, "mean_mttr": round(statistics.mean(vs), 1)} for d, vs in daily.items()],
            key=lambda x: x["date"],
        )

        return {
            "sample_size": len(mttr_vals),
            "mttr_seconds": _summary(mttr_vals),
            "mttd_seconds": _summary(mttd_vals),
            "by_severity": {
                sev: {
                    "mean_mttr": round(statistics.mean(vals), 1),
                    "count": len(vals),
                }
                for sev, vals in by_sev.items()
            },
            "trend": trend,
        }
