"""Smoke test for the /api/v1/explain NDJSON streaming endpoint.

Runs the actual `_stream_explanation` async generator against a realistic
alert payload (impossible-travel ATO with MITRE T1078) and validates every
emitted frame:

    * Order: section → (delta|ocsf|mitre|evidence|next_step) → done
    * No malformed JSON, no missing required keys per `kind`
    * MITRE technique cards resolve from the local corpus when available
      (we tolerate `found=False` because the corpus loader is async and
       fires on FastAPI startup, not from a bare smoke)
    * `done` frame echoes the incoming alert id

Run with::

    cd services/agents
    PYTHONPATH=. .venv/bin/python tests/smoke_explain.py

Exits non-zero on any structural failure so CI can pick it up later.
"""

from __future__ import annotations

import asyncio
import json

# Force LLM off so the smoke is deterministic and offline.
import os
import sys
from typing import Any

os.environ.pop("OPENAI_API_KEY", None)
os.environ["AISOC_AIRGAPPED"] = "true"

from app.api.explain import ExplainRequest, _stream_explanation  # noqa: E402
from app.security.llm_resolver import LlmConfig  # noqa: E402

SAMPLE_ALERT: dict[str, Any] = {
    "id": "ALERT-SMOKE-0001",
    "title": "Impossible travel — login from Frankfurt then Tokyo within 8 minutes",
    "severity": "high",
    "source": "okta",
    "description": (
        "User authenticated successfully from two geographically impossible locations within an 8-minute window. Likely account takeover."
    ),
    "tags": ["account-takeover", "ato", "identity"],
    "mitreAttack": [{"techniqueId": "T1078"}],
    "iocs": [
        {"type": "ip", "value": "203.0.113.42"},
        {"type": "ip", "value": "198.51.100.7"},
    ],
    "rawEvent": {
        "user_name": "alice.tan",
        "src_ip": "203.0.113.42",
        "hostname": "okta-prod",
    },
}


REQUIRED_KEYS = {
    "section": {"kind", "id", "title"},
    "delta": {"kind", "section", "text"},
    "ocsf": {"kind", "category", "category_uid", "class", "class_uid", "activity", "fields"},
    "mitre": {"kind", "id", "name", "tactic_names", "description", "url", "found"},
    "evidence": {"kind", "label", "value", "annotation"},
    "next_step": {"kind", "title", "rationale", "playbook_id"},
    "done": {"kind", "alert_id"},
    "error": {"kind", "error"},
}


async def _run() -> int:
    req = ExplainRequest(alert=SAMPLE_ALERT, alert_id=SAMPLE_ALERT["id"])
    llm_config = LlmConfig(
        allowed=False,
        base_url="http://localhost",
        model="none",
        api_key=None,
        source="none",
        reason="air-gapped smoke test",
    )

    frames: list[dict[str, Any]] = []
    async for chunk in _stream_explanation(req, llm_config):
        line = chunk.decode().strip()
        if not line:
            continue
        try:
            frame = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"FAIL: malformed JSON line: {line!r} ({exc})")
            return 1
        frames.append(frame)
        # One-line preview so we can eyeball the actual content.
        preview = json.dumps(frame)
        print(preview[:160] + ("…" if len(preview) > 160 else ""))

    # ── Structural assertions ────────────────────────────────────────────
    if not frames:
        print("FAIL: no frames emitted")
        return 1

    # 1. Last frame is `done` (no error).
    last = frames[-1]
    if last.get("kind") == "error":
        print(f"FAIL: stream errored: {last.get('error')}")
        return 1
    if last.get("kind") != "done":
        print(f"FAIL: last frame is {last.get('kind')!r}, expected 'done'")
        return 1
    if last.get("alert_id") != SAMPLE_ALERT["id"]:
        print(f"FAIL: done frame alert_id mismatch: {last.get('alert_id')!r}")
        return 1

    # 2. Every frame has the required keys for its kind.
    for i, frame in enumerate(frames):
        kind = frame.get("kind")
        if kind not in REQUIRED_KEYS:
            print(f"FAIL: frame {i} has unknown kind {kind!r}")
            return 1
        missing = REQUIRED_KEYS[kind] - frame.keys()
        if missing:
            print(f"FAIL: frame {i} ({kind}) missing keys {missing}")
            return 1

    # 3. Each canonical section opens with a `section` frame.
    section_ids = [f["id"] for f in frames if f["kind"] == "section"]
    expected_sections = ["summary", "ocsf", "mitre", "evidence", "next"]
    if section_ids != expected_sections:
        print(f"FAIL: section order is {section_ids!r}, expected {expected_sections!r}")
        return 1

    # 4. We got a real OCSF mapping for an Okta-sourced alert.
    ocsf_frame = next((f for f in frames if f["kind"] == "ocsf"), None)
    if ocsf_frame is None:
        print("FAIL: no ocsf frame")
        return 1
    if ocsf_frame["class_uid"] != 3002:
        print(f"FAIL: Okta alert should map to OCSF class_uid=3002 (Authentication), got {ocsf_frame['class_uid']}")
        return 1

    # 5. T1078 came through. The corpus may or may not be loaded in this
    #    bare-process smoke — we accept `found=False` but the ID and a
    #    valid attack.mitre.org URL must be present.
    mitre_frames = [f for f in frames if f["kind"] == "mitre"]
    if not any(f["id"] == "T1078" for f in mitre_frames):
        print(f"FAIL: expected MITRE T1078 card, got {[f['id'] for f in mitre_frames]}")
        return 1
    for m in mitre_frames:
        if not m["url"].startswith("https://attack.mitre.org/techniques/"):
            print(f"FAIL: MITRE frame {m['id']} has bad url {m['url']!r}")
            return 1

    # 6. ATO tags should produce the ATO containment playbook recommendation.
    next_frames = [f for f in frames if f["kind"] == "next_step"]
    if not any(f["playbook_id"] == "ato-impossible-travel-block-v1" for f in next_frames):
        print(
            "FAIL: ATO-tagged alert should recommend "
            "'ato-impossible-travel-block-v1' playbook; got "
            f"{[f['playbook_id'] for f in next_frames]}"
        )
        return 1

    # 7. Evidence must contain the user from rawEvent.
    evidence = [f for f in frames if f["kind"] == "evidence"]
    if not any("alice.tan" in f["value"] for f in evidence):
        print(f"FAIL: evidence missing the user from rawEvent: {[(f['label'], f['value']) for f in evidence]}")
        return 1

    print()
    print(
        f"PASS: {len(frames)} frames, sections={section_ids}, "
        f"mitre={[m['id'] for m in mitre_frames]}, "
        f"playbooks={[n['playbook_id'] for n in next_frames]}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_run()))
