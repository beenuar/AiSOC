"""Voice readout for mobile/on-call HITL approvals (Theme 2m).

When the SOC pages an on-call analyst at 2am, the phone is the device
nearest to them. A passkey solves the "do I have my YubiKey" problem; the
voice readout solves the "what am I actually approving" problem. The
analyst should be able to hold the phone up, hear a 10-second TL;DR of the
proposed action and its blast radius, and then biometric-tap to approve or
deny.

This module deliberately separates two concerns:

1. **Script generation.** Pure function over a :class:`HitlRequest` that
   produces a short, structured spoken script. No I/O — easy to test,
   deterministic in CI, and the script is what we log to the audit row so
   the audit trail records "what the analyst heard", not just "what was in
   the database".
2. **Audio synthesis.** Pluggable :class:`VoiceSynth` backend. The default
   :class:`SsmlVoiceSynth` returns SSML the client TTS engine speaks
   locally (no audio bytes shipped from the server, so this works without
   a cloud TTS dependency). A production deployment binds to Polly /
   ElevenLabs / Google TTS by registering a different backend.

Keeping the seam at the synth layer means we can swap engines per tenant
(some regulated tenants want on-device only) without touching the script
or the routes.
"""
from __future__ import annotations

import html
import json
from dataclasses import dataclass
from typing import Protocol

from app.models.hitl import HitlRequest


# ── Script generation ────────────────────────────────────────────────────


@dataclass
class HitlReadout:
    """The fully rendered readout for a single HITL request."""

    script: str  # plain-text TL;DR (logged to audit)
    ssml: str  # SSML markup for client-side TTS
    duration_estimate_s: float  # rough wall-clock estimate for the readout
    summary_lines: list[str]  # structured lines (UI bullets)


def _risk_phrasing(risk_class: str) -> str:
    """Map a structured risk class to spoken language.

    We bias toward calm but unambiguous wording. The on-call analyst's
    brain is half-asleep; "destructive, immediate impact" beats "RC-D".
    """
    return {
        "READ": "read-only, low impact",
        "WRITE_REVERSIBLE": "writable but reversible",
        "WRITE_SIGNIFICANT": "writable and significant",
        "DESTRUCTIVE": "destructive, immediate impact",
    }.get(risk_class, risk_class.lower().replace("_", " "))


def _summarize_blast_radius(blast: dict) -> str:
    """Spoken summary of the blast radius dict.

    Picks the highest-signal fields the Responder writes (users, hosts,
    integrations) and renders them as a single short clause. Returns
    empty string when nothing meaningful is set — silence beats noise.
    """
    if not blast:
        return ""
    parts: list[str] = []
    users = blast.get("users") or blast.get("affected_users")
    hosts = blast.get("hosts") or blast.get("affected_hosts")
    integrations = blast.get("integrations") or blast.get("affected_integrations")
    if isinstance(users, list) and users:
        parts.append(f"{len(users)} user{'s' if len(users) != 1 else ''}")
    elif isinstance(users, int) and users:
        parts.append(f"{users} user{'s' if users != 1 else ''}")
    if isinstance(hosts, list) and hosts:
        parts.append(f"{len(hosts)} host{'s' if len(hosts) != 1 else ''}")
    elif isinstance(hosts, int) and hosts:
        parts.append(f"{hosts} host{'s' if hosts != 1 else ''}")
    if isinstance(integrations, list) and integrations:
        parts.append(", ".join(integrations[:3]))
    if not parts:
        return ""
    return "Affects " + " and ".join(parts) + "."


def _truncate_params(params: dict, limit: int = 4) -> list[tuple[str, str]]:
    """Return up to ``limit`` (key, value) pairs for spoken context.

    Long parameter blobs ("body": "<50KB JSON") would drown the readout.
    We pick the first few stable keys and stringify their values shallowly.
    """
    out: list[tuple[str, str]] = []
    for k, v in list(params.items())[:limit]:
        if isinstance(v, (dict, list)):
            v_str = json.dumps(v)
            if len(v_str) > 60:
                v_str = v_str[:57] + "..."
        else:
            v_str = str(v)
            if len(v_str) > 60:
                v_str = v_str[:57] + "..."
        out.append((str(k), v_str))
    return out


def build_readout(req: HitlRequest) -> HitlReadout:
    """Render a structured readout for a HITL request.

    The output is deterministic and includes nothing the gateway hasn't
    already persisted, so the same readout is reproducible at audit time.
    """
    risk = _risk_phrasing(req.risk_class)
    blast = _summarize_blast_radius(req.blast_radius or {})
    rationale = (req.rationale or "").strip()

    summary_lines: list[str] = [
        f"Action: {req.tool_name} on {req.integration}.",
        f"Requested by: {req.agent}.",
        f"Risk: {risk}.",
    ]
    if blast:
        summary_lines.append(blast)
    if rationale:
        # Truncate the rationale at a sentence-ish boundary; the analyst
        # can read the full text on screen — the readout is the TL;DR.
        short = rationale if len(rationale) <= 140 else rationale[:137].rstrip() + "..."
        summary_lines.append(f"Reason: {short}")
    param_pairs = _truncate_params(req.params or {})
    if param_pairs:
        joined = "; ".join(f"{k}={v}" for k, v in param_pairs)
        summary_lines.append(f"Parameters: {joined}.")

    script = " ".join(summary_lines)

    # SSML: short pauses between clauses + emphasis on risk. Clients pick
    # voice / language per device locale; we don't hardcode either.
    parts = ["<speak>"]
    parts.append(
        f"<s>Approval requested: {html.escape(req.tool_name)} on "
        f"{html.escape(req.integration)} by {html.escape(req.agent)}.</s>"
    )
    parts.append(
        f"<break time='200ms'/><s>Risk: <emphasis level='strong'>"
        f"{html.escape(risk)}</emphasis>.</s>"
    )
    if blast:
        parts.append(f"<break time='200ms'/><s>{html.escape(blast)}</s>")
    if rationale:
        short = rationale if len(rationale) <= 140 else rationale[:137].rstrip() + "..."
        parts.append(f"<break time='200ms'/><s>Reason: {html.escape(short)}</s>")
    parts.append(
        "<break time='300ms'/><s>Approve or deny.</s></speak>"
    )
    ssml = "".join(parts)

    # Rough estimate: ~3 words per second, calm pace.
    word_count = sum(len(line.split()) for line in summary_lines)
    duration = round(word_count / 3.0 + 1.0, 1)  # +1s for inter-clause pauses

    return HitlReadout(
        script=script,
        ssml=ssml,
        duration_estimate_s=duration,
        summary_lines=summary_lines,
    )


# ── Pluggable synth backend (default: client-side TTS via SSML) ──────────


class VoiceSynth(Protocol):
    """Pluggable speech-synthesis backend."""

    def synthesize(self, readout: HitlReadout) -> dict:
        """Return a JSON-serializable payload the mobile client can play."""
        ...


class SsmlVoiceSynth:
    """Default backend: hand the SSML to the client and let its TTS engine speak.

    This keeps the API self-contained (no Polly/ElevenLabs credentials
    needed for the dev demo), and avoids streaming audio bytes through the
    backend just to play a 5-second readout. Mobile platforms (iOS
    ``AVSpeechSynthesizer``, Android ``TextToSpeech``, browser
    ``SpeechSynthesisUtterance``) accept SSML directly.
    """

    def synthesize(self, readout: HitlReadout) -> dict:
        return {
            "mode": "client-ssml",
            "ssml": readout.ssml,
            "fallback_text": readout.script,
            "duration_estimate_s": readout.duration_estimate_s,
        }


_default_synth: VoiceSynth = SsmlVoiceSynth()


def render_voice_payload(req: HitlRequest, synth: VoiceSynth | None = None) -> dict:
    """Return the structured payload the mobile client uses to play and display."""
    readout = build_readout(req)
    chosen = synth or _default_synth
    return {
        "request_id": req.id,
        "tenant_id": req.tenant_id,
        "summary_lines": readout.summary_lines,
        "script": readout.script,
        "audio": chosen.synthesize(readout),
    }


__all__ = [
    "HitlReadout",
    "SsmlVoiceSynth",
    "VoiceSynth",
    "build_readout",
    "render_voice_payload",
]
