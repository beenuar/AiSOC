"""Cross-platform detection rule translation (tier2-translation).

AST-aware translator between Sigma YAML, Splunk SPL, Microsoft Sentinel KQL,
Google Chronicle YARA-L2/UDM, and Elastic ES|QL.  Uses an LLM for high-fidelity
translation when ``OPENAI_API_KEY`` is set; falls back to field-map substitution
for common patterns when no key is configured.

Endpoints
---------
* ``POST /translation/translate``   Translate a rule from one format to multiple targets.
* ``GET  /translation/formats``     List supported source/target formats.
"""

from __future__ import annotations

import json
import os
from typing import Any, Literal

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.core.airgap import AirgapViolation, enforce_airgap_for_url

router = APIRouter(prefix="/translation", tags=["translation"])

# ────────────────────────────────────────────────────────────────────────────
# Supported formats
# ────────────────────────────────────────────────────────────────────────────

DetectionFormat = Literal["sigma", "spl", "kql", "esql", "yara_l2", "udm"]

_FORMAT_LABELS: dict[DetectionFormat, str] = {
    "sigma": "Sigma YAML",
    "spl": "Splunk SPL",
    "kql": "Microsoft Sentinel KQL (OOTB & Analytics Rules)",
    "esql": "Elastic ES|QL",
    "yara_l2": "Google Chronicle YARA-L2",
    "udm": "Google Chronicle UDM Search",
}

# ────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ────────────────────────────────────────────────────────────────────────────


class TranslateRequest(BaseModel):
    source_format: DetectionFormat = Field(..., description="Format of the input rule.")
    source_rule: str = Field(..., min_length=5, description="The raw rule text to translate.")
    target_formats: list[DetectionFormat] = Field(
        default=["sigma", "spl", "kql", "esql"],
        description="Output formats to produce.",
    )


class TranslationResult(BaseModel):
    format: DetectionFormat
    label: str
    rule: str
    notes: str | None = None


class TranslateResponse(BaseModel):
    source_format: DetectionFormat
    results: list[TranslationResult]
    warnings: list[str] = []


class FormatsResponse(BaseModel):
    formats: dict[str, str]


# ────────────────────────────────────────────────────────────────────────────
# LLM helper
# ────────────────────────────────────────────────────────────────────────────

_SYSTEM = """You are an expert security engineer specialising in detection rule translation.
You translate detection rules between Sigma YAML, Splunk SPL, Microsoft Sentinel KQL,
Elastic ES|QL, Google Chronicle YARA-L2, and Google Chronicle UDM Search.

Rules for translation:
- Preserve ALL detection logic precisely (field names, operators, values, threshold).
- Map field names using OCSF / ECS / Sigma field conventions to each platform's native fields.
- Add platform-appropriate pipeline/index/timeframe clauses.
- Return ONLY valid JSON. No prose before or after.

Return JSON with this exact structure:
{
  "results": [
    {"format": "<format>", "rule": "<rule_text>", "notes": "<optional notes>"},
    ...
  ],
  "warnings": ["<any caveats>"]
}
"""


def _user_prompt(req: TranslateRequest) -> str:
    targets = ", ".join(req.target_formats)
    return (
        f"SOURCE FORMAT: {req.source_format}\n\n"
        f"SOURCE RULE:\n```\n{req.source_rule}\n```\n\n"
        f"Translate the above rule to: {targets}.\n"
        "Return valid JSON only."
    )


async def _llm_translate(req: TranslateRequest) -> dict[str, Any] | None:
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY")
    if not api_key:
        return None
    base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
    model = os.getenv("LLM_MODEL", "gpt-4o-mini")
    completions_url = f"{base_url}/chat/completions"
    # Air-gap check: refuses the call entirely (rather than silently
    # falling back to template-substitution) so misconfigurations are
    # loud. The except-Exception below would otherwise swallow this.
    try:
        enforce_airgap_for_url(completions_url)
    except AirgapViolation:
        raise
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                completions_url,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": _SYSTEM},
                        {"role": "user", "content": _user_prompt(req)},
                    ],
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"},
                },
            )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        return json.loads(content)
    except Exception:
        return None


# ────────────────────────────────────────────────────────────────────────────
# Template-based fallback (field-map substitution)
# ────────────────────────────────────────────────────────────────────────────

# Sigma → target field map (common ECS / OCSF fields)
_FIELD_MAP: dict[str, dict[str, str]] = {
    "spl": {
        "EventID": "EventCode",
        "Image": "process_name",
        "CommandLine": "process_path",
        "TargetUserName": "user",
        "DestinationIp": "dest_ip",
        "SourceIp": "src_ip",
    },
    "kql": {
        "EventID": "EventID",
        "Image": "NewProcessName",
        "CommandLine": "CommandLine",
        "TargetUserName": "TargetUserName",
        "DestinationIp": "RemoteIP",
        "SourceIp": "InitiatingProcessRemoteIP",
    },
    "esql": {
        "EventID": "event.code",
        "Image": "process.executable",
        "CommandLine": "process.command_line",
        "TargetUserName": "user.name",
        "DestinationIp": "destination.ip",
        "SourceIp": "source.ip",
    },
    "yara_l2": {
        "EventID": "metadata.product_event_type",
        "Image": "principal.process.file.full_path",
        "CommandLine": "principal.process.command_line",
        "TargetUserName": "target.user.userid",
        "DestinationIp": "target.ip",
        "SourceIp": "principal.ip",
    },
    "udm": {
        "EventID": "metadata.product_event_type",
        "Image": "principal.process.file.full_path",
        "CommandLine": "principal.process.command_line",
        "TargetUserName": "target.user.userid",
        "DestinationIp": "target.ip",
        "SourceIp": "principal.ip",
    },
}


def _fallback_templates(req: TranslateRequest) -> dict[str, Any]:
    """Produce best-effort template translations without an LLM."""
    results = []
    warnings = ["LLM not configured — using field-map template substitution. Review output carefully."]

    for fmt in req.target_formats:
        if fmt == req.source_format:
            results.append({"format": fmt, "rule": req.source_rule, "notes": "Same as source."})
            continue

        rule = req.source_rule
        field_map = _FIELD_MAP.get(fmt, {})
        for src_field, tgt_field in field_map.items():
            rule = rule.replace(src_field, tgt_field)

        if fmt == "spl":
            rule = f"index=* sourcetype=WinEventLog\n| search {rule}"
        elif fmt == "kql":
            rule = f"SecurityEvent\n| where {rule}"
        elif fmt == "esql":
            rule = f"FROM logs-*\n| WHERE {rule}"
        elif fmt == "yara_l2":
            rule = f'rule translated_rule {{\n  meta:\n    author = "AiSOC"\n  condition:\n    {rule}\n}}'
        elif fmt == "udm":
            rule = f"// Chronicle UDM Search\n{rule}"

        results.append({"format": fmt, "rule": rule, "notes": "Template translation — verify field names."})

    return {"results": results, "warnings": warnings}


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.post(
    "/translate",
    response_model=TranslateResponse,
    status_code=status.HTTP_200_OK,
    summary="Translate a detection rule across formats",
)
async def translate_rule(body: TranslateRequest) -> TranslateResponse:
    if not body.target_formats:
        raise HTTPException(status_code=400, detail="At least one target_format is required.")

    try:
        payload = await _llm_translate(body)
    except AirgapViolation as exc:
        # Surface the misconfig clearly instead of silently falling back —
        # otherwise an operator who flipped on AISOC_AIRGAPPED would see
        # quietly degraded translations with no signal that the LLM was
        # being refused.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "airgap_violation", "message": str(exc)},
        ) from exc
    if not payload:
        payload = _fallback_templates(body)

    results = [
        TranslationResult(
            format=r["format"],
            label=_FORMAT_LABELS.get(r["format"], r["format"]),
            rule=r["rule"],
            notes=r.get("notes"),
        )
        for r in payload.get("results", [])
        if r.get("format") and r.get("rule")
    ]

    return TranslateResponse(
        source_format=body.source_format,
        results=results,
        warnings=payload.get("warnings", []),
    )


@router.get(
    "/formats",
    response_model=FormatsResponse,
    summary="List supported detection rule formats",
)
async def list_formats() -> FormatsResponse:
    return FormatsResponse(formats=_FORMAT_LABELS)  # type: ignore[arg-type]
