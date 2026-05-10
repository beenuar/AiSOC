"""Natural-language detection authoring endpoint.

Accepts a plain-English description of a threat and returns:
  - A Sigma YAML rule
  - Equivalent KQL (Microsoft Sentinel)
  - Equivalent SPL (Splunk)
  - Equivalent ES|QL (Elastic)

Uses an LLM (OpenAI-compatible) to perform the translation. Falls back to a
template-based stub when no LLM key is configured so the endpoint stays
functional in all deployment environments.
"""

from __future__ import annotations

import os
from typing import Literal

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.core.airgap import AirgapViolation, enforce_airgap_for_url

logger = structlog.get_logger()

router = APIRouter(prefix="/nl-detection", tags=["nl_detection"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class NLDetectionRequest(BaseModel):
    description: str = Field(
        ...,
        description="Plain-English description of the threat behaviour to detect.",
        min_length=10,
        max_length=2000,
    )
    target_platforms: list[Literal["sigma", "kql", "spl", "esql"]] = Field(
        default=["sigma", "kql", "spl", "esql"],
        description="Which rule languages to generate.",
    )
    severity: Literal["informational", "low", "medium", "high", "critical"] = "medium"
    mitre_techniques: list[str] = Field(default_factory=list)


class NLDetectionResponse(BaseModel):
    description: str
    sigma: str | None = None
    kql: str | None = None
    spl: str | None = None
    esql: str | None = None
    model_used: str


# ---------------------------------------------------------------------------
# LLM translation helpers
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a detection engineering expert.
Given a plain-English threat description, generate detection rules in the
requested formats. Output ONLY valid rule content, no prose.

For Sigma: output valid YAML.
For KQL: output a valid Kusto query.
For SPL: output a valid Splunk search.
For ES|QL: output a valid Elastic ES|QL query.
"""

_TEMPLATE = {
    "sigma": """\
title: {title}
status: experimental
description: {description}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: '<KEYWORD>'
  condition: selection
falsepositives:
  - Legitimate administration activity
level: {severity}
""",
    "kql": """\
// {title}
// {description}
SecurityEvent
| where EventID == 4688
| where CommandLine contains "<KEYWORD>"
| project TimeGenerated, Computer, Account, CommandLine
""",
    "spl": """\
// {title} — {description}
index=windows EventCode=4688
| where like(CommandLine, "%<KEYWORD>%")
| table _time, host, user, CommandLine
""",
    "esql": """\
// {title}
// {description}
FROM logs-*
| WHERE process.command_line LIKE "*<KEYWORD>*"
| KEEP @timestamp, host.name, user.name, process.command_line
""",
}


async def _llm_translate(request: NLDetectionRequest) -> dict[str, str | None]:
    """Attempt LLM-based translation; fall back to templates on any error."""
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        logger.debug("nl_detection.llm_unavailable", reason="no OPENAI_API_KEY")
        return _template_fallback(request)

    platforms_str = ", ".join(request.target_platforms)
    user_prompt = (
        f"Threat description: {request.description}\n\n"
        f"Severity: {request.severity}\n"
        f"MITRE techniques: {', '.join(request.mitre_techniques) or 'unknown'}\n\n"
        f"Generate detection rules for: {platforms_str}.\n"
        f"Return JSON with keys matching the platform names (sigma, kql, spl, esql)."
    )

    completions_url = "https://api.openai.com/v1/chat/completions"
    try:
        enforce_airgap_for_url(completions_url)
    except AirgapViolation as exc:
        logger.info("nl_detection.airgap_block", url=completions_url, reason=str(exc))
        return _template_fallback(request)

    try:
        import httpx

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                completions_url,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.1,
                    "max_tokens": 2000,
                },
            )
            resp.raise_for_status()
            import json

            content = resp.json()["choices"][0]["message"]["content"]
            rules = json.loads(content)
            return {
                "sigma": rules.get("sigma") if "sigma" in request.target_platforms else None,
                "kql": rules.get("kql") if "kql" in request.target_platforms else None,
                "spl": rules.get("spl") if "spl" in request.target_platforms else None,
                "esql": rules.get("esql") if "esql" in request.target_platforms else None,
                "_model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
            }
    except Exception as exc:
        logger.warning("nl_detection.llm_error", error=str(exc))
        return _template_fallback(request)


def _template_fallback(request: NLDetectionRequest) -> dict[str, str | None]:
    title = request.description[:60].replace("\n", " ").strip()
    ctx = {"title": title, "description": request.description, "severity": request.severity}
    return {
        "sigma": _TEMPLATE["sigma"].format(**ctx) if "sigma" in request.target_platforms else None,
        "kql": _TEMPLATE["kql"].format(**ctx) if "kql" in request.target_platforms else None,
        "spl": _TEMPLATE["spl"].format(**ctx) if "spl" in request.target_platforms else None,
        "esql": _TEMPLATE["esql"].format(**ctx) if "esql" in request.target_platforms else None,
        "_model": "template",
    }


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post("/translate", response_model=NLDetectionResponse)
async def translate_detection(payload: NLDetectionRequest) -> NLDetectionResponse:
    """Convert a plain-English threat description into multi-platform detection rules."""
    if not payload.description.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="description must not be empty",
        )

    rules = await _llm_translate(payload)
    model_used = rules.pop("_model", "unknown")

    logger.info(
        "nl_detection.translate",
        platforms=payload.target_platforms,
        model=model_used,
        description_len=len(payload.description),
    )

    return NLDetectionResponse(
        description=payload.description,
        sigma=rules.get("sigma"),
        kql=rules.get("kql"),
        spl=rules.get("spl"),
        esql=rules.get("esql"),
        model_used=model_used,
    )
