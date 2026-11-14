"""Emit AI-estate telemetry to AiSOC from inside an agent or LLM app.

AiSOC could already ingest an organisation's OpenAI and Anthropic *audit logs*
— who minted an API key, who was made an owner. That is control-plane
governance and says nothing about what the agents did once running. This is the
runtime half: tool calls, model invocations and guardrail findings, landing in
the same pipeline as every other security signal.

    from aisoc_ai import AiSocAiClient

    aisoc = AiSocAiClient(
        endpoint="https://aisoc.example.com/v1/inbox/<runtime-token>",
        finding_endpoint="https://aisoc.example.com/v1/inbox/<finding-token>",
        agent_id="support-bot",
    )

    aisoc.tool_call("search_tickets", on_behalf_of="alice@example.com")
    aisoc.finding("prompt_injection", "Instruction override in retrieved doc")

Prompt and response content is hashed by default and never transmitted unless
the caller opts in. See `redaction.py`.
"""

from aisoc_ai.client import AiSocAiClient
from aisoc_ai.redaction import CaptureMode, RedactedText, redact, secret_kinds

__all__ = [
    "AiSocAiClient",
    "CaptureMode",
    "RedactedText",
    "redact",
    "secret_kinds",
]
