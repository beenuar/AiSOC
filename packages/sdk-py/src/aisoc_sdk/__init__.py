"""aisoc-sdk — Python client for AiSOC.

Usage::

    from aisoc_sdk import AiSOCClient

    async with AiSOCClient(base_url="https://soc.example.com", token="aisoc_...") as client:
        alerts = await client.alerts.list(severity="critical")
"""

from .client import AiSOCClient, AiSOCError
from .models import (
    Alert,
    AlertFilters,
    AlertSeverity,
    AlertStatus,
    ApiKey,
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    Case,
    CaseFilters,
    CasePriority,
    CaseStatus,
    Connector,
    DetectionRule,
    Page,
    Playbook,
    PlaybookRun,
)

__all__ = [
    "AiSOCClient",
    "AiSOCError",
    "Alert",
    "AlertFilters",
    "AlertSeverity",
    "AlertStatus",
    "ApiKey",
    "ApiKeyCreateRequest",
    "ApiKeyCreateResponse",
    "Case",
    "CaseFilters",
    "CasePriority",
    "CaseStatus",
    "Connector",
    "DetectionRule",
    "Page",
    "Playbook",
    "PlaybookRun",
]

__version__ = "4.0.0"
