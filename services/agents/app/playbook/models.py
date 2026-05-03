"""Playbook data models — Pydantic v2."""
from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class StepType(str, Enum):
    """Supported step action types."""
    ENRICH = "enrich"           # Call enrichment service
    INVESTIGATE = "investigate" # Trigger AI investigator
    NOTIFY = "notify"           # Send notification (Slack, email, webhook)
    BLOCK_IP = "block_ip"       # Call firewall/EDR action
    ISOLATE_HOST = "isolate_host"
    CREATE_TICKET = "create_ticket"
    CLOSE_CASE = "close_case"
    HTTP = "http"               # Generic outbound HTTP call
    CONDITION = "condition"     # Branching / gate


class StepCondition(BaseModel):
    """Optional condition guard that must be true before this step runs."""
    field: str = Field(..., description="JSONPath into run context, e.g. 'verdict'")
    operator: Literal["eq", "ne", "gt", "lt", "contains", "exists"] = "eq"
    value: Any = None


class PlaybookStep(BaseModel):
    """A single step in a playbook."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str
    type: StepType
    params: dict[str, Any] = Field(default_factory=dict)
    condition: StepCondition | None = None
    on_failure: Literal["abort", "continue", "retry"] = "abort"
    retry_max: int = 0
    timeout_seconds: int = 30
    # For branching: step IDs to jump to on true / false
    next_true: str | None = None
    next_false: str | None = None


class Playbook(BaseModel):
    """A complete playbook definition."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    version: str = "1.0.0"
    tags: list[str] = Field(default_factory=list)
    # Trigger configuration
    trigger: dict[str, Any] = Field(
        default_factory=dict,
        description="e.g. {'on': 'alert', 'severity': ['high','critical']}",
    )
    steps: list[PlaybookStep] = Field(default_factory=list)
    # Metadata
    author: str = "AiSOC"
    enabled: bool = True
    created_at: str = ""
    updated_at: str = ""
