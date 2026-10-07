"""Playbook data models — Pydantic v2."""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, Field

from .bounds import (
    ABSOLUTE_MAX_RETRIES,
    ABSOLUTE_MAX_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS,
)


class StepType(str, Enum):
    """Supported step action types."""

    ENRICH = "enrich"  # Call enrichment service
    INVESTIGATE = "investigate"  # Trigger AI investigator
    NOTIFY = "notify"  # Send notification (Slack, email, webhook)
    BLOCK_IP = "block_ip"  # Call firewall/EDR action
    BLOCK_IOC = "block_ioc"  # Block an IOC (hash, domain, IP)
    ISOLATE_HOST = "isolate_host"
    CREATE_TICKET = "create_ticket"
    CLOSE_CASE = "close_case"
    HTTP = "http"  # Generic outbound HTTP call
    CONDITION = "condition"  # Branching / gate
    OSQUERY_LIVE_QUERY = "osquery_live_query"  # Distributed osquery via osctrl/FleetDM/aisoc-direct
    # Control flow. A playbook could branch and it could not wait, fan out
    # or repeat, so anything shaped "contain, then check again in five
    # minutes" or "revoke every session this user has" had to be written as
    # a hand-unrolled chain of steps — which is why none of the 62 shipped
    # packs attempts either.
    WAIT = "wait"  # Hold for a timer or a callback
    PARALLEL = "parallel"  # Run child steps concurrently, then join
    LOOP = "loop"  # Run child steps once per item, bounded
    # Human-in-the-loop
    APPROVAL = "approval"  # Require analyst approval before proceeding
    # Identity response
    DISABLE_USER = "disable_user"
    RESET_PASSWORD = "reset_password"
    REVOKE_SESSION = "revoke_session"
    FORCE_MFA = "force_mfa"
    # Endpoint response
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    RUN_AV_SCAN = "run_av_scan"
    RUN_SCRIPT = "run_script"
    # SIEM / investigation
    SEARCH_SIEM = "search_siem"
    CREATE_NOTABLE_EVENT = "create_notable_event"


class StepCondition(BaseModel):
    """Optional condition guard that must be true before this step runs.

    Accepts either a structured dict (field/operator/value) or a plain
    expression string such as ``"inputs.source_ip != null"``.  The string
    form is evaluated at runtime by the playbook engine; the structured form
    is kept for backwards compatibility and IDE tooling.
    """

    field: str = Field("", description="JSONPath into run context, e.g. 'verdict'")
    operator: Literal["eq", "ne", "gt", "lt", "contains", "exists"] = "eq"
    value: Any = None
    # Expression-string form (mutually exclusive with field/operator/value)
    expression: str | None = None


def _coerce_condition(v: Any) -> Any:
    """Allow StepCondition to be specified as a plain expression string."""
    if isinstance(v, str):
        return {"expression": v}
    return v


# Annotated type that coerces string conditions to dict before Pydantic parses them
StepConditionField = Annotated[StepCondition | None, BeforeValidator(_coerce_condition)]


class PlaybookStep(BaseModel):
    """A single step in a playbook."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str
    type: StepType
    params: dict[str, Any] = Field(default_factory=dict)
    condition: StepConditionField = None
    on_failure: Literal["abort", "continue", "retry"] = "abort"
    # Hard ceilings — see services/agents/app/playbook/bounds.py for rationale.
    # Pydantic validates these on the typed field; handlers that read
    # ``params.timeout_seconds`` directly MUST also pass the value through
    # ``bounds.clamp_timeout`` at runtime.
    retry_max: int = Field(default=0, ge=0, le=ABSOLUTE_MAX_RETRIES)
    timeout_seconds: int = Field(
        default=30,
        ge=MIN_TIMEOUT_SECONDS,
        le=ABSOLUTE_MAX_TIMEOUT_SECONDS,
    )
    # For branching: step IDs to jump to on true / false
    next_true: str | None = None
    next_false: str | None = None
    #: Child steps, for ``parallel`` (run concurrently, then joined) and
    #: ``loop`` (run in order, once per item). Empty for every other type,
    #: and the engine fails a ``parallel`` or ``loop`` that declares none
    #: rather than treating it as a no-op that reports success.
    #:
    #: One field for both rather than ``branches`` and ``body``: they are
    #: the same thing — an ordered list of steps the engine owns — and two
    #: fields would be two shapes for the editor, the schema and the
    #: validator to agree about.
    steps: list[PlaybookStep] = Field(default_factory=list)


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
