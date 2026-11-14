"""Response-action plugin base class."""

from __future__ import annotations

from abc import abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from .plugin import AiSOCPlugin, PluginContext


class ActionRequest(BaseModel):
    """Payload sent to a response-action plugin."""

    action_id: str = Field(..., description="Registered action identifier")
    params: dict[str, Any] = Field(default_factory=dict, description="Action-specific parameters")
    dry_run: bool = Field(
        False,
        description="If True the plugin must validate params and return what would happen without executing",
    )
    case_id: str | None = Field(None, description="Associated case ID, if any")
    playbook_run_id: str | None = Field(None, description="Playbook run that triggered this action")


class ActionResult(BaseModel):
    """Result returned by a response-action plugin."""

    action_id: str
    success: bool
    dry_run: bool = False
    summary: str = Field(default="", description="Human-readable one-liner of what happened")
    details: dict[str, Any] = Field(default_factory=dict, description="Structured action output")
    error: str | None = None


class ActionPlugin(AiSOCPlugin):
    """Base class for response-action plugins."""

    @abstractmethod
    def supported_actions(self) -> list[str]:
        """Return list of action IDs this plugin handles."""

    @abstractmethod
    async def execute(self, request: ActionRequest, ctx: PluginContext) -> ActionResult:
        """Execute the action and return a structured result."""
