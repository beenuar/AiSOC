"""
Base executor interface for all action types.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.models.action import ActionRequest, ActionResult

# Appended to every simulation-mode note so operators know how to move from
# a stub to a live integration without leaving the workflow.
#
# Plugin SDK docs let contributors build and publish a signed integration
# in minutes.  The GitHub issue template pre-fills a "connector request" so
# the AiSOC maintainers can co-author and review the new integration.
_SIM_FUNNEL_CTA: str = (
    " | To wire in a live integration, see the Plugin SDK: "
    "https://docs.tryaisoc.com/plugins/overview"
    " | Want this integration co-authored? Open a request: "
    "https://github.com/beenuar/AiSOC/issues/new"
    "?labels=connector-request&template=connector_request.md"
)


class BaseExecutor(ABC):
    """Abstract base class for action executors."""

    @abstractmethod
    async def execute(self, request: ActionRequest) -> ActionResult:
        """Execute the action and return a result."""

    async def rollback(self, result: ActionResult) -> bool:
        """
        Rollback the action if possible.
        Returns True if rollback succeeded, False otherwise.
        """
        return False
