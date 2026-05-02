"""
Base executor interface for all action types.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from app.models.action import ActionRequest, ActionResult


class BaseExecutor(ABC):
    """Abstract base class for action executors."""

    @abstractmethod
    async def execute(self, request: ActionRequest) -> ActionResult:
        """Execute the action and return a result."""
        ...

    async def rollback(self, result: ActionResult) -> bool:
        """
        Rollback the action if possible.
        Returns True if rollback succeeded, False otherwise.
        """
        return False
