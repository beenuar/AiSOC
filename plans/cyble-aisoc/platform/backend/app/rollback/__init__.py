"""Rollback service.

Paired-reverse-action engine for the t1-reverse-actions theme. Given a
historical ``ToolCall`` row, this module resolves the registered reverse
tool (via :class:`app.tools.registry.ToolDef.reverse_tool`), derives the
inverse parameters with the tool's ``reverse_params_builder``, and
dispatches the undo through :meth:`BaseAgent.call_tool` with
``rollback_of_id`` set so the paired audit trail (forward row +
reverse row) is stamped atomically.
"""
from app.rollback.service import (
    RollbackError,
    RollbackNotEligible,
    execute_rollback,
    list_rollback_eligible,
    rollback_eligibility,
)

__all__ = [
    "RollbackError",
    "RollbackNotEligible",
    "execute_rollback",
    "list_rollback_eligible",
    "rollback_eligibility",
]
