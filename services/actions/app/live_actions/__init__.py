"""
Generic live-action interface for AiSOC.

This package implements Stage 2 #8: a registry-driven layer that lets
plugins (and in-tree adapters) implement action verbs (``isolate_host``,
``block_ip``, ...) for specific vendors (``crowdstrike``, ``defender``,
``aws_security_groups``, ...). The agent loop and playbook engine call
:func:`dispatcher.dispatch` with a :class:`models.LiveActionRequest`
keyed by ``(capability, vendor_id)`` and get a uniform
:class:`models.LiveActionResult` back.

Why this lives alongside (not on top of) the legacy ``ActionType``
registry:
  The legacy registry is used by the established Action Execution REST
  API and a large test suite. The live-action layer adds a more general
  routing model without forcing every downstream caller to migrate at
  once. Builtin adapters in :mod:`builtins` re-expose the existing
  executors under the new ``(vendor_id, capability)`` shape so the new
  endpoints work out of the box, and plugins can register additional
  executors via :func:`registry.register_executor` from their setup
  hook.

Public surface (the only names callers should import):

  - :class:`LiveActionRequest`, :class:`LiveActionResult`,
    :class:`LiveActionStatus`, :class:`LiveActionDescriptor`
  - :class:`LiveActionExecutor`
  - :func:`dispatch`
  - :func:`register_executor`, :func:`unregister_executor`,
    :func:`get_executor`, :func:`list_descriptors`
  - :func:`register_builtin_executors`
"""

from .builtins import register_builtin_executors
from .capabilities import KNOWN_CAPABILITIES
from .dispatcher import dispatch
from .executor import LiveActionExecutor
from .models import (
    LiveActionDescriptor,
    LiveActionRequest,
    LiveActionResult,
    LiveActionStatus,
)
from .registry import (
    get_executor,
    list_capabilities_for_vendor,
    list_descriptors,
    list_vendors_for_capability,
    register_executor,
    reset_for_tests,
    unregister_executor,
)

__all__ = [
    "KNOWN_CAPABILITIES",
    "LiveActionDescriptor",
    "LiveActionExecutor",
    "LiveActionRequest",
    "LiveActionResult",
    "LiveActionStatus",
    "dispatch",
    "get_executor",
    "list_capabilities_for_vendor",
    "list_descriptors",
    "list_vendors_for_capability",
    "register_builtin_executors",
    "register_executor",
    "reset_for_tests",
    "unregister_executor",
]
