"""
Registry for :class:`LiveActionExecutor` implementations.

The registry is a simple dict keyed by ``(vendor_id, capability)`` plus
provenance metadata so the discovery endpoint can distinguish builtin
adapters from plugin registrations.

Why a module-level singleton instead of FastAPI dependency injection:
  Plugin code runs at import time (when the plugin's ``setup()`` hook
  fires), which is well before the first request. A module-level
  registry is the natural shape for that lifecycle. We expose
  ``reset_for_tests()`` so unit tests can guarantee isolation.

Thread-safety: registration happens at startup from a single thread.
Read paths (``get``, ``list_descriptors``) are safe to call concurrently
from FastAPI workers because dict reads are atomic in CPython and we
never mutate the registry on the request path.
"""

from __future__ import annotations

import structlog

from .capabilities import KNOWN_CAPABILITIES
from .executor import LiveActionExecutor
from .models import LiveActionDescriptor

logger = structlog.get_logger(__name__)

# (vendor_id, capability) -> (executor, source)
_REGISTRY: dict[tuple[str, str], tuple[LiveActionExecutor, str]] = {}


def register_executor(
    executor: LiveActionExecutor,
    *,
    source: str = "plugin",
    overwrite: bool = False,
) -> None:
    """Register a live-action executor.

    ``source`` is ``"builtin"`` for adapters shipped with the actions
    service and ``"plugin"`` for everything else. The default is
    ``"plugin"`` because that is the path plugin authors will hit.

    ``overwrite=False`` is the safe default: registering two executors
    for the same ``(vendor_id, capability)`` is almost always a bug
    (e.g. two plugins fighting for the same key). Tests and adapters
    that *intentionally* replace a binding can pass ``overwrite=True``.
    """
    if not executor.vendor_id or not executor.capability:
        raise ValueError(
            "LiveActionExecutor must declare vendor_id and capability "
            f"(got vendor_id={executor.vendor_id!r}, "
            f"capability={executor.capability!r})"
        )

    # Soft validation against the known capability vocabulary. We log a
    # warning rather than raising so plugin authors can experiment with
    # new verbs without first patching the core service. The warning
    # surfaces drift in production logs so we can decide whether to
    # promote a new verb into the canonical set.
    if executor.capability not in KNOWN_CAPABILITIES:
        logger.warning(
            "live_action.capability_unknown",
            vendor_id=executor.vendor_id,
            capability=executor.capability,
            hint=(
                "Capability is not in the canonical set defined in "
                "services/connectors/app/connectors/base.py::Capability. "
                "Add it there (and to capabilities.py mirror) if it should "
                "be promoted, or ignore this if it is a plugin-private verb."
            ),
        )

    key = (executor.vendor_id, executor.capability)
    if key in _REGISTRY and not overwrite:
        existing, existing_source = _REGISTRY[key]
        raise ValueError(
            f"Live action {executor.vendor_id}/{executor.capability} is "
            f"already registered (source={existing_source}, "
            f"class={type(existing).__name__}). Pass overwrite=True to "
            "replace it intentionally."
        )

    _REGISTRY[key] = (executor, source)
    logger.info(
        "live_action.registered",
        vendor_id=executor.vendor_id,
        capability=executor.capability,
        source=source,
        executor=type(executor).__name__,
    )


def unregister_executor(vendor_id: str, capability: str) -> bool:
    """Remove an executor registration. Returns True if something was removed.

    Used by the plugin shutdown path so unloading a plugin doesn't leave
    dangling executors behind. Tests also use this for targeted cleanup.
    """
    return _REGISTRY.pop((vendor_id, capability), None) is not None


def get_executor(vendor_id: str, capability: str) -> LiveActionExecutor | None:
    """Look up an executor. Returns ``None`` if no implementation is registered."""
    entry = _REGISTRY.get((vendor_id, capability))
    return entry[0] if entry else None


def list_descriptors() -> list[LiveActionDescriptor]:
    """Return one descriptor per registered executor for the discovery API.

    The list is sorted ``(vendor_id, capability)`` so the output is stable
    across processes — useful for diffing the discovery JSON in CI.
    """
    descriptors: list[LiveActionDescriptor] = []
    for (vendor_id, capability), (executor, source) in sorted(_REGISTRY.items()):
        descriptors.append(
            LiveActionDescriptor(
                vendor_id=vendor_id,
                capability=capability,
                description=executor.description or "",
                source=source,
                requires_credentials=executor.requires_credentials,
            )
        )
    return descriptors


def list_capabilities_for_vendor(vendor_id: str) -> list[str]:
    """Return all capabilities registered for ``vendor_id`` (sorted)."""
    return sorted(cap for (vid, cap) in _REGISTRY.keys() if vid == vendor_id)


def list_vendors_for_capability(capability: str) -> list[str]:
    """Return all vendor IDs that implement ``capability`` (sorted).

    Useful for the agent planner: "I want to isolate a host — which
    vendors can do that right now?".
    """
    return sorted(vid for (vid, cap) in _REGISTRY.keys() if cap == capability)


def reset_for_tests() -> None:
    """Wipe the registry. Test-only — NEVER call from production code."""
    _REGISTRY.clear()
