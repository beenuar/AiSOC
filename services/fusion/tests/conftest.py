"""
Pytest config for the fusion service test suite.

Sets ``asyncio_mode = auto`` so the ``@pytest.mark.asyncio`` decorators in
``test_entity_risk.py`` resolve without per-test event-loop boilerplate. The
existing ``test_alert_model.py`` is sync and unaffected.
"""

from __future__ import annotations

import pytest


def pytest_collection_modifyitems(items):
    # Apply asyncio mark to every coroutine test function — keeps the suite
    # working without a [tool.pytest.ini_options] block in pyproject.toml.
    for item in items:
        if isinstance(item, pytest.Function) and item.get_closest_marker("asyncio") is None:
            if callable(item.function):
                import asyncio
                if asyncio.iscoroutinefunction(item.function):
                    item.add_marker(pytest.mark.asyncio)
