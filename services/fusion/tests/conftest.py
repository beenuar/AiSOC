"""
Pytest config for the fusion service test suite.

Sets ``asyncio_mode = auto`` so the ``@pytest.mark.asyncio`` decorators in
``test_entity_risk.py`` resolve without per-test event-loop boilerplate. The
existing ``test_alert_model.py`` is sync and unaffected.

The canonical Kafka producer double lives in ``tests/kafka_doubles.py``:
anything reaching a publish must use it rather than ``AsyncMock()``, which
cannot tell an enqueue from a delivery.
"""

from __future__ import annotations

import pytest
from app.core.config import settings


@pytest.fixture(autouse=True)
def _isolated_lake_spool(tmp_path, monkeypatch):
    """Point lake archival at a per-test directory.

    The lake writer spools to disk before reporting an event durable, so
    without this every test that touches it would append to one shared
    directory: tests would see each other's backlog, and a suite run would
    leave rows behind on a contributor's machine.
    """
    monkeypatch.setattr(settings, "lake_spool_dir", str(tmp_path / "lake-spool"))


def pytest_collection_modifyitems(items):
    # Apply asyncio mark to every coroutine test function — keeps the suite
    # working without a [tool.pytest.ini_options] block in pyproject.toml.
    for item in items:
        if isinstance(item, pytest.Function) and item.get_closest_marker("asyncio") is None:
            if callable(item.function):
                import asyncio

                if asyncio.iscoroutinefunction(item.function):
                    item.add_marker(pytest.mark.asyncio)
