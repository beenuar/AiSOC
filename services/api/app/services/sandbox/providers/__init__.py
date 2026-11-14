"""Adapters. One open-source reference, one mock, one commercial.

Adding a fourth means implementing
:class:`~app.services.sandbox.base.SandboxProvider` and registering it in
:mod:`app.services.sandbox.registry`. Nothing outside this package should
learn the new provider's name.
"""

from app.services.sandbox.providers.capev2 import CapeV2Provider
from app.services.sandbox.providers.malwareanalyzer import MalwareAnalyzerProvider
from app.services.sandbox.providers.mock import MockSandboxProvider

__all__ = ["CapeV2Provider", "MalwareAnalyzerProvider", "MockSandboxProvider"]
