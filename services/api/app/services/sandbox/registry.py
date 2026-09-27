"""Which providers a deployment has, and which of them it may use right now.

Configuration is by environment variable because a sandbox is a deployment
fact, not a tenant one: the tenant decides whether its *files* may go to a
provider, the operator decides whether the provider exists at all. Keeping the
two apart is what makes the consent question answerable, because a tenant
cannot consent to a provider nobody configured.

The mock is always present. A deployment with no sandbox configured still has
the wiring exercised on every path, and the mock knows nothing, so the honest
answer on a first run is "not seen by any provider" rather than silence.
"""

from __future__ import annotations

import os

import structlog

from app.core.config import settings
from app.services.sandbox.base import SandboxProvider
from app.services.sandbox.providers.capev2 import CapeV2Provider
from app.services.sandbox.providers.malwareanalyzer import MalwareAnalyzerProvider
from app.services.sandbox.providers.mock import MockSandboxProvider

log = structlog.get_logger(__name__)

__all__ = ["SandboxRegistry", "build_registry"]


class SandboxRegistry:
    """The configured providers, and the air-gap rule over them."""

    def __init__(self, providers: list[SandboxProvider], *, airgapped: bool | None = None) -> None:
        self._providers = {p.name: p for p in providers}
        self._airgapped = settings.AISOC_AIRGAPPED if airgapped is None else airgapped

    @property
    def airgapped(self) -> bool:
        return self._airgapped

    def names(self) -> list[str]:
        """Every configured provider, including ones air-gap mode forbids.

        Forbidden is not absent: an operator whose provider has been excluded
        needs to see it excluded, with the reason, rather than watch it vanish
        from the settings page.
        """
        return sorted(self._providers)

    def usable_names(self) -> list[str]:
        return sorted(name for name, p in self._providers.items() if self.is_usable(p))

    def is_usable(self, provider: SandboxProvider) -> bool:
        return provider.local or not self._airgapped

    def get(self, name: str) -> SandboxProvider | None:
        return self._providers.get((name or "").strip().lower())

    def default(self) -> SandboxProvider | None:
        """The provider a caller that named none should get.

        A local provider wins over a hosted one at equal configuration, because
        the local one discloses nothing. Within that, configuration order is
        preserved, so an operator running CAPEv2 gets CAPEv2 and not the mock.
        """
        usable = [p for p in self._providers.values() if self.is_usable(p)]
        if not usable:
            return None
        real = [p for p in usable if p.name != "mock"]
        pool = real or usable
        return next((p for p in pool if p.local), pool[0])

    async def aclose(self) -> None:
        for provider in self._providers.values():
            await provider.aclose()


def build_registry(*, airgapped: bool | None = None) -> SandboxRegistry:
    """Assemble the providers this deployment has configured."""
    providers: list[SandboxProvider] = []

    cape_url = (os.getenv("AISOC_CAPEV2_URL") or "").strip()
    if cape_url:
        providers.append(CapeV2Provider(cape_url, api_token=os.getenv("AISOC_CAPEV2_TOKEN")))

    if _enabled("AISOC_MALWAREANALYZER_ENABLED"):
        providers.append(MalwareAnalyzerProvider())

    providers.append(MockSandboxProvider())
    registry = SandboxRegistry(providers, airgapped=airgapped)
    log.info(
        "sandbox.registry",
        providers=registry.names(),
        usable=registry.usable_names(),
        airgapped=registry.airgapped,
    )
    return registry


def _enabled(name: str) -> bool:
    """Default off.

    A hosted analysis provider that switched itself on because a base URL had a
    default would be a deployment making outbound calls nobody asked for, which
    is the shape the upload policy exists to prevent one level down.
    """
    return (os.getenv(name) or "").strip().lower() in {"1", "true", "yes", "on"}
