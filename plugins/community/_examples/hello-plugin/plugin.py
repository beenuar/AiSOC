"""Reference implementation for the "Hello, plugin" tutorial.

Walks through every step of writing an AiSOC enricher with the Python plugin
SDK. The full walkthrough lives at apps/docs/docs/plugins/hello-plugin.md —
this file is the runnable companion.

The enricher is intentionally trivial: it computes a deterministic SHA-256
hash of the indicator value and returns it as enrichment metadata. No
network calls, no external APIs, no credentials. That keeps the example:

- usable in air-gapped environments,
- reproducible in CI without secrets,
- focused on the *contract* rather than on third-party authentication.

When you're ready to write a real enricher, copy this file, replace the
hashing call with whatever vendor SDK you need, and keep the manifest +
``create_plugin`` factory shape exactly as-is.
"""

from __future__ import annotations

import hashlib

from aisoc_plugin_sdk import (
    AiSOCPlugin,
    EnricherPlugin,
    EnrichmentRequest,
    EnrichmentResult,
    PluginContext,
    PluginManifest,
)


class HelloPlugin(EnricherPlugin):
    """Deterministic, offline enricher used by the hello-plugin tutorial."""

    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="aisoc.hello-plugin",
            name="Hello Plugin (Tutorial)",
            version="1.0.0",
            description=(
                "Tutorial enricher that hashes indicator values locally. "
                "Reference implementation for "
                "apps/docs/docs/plugins/hello-plugin.md."
            ),
            author="AiSOC Tutorial",
            tags=["tutorial", "enricher", "offline"],
            plugin_type="enricher",
        )

    async def on_load(self, ctx: PluginContext) -> None:
        # The tutorial uses on_load() to demonstrate the lifecycle hook.
        # A real enricher might open a long-lived HTTP client, prime a cache,
        # or validate that required config keys are present. We just stash the
        # configured hash algorithm so we can reuse it from enrich().
        self._algorithm = (ctx.config.get("algorithm") or "sha256").lower()
        if self._algorithm not in hashlib.algorithms_guaranteed:
            raise ValueError(
                f"Unsupported hash algorithm: {self._algorithm!r}. "
                f"Pick one of: {sorted(hashlib.algorithms_guaranteed)}"
            )

    async def enrich(
        self, request: EnrichmentRequest, ctx: PluginContext
    ) -> EnrichmentResult:
        # Hash the indicator value with the configured algorithm. This is
        # deterministic and offline, so the same input always yields the same
        # enrichment — perfect for a tutorial and for snapshot tests.
        algorithm = getattr(self, "_algorithm", "sha256")
        digest = hashlib.new(algorithm, request.indicator_value.encode("utf-8")).hexdigest()

        return EnrichmentResult(
            indicator_type=request.indicator_type,
            indicator_value=request.indicator_value,
            enrichments={
                "hello_plugin.algorithm": algorithm,
                "hello_plugin.digest": digest,
                "hello_plugin.length": len(digest),
            },
            tags=["hello-plugin"],
            # The tutorial enricher never has an opinion on maliciousness —
            # leaving this as None is the honest answer and prevents the
            # alert UI from drawing a red badge based on a meaningless signal.
            malicious=None,
            confidence=None,
            raw={"input": request.indicator_value, "digest": digest},
        )


def create_plugin() -> AiSOCPlugin:
    """Factory called by ``load_plugin_from_directory``.

    The loader looks for a top-level ``create_plugin`` callable in
    ``plugin.py`` and uses whatever it returns as the plugin instance.
    Returning a fresh instance per call keeps every load isolated, which
    matters when the same process loads the same plugin under multiple
    tenants.
    """

    return HelloPlugin()
