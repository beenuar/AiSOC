---
sidebar_position: 3
title: Hello, plugin — write your first AiSOC enricher
description: A walkthrough that ships a runnable AiSOC plugin end to end. Author the manifest, implement the EnricherPlugin contract, register it with the runtime, and pin the whole thing with a smoke test — no vendor account, no API key, just the Python plugin SDK front to back.
---

# Hello, plugin

This tutorial walks you end-to-end through the work of adding a new plugin to AiSOC. By the end you will have:

- An `aisoc-plugin.yaml` manifest the plugin loader can validate.
- A `plugin.py` that subclasses `EnricherPlugin` and exposes a `create_plugin()` factory.
- A working `on_load()` lifecycle hook that reads tenant config out of `PluginContext`.
- A working `enrich()` method that returns a typed `EnrichmentResult` the platform can write to indicator records.
- A `PluginRegistry` flow that mirrors what the AiSOC runtime does at boot.
- A smoke test that pins all of the above against the real loader, so the docs page can never silently drift away from the code.

The example enricher is intentionally trivial — it computes a deterministic SHA-256 hash of the indicator value and returns the digest as enrichment metadata. There is no network call, no external API, no credential. That keeps the tutorial:

- runnable in air-gapped environments,
- reproducible in CI without secrets,
- focused on the *contract* rather than on third-party authentication,
- safe to copy as a starting point — when you swap the hash for a vendor SDK the manifest and entry-point shape stay identical.

When you're ready to write a real enricher, copy the example, replace the hashing call with whatever vendor SDK you need, and keep the manifest + `create_plugin` factory shape exactly as-is.

## Where the example lives

The reference plugin and its smoke test live at:

```text
plugins/community/_examples/hello-plugin/aisoc-plugin.yaml
plugins/community/_examples/hello-plugin/plugin.py
plugins/community/_examples/hello-plugin/README.md
packages/plugin-sdk-py/tests/test_hello_plugin_example.py
```

The `_examples/` directory is **deliberately not** picked up by [`scripts/build_marketplace.py`](https://github.com/beenuar/AiSOC/blob/main/scripts/build_marketplace.py). The marketplace builder scans `plugins/community/<id>/plugin.yaml`, and the tutorial avoids both signals on purpose:

1. It lives one directory deeper, under `_examples/hello-plugin/`.
2. Its manifest is named `aisoc-plugin.yaml` (the SDK loader filename), not `plugin.yaml` (the marketplace filename).

That means the example can never accidentally ship to a real tenant. The smoke test pins this invariant — if anyone "fixes" either of those, CI fails. The same pattern is used by [Hello, connector](/docs/connectors/hello-connector) and [Hello, hunt](/docs/detections/hello-hunt).

## Plugin types — pick the right base class first

The Python SDK ships three plugin types, each with a different contract:

| Type        | Base class                  | Contract method                              | Use it when…                                                                                                  |
| ----------- | --------------------------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `enricher`  | `EnricherPlugin`            | `async def enrich(req, ctx) -> EnrichmentResult` | You take an indicator (IP, domain, URL, hash, email) and return structured intel about it.                  |
| `action`    | `ActionPlugin`              | `async def execute(req, ctx) -> ActionResult`    | You take a response action (block IP, isolate host, page on-call) and report success or failure back.        |
| `connector` | `ConnectorPlugin` *(plugin)*| `async def fetch_alerts(...)`                    | You poll a vendor API and emit normalized alerts. **For first-class connectors use [`BaseConnector`](/docs/connectors/hello-connector) instead — the connector plugin type exists for marketplace-shipped third-party integrations.** |

This tutorial sticks to `enricher` because it's the simplest contract — one input record in, one output record out, no scheduler, no retry policy, no normalisation. When you've internalised the manifest + `create_plugin()` shape here, the action and connector plugin types will feel familiar.

## Step 1 — Pick a stable plugin `id`

```yaml
id: aisoc.hello-plugin
```

Three rules to internalise:

1. **Lowercase, dotted, no spaces.** The `id` is a wire identifier — it ends up in `marketplace/index.json`, in tenant install records, and in audit logs whenever the registry resolves an enricher. Treat it like a primary key.
2. **Prefix with your namespace.** Use `<your-org>.` or `<your-handle>.` so two contributors don't ship `vt-enricher` and collide. The `aisoc.` prefix is reserved for first-party tutorial and reference plugins; real contributions use `acme.virustotal` or `jdoe.greynoise`.
3. **Never change it after merge.** Renaming a plugin orphans every tenant install that references the old id. If the plugin needs a v2 with breaking config changes, give it a new id and deprecate the old one — the marketplace publishing flow has a `deprecated` field for exactly this reason. See [Publishing plugins](/docs/plugins/publishing).

The example uses `aisoc.hello-plugin` because the AiSOC project itself is the author.

## Step 2 — Write the manifest

The manifest is parsed by [`load_manifest`](https://github.com/beenuar/AiSOC/blob/main/packages/plugin-sdk-py/src/aisoc_plugin_sdk/loader.py) and validated against [`PluginManifest`](https://github.com/beenuar/AiSOC/blob/main/packages/plugin-sdk-py/src/aisoc_plugin_sdk/plugin.py). Anything that doesn't match the schema is rejected at load time with a `PluginLoadError`.

```yaml title="plugins/community/_examples/hello-plugin/aisoc-plugin.yaml"
id: aisoc.hello-plugin
name: Hello Plugin (Tutorial)
version: 1.0.0
plugin_type: enricher
description: >
  Tutorial enricher that hashes the indicator value with SHA-256 locally.
  Reference implementation for apps/docs/docs/plugins/hello-plugin.md.
  Deliberately offline so it can run in air-gapped environments and CI
  without any external API calls.
author: AiSOC Tutorial
tags:
  - tutorial
  - enricher
  - offline
```

A few non-obvious things:

- **`plugin_type` is regex-validated.** The schema enforces `^(enricher|action|connector)$`. Misspelling it (`enrichers`, `Enricher`, `connect`) fails the load with a Pydantic validation error before your `plugin.py` is even imported.
- **`version` is treated as SemVer.** The marketplace orders installable versions by SemVer comparison, and the publishing flow uses it to decide whether a tenant has an upgrade available. Use real SemVer (`1.0.0`, `1.0.1`, `2.0.0-rc.1`) — calendar versions like `2025.05` will sort but won't trigger upgrade notifications cleanly.
- **`tags` are free-form** and mostly used for marketplace filtering. There is no enforced taxonomy (yet). Keep them lowercase and hyphen-separated for consistency with the connectors layer.
- **Two manifest filenames exist.** The SDK loader (`load_manifest`) reads `aisoc-plugin.yaml`. The marketplace builder (`scripts/build_marketplace.py`) reads `plugin.yaml`. The two formats are nearly identical, but the marketplace one carries extra publish metadata (signature URL, registry URL, install instructions). When you graduate from `_examples/` to `plugins/community/<your-id>/`, you will write **both** files. See [Publishing plugins](/docs/plugins/publishing) for the marketplace shape.

## Step 3 — Implement the plugin class

Now the code. Two ways to do this — class-based and decorator-based. The tutorial uses the class-based path because it makes the `on_load`/`on_unload` lifecycle hooks explicit, which you'll want as soon as a real enricher needs an HTTP client or a cached secret.

```python title="plugins/community/_examples/hello-plugin/plugin.py"
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
```

Three things to call out:

1. **`manifest` is a `@property`, not a method.** The SDK defines `manifest` as `@property @abstractmethod` on `AiSOCPlugin`. If you write `def manifest(self)` instead of `@property def manifest(self)`, the registry will receive a *bound method* instead of a `PluginManifest` instance and every lookup will explode at runtime. The smoke test pins the property contract.
2. **The manifest values must mirror `aisoc-plugin.yaml`.** The loader trusts the YAML for discovery, but every code path past the load step reads the manifest off the *plugin instance*. If the two drift, the marketplace will list one version and the runtime will report another. Keep them in lockstep, or have a build step that reads the YAML and constructs the manifest from it.
3. **You're inheriting from `EnricherPlugin`, not `AiSOCPlugin` directly.** This is what makes the registry route enrichment requests to your plugin. Inheriting from the wrong base class is a silent bug — the plugin loads fine, registers fine, and never receives any enrichment work.

## Step 4 — Implement the lifecycle hook

`on_load(ctx)` is called exactly once, after the plugin is registered and before the runtime sends it any work. The `PluginContext` argument carries the API base URL, a scoped API token, and the tenant's plugin config dict.

```python
async def on_load(self, ctx: PluginContext) -> None:
    self._algorithm = (ctx.config.get("algorithm") or "sha256").lower()
    if self._algorithm not in hashlib.algorithms_guaranteed:
        raise ValueError(
            f"Unsupported hash algorithm: {self._algorithm!r}. "
            f"Pick one of: {sorted(hashlib.algorithms_guaranteed)}"
        )
```

What's happening:

- **`ctx.config` is the per-tenant configuration.** Whatever the tenant set in their plugin install settings ends up here. The tutorial reads a single optional `algorithm` key — a real enricher might read API endpoints, rate-limit budgets, or per-customer feature flags.
- **The hook can raise.** If `on_load` raises, the runtime marks the plugin install as failed and surfaces the error message to the tenant. Use this to fail fast on bad config — empty API keys, unreachable endpoints, malformed allow-lists. Failing here is cheaper than failing later in `enrich()`, where the same error will repeat for every indicator.
- **There is also `on_unload()`.** It's called when the plugin is uninstalled or when the runtime shuts down. The tutorial doesn't override it because there's nothing to clean up. A real enricher with a long-lived `httpx.AsyncClient` should `await client.aclose()` here.

## Step 5 — Implement `enrich()`

This is the actual work the platform calls.

```python
async def enrich(
    self, request: EnrichmentRequest, ctx: PluginContext
) -> EnrichmentResult:
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
        malicious=None,
        confidence=None,
        raw={"input": request.indicator_value, "digest": digest},
    )
```

The contract:

- **`request.indicator_type` and `request.indicator_value` come from the indicator that triggered enrichment.** The five types AiSOC routes today are `ip | domain | url | hash | email`. A real enricher should branch on `indicator_type` and short-circuit (or return an empty result) for types it doesn't support — the tutorial hashes everything because hash-of-anything is well-defined.
- **`enrichments` is a flat dict that's merged into the indicator record.** Namespace your keys with `<plugin-id>.<field>` (the tutorial uses `hello_plugin.*`) so two enrichers writing to the same indicator can't stomp each other.
- **`tags` are appended to the indicator's tag list.** Use them for downstream filtering — e.g. `["malicious", "vt-detected"]` or `["benign", "alexa-top-1k"]`.
- **`malicious` is a tri-state.** `True` means the enricher is confident it's bad. `False` means the enricher is confident it's clean. `None` means the enricher has no opinion. **Don't return `False` just because your API returned no hits** — that's an opinion you don't have. The tutorial returns `None` because hashing a value tells you nothing about its reputation.
- **`confidence` is `[0.0, 1.0]` or `None`.** Pydantic enforces the range; out-of-band values raise at construction time. Skip the field unless your upstream actually returns a confidence score.
- **`raw` is for audit.** Store the upstream API response (or a redacted version) so investigators can reproduce the decision later. Don't put secrets in here — the indicator record is readable by anyone with case access.

## Step 6 — Expose `create_plugin()`

The loader doesn't import your class directly. It looks for a top-level `create_plugin()` factory in `plugin.py` and uses whatever it returns:

```python
def create_plugin() -> AiSOCPlugin:
    """Factory called by ``load_plugin_from_directory``."""
    return HelloPlugin()
```

Why a factory and not the class itself:

- **Per-tenant isolation.** Every tenant install gets its own plugin instance, so per-tenant state (cached HTTP client, last-seen timestamp, rate-limit bucket) lives on the instance and can't leak across tenants.
- **Lazy construction.** The class can defer expensive work (loading a model, opening a file) until the runtime actually needs it. The loader pays the cost of `create_plugin()`; the import of `plugin.py` stays cheap.
- **Test-friendly.** The smoke test calls `load_plugin_from_directory(...)` exactly the way the runtime does. If `create_plugin` is missing, returns `None`, or returns something that isn't an `AiSOCPlugin`, the loader raises `PluginLoadError` with a precise message. You don't need to mock anything.

## Step 7 — Run the smoke test

The companion smoke test lives at `packages/plugin-sdk-py/tests/test_hello_plugin_example.py` and pins the entire contract: the files exist, the example is excluded from the marketplace, the loader accepts the manifest + factory shape, the lifecycle hook validates config, and the enrichment is deterministic.

```bash
cd packages/plugin-sdk-py
.venv/bin/python -m pytest tests/test_hello_plugin_example.py -v
```

Expected output:

```text
tests/test_hello_plugin_example.py::test_hello_plugin_example_files_exist PASSED
tests/test_hello_plugin_example.py::test_hello_plugin_is_excluded_from_marketplace PASSED
tests/test_hello_plugin_example.py::test_hello_plugin_loads_via_loader PASSED
tests/test_hello_plugin_example.py::test_on_load_defaults_to_sha256 PASSED
tests/test_hello_plugin_example.py::test_on_load_accepts_configured_algorithm PASSED
tests/test_hello_plugin_example.py::test_on_load_rejects_unknown_algorithm PASSED
tests/test_hello_plugin_example.py::test_enrich_is_deterministic PASSED
tests/test_hello_plugin_example.py::test_enrich_uses_configured_algorithm PASSED
tests/test_hello_plugin_example.py::test_hello_plugin_registers_as_enricher PASSED
9 passed
```

The two tests worth understanding before you write your own plugin:

### `test_hello_plugin_loads_via_loader`

```python
def test_hello_plugin_loads_via_loader() -> None:
    plugin = load_plugin_from_directory(HELLO_PLUGIN_DIR)

    assert isinstance(plugin, EnricherPlugin)
    assert plugin.manifest.id == "aisoc.hello-plugin"
    assert plugin.manifest.plugin_type == "enricher"
```

This is the single most useful test you can write for a plugin. It calls `load_plugin_from_directory` exactly the way the runtime does, which proves:

- the manifest YAML is parseable and schema-valid,
- the entry point file exists and is importable,
- `create_plugin()` is defined and returns the expected base class,
- the manifest property returns a real `PluginManifest` (not a method, not `None`).

If this test passes, the runtime will be able to load your plugin. If it fails, the error message points at exactly which contract you broke.

### `test_enrich_is_deterministic`

```python
async def test_enrich_is_deterministic(ctx: PluginContext) -> None:
    plugin = load_plugin_from_directory(HELLO_PLUGIN_DIR)
    await plugin.on_load(ctx)

    request = EnrichmentRequest(
        indicator_type="ip", indicator_value="203.0.113.42",
    )
    expected_digest = hashlib.sha256(b"203.0.113.42").hexdigest()

    result_a = await plugin.enrich(request, ctx)
    result_b = await plugin.enrich(request, ctx)

    assert result_a.enrichments["hello_plugin.digest"] == expected_digest
    assert result_a.model_dump() == result_b.model_dump()
```

Two reasons this matters:

1. **The same input must always yield the same enrichment.** That's what makes the result cacheable, replayable, and trustworthy in case investigations. If your enricher hits a vendor API, mock the API in the test (with `respx` or `pytest-httpx`) so the test stays deterministic — you're testing *your code*, not the vendor's uptime.
2. **Snapshot equality on `model_dump()`** is the cheapest way to catch accidental breaking changes. If you add a new key to `enrichments`, this assertion still passes (because it's the same on both calls). If you start mutating shared state across calls, it fails immediately.

## Step 8 — Register with the runtime

In production, the AiSOC plugin runtime constructs a `PluginRegistry`, loads every installed plugin from disk, and calls `load_all()` once per tenant. The smoke test mirrors this so you can validate it locally:

```python
async def test_hello_plugin_registers_as_enricher(ctx: PluginContext) -> None:
    plugin = load_plugin_from_directory(HELLO_PLUGIN_DIR)
    registry = PluginRegistry()
    registry.register(plugin)

    await registry.load_all(ctx)

    assert len(registry) == 1
    enrichers = registry.enrichers()
    assert len(enrichers) == 1
    assert enrichers[0].manifest.id == "aisoc.hello-plugin"
    assert registry.get("aisoc.hello-plugin") is plugin
```

Three things this proves:

- `PluginRegistry.register()` accepts the plugin and stores it under `manifest.id`. Registering the same id twice raises — the runtime relies on this to surface duplicate installs.
- `load_all()` calls `on_load(ctx)` for every plugin and propagates exceptions. If your `on_load` raises, the registry stays in a half-loaded state and the runtime surfaces the error to the tenant.
- `enrichers()` returns only `EnricherPlugin` instances. The same registry can hold actions and connectors side-by-side; the type-segmented accessors (`enrichers()`, `actions()`, `connectors()`) are how the runtime routes work.

## What you don't get from the tutorial

The tutorial is intentionally narrow. Real plugins eventually need:

- **Authentication.** Most real enrichers need an API key or OAuth token. Read it from `ctx.config`, never from env vars — env vars are global and the runtime sets them per-process, not per-tenant. The credential vault encrypts secrets at rest; see [Operations → Credentials](/docs/operations/credentials).
- **An HTTP client.** Open one `httpx.AsyncClient` in `on_load`, store it on `self`, reuse it from every `enrich()`, and close it in `on_unload`. Don't open a fresh client per request — connection pooling matters even for low-volume enrichers.
- **Error handling.** The current `enrich()` will raise if the algorithm is missing or invalid. A real enricher should catch upstream API errors, classify them (timeout vs. 4xx vs. 5xx), and either return an empty `EnrichmentResult` or raise — the runtime treats unhandled exceptions as fatal for the request, not for the plugin.
- **Rate limiting.** If your vendor enforces a request-per-second budget, enforce it in the plugin with `asyncio.Semaphore` or `aiolimiter`. The runtime won't do it for you, and bursting will get the tenant's API key throttled or banned.
- **Observability.** The `AiSOCClient` (exported from `aisoc_plugin_sdk`) gives you authenticated access to the AiSOC API for emitting plugin-side events and metrics. Use it sparingly — every call goes back over the network.

When you wire any of these in, the contract you wrote in this tutorial — manifest, `create_plugin()`, `on_load`, `enrich`, registry — does not change. That's the value of the SDK.

## Graduating from `_examples/` to the marketplace

When you're ready to ship the plugin to real tenants:

1. Copy `plugins/community/_examples/hello-plugin/` to `plugins/community/<your-id>/`.
2. Rename `aisoc-plugin.yaml` → `plugin.yaml` and add the marketplace fields (`signature_url`, `registry_url`, `install_command`). The full schema lives in [Publishing plugins](/docs/plugins/publishing).
3. Sign the plugin with your maintainer Ed25519 key (`scripts/sign_plugin.py`).
4. Add an entry to `marketplace/index.json` and run `pnpm marketplace:sync`.
5. Open a PR. Maintainers will review the plugin, validate the signature against your registered public key, and merge.

After merge the plugin shows up in every tenant's in-app marketplace under the **Community** badge. Tenants install it with one click, and the runtime calls the same `load_plugin_from_directory()` you tested locally.

That's the whole loop.
