# Hello Plugin (Tutorial)

Reference implementation for [apps/docs/docs/plugins/hello-plugin.md](../../../../apps/docs/docs/plugins/hello-plugin.md).

A deterministic, offline AiSOC enricher that hashes indicator values with
SHA-256 and returns the digest as enrichment metadata. No network calls, no
credentials, no external dependencies beyond `aisoc-plugin-sdk` itself.

## Why this lives under `_examples/`

Anything under `plugins/community/_examples/` is documentation only:

- It is **not** picked up by `scripts/build_marketplace.py`.
- It does **not** appear in the in-app marketplace.
- It is **not** loaded by the plugin runtime in any environment.

The directory exists so contributors have a runnable, reviewable starting
point that can never accidentally ship to a real tenant. When you're ready
to graduate, copy the directory to `plugins/community/<your-id>/` and the
marketplace builder will pick it up on the next `pnpm marketplace:build`.

## Files

| Path                  | Purpose                                                   |
| --------------------- | --------------------------------------------------------- |
| `aisoc-plugin.yaml`   | Plugin manifest (id, name, version, plugin_type).         |
| `plugin.py`           | Plugin entry point with `HelloPlugin` + `create_plugin()`. |
| `README.md`           | This file.                                                |

## Run the smoke test

```bash
cd packages/plugin-sdk-py
.venv/bin/python -m pytest tests/test_hello_plugin_example.py -v
```

The smoke test pins:

1. The example is **not** importable as a real plugin (kept under `_examples/`).
2. `load_plugin_from_directory()` accepts the manifest + `create_plugin()` shape.
3. The enrichment is deterministic for the same input.
4. The `on_load()` hook validates the algorithm config.
5. The `PluginRegistry` correctly registers it as an enricher.

If you change the manifest, the algorithm, or the enrichment shape, the
test will fail and the docs page will need a matching update.
