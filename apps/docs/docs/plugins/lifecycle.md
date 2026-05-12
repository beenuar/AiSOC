---
sidebar_position: 6
title: Plugin lifecycle
description: How a plugin moves from "files on disk" to "running, signature-verified, hot-reloadable code in the platform" — and how to operate it once it is loaded.
---

# Plugin lifecycle

The [overview](./overview) and [publishing](./publishing) pages cover the
*author*'s side of the story. This page is the *operator*'s side: what the
platform actually does between "plugin files appear on disk" and "the plugin
is running inside `services/api`", and what controls you have at each step.

## States

Every loaded plugin sits in exactly one of these states. The `signature_status`
field is independent — a plugin can be `enabled` and `unsigned`, or
`disabled` and `verified`. Both are exposed on `GET /api/v1/plugins`.

| State | Meaning | Reachable from |
|---|---|---|
| **Discovered** | A directory with a valid `plugin.yaml` (or legacy `aisoc-plugin.json`) was found in `AISOC_PLUGINS_DIR`. | `POST /plugins/discover`, startup auto-discovery |
| **Loaded** | The Python module imported successfully and the manifest schema validated. | Discovered → Loaded (automatic) |
| **Enabled** | Loaded **and** invocations are accepted. The default for newly discovered plugins. | Loaded, Disabled |
| **Disabled** | Loaded **but** `run` calls are blocked at the manager. Useful for "keep it warm but stop traffic." | Enabled |
| **Unloaded** | Removed from memory. Files remain on disk. The next discovery cycle will load it again unless the directory is removed. | Enabled, Disabled |
| **Failed** | Discovery / load raised an error. The error string is returned on `GET /plugins/{id}`. | Discovered → Failed |

| `signature_status` | Meaning |
|---|---|
| `verified` | Ed25519 signature matched a key in `PLUGIN_TRUSTED_KEYS_DIR`. |
| `unsigned` | No `plugin.sig` file present. Loadable only when `PLUGIN_TRUST_MODE != strict`. |
| `invalid` | A `plugin.sig` exists but failed verification. Loadable only in `warn`. |
| `skipped` | `PLUGIN_TRUST_MODE=disabled` — checks were not run. **Not** for production. |

## Lifecycle diagram

```text
   ┌──────────┐  discover()     ┌─────────┐  signature  ┌─────────┐
   │  on disk │────────────────▶│ Loaded  │────check───▶│ Enabled │
   └──────────┘                 └─────────┘             └────┬────┘
        ▲                            │                       │
        │                            │ disable()             │ enable()
        │                            ▼                       ▼
        │                       ┌──────────┐           ┌──────────┐
        │   reload()            │ Disabled │◀──────────│ Enabled  │
        └──── unload() ─────────└──────────┘           └──────────┘
```

`reload()` re-imports the Python module from disk in place, so a hot-fix can
land without restarting the API process. The plugin's previous `enabled`
state is preserved across the reload.

## Trust modes

`PLUGIN_TRUST_MODE` is the single switch that decides what the loader does
on signature failure. The default in production is `strict` for a reason —
plugins execute arbitrary Python via `importlib.exec_module`, so an
unsigned/invalid plugin is a remote code execution vector if `AISOC_PLUGINS_DIR`
is writable by anyone other than the operator.

| Mode | On unsigned | On invalid signature | On valid + trusted | Use for |
|---|---|---|---|---|
| `strict` (default) | Refuse to load | Refuse to load | Load, `verified` | Production. |
| `warn` | Load, `unsigned` | Load, `invalid` | Load, `verified` | Bootstrapping a key-rotation programme. |
| `disabled` | Load, `skipped` | Load, `skipped` | Load, `skipped` | Throwaway dev sandboxes only. |

The settings preflight (`services/api/app/core/config.py`) emits a
`PLUGIN_TRUST_MODE=disabled outside development` warning at startup if you
ship `disabled` to a non-dev `ENVIRONMENT`. Listen to it.

## Discovery

Two ways a plugin gets discovered:

### 1. Filesystem (`AISOC_PLUGINS_DIR`)

On startup the API scans `AISOC_PLUGINS_DIR` (default `/opt/aisoc/plugins`)
for any subdirectory containing a manifest. Anything new is loaded; anything
that disappeared is left behind in memory until the operator calls
`DELETE /plugins/{id}`.

To trigger a re-scan without a restart:

```bash
curl -X POST "$AISOC_API/api/v1/plugins/discover" \
  -H "Authorization: Bearer $TOKEN"
# → { "discovered": ["wazuh-connector", "shodan-enricher"] }
```

Required permission: `plugins:admin`.

### 2. OCI image (`install_from_oci`)

For pull-based delivery (CI / GitOps-style flows), the manager can pull a
plugin from an OCI registry via the [ORAS](https://oras.land) CLI:

```python
plugin_id = await plugin_manager.install_from_oci(
    "ghcr.io/myorg/aisoc-plugins/shodan-enricher:1.2.0",
)
```

The image's primary layer is extracted into `AISOC_PLUGINS_DIR/<plugin_id>`
and then loaded through the same discovery path. Signature checks still
apply — packing a `plugin.sig` into the OCI artifact is part of your CI
build, not something AiSOC fakes for you.

## Operator API

Every endpoint requires a token with the matching permission. Operator
tokens are RBAC-controlled, not service-scoped — you do **not** want a
shared `aisoc_*` API key holding `plugins:admin` in production.

| Endpoint | Permission | What it does |
|---|---|---|
| `GET /api/v1/plugins` | `plugins:read` | List all loaded plugins. Optional `?plugin_type=connector` filter. |
| `GET /api/v1/plugins/{id}` | `plugins:read` | Single-plugin detail incl. `signature_status` and `error`. |
| `POST /api/v1/plugins/discover` | `plugins:admin` | Re-scan `AISOC_PLUGINS_DIR`. |
| `POST /api/v1/plugins/{id}/enable` | `plugins:admin` | Move `Disabled` → `Enabled`. |
| `POST /api/v1/plugins/{id}/disable` | `plugins:admin` | Move `Enabled` → `Disabled`. Keeps it loaded. |
| `POST /api/v1/plugins/{id}/reload` | `plugins:admin` | Re-import the module from disk. Preserves `enabled` state. |
| `DELETE /api/v1/plugins/{id}` | `plugins:admin` | Unload from memory. Files on disk are untouched. |
| `POST /api/v1/plugins/{id}/run` | `plugins:execute` | Direct invocation. Useful for one-off enrichment, smoke tests, and `aisoc-cli`. |

A typical operator pipeline:

```bash
# 1. Author publishes a new version → CI uploads to OCI registry.
# 2. Operator pulls and loads it:
curl -X POST "$AISOC_API/api/v1/plugins/install_from_oci" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"oci_ref": "ghcr.io/myorg/aisoc-plugins/shodan-enricher:1.2.0"}'

# 3. Smoke-test it with a real input:
curl -X POST "$AISOC_API/api/v1/plugins/shodan-enricher/run" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"payload": {"ip": "1.1.1.1"}}'

# 4. If the smoke test looks bad, disable without unloading:
curl -X POST "$AISOC_API/api/v1/plugins/shodan-enricher/disable" \
  -H "Authorization: Bearer $TOKEN"

# 5. Roll a hot-fix → push new commits to the plugin directory → reload:
curl -X POST "$AISOC_API/api/v1/plugins/shodan-enricher/reload" \
  -H "Authorization: Bearer $TOKEN"
```

## Configuration reference

| Variable | Default | Purpose |
|---|---|---|
| `AISOC_PLUGINS_DIR` | `/opt/aisoc/plugins` | Where the loader looks for plugin directories. |
| `PLUGIN_TRUST_MODE` | `strict` | One of `strict`, `warn`, `disabled`. |
| `PLUGIN_TRUSTED_KEYS_DIR` | `/opt/aisoc/plugin-keys` | Directory of PEM-encoded Ed25519 public keys. **All** PEMs in it are tried per signature; one match is enough. |

Mount these the way you mount any other piece of trust:

- `AISOC_PLUGINS_DIR` — typically a Persistent Volume (k8s) or a host-bind mount (Docker Compose). It must **not** be writable by anyone other than the operator role that pulls plugins.
- `PLUGIN_TRUSTED_KEYS_DIR` — read-only mount, owned by root, mode `0444` per file.

## Versioning, upgrades, and rollback

The loader's identity is `manifest.id`, **not** the directory name. That means:

- Upgrading is "drop a new version of the same `id` into a new directory, reload, delete the old directory, re-discover." A reload is not enough on its own to switch versions because the previous module is what gets re-imported — you need the new files on disk, then the operator decides whether to swap.
- Rollback is the reverse: drop the previous version back into `AISOC_PLUGINS_DIR`, run discovery, run reload. The platform never deletes plugin files — that is always the operator's call.
- Two plugins with the same `manifest.id` is a **load-time error**. The first one wins; the second is reported as `Failed` with a clear duplicate-id message in `error`.

## Observability

Every state transition is logged through `structlog` and shows up in your
audit pipeline if you have `services/api/app/middleware/audit_middleware.py`
forwarding to it. The events worth alerting on:

| Event | Meaning |
|---|---|
| `plugin.load.failed` | Discovery found a manifest but the module would not import. |
| `plugin.signature.invalid` | A `plugin.sig` exists but did not match a trusted key. **In production this is a red flag** — it usually means the key got rotated without the operator copying the new PEM into `PLUGIN_TRUSTED_KEYS_DIR`. |
| `plugin.signature.unsigned` (warn mode only) | An unsigned plugin loaded. |
| `plugin.duplicate_id` | Two directories ship the same `manifest.id`. |
| `plugin.reload.completed` | A hot-reload landed cleanly. Useful for change tracking. |

## Related

- [Plugin Overview](./overview) — types, marketplace, and high-level model.
- [Publishing Plugins](./publishing) — Ed25519 signing flow and trust setup.
- [Plugin CLI](./cli) — `aisoc plugin {new,validate,sign,package}` commands.
- [Live Actions](../concepts/live-actions) — how a `LiveActionExecutor` plugin is discovered and dispatched at run time.
