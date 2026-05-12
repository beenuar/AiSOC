---
sidebar_position: 5
---

# Plugin CLI (`aisoc-cli`)

The `aisoc-cli` ships scaffolding, validation, packaging, signing, and trust
management commands for every supported plugin type — `enricher`, `connector`,
`responder`, `detection`, and `widget`.

The CLI source lives under `packages/aisoc-cli/`. Install it from the repo for
hacking on it locally:

```bash
pip install -e packages/aisoc-cli
```

Or install the published wheel:

```bash
pip install aisoc-cli
```

## Scaffolding new plugins

Use `aisoc plugin new` to scaffold a brand-new plugin from the bundled
templates for its type. The legacy `aisoc plugin scaffold` command remains
available as an alias for backwards compatibility.

```bash
# Recommended
aisoc plugin new "Wazuh Connector" \
  --type connector \
  --output-dir plugins/ \
  --author "My Org <security@example.com>"

# Backwards-compatible alias
aisoc plugin scaffold "Wazuh Connector" --type connector --output-dir plugins/
```

| Flag | Default | Description |
|---|---|---|
| `NAME` (positional) | — | Human-readable plugin name. Lower-cased and dash-separated to derive the slug used as `id` and directory name. |
| `--type, -t` | `enricher` | One of `enricher`, `connector`, `responder`, `detection`, `widget`. |
| `--output-dir, -o` | `.` | Parent directory to create the plugin folder in. |
| `--author` | `Your Name <you@example.com>` | Author string written into `plugin.yaml`. |

The command refuses to overwrite an existing directory and prints the next
steps (edit `plugin.yaml`, implement the entry point, run `aisoc plugin
validate`).

### What you get per plugin type

The scaffolder uses [string.Template](https://docs.python.org/3/library/string.html#template-strings)
substitution for `${slug}`, `${name}`, and `${author}` and lays out the
following files:

| Type | Files |
|---|---|
| `enricher` | `plugin.yaml`, `plugin.py`, `README.md` |
| `connector` | `plugin.yaml`, `connector.py`, `README.md` |
| `responder` | `plugin.yaml`, `plugin.py`, `README.md` |
| `detection` | `plugin.yaml`, `rules/example.yaml`, `README.md` |
| `widget` | `plugin.yaml`, `widget.py`, `README.md` |

The canonical templates live inside the CLI package at
`packages/aisoc-cli/src/aisoc_cli/templates/<type>/` and are loaded at runtime
via `importlib.resources`, so they ship inside the wheel. Edit the `.tmpl`
files there to change what new plugins look like.

The repo-level `plugins/templates/README.md` is a documentation pointer to
that location.

## Validating plugins

```bash
aisoc plugin validate plugins/wazuh-connector/plugin.yaml
# or pass the directory and validate all manifests inside
aisoc plugin validate plugins/wazuh-connector
```

`validate` parses the YAML manifest against the same JSON schema the platform
uses at install time. It checks required fields (`id`, `name`, `version`,
`plugin_type`, `entry_point`, …), enum values, and the `id` slug pattern.

## Packaging, signing, and trust

The CLI also wraps the workflows documented under
[Publishing Plugins](./publishing):

```bash
aisoc plugin keygen   --out ./keys/myorg
aisoc plugin sign     --plugin-dir ./my-enricher --private-key $KEY
aisoc plugin package  --plugin-dir ./my-enricher --out dist/
```

Run `aisoc plugin --help` for the full command list and `aisoc plugin <cmd>
--help` for individual command flags.
