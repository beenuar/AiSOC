# Community Plugins

This directory holds plugins contributed by the AiSOC community.

Each plugin is a self-contained directory with `plugin.yaml` + at least one
SDK implementation (`plugin.py` and/or `go/main.go`). They are auto-indexed by
[`scripts/build_marketplace.py`](../../scripts/build_marketplace.py) on the
next `pnpm marketplace:build` and shown in the in-app marketplace with a
**Community** badge.

## Plugin layout

```
plugins/community/<your-plugin-id>/
├── plugin.yaml         # required: manifest
├── plugin.py           # Python SDK reference impl (recommended)
├── README.md           # what it does, how to configure it
└── go/                 # optional: Go SDK reference impl
    └── main.go
```

The plugin ID is the directory name and **must match `plugin.yaml`'s `id`
field**. Convention for community plugins: `community-<github-handle>-<short-name>`.

## Authoring rules

- Implement the right SDK interface for the plugin type:
  - **Connector** → ingests events from a third-party source. Implements
    `aisoc.Connector` (Go) or `aisoc_plugin_sdk.Connector` (Python).
  - **Enricher** → augments alerts/cases with extra context. Implements
    `aisoc.Enricher` / `aisoc_plugin_sdk.Enricher`.
  - **Action** → performs an external action (page, message, contain, …).
    Implements `aisoc.Action` / `aisoc_plugin_sdk.Action`.
  - **Widget** → renders a dashboard tile. Implements `aisoc.Widget`
    / `aisoc_plugin_sdk.Widget`.
- Required `plugin.yaml` fields: `id`, `name`, `version`, `author`,
  `description`, `plugin_type`, `license`, `min_aisoc_version`, `homepage`.
- Cross-language parity is encouraged but not required. If you ship Python
  only or Go only, the marketplace will display the available SDKs as
  badges (Py / Go).
- Make all network I/O go through the SDK's HTTP helpers — they handle
  retries, rate limits, and per-tenant TLS — never use bare `requests` or
  `net/http` calls.
- Treat secrets as `config.secrets.*`. Never log them. Never inline them in
  manifests.

## Validation

```bash
# Python check
python3 -c "import yaml; yaml.safe_load(open('plugins/community/<id>/plugin.yaml'))"

# Go build (if you ship a Go impl)
cd plugins/community/<id>/go && go build ./...

# Marketplace index
pnpm marketplace:build
pnpm marketplace:check
```

## Promotion path

Community plugins start with `verified: false` and `source: "community"`.
Once a plugin has been hardened (tests, two-SDK parity, real-world use)
maintainers can promote it to the top-level `plugins/<id>/` folder and mark
it verified.
