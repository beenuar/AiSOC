# Plugin templates

This directory is intentionally a documentation pointer. The canonical
plugin scaffolding templates live inside the `aisoc-cli` package so they
can be loaded at runtime via `importlib.resources` and bundled into the
distributed wheel:

```
packages/aisoc-cli/src/aisoc_cli/templates/
├── enricher/
│   ├── plugin.yaml.tmpl
│   ├── plugin.py.tmpl
│   └── README.md.tmpl
├── connector/
│   ├── plugin.yaml.tmpl
│   ├── connector.py.tmpl
│   └── README.md.tmpl
├── responder/
│   ├── plugin.yaml.tmpl
│   ├── plugin.py.tmpl
│   └── README.md.tmpl
├── detection/
│   ├── plugin.yaml.tmpl
│   ├── rules/example.yaml.tmpl
│   └── README.md.tmpl
└── widget/
    ├── plugin.yaml.tmpl
    ├── widget.py.tmpl
    └── README.md.tmpl
```

## Scaffolding a new plugin

```bash
aisoc plugin new "My Plugin" --type connector --output-dir plugins/
# or, for backwards compatibility:
aisoc plugin scaffold "My Plugin" --type connector --output-dir plugins/
```

Supported `--type` values: `enricher | connector | responder | detection | widget`.

The `--author` flag is also supported and is written into the generated
`plugin.yaml`. Templates use `string.Template` substitution with these
variables: `$slug`, `$name`, and `$author` (use `${slug}` braces if the
placeholder is followed by an identifier character).

## Editing the templates

Edit the `.tmpl` files in `packages/aisoc-cli/src/aisoc_cli/templates/<type>/`
directly. They are loaded via `importlib.resources` at runtime, so changes
are picked up by an editable install (`pip install -e packages/aisoc-cli`).

Tests for the scaffolder live at
`packages/aisoc-cli/tests/test_cli.py::test_plugin_new_per_type` and exercise
every plugin type end-to-end.
