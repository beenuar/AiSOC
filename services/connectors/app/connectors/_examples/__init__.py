"""
Reference connector examples.

Modules under this package are **tutorial-only**. They are intentionally
*not* registered in ``services/connectors/app/connectors/__init__.py``
and therefore never appear in the catalog, the polling scheduler, or
the marketplace index.

The examples exist so that:

* The hello-connector tutorial in ``apps/docs/docs/connectors/hello-connector.md``
  can point at a real, importable, type-checked file rather than an inline
  code snippet that drifts from reality.
* Connector authors can copy a known-good starting point instead of
  scaffolding from one of the production connectors (which carry vendor
  quirks that obscure the required interface).

If you ever want to actually ship one of these examples as a real
connector, move it out of ``_examples/`` into ``app/connectors/`` and
register it in the parent ``__init__.py``.
"""
