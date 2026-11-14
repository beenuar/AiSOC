"""Background workers that run inside the API process.

These workers are started from :func:`app.main.lifespan` and live inside
the API event loop. They are intentionally **not** APScheduler jobs —
the API has no scheduler dependency and we don't want to introduce one
just for periodic loops. Each worker is a long-running ``asyncio.Task``
that owns its own cadence and shutdown semantics.

Workers currently shipped:

* :mod:`oauth_refresh` — auto-rotates expiring OAuth access tokens for
  every connector provisioned via the hosted ``/oauth/start`` flow.
"""

from __future__ import annotations
