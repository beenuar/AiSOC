"""Repo-root shim for ``app.scripts.demo_seed``.

The canonical implementation lives inside the api package at
``services/api/app/scripts/demo_seed.py`` so it can be invoked inside the
api container on Fly.io as ``python -m app.scripts.demo_seed``. This shim
exists so self-hosters running from the repo root can still type
``python scripts/demo_seed.py --reset`` without juggling PYTHONPATH.

If you're editing the seed logic, edit the canonical module — not this file.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_API_ROOT = _REPO_ROOT / "services" / "api"

# Put services/api on the path so ``from app.scripts.demo_seed import main``
# resolves to the canonical implementation.
if str(_API_ROOT) not in sys.path:
    sys.path.insert(0, str(_API_ROOT))

# Default the API URLs to docker-compose host ports when running locally; the
# Fly demo overrides via env on the api machine.
os.environ.setdefault("CORE_API_URL", "http://localhost:8081")
os.environ.setdefault("AGENTS_API_URL", "http://localhost:8084")

from app.scripts.demo_seed import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
