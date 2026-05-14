"""
Pytest fixtures for the Teams bot.

We add ``services/teams-bot`` to ``sys.path`` so ``import app`` works
when pytest is invoked from the service directory (mirrors how the
Slack bot test suite is laid out).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
