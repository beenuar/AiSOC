"""
Playbook Store
==============
Simple in-process store backed by a JSON file (``playbooks.json``).
In production this would be replaced with a Postgres-backed store, but
the file-based approach lets us ship playbooks as part of the repo and
have zero DB migrations for Pillar-2.

The store is a singleton; mount it at app startup:

    store = PlaybookStore.default()   # loads from data/playbooks/
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import Playbook, PlaybookStep, StepType

logger = logging.getLogger("aisoc.playbook.store")

_DEFAULT_STORE_DIR = Path(__file__).parent.parent.parent / "data" / "playbooks"

# services/agents/app/playbook/store.py -> services/agents/app/playbook ->
# services/agents/app -> services/agents -> services -> repo root
_REPO_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_PACK_ROOT = _REPO_ROOT / "playbooks" / "packs" / "v1"


class PlaybookStore:
    """CRUD store for Playbook objects, backed by a JSON manifest file."""

    def __init__(
        self,
        store_dir: Path | None = None,
        pack_root: Path | None = None,
    ) -> None:
        self._dir = store_dir or Path(
            os.getenv("PLAYBOOK_STORE_DIR", str(_DEFAULT_STORE_DIR))
        )
        self._dir.mkdir(parents=True, exist_ok=True)
        # Optional canonical pack tree (playbooks/packs/v1/<category>/<slug>.playbook.json).
        # Loaded read-only — mutations always go to self._dir/index.json.
        self._pack_root = pack_root or Path(
            os.getenv("PLAYBOOK_PACK_ROOT", str(_DEFAULT_PACK_ROOT))
        )
        self._manifest_path = self._dir / "index.json"
        self._playbooks: dict[str, Playbook] = {}
        self._load()

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    _instance: PlaybookStore | None = None

    @classmethod
    def default(cls) -> "PlaybookStore":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_one(self, fixture: Path) -> None:
        try:
            data = json.loads(fixture.read_text())
            pb = Playbook.model_validate(data)
            if pb.id not in self._playbooks:
                self._playbooks[pb.id] = pb
        except Exception as exc:
            logger.warning("Skipping invalid fixture %s: %s", fixture.name, exc)

    def _load(self) -> None:
        # 1) Load individual *.playbook.json fixture files shipped with the runtime dir
        for fixture in sorted(self._dir.glob("*.playbook.json")):
            self._load_one(fixture)

        # 2) Load the canonical v1 production pack (playbooks/packs/v1/**/*.playbook.json)
        #    if present. These ship with the repo and are read-only here.
        if self._pack_root.exists():
            pack_count_before = len(self._playbooks)
            for fixture in sorted(self._pack_root.rglob("*.playbook.json")):
                self._load_one(fixture)
            pack_count = len(self._playbooks) - pack_count_before
            if pack_count:
                logger.info(
                    "Loaded %d playbooks from production pack %s",
                    pack_count,
                    self._pack_root,
                )

        # 3) Load/merge from the mutable index.json (user-created / API-created playbooks)
        if not self._manifest_path.exists():
            if self._playbooks:
                logger.info(
                    "Loaded %d fixture+pack playbooks (no user index.json yet)",
                    len(self._playbooks),
                )
            return
        try:
            raw: list[dict] = json.loads(self._manifest_path.read_text())
            for entry in raw:
                pb = Playbook.model_validate(entry)
                self._playbooks[pb.id] = pb  # index.json wins over fixtures
            logger.info("Loaded %d playbooks from %s", len(self._playbooks), self._manifest_path)
        except Exception as exc:
            logger.error("Failed to load playbooks: %s", exc)

    def _save(self) -> None:
        data = [pb.model_dump() for pb in self._playbooks.values()]
        self._manifest_path.write_text(json.dumps(data, indent=2))

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def list(self, *, enabled_only: bool = False) -> list[Playbook]:
        pbs = list(self._playbooks.values())
        if enabled_only:
            pbs = [p for p in pbs if p.enabled]
        return pbs

    def get(self, playbook_id: str) -> Playbook | None:
        return self._playbooks.get(playbook_id)

    def create(self, playbook: Playbook) -> Playbook:
        now = datetime.now(UTC).isoformat()
        if not playbook.id:
            playbook = playbook.model_copy(update={"id": str(uuid.uuid4())})
        playbook = playbook.model_copy(update={"created_at": now, "updated_at": now})
        self._playbooks[playbook.id] = playbook
        self._save()
        return playbook

    def update(self, playbook_id: str, data: dict[str, Any]) -> Playbook | None:
        pb = self._playbooks.get(playbook_id)
        if pb is None:
            return None
        now = datetime.now(UTC).isoformat()
        data["updated_at"] = now
        updated = pb.model_copy(update=data)
        self._playbooks[playbook_id] = updated
        self._save()
        return updated

    def delete(self, playbook_id: str) -> bool:
        if playbook_id not in self._playbooks:
            return False
        del self._playbooks[playbook_id]
        self._save()
        return True

    # ------------------------------------------------------------------
    # Trigger matching
    # ------------------------------------------------------------------

    def find_matching(self, event: str, context: dict[str, Any]) -> list[Playbook]:
        """Return all enabled playbooks whose trigger matches this event/context."""
        matches: list[Playbook] = []
        for pb in self._playbooks.values():
            if not pb.enabled:
                continue
            trigger = pb.trigger
            if trigger.get("on") != event:
                continue
            # Optional severity filter
            if "severity" in trigger:
                allowed = trigger["severity"]
                if context.get("severity") not in allowed:
                    continue
            # Optional tag filter
            if "tags" in trigger:
                required_tags = set(trigger["tags"])
                ctx_tags = set(context.get("tags", []))
                if not required_tags.intersection(ctx_tags):
                    continue
            matches.append(pb)
        return matches

    # ------------------------------------------------------------------
    # Seed helpers (used by seed_demo.py)
    # ------------------------------------------------------------------

    def seed_defaults(self) -> int:
        """Seed the store with built-in starter playbooks if store is empty."""
        if self._playbooks:
            return 0
        from .templates import STARTER_PLAYBOOKS
        count = 0
        for pb_dict in STARTER_PLAYBOOKS:
            pb = Playbook.model_validate(pb_dict)
            self.create(pb)
            count += 1
        logger.info("Seeded %d default playbooks", count)
        return count
