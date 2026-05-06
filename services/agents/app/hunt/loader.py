"""Hunt YAML loader.

Reads the ``hunts/`` corpus from disk into typed Pydantic models. The loader
is best-effort: invalid hunts are logged and skipped so a single bad YAML
file cannot take down the scheduler.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger("aisoc.hunt.loader")


# ---------------------------------------------------------------------------
# Pydantic models — the YAML schema (mirrors hunts/README.md)
# ---------------------------------------------------------------------------


class HuntSchedule(BaseModel):
    enabled: bool = True
    interval_minutes: int = 60
    jitter_seconds: int = 60


class HuntIndicator(BaseModel):
    """One indicator in ``hypothesis.indicators``.

    Mirrors the YAML shape; only one of
    ``equals|in|regex|gte|lte|exists|contains_any|iendswith`` is expected to
    be set per row, but we stay permissive so authors can chain them when
    needed.
    """

    field: str
    equals: Any | None = None
    in_: list[Any] | None = Field(default=None, alias="in")
    regex: str | None = None
    gte: float | None = None
    lte: float | None = None
    exists: bool | None = None
    # Array intersection: indicator fires when any of these values is present in
    # the (list-typed) event field. Used for OAuth scope / tag matching.
    contains_any: list[Any] | None = None
    # Case-insensitive string suffix match. Used for executable paths (e.g.
    # ``\\rundll32.exe``) where the engine should not care about case or
    # parent directories.
    iendswith: str | None = None

    model_config = {"populate_by_name": True}


class HuntHypothesisBlock(BaseModel):
    question: str = ""
    indicators: list[HuntIndicator] = Field(default_factory=list)


class HuntExpected(BaseModel):
    """Eval-grading expectations: which synthetic incident the hunt should
    fire on, which it must NOT fire on, and the minimum match score."""

    positive_incident_id: str | None = None
    positive_template_id: str | None = None
    negative_incident_id: str | None = None
    min_match_score: float = 0.8


class HuntDefinition(BaseModel):
    id: str
    name: str
    description: str = ""
    version: str = "1.0.0"
    severity: str = "medium"
    category: str = "other"
    tags: list[str] = Field(default_factory=list)
    log_sources: list[str] = Field(default_factory=list)
    schedule: HuntSchedule = Field(default_factory=HuntSchedule)
    hypothesis: HuntHypothesisBlock = Field(default_factory=HuntHypothesisBlock)
    expected: HuntExpected = Field(default_factory=HuntExpected)
    references: list[str] = Field(default_factory=list)
    author: str | None = None

    # Computed at load time so callers can detect when the YAML body changed
    # and re-sync the database catalog row.
    source_sha256: str | None = None
    source_path: str | None = None

    @property
    def mitre_techniques(self) -> list[str]:
        """Pull MITRE technique IDs out of ``tags`` (e.g. ``mitre.attack.t1078``).

        Tags are stored as lowercase slugs; we normalise to ``T1078.002``-style
        identifiers because that's what the rest of the platform speaks.
        """
        techniques: list[str] = []
        for tag in self.tags:
            t = tag.strip().lower()
            if not t.startswith("mitre.attack."):
                continue
            tech = t.removeprefix("mitre.attack.")
            # ``t1078.002`` -> ``T1078.002``
            techniques.append(tech.upper())
        return techniques


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------


def _resolve_corpus_dir() -> Path:
    """Find the ``hunts/`` directory.

    Honours ``AISOC_HUNTS_DIR`` first, then walks parents of this file looking
    for a sibling ``hunts/`` (matches the playbook ``_resolve_repo_root`` trick
    so this works both on the host and inside the agents Docker image).
    """
    env_dir = os.getenv("AISOC_HUNTS_DIR", "").strip()
    if env_dir:
        return Path(env_dir).expanduser().resolve()
    here = Path(__file__).resolve()
    for candidate in here.parents:
        d = candidate / "hunts"
        if d.is_dir():
            return d
    # Fall back to the conventional host layout (parents[4]/hunts).
    parents = list(here.parents)
    if len(parents) > 4:
        return parents[4] / "hunts"
    return Path("hunts").resolve()


class HuntCorpus:
    """In-memory cache of hunt definitions loaded from disk.

    Hot-reload is intentional: ``reload()`` re-reads every YAML file. The
    scheduler calls it on a slow timer so authors can edit hunts without
    bouncing the agents service.
    """

    _instance: HuntCorpus | None = None

    def __init__(self, corpus_dir: Path | None = None) -> None:
        self._dir: Path = corpus_dir or _resolve_corpus_dir()
        self._hunts: dict[str, HuntDefinition] = {}

    @classmethod
    def default(cls) -> HuntCorpus:
        if cls._instance is None:
            cls._instance = cls()
            cls._instance.reload()
        return cls._instance

    @property
    def directory(self) -> Path:
        return self._dir

    def list(self, *, enabled_only: bool = False) -> list[HuntDefinition]:
        hunts = list(self._hunts.values())
        if enabled_only:
            hunts = [h for h in hunts if h.schedule.enabled]
        return sorted(hunts, key=lambda h: h.id)

    def get(self, hunt_id: str) -> HuntDefinition | None:
        return self._hunts.get(hunt_id)

    def reload(self) -> int:
        """Re-read every YAML file under ``hunts/``. Returns the number loaded."""
        if not self._dir.exists():
            logger.warning("hunt.corpus.missing", extra={"dir": str(self._dir)})
            self._hunts = {}
            return 0
        loaded: dict[str, HuntDefinition] = {}
        for path in sorted(self._dir.glob("*.yaml")):
            hunt = self._load_one(path)
            if hunt is None:
                continue
            if hunt.id in loaded:
                logger.warning(
                    "hunt.corpus.duplicate_id",
                    extra={"hunt_id": hunt.id, "path": str(path)},
                )
                continue
            loaded[hunt.id] = hunt
        self._hunts = loaded
        logger.info(
            "hunt.corpus.loaded",
            extra={"count": len(loaded), "dir": str(self._dir)},
        )
        return len(loaded)

    def _load_one(self, path: Path) -> HuntDefinition | None:
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("hunt.corpus.read_failed", extra={"path": str(path), "error": str(exc)})
            return None

        try:
            data = yaml.safe_load(raw) or {}
        except yaml.YAMLError as exc:
            logger.warning("hunt.corpus.invalid_yaml", extra={"path": str(path), "error": str(exc)})
            return None

        if not isinstance(data, dict):
            logger.warning("hunt.corpus.invalid_root", extra={"path": str(path)})
            return None

        try:
            hunt = HuntDefinition.model_validate(data)
        except ValidationError as exc:
            logger.warning(
                "hunt.corpus.validation_failed",
                extra={"path": str(path), "error": exc.errors()},
            )
            return None

        sha = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return hunt.model_copy(update={"source_sha256": sha, "source_path": str(path)})
