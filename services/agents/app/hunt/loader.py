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


#: The copy that ships. ``hunts/`` lives at the repository root, outside the
#: agents build context (``context: ./services/agents``), so no ``COPY`` could
#: ever reach it and every container loaded zero hunts while every test —
#: all of which run in a source checkout — found the corpus and passed.
#: ``scripts/sync_packaged_hunt_corpus.py`` holds this directory byte-identical
#: to ``hunts/`` in both directions and reads this name, so renaming it here
#: without renaming it there is a failed gate rather than a silent fallback.
PACKAGED_CORPUS_DIRNAME = "corpus"

#: Where that copy sits relative to this module: ``app/hunt/corpus``. The
#: parent walk below cannot find it — ``corpus`` is not a *sibling* named
#: ``hunts`` — which is exactly why it is named rather than discovered.
_PACKAGED_CORPUS_DIR = Path(__file__).resolve().parent / PACKAGED_CORPUS_DIRNAME


def _candidate_corpus_dirs() -> list[Path]:
    """Every place the corpus could be, in the order they are preferred.

    Source checkout first, packaged copy second, and both are real: a
    developer editing ``hunts/`` keeps hot reload, and a container — where the
    repository root does not exist — gets the packaged copy. The sync gate
    holds the two identical, so the order changes which file is read and never
    what it says.

    Returned as a list rather than resolved inline so ``reload()`` can name
    everything it looked at when it finds nothing. The fallback this replaced
    returned ``parents[4]/hunts``, "the conventional host layout", which on a
    deployment is a path that has never existed — so a corpus of zero hunts
    was reported against a directory nobody could go and look at.
    """
    env_dir = os.getenv("AISOC_HUNTS_DIR", "").strip()
    if env_dir:
        return [Path(env_dir).expanduser().resolve()]

    candidates: list[Path] = []
    for parent in Path(__file__).resolve().parents:
        candidates.append(parent / "hunts")
    candidates.append(_PACKAGED_CORPUS_DIR)
    return candidates


def _resolve_corpus_dir() -> Path:
    """Find the hunt corpus, preferring a directory that actually has hunts.

    ``AISOC_HUNTS_DIR`` wins outright, including when it is wrong: an operator
    who names a directory gets that directory, and an empty one is reported as
    empty rather than quietly swapped for another.
    """
    candidates = _candidate_corpus_dirs()
    for candidate in candidates:
        if candidate.is_dir() and any(candidate.glob("*.yaml")):
            return candidate
    # Nothing holds hunts. Return the packaged location rather than a host path
    # that does not exist on a deployment, so the "missing" log names somewhere
    # the operator can actually look.
    return candidates[0] if len(candidates) == 1 else _PACKAGED_CORPUS_DIR


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
        """Re-read every YAML file under the corpus directory. Returns the count."""
        if not self._dir.exists():
            # Name every place that was looked at. "hunt.corpus.missing dir=…"
            # pointed at one path and said nothing about why that path, which
            # left an operator with a directory that does not exist on their
            # deployment and no next step.
            logger.error(
                "hunt.corpus.missing",
                extra={
                    "dir": str(self._dir),
                    "searched": [str(p) for p in _candidate_corpus_dirs()],
                    "hint": (
                        "the agents image ships the corpus at app/hunt/corpus; "
                        "run scripts/sync_packaged_hunt_corpus.py if it is absent from this tree"
                    ),
                },
            )
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
