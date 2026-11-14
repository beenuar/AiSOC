"""Detection Knowledge Base — the fourth memory layer.

Where the other memory layers store *what happened* (episodic cases,
threat graph entities) or *what's happening right now* (scratchpad),
the Detection KB stores *what we know how to look for*.

It indexes every Sigma rule we ship — plus future tenant overrides
(Theme 3d "vertical packs") — so the agent fleet can answer:

* "Do we already have a detection for OAuth consent grant abuse?"
  (Hunter, before kicking off a retro-hunt.)
* "Find detection content related to this threat report so I don't
  re-author what's already shipped."  (Detection Author.)
* "What active rules cover this MITRE technique?"
  (Reporter, when building the ATT&CK heatmap.)

Design choices:

* Detection content is *shared*, not tenant-isolated. Rules are content,
  not customer data. The search API still accepts an optional
  ``tenant_id`` so per-tenant rule packs (Theme 3d) can shadow built-ins
  by id without breaking the global pack — when that lands, the
  tenant-namespaced view will be layered on top of the shared index.
* Hybrid search by default: vector similarity (using the same embedding
  provider as episodic memory, so a single ``AISOC_EMBEDDING_PROVIDER``
  switch flips everything to real embeddings) blended with keyword
  scoring on title/description/tags/logsource. A strong keyword hit
  beats a fuzzy semantic match — analysts grep, the LLM dreams; we
  want both.
* Two-tier durability mirroring the rest of memory:
    - in-memory index is the source of truth at runtime;
    - optional Elasticsearch/OpenSearch backend for clusters that
      already operate one. Failing to reach ES degrades to in-memory
      with a warning, never a hard crash.
* Lazy singleton: the KB is loaded once per process from the
  configured rules directory. Tests reset it with ``reset_detection_kb()``.

The detection-engine (Theme 1: t1-detection-engine) owns *matching*
events against rules. This module owns *finding* the rule by intent.
They share the same ``RulePack`` so the two stay in lockstep — there
is exactly one copy of the rules in memory.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Iterable

from app.config import settings
from app.detections.pack import RulePack
from app.detections.sigma import Severity, SigmaRule
from app.memory.embedding import cosine, embed

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Public dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DetectionMatch:
    """A scored search hit against the detection knowledge base.

    ``score`` is the hybrid blend of cosine similarity (semantic) and a
    keyword score in [0, 1]. ``rule`` is the live :class:`SigmaRule`,
    not a copy, so callers can re-use it for matching or translation
    without going back through the loader.
    """

    rule_id: str
    title: str
    description: str
    severity: Severity
    tags: tuple[str, ...]
    logsource: dict[str, Any]
    score: float
    vector_score: float
    keyword_score: float
    matched_terms: tuple[str, ...]
    rule: SigmaRule = field(repr=False)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe view for API responses and audit trails."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "tags": list(self.tags),
            "logsource": dict(self.logsource),
            "score": round(self.score, 4),
            "vector_score": round(self.vector_score, 4),
            "keyword_score": round(self.keyword_score, 4),
            "matched_terms": list(self.matched_terms),
        }


# --------------------------------------------------------------------------- #
# In-memory index
# --------------------------------------------------------------------------- #


_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def _tokenize(text: str) -> list[str]:
    """Lowercase tokens for keyword scoring + index building."""
    return [t.lower() for t in _TOKEN_RE.findall(text or "")]


def _searchable_text(rule: SigmaRule) -> str:
    """Flatten a rule into a single document for embedding + keyword search."""
    parts: list[str] = [rule.title, rule.description]
    parts.extend(rule.tags)
    parts.extend(rule.falsepositives)
    ls = rule.logsource or {}
    for key in ("category", "product", "service", "definition"):
        v = ls.get(key)
        if v:
            parts.append(f"{key}:{v}")
    return " \n".join(p for p in parts if p)


@dataclass
class _IndexedRule:
    rule: SigmaRule
    text: str
    tokens: frozenset[str]  # for fast keyword hit-rate scoring
    embedding: list[float]
    # token -> term frequency; helps coverage scoring beat exact-match noise.
    term_freq: dict[str, int]


class DetectionKB:
    """Searchable index over a :class:`RulePack`.

    The class is intentionally backend-agnostic on the read path: every
    public method returns plain ``DetectionMatch`` objects. The
    ``backend`` field is informational only — used by tests and the
    ``/health`` endpoint to confirm we wired up the configured store.
    """

    def __init__(self, pack: RulePack, *, backend: str = "memory") -> None:
        self.pack = pack
        self.backend = backend
        self._items: list[_IndexedRule] = []
        self._by_id: dict[str, _IndexedRule] = {}
        self._lock = Lock()
        self._rebuild_index()

    # -- index lifecycle -------------------------------------------------

    def _rebuild_index(self) -> None:
        with self._lock:
            self._items = []
            self._by_id = {}
            for rule in self.pack:
                self._index_rule_locked(rule)
        logger.info(
            "detection_kb:indexed backend=%s rules=%d",
            self.backend,
            len(self._items),
        )

    def _index_rule_locked(self, rule: SigmaRule) -> None:
        text = _searchable_text(rule)
        tokens = _tokenize(text)
        try:
            vec = embed(text)
        except Exception as exc:  # pragma: no cover - embedding has its own fallback
            logger.warning("detection_kb:embed_failed rule=%s err=%s", rule.id, exc)
            vec = []
        tf: dict[str, int] = {}
        for tok in tokens:
            tf[tok] = tf.get(tok, 0) + 1
        item = _IndexedRule(
            rule=rule,
            text=text,
            tokens=frozenset(tokens),
            embedding=vec,
            term_freq=tf,
        )
        # Replacement semantics match RulePack.add: later wins by id.
        existing = self._by_id.get(rule.id)
        if existing is not None:
            for i, it in enumerate(self._items):
                if it.rule.id == rule.id:
                    self._items[i] = item
                    break
        else:
            self._items.append(item)
        self._by_id[rule.id] = item

    def reload(self) -> None:
        """Re-index the underlying pack. Cheap — O(rules)."""
        self._rebuild_index()

    def add_rule(self, rule: SigmaRule) -> None:
        """Add or replace a single rule (used by tenant overrides + tests)."""
        with self._lock:
            self.pack.add(rule)
            self._index_rule_locked(rule)

    # -- accessors -------------------------------------------------------

    def __len__(self) -> int:
        return len(self._items)

    def count(self) -> int:
        return len(self._items)

    def backend_name(self) -> str:
        return self.backend

    def by_id(self, rule_id: str) -> SigmaRule | None:
        item = self._by_id.get(rule_id)
        return item.rule if item else None

    def all_rules(self) -> list[SigmaRule]:
        return [it.rule for it in self._items]

    # -- search ----------------------------------------------------------

    def search(
        self,
        query: str,
        *,
        k: int = 5,
        severity: str | Iterable[str] | None = None,
        tag: str | None = None,
        logsource: dict[str, str] | None = None,
        min_score: float = 0.0,
        tenant_id: str | None = None,  # noqa: ARG002 - reserved for vertical packs
    ) -> list[DetectionMatch]:
        """Hybrid (vector + keyword) search over the indexed rules.

        Args:
            query: Free-form natural-language query. Empty queries are
                allowed and short-circuit to a filter-only browse.
            k: Max matches to return.
            severity: Restrict to one or more severity levels
                (``"low"``/``"medium"``/``"high"``/``"critical"``).
            tag: Substring, case-insensitive — useful for
                ``"attack.t1078"`` or ``"identity"``.
            logsource: Subset-match on the rule's logsource dict
                (e.g. ``{"category": "process_creation"}``).
            min_score: Drop matches below this hybrid score.
            tenant_id: Reserved — when vertical packs land we shadow
                built-ins with the tenant's own rules by id.

        Returns matches sorted by descending score. Filter-only browses
        (empty query) still produce a stable ordering by severity then
        rule_id.
        """
        candidates = self._filter(severity=severity, tag=tag, logsource=logsource)
        if not candidates:
            return []

        q = (query or "").strip()
        if not q:
            return self._browse(candidates, k)

        qvec = embed(q)
        q_tokens = _tokenize(q)
        unique_q_tokens = frozenset(q_tokens)

        w_vec = float(settings.detection_kb_weight_vector)
        w_kw = float(settings.detection_kb_weight_keyword)
        # Guard against mis-config — never let the weights be zero, which
        # would silently turn search into "first k rules".
        if w_vec + w_kw <= 0:
            w_vec, w_kw = 0.6, 0.4

        results: list[DetectionMatch] = []
        for item in candidates:
            vec_score = cosine(qvec, item.embedding) if item.embedding else 0.0
            kw_score, matched = self._keyword_score(q_tokens, unique_q_tokens, item)
            blended = w_vec * vec_score + w_kw * kw_score
            if blended < min_score:
                continue
            results.append(
                DetectionMatch(
                    rule_id=item.rule.id,
                    title=item.rule.title,
                    description=item.rule.description,
                    severity=item.rule.severity,
                    tags=item.rule.tags,
                    logsource=dict(item.rule.logsource or {}),
                    score=blended,
                    vector_score=vec_score,
                    keyword_score=kw_score,
                    matched_terms=tuple(matched),
                    rule=item.rule,
                )
            )
        results.sort(key=lambda m: (-m.score, m.rule_id))
        return results[: max(k, 0)]

    def search_by_tag(self, tag: str, *, k: int | None = None) -> list[DetectionMatch]:
        """Browse rules carrying a tag (substring, case-insensitive)."""
        candidates = self._filter(tag=tag)
        limit = k if k is not None else len(candidates)
        return self._browse(candidates, limit)

    def search_by_logsource(
        self,
        *,
        category: str | None = None,
        product: str | None = None,
        service: str | None = None,
        k: int | None = None,
    ) -> list[DetectionMatch]:
        """Browse rules whose logsource matches the given dimensions."""
        logsource = {
            k_: v
            for k_, v in {"category": category, "product": product, "service": service}.items()
            if v is not None
        }
        candidates = self._filter(logsource=logsource)
        limit = k if k is not None else len(candidates)
        return self._browse(candidates, limit)

    # -- internals -------------------------------------------------------

    def _filter(
        self,
        *,
        severity: str | Iterable[str] | None = None,
        tag: str | None = None,
        logsource: dict[str, str] | None = None,
    ) -> list[_IndexedRule]:
        wanted_severities: set[str] | None = None
        if severity is not None:
            if isinstance(severity, str):
                wanted_severities = {severity.lower()}
            else:
                wanted_severities = {s.lower() for s in severity}

        tag_needle = tag.lower() if tag else None

        out: list[_IndexedRule] = []
        for item in self._items:
            if wanted_severities and item.rule.severity.value not in wanted_severities:
                continue
            if tag_needle:
                if not any(tag_needle in t.lower() for t in item.rule.tags):
                    continue
            if logsource:
                ls = item.rule.logsource or {}
                if not all(
                    str(ls.get(key, "")).lower() == str(val).lower()
                    for key, val in logsource.items()
                ):
                    continue
            out.append(item)
        return out

    def _browse(self, candidates: list[_IndexedRule], k: int) -> list[DetectionMatch]:
        """Filter-only ordering: severity desc, then rule_id."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }
        ordered = sorted(
            candidates,
            key=lambda it: (severity_order.get(it.rule.severity, 9), it.rule.id),
        )
        results: list[DetectionMatch] = []
        for item in ordered[: max(k, 0)]:
            results.append(
                DetectionMatch(
                    rule_id=item.rule.id,
                    title=item.rule.title,
                    description=item.rule.description,
                    severity=item.rule.severity,
                    tags=item.rule.tags,
                    logsource=dict(item.rule.logsource or {}),
                    score=0.0,
                    vector_score=0.0,
                    keyword_score=0.0,
                    matched_terms=(),
                    rule=item.rule,
                )
            )
        return results

    @staticmethod
    def _keyword_score(
        q_tokens: list[str],
        unique_q_tokens: frozenset[str],
        item: _IndexedRule,
    ) -> tuple[float, list[str]]:
        """Coverage-weighted keyword score normalized into ``[0, 1]``.

        We blend two signals so the index isn't fooled by stuffed tags:

        * **coverage**: fraction of unique query terms that appear in the
          rule at all. This dominates so a query that mentions every
          important term scores well.
        * **density**: log-dampened term-frequency hits so a rule whose
          title literally contains the term still beats one where the
          term appears once in a tag — without letting tag-spam win.
        """
        if not unique_q_tokens:
            return 0.0, []

        matched: list[str] = []
        density = 0.0
        for tok in unique_q_tokens:
            if tok in item.tokens:
                matched.append(tok)
                density += math.log1p(item.term_freq.get(tok, 1))

        if not matched:
            return 0.0, []

        coverage = len(matched) / len(unique_q_tokens)
        # Normalize density by the max it could plausibly take for this
        # query (each term hitting ~4 times — past that we cap).
        density_norm = min(1.0, density / (len(unique_q_tokens) * math.log1p(4)))
        score = 0.7 * coverage + 0.3 * density_norm
        return min(1.0, score), matched


# --------------------------------------------------------------------------- #
# Backend selection + singleton
# --------------------------------------------------------------------------- #


_kb_lock = Lock()
_kb_instance: DetectionKB | None = None


def _load_pack() -> RulePack:
    """Load the configured rule pack, with a permissive fallback."""
    root = Path(settings.detection_kb_rules_path)
    if not root.is_absolute():
        # Resolve relative to the backend working dir so tests + uvicorn
        # both find the bundled pack regardless of CWD.
        candidate = Path.cwd() / root
        if not candidate.exists():
            # Walk up: the `app/` package lives next to the backend root,
            # which is the most common run-from location.
            backend_root = Path(__file__).resolve().parents[2]
            candidate = backend_root / root
        root = candidate
    if not root.exists():
        logger.warning(
            "detection_kb:rules_path_missing path=%s — starting with an empty KB",
            root,
        )
        return RulePack(name="empty")
    try:
        return RulePack.load_directory(root, name="builtin", strict=False)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("detection_kb:load_failed path=%s err=%s", root, exc)
        return RulePack(name="empty")


def _build_kb() -> DetectionKB:
    configured = (settings.detection_kb_backend or "memory").lower()
    pack = _load_pack()

    if configured == "elasticsearch":
        # We index in-memory regardless — that's the source of truth at
        # runtime. ES is *only* there for clusters that already operate
        # one and want detection content to show up in their existing
        # KB search UI. If we can't reach ES we degrade silently.
        backend = "memory"
        try:
            from elasticsearch import Elasticsearch  # type: ignore

            url = settings.elasticsearch_url
            if not url:
                logger.warning(
                    "detection_kb_backend=elasticsearch but AISOC_ELASTICSEARCH_URL "
                    "is unset; degrading to in-memory only",
                )
            else:
                client_kwargs: dict[str, Any] = {"hosts": [url]}
                if settings.elasticsearch_api_key:
                    client_kwargs["api_key"] = settings.elasticsearch_api_key
                elif settings.elasticsearch_username and settings.elasticsearch_password:
                    client_kwargs["basic_auth"] = (
                        settings.elasticsearch_username,
                        settings.elasticsearch_password,
                    )
                client = Elasticsearch(**client_kwargs)
                # Ping is best-effort; if it fails we still serve from memory.
                if client.ping():
                    backend = "elasticsearch+memory"
                    _push_to_elasticsearch(client, pack)
                else:
                    logger.warning(
                        "detection_kb:elasticsearch_unreachable url=%s — memory only",
                        url,
                    )
        except Exception as exc:  # pragma: no cover - depends on env
            logger.warning(
                "detection_kb:elasticsearch_init_failed err=%s — memory only", exc
            )
    else:
        backend = "memory"

    return DetectionKB(pack, backend=backend)


def _push_to_elasticsearch(client: Any, pack: RulePack) -> None:
    """Bulk-index the pack into Elasticsearch. Best-effort."""
    index = settings.detection_kb_index
    try:
        # Idempotent create — ignore-409 style.
        if not client.indices.exists(index=index):
            client.indices.create(
                index=index,
                body={
                    "mappings": {
                        "properties": {
                            "rule_id": {"type": "keyword"},
                            "title": {"type": "text"},
                            "description": {"type": "text"},
                            "severity": {"type": "keyword"},
                            "tags": {"type": "keyword"},
                            "logsource": {"type": "object"},
                            "status": {"type": "keyword"},
                            "author": {"type": "keyword"},
                        }
                    }
                },
            )
        for rule in pack:
            client.index(
                index=index,
                id=rule.id,
                document={
                    "rule_id": rule.id,
                    "title": rule.title,
                    "description": rule.description,
                    "severity": rule.severity.value,
                    "tags": list(rule.tags),
                    "logsource": rule.logsource or {},
                    "status": rule.status,
                    "author": rule.author,
                },
            )
    except Exception as exc:  # pragma: no cover - depends on env
        logger.warning("detection_kb:elasticsearch_push_failed err=%s", exc)


def get_detection_kb() -> DetectionKB:
    """Lazy process-wide singleton accessor."""
    global _kb_instance
    if _kb_instance is not None:
        return _kb_instance
    with _kb_lock:
        if _kb_instance is None:
            _kb_instance = _build_kb()
        return _kb_instance


def reset_detection_kb() -> None:
    """Drop the cached KB so the next ``get_detection_kb`` reloads.

    Used by tests + the admin "reload detections" endpoint after
    deploying new content.
    """
    global _kb_instance
    with _kb_lock:
        _kb_instance = None


def detection_kb_backend_name() -> str:
    """Inspect the backend the singleton ended up with (memory | elasticsearch+memory)."""
    return get_detection_kb().backend_name()


# --------------------------------------------------------------------------- #
# Convenience wrappers — match the style of episodic_recall / graph_neighbors
# --------------------------------------------------------------------------- #


def detection_search(
    query: str,
    *,
    k: int = 5,
    severity: str | Iterable[str] | None = None,
    tag: str | None = None,
    logsource: dict[str, str] | None = None,
    tenant_id: str | None = None,
) -> list[DetectionMatch]:
    return get_detection_kb().search(
        query,
        k=k,
        severity=severity,
        tag=tag,
        logsource=logsource,
        tenant_id=tenant_id,
    )


def detection_by_id(rule_id: str) -> SigmaRule | None:
    return get_detection_kb().by_id(rule_id)


def detection_count() -> int:
    return get_detection_kb().count()
