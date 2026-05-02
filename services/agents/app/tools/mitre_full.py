"""
MITRE ATT&CK Full Corpus Loader
================================
Loads the complete MITRE ATT&CK Enterprise STIX 2.1 bundle and provides
comprehensive technique/actor/mitigation lookups.

On startup, this module:
1. Tries to load the bundle from ATTCK_DATA_PATH (local file).
2. Falls back to downloading the bundle from MITRE's GitHub CDN.
3. Builds in-memory indexes for O(1) lookups.
4. Optionally embeds technique descriptions into Qdrant for semantic RAG.

Cyble Open-Source AI Security Operations Center — MIT License
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import time
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

ATTCK_CDN_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
ATTCK_DATA_PATH = os.getenv("ATTCK_DATA_PATH", "/data/enterprise-attack.json")
_CACHE_TTL_HOURS = 24
_EMBED_BATCH_SIZE = 50


# ─── Data Model ───────────────────────────────────────────────────────────────

class MitreTechnique:
    """Represents a single ATT&CK technique or sub-technique."""

    __slots__ = (
        "id", "name", "description", "tactic_ids", "tactic_names",
        "platforms", "data_sources", "mitigations", "detections",
        "is_subtechnique", "parent_id", "url", "version",
    )

    def __init__(self, **kw: Any) -> None:
        for slot in self.__slots__:
            setattr(self, slot, kw.get(slot))

    def to_dict(self) -> dict[str, Any]:
        return {s: getattr(self, s) for s in self.__slots__}


class MitreActor:
    """Represents a threat actor / intrusion set."""

    __slots__ = ("id", "name", "description", "aliases", "techniques", "url", "groups")

    def __init__(self, **kw: Any) -> None:
        for slot in self.__slots__:
            setattr(self, slot, kw.get(slot, []))

    def to_dict(self) -> dict[str, Any]:
        return {s: getattr(self, s) for s in self.__slots__}


class MitreMitigation:
    """Represents a course of action / mitigation."""

    __slots__ = ("id", "name", "description", "techniques")

    def __init__(self, **kw: Any) -> None:
        for slot in self.__slots__:
            setattr(self, slot, kw.get(slot, []))


# ─── Global Indexes ───────────────────────────────────────────────────────────

_techniques: dict[str, MitreTechnique] = {}
_actors: dict[str, MitreActor] = {}
_mitigations: dict[str, MitreMitigation] = {}
_tactic_map: dict[str, str] = {}        # tactic shortname → display name
_loaded = False
_load_time: float = 0.0


# ─── Loader ───────────────────────────────────────────────────────────────────

def _parse_stix_bundle(bundle: dict[str, Any]) -> None:
    """Parse a STIX 2.1 ATT&CK bundle and populate in-memory indexes."""
    global _loaded, _load_time

    objects: list[dict] = bundle.get("objects", [])

    # First pass – build lookup maps
    id_to_obj: dict[str, dict] = {o["id"]: o for o in objects}
    tactic_objs: dict[str, dict] = {}

    # Tactic phase → display name
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            shortname = obj.get("x_mitre_shortname", "")
            _tactic_map[shortname] = obj.get("name", shortname)
            tactic_objs[shortname] = obj

    # Relationship maps
    tech_tactic: dict[str, list[str]] = {}
    tech_mitigations: dict[str, list[str]] = {}
    actor_techniques: dict[str, list[str]] = {}
    mitigation_techniques: dict[str, list[str]] = {}

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rel_type = obj.get("relationship_type", "")
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")

        if rel_type == "uses":
            # Actor uses technique
            src_obj = id_to_obj.get(src, {})
            if src_obj.get("type") in ("intrusion-set", "campaign", "malware", "tool"):
                actor_techniques.setdefault(src, []).append(tgt)

        elif rel_type == "mitigates":
            mitigation_techniques.setdefault(src, []).append(tgt)
            tech_mitigations.setdefault(tgt, []).append(src)

    # Second pass – build technique objects
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        ext = obj.get("x_mitre_", {})
        is_deprecated = obj.get("x_mitre_deprecated", False) or obj.get("revoked", False)
        if is_deprecated:
            continue

        stix_id = obj["id"]
        ext_refs = obj.get("external_references", [])
        attck_ref = next(
            (r for r in ext_refs if r.get("source_name") == "mitre-attack"), {}
        )
        tech_id = attck_ref.get("external_id", "")
        if not tech_id:
            continue

        kill_chain_phases = obj.get("kill_chain_phases", [])
        tactic_ids = [
            p["phase_name"] for p in kill_chain_phases if p.get("kill_chain_name") == "mitre-attack"
        ]
        tactic_names = [_tactic_map.get(t, t) for t in tactic_ids]

        parent_id = None
        is_sub = "." in tech_id
        if is_sub:
            parent_id = tech_id.split(".")[0]

        mitigation_ids = tech_mitigations.get(stix_id, [])
        mitigation_names = [
            id_to_obj.get(mid, {}).get("name", mid) for mid in mitigation_ids
        ]

        # Detection notes from x_mitre_detection
        detection = obj.get("x_mitre_detection", "")

        technique = MitreTechnique(
            id=tech_id,
            name=obj.get("name", ""),
            description=obj.get("description", "")[:2000],  # cap length
            tactic_ids=tactic_ids,
            tactic_names=tactic_names,
            platforms=obj.get("x_mitre_platforms", []),
            data_sources=obj.get("x_mitre_data_sources", []),
            mitigations=mitigation_names,
            detections=[detection] if detection else [],
            is_subtechnique=is_sub,
            parent_id=parent_id,
            url=attck_ref.get("url", ""),
            version=obj.get("x_mitre_version", ""),
        )
        _techniques[tech_id] = technique

    # Third pass – actors
    for obj in objects:
        obj_type = obj.get("type", "")
        if obj_type not in ("intrusion-set",):
            continue

        stix_id = obj["id"]
        ext_refs = obj.get("external_references", [])
        attck_ref = next((r for r in ext_refs if r.get("source_name") == "mitre-attack"), {})
        actor_id = attck_ref.get("external_id", stix_id)

        # Resolve technique IDs from STIX IDs
        used_stix_ids = actor_techniques.get(stix_id, [])
        tech_ids = []
        for sid in used_stix_ids:
            src_obj = id_to_obj.get(sid, {})
            if src_obj.get("type") == "attack-pattern":
                src_refs = src_obj.get("external_references", [])
                src_attck = next((r for r in src_refs if r.get("source_name") == "mitre-attack"), {})
                tid = src_attck.get("external_id", "")
                if tid:
                    tech_ids.append(tid)

        actor = MitreActor(
            id=actor_id,
            name=obj.get("name", ""),
            description=obj.get("description", "")[:1000],
            aliases=obj.get("aliases", []),
            techniques=tech_ids,
            url=attck_ref.get("url", ""),
        )
        _actors[actor_id] = actor

    _loaded = True
    _load_time = time.time()
    logger.info(
        "MITRE ATT&CK corpus loaded",
        techniques=len(_techniques),
        actors=len(_actors),
        tactics=len(_tactic_map),
    )


async def _download_bundle() -> dict[str, Any]:
    """Download the ATT&CK STIX bundle from MITRE GitHub."""
    logger.info("Downloading MITRE ATT&CK bundle from CDN", url=ATTCK_CDN_URL)
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        resp = await client.get(ATTCK_CDN_URL)
        resp.raise_for_status()
        return resp.json()


async def load_attck_corpus(force_reload: bool = False) -> None:
    """
    Load the MITRE ATT&CK corpus.
    Priority:
      1. Local file at ATTCK_DATA_PATH
      2. Download from MITRE CDN
    Results are cached; re-load after _CACHE_TTL_HOURS.
    """
    global _loaded, _load_time

    age_hours = (time.time() - _load_time) / 3600 if _load_time else float("inf")
    if _loaded and not force_reload and age_hours < _CACHE_TTL_HOURS:
        return

    bundle: dict[str, Any] | None = None

    # Try local file first
    local_path = pathlib.Path(ATTCK_DATA_PATH)
    if local_path.exists():
        try:
            logger.info("Loading MITRE ATT&CK from local file", path=str(local_path))
            bundle = json.loads(local_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to read local ATT&CK bundle", error=str(exc))

    # Fall back to CDN download
    if bundle is None:
        try:
            bundle = await _download_bundle()
            # Save for future use
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_text(json.dumps(bundle), encoding="utf-8")
            logger.info("ATT&CK bundle cached locally", path=str(local_path))
        except Exception as exc:
            logger.error("Failed to download ATT&CK bundle", error=str(exc))
            # Load stub corpus so service stays up
            _load_stub_corpus()
            return

    await asyncio.get_event_loop().run_in_executor(None, _parse_stix_bundle, bundle)


def _load_stub_corpus() -> None:
    """Populate a minimal stub corpus when the full bundle is unavailable."""
    global _loaded, _load_time
    from app.tools.mitre import (
        _MITRE_TACTICS as TACTICS,
        _MITRE_TECHNIQUES as TECHS,
        _MITRE_MITIGATIONS as MITS,
    )
    _tactic_map.update({k: v for k, v in TACTICS.items()})
    for tid, info in TECHS.items():
        tactic_id = info["tactic"]
        _techniques[tid] = MitreTechnique(
            id=tid,
            name=info["name"],
            description="",
            tactic_ids=[tactic_id],
            tactic_names=[TACTICS.get(tactic_id, tactic_id)],
            platforms=[],
            data_sources=[],
            mitigations=MITS.get(tid, []),
            detections=[],
            is_subtechnique="." in tid,
            parent_id=tid.split(".")[0] if "." in tid else None,
            url="",
            version="",
        )
    _loaded = True
    _load_time = time.time()
    logger.warning("ATT&CK stub corpus loaded (limited techniques)")


# ─── Qdrant Embedding ─────────────────────────────────────────────────────────

async def embed_techniques_into_qdrant(
    qdrant_url: str,
    openai_api_key: str,
    collection: str = "attck_techniques",
) -> None:
    """
    Embed ATT&CK technique descriptions into Qdrant for semantic RAG.
    Only embeds techniques that are not already present in the collection.
    """
    if not _loaded:
        await load_attck_corpus()

    try:
        from qdrant_client import AsyncQdrantClient
        from qdrant_client.models import Distance, PointStruct, VectorParams
        import openai
    except ImportError as exc:
        logger.warning("Qdrant/OpenAI client not available for ATT&CK embedding", error=str(exc))
        return

    oai = openai.AsyncOpenAI(api_key=openai_api_key)
    qdrant = AsyncQdrantClient(url=qdrant_url)

    # Ensure collection exists
    try:
        await qdrant.create_collection(
            collection_name=collection,
            vectors_config=VectorParams(size=3072, distance=Distance.COSINE),
            on_disk_payload=True,
        )
        logger.info("Created Qdrant collection for ATT&CK", collection=collection)
    except Exception:
        pass  # Collection already exists

    techniques_list = list(_techniques.values())
    total = len(techniques_list)
    embedded = 0

    for i in range(0, total, _EMBED_BATCH_SIZE):
        batch = techniques_list[i : i + _EMBED_BATCH_SIZE]
        texts = [
            f"{t.id} {t.name}: {t.description or ''} Tactics: {', '.join(t.tactic_names or [])}"
            for t in batch
        ]
        try:
            resp = await oai.embeddings.create(
                model="text-embedding-3-large",
                input=texts,
                dimensions=3072,
            )
            vectors = [e.embedding for e in resp.data]
            points = [
                PointStruct(
                    id=abs(hash(t.id)) % (2**63),
                    vector=vec,
                    payload={
                        "technique_id": t.id,
                        "name": t.name,
                        "tactic_names": t.tactic_names,
                        "platforms": t.platforms,
                        "url": t.url,
                    },
                )
                for t, vec in zip(batch, vectors)
            ]
            await qdrant.upsert(collection_name=collection, points=points)
            embedded += len(batch)
            logger.info(
                "ATT&CK embedding progress",
                embedded=embedded,
                total=total,
            )
        except Exception as exc:
            logger.warning("Batch embedding error", batch_start=i, error=str(exc))

    logger.info("ATT&CK embedding complete", total_embedded=embedded)
    await qdrant.close()


async def semantic_technique_search(
    query: str,
    qdrant_url: str,
    openai_api_key: str,
    collection: str = "attck_techniques",
    top_k: int = 5,
) -> list[dict[str, Any]]:
    """
    Perform semantic search over ATT&CK techniques using Qdrant.
    Returns the top_k most relevant techniques.
    """
    try:
        from qdrant_client import AsyncQdrantClient
        import openai
    except ImportError:
        return []

    oai = openai.AsyncOpenAI(api_key=openai_api_key)
    qdrant = AsyncQdrantClient(url=qdrant_url)

    try:
        emb_resp = await oai.embeddings.create(
            model="text-embedding-3-large",
            input=[query],
            dimensions=3072,
        )
        query_vector = emb_resp.data[0].embedding

        hits = await qdrant.search(
            collection_name=collection,
            query_vector=query_vector,
            limit=top_k,
            with_payload=True,
        )

        results = []
        for hit in hits:
            payload = hit.payload or {}
            tid = payload.get("technique_id", "")
            tech = _techniques.get(tid)
            result = {
                "technique_id": tid,
                "name": payload.get("name", ""),
                "tactic_names": payload.get("tactic_names", []),
                "score": hit.score,
                "description": tech.description if tech else "",
                "mitigations": tech.mitigations if tech else [],
                "url": payload.get("url", ""),
            }
            results.append(result)
        return results
    except Exception as exc:
        logger.warning("Semantic ATT&CK search failed", error=str(exc))
        return []
    finally:
        await qdrant.close()


# ─── Public Lookup API ────────────────────────────────────────────────────────

def get_technique(technique_id: str) -> dict[str, Any]:
    """Return full technique details by ATT&CK ID (e.g. 'T1059' or 'T1059.001')."""
    tech = _techniques.get(technique_id)
    if tech is None:
        return {"id": technique_id, "name": "Unknown", "found": False}
    return {**tech.to_dict(), "found": True}


def get_actor(actor_id: str) -> dict[str, Any]:
    """Return full actor details by ATT&CK group ID (e.g. 'G0016')."""
    actor = _actors.get(actor_id)
    if actor is None:
        return {"id": actor_id, "name": "Unknown", "found": False}
    return {**actor.to_dict(), "found": True}


def get_actor_techniques(actor_id: str) -> list[dict[str, Any]]:
    """Return all techniques attributed to a threat actor."""
    actor = _actors.get(actor_id)
    if actor is None:
        return []
    return [get_technique(tid) for tid in (actor.techniques or [])]


def search_techniques_by_name(keyword: str, limit: int = 20) -> list[dict[str, Any]]:
    """Full-text search across technique names and descriptions."""
    kw = keyword.lower()
    results = []
    for tech in _techniques.values():
        if kw in (tech.name or "").lower() or kw in (tech.description or "").lower():
            results.append(tech.to_dict())
        if len(results) >= limit:
            break
    return results


def get_techniques_by_tactic(tactic_name: str) -> list[dict[str, Any]]:
    """Return all techniques belonging to a given tactic."""
    tactic_lower = tactic_name.lower()
    return [
        t.to_dict()
        for t in _techniques.values()
        if any(tn.lower() == tactic_lower for tn in (t.tactic_names or []))
    ]


def get_coverage_summary() -> dict[str, Any]:
    """Return a summary of loaded ATT&CK data."""
    tactic_counts: dict[str, int] = {}
    for tech in _techniques.values():
        for tname in (tech.tactic_names or []):
            tactic_counts[tname] = tactic_counts.get(tname, 0) + 1
    return {
        "total_techniques": len(_techniques),
        "total_actors": len(_actors),
        "total_tactics": len(_tactic_map),
        "techniques_by_tactic": tactic_counts,
        "corpus_loaded": _loaded,
        "load_age_hours": round((time.time() - _load_time) / 3600, 1) if _load_time else None,
    }


def map_techniques_to_kill_chain(technique_ids: list[str]) -> dict[str, list[str]]:
    """Map technique IDs to their kill-chain phases."""
    result: dict[str, list[str]] = {}
    for tid in technique_ids:
        tech = _techniques.get(tid)
        if tech is None:
            result.setdefault("Unknown", []).append(tid)
            continue
        for tname in (tech.tactic_names or ["Unknown"]):
            result.setdefault(tname, []).append(f"{tid}: {tech.name}")
    return result
