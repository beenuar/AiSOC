"""
Threat Actor Attribution Engine.

Scores observed indicators (IOCs), MITRE ATT&CK techniques, used tools, and
target sectors against a small in-memory catalog of well-documented threat
actors and returns the best match above a configurable confidence threshold.

This is a v0 attribution engine intended as a foundation. The actor catalog
is currently hardcoded with three high-profile public profiles (APT28,
APT29, Lazarus). Sourcing from STIX/TAXII or a curated YAML/JSON corpus is
the obvious next step.

The IOC component of the score is intentionally conservative: it only
contributes when an OpenSearch store is available and an exact-value match
is found in collected threat intel. There is no synthetic "every IOC counts
as a match" inflation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

WEIGHT_TTP = 0.4
WEIGHT_TOOL = 0.3
WEIGHT_TARGET = 0.2
WEIGHT_IOC = 0.1
DEFAULT_CONFIDENCE_THRESHOLD = 0.3


class ThreatActorProfile(BaseModel):
    """Profile of a threat actor with associated attributes."""

    id: str
    name: str
    aliases: List[str] = Field(default_factory=list)
    description: str = ""
    sophistication_level: str = "unknown"  # novice | intermediate | advanced | expert
    primary_motivation: str = ""
    secondary_motivations: List[str] = Field(default_factory=list)
    ttps: List[str] = Field(default_factory=list)
    tools: List[str] = Field(default_factory=list)
    targets: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    confidence_score: float = 0.5


class AttributionResult(BaseModel):
    """Result of threat actor attribution analysis."""

    actor_id: str
    actor_name: str
    confidence_score: float
    matched_indicators: List[str] = Field(default_factory=list)
    reasoning: List[str] = Field(default_factory=list)
    timestamp: datetime


def _seed_actor_catalog() -> Dict[str, ThreatActorProfile]:
    """Return the v0 hardcoded actor catalog.

    Public-domain profiles based on MITRE ATT&CK Groups documentation.
    Confidence values reflect public-source data quality only; they are not
    a claim about real-world certainty in any particular incident.
    """
    return {
        "APT28": ThreatActorProfile(
            id="APT28",
            name="APT28 (Fancy Bear)",
            aliases=["Sofacy", "Pawn Storm", "Sednit", "Tsar Team"],
            description="Russian cyber espionage group; well-documented in MITRE ATT&CK Groups.",
            sophistication_level="advanced",
            primary_motivation="espionage",
            secondary_motivations=["disruption"],
            ttps=["T1566", "T1059", "T1071", "T1041", "T1562", "T1089", "T1070"],
            tools=["x-agent", "sofacy"],
            targets=["government", "military", "political parties"],
            confidence_score=0.85,
        ),
        "APT29": ThreatActorProfile(
            id="APT29",
            name="APT29 (Cozy Bear)",
            aliases=["The Dukes", "Group 100", "CozyDuke"],
            description="Russian state-sponsored group with mature tradecraft.",
            sophistication_level="expert",
            primary_motivation="espionage",
            secondary_motivations=[],
            ttps=["T1059", "T1071", "T1041", "T1021", "T1562", "T1089", "T1070"],
            tools=["miniduke", "cosmicduke"],
            targets=["government", "technology", "think tanks"],
            confidence_score=0.85,
        ),
        "Lazarus": ThreatActorProfile(
            id="Lazarus",
            name="Lazarus Group",
            aliases=["Hidden Cobra", "Guardians of Peace"],
            description="DPRK-aligned group active against finance, crypto, and entertainment.",
            sophistication_level="advanced",
            primary_motivation="financial gain",
            secondary_motivations=["espionage", "disruption"],
            ttps=["T1059", "T1071", "T1041", "T1036", "T1562", "T1089", "T1070"],
            tools=["destover", "wannacry"],
            targets=["financial institutions", "entertainment", "cryptocurrency"],
            confidence_score=0.80,
        ),
    }


class ThreatActorAttributionEngine:
    """Score observed indicators against a catalog of known threat actors.

    Args:
        catalog: Optional override for the actor catalog. If omitted, the v0
            hardcoded catalog is loaded.
        os_store: Optional OpenSearch store (the same instance used by the
            threat-intel feed pipeline) used to verify IOC values against
            collected intel. If ``None``, the IOC component of the score is
            zero and reasoning makes that explicit.
        confidence_threshold: Minimum total score required to return a named
            actor; below this, ``"unknown"`` is returned.
    """

    def __init__(
        self,
        catalog: Optional[Dict[str, ThreatActorProfile]] = None,
        os_store: Any = None,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    ) -> None:
        self._actor_profiles: Dict[str, ThreatActorProfile] = (
            catalog if catalog is not None else _seed_actor_catalog()
        )
        self._os_store = os_store
        self._confidence_threshold = confidence_threshold

    async def attribute_incident(
        self,
        iocs: List[Dict[str, Any]],
        mitre_techniques: List[str],
        case_metadata: Dict[str, Any],
    ) -> AttributionResult:
        """Attribute an incident to the highest-scoring known actor.

        Args:
            iocs: Observed indicators, each a dict with at least a ``value``
                field; ``type`` is optional but recommended.
            mitre_techniques: Observed MITRE ATT&CK technique IDs
                (e.g. ``["T1566", "T1059"]``).
            case_metadata: Free-form case metadata; ``targets`` (list of
                sector strings) is the only field consulted today.

        Returns:
            ``AttributionResult``. If no actor exceeds
            ``confidence_threshold``, ``actor_id`` is ``"unknown"``.
        """
        logger.info(
            "Starting threat actor attribution",
            ioc_count=len(iocs),
            technique_count=len(mitre_techniques),
            actor_count=len(self._actor_profiles),
        )

        if not self._actor_profiles:
            return AttributionResult(
                actor_id="unknown",
                actor_name="Unknown Actor",
                confidence_score=0.0,
                matched_indicators=[],
                reasoning=["Actor catalog is empty"],
                timestamp=datetime.now(timezone.utc),
            )

        actor_scores: Dict[str, Dict[str, Any]] = {}
        for actor_id, profile in self._actor_profiles.items():
            actor_scores[actor_id] = await self._score_actor_match(
                profile, iocs, mitre_techniques, case_metadata
            )

        best_actor_id = max(
            actor_scores.keys(), key=lambda k: actor_scores[k]["total_score"]
        )
        best = actor_scores[best_actor_id]

        if best["total_score"] < self._confidence_threshold:
            return AttributionResult(
                actor_id="unknown",
                actor_name="Unknown Actor",
                confidence_score=0.0,
                matched_indicators=[],
                reasoning=[
                    f"No actor exceeded confidence threshold of {self._confidence_threshold}"
                ],
                timestamp=datetime.now(timezone.utc),
            )

        return AttributionResult(
            actor_id=best_actor_id,
            actor_name=self._actor_profiles[best_actor_id].name,
            confidence_score=round(best["total_score"], 4),
            matched_indicators=best["matched_indicators"],
            reasoning=best["reasoning"],
            timestamp=datetime.now(timezone.utc),
        )

    async def _score_actor_match(
        self,
        profile: ThreatActorProfile,
        iocs: List[Dict[str, Any]],
        mitre_techniques: List[str],
        case_metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Score one actor profile against the observed indicators."""
        matched_indicators: List[str] = []
        reasoning: List[str] = []
        components = {"ttp": 0.0, "tool": 0.0, "target": 0.0, "ioc": 0.0}

        if profile.ttps:
            matched_techniques = sorted(set(profile.ttps) & set(mitre_techniques))
            if matched_techniques:
                ratio = len(matched_techniques) / len(profile.ttps)
                components["ttp"] = ratio * WEIGHT_TTP
                matched_indicators.extend(matched_techniques)
                reasoning.append(
                    f"Matched {len(matched_techniques)}/{len(profile.ttps)} TTPs: "
                    + ", ".join(matched_techniques)
                )

        if profile.tools:
            actor_tools_lower = [t.lower() for t in profile.tools]
            matched_tools: List[str] = []
            for ioc in iocs:
                value = str(ioc.get("value", "")).lower()
                if not value:
                    continue
                for tool in actor_tools_lower:
                    if tool and tool in value:
                        matched_tools.append(tool)
            unique_tools = sorted(set(matched_tools))
            if unique_tools:
                ratio = len(unique_tools) / len(profile.tools)
                components["tool"] = ratio * WEIGHT_TOOL
                matched_indicators.extend(unique_tools)
                reasoning.append("Matched tools: " + ", ".join(unique_tools))

        case_targets = case_metadata.get("targets", []) if case_metadata else []
        if profile.targets and case_targets:
            matched_targets = sorted(
                {t.lower() for t in profile.targets}
                & {t.lower() for t in case_targets}
            )
            if matched_targets:
                ratio = len(matched_targets) / len(profile.targets)
                components["target"] = ratio * WEIGHT_TARGET
                matched_indicators.extend(matched_targets)
                reasoning.append("Matched target sectors: " + ", ".join(matched_targets))

        if iocs and self._os_store is not None:
            try:
                hits = await self._lookup_iocs(iocs)
                if hits:
                    matched_indicators.extend(hits)
                    ratio = min(len(hits) / max(len(iocs), 1), 1.0)
                    components["ioc"] = ratio * WEIGHT_IOC
                    reasoning.append(
                        f"Matched {len(hits)}/{len(iocs)} IOCs against collected threat intel"
                    )
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("IOC lookup failed; ignoring IOC component", error=str(exc))
        elif iocs:
            reasoning.append(
                "IOC component unavailable: no os_store wired (TTP/tool/target only)"
            )

        total_score = sum(components.values()) * profile.confidence_score
        return {
            "total_score": total_score,
            "components": components,
            "matched_indicators": matched_indicators,
            "reasoning": reasoning,
        }

    async def _lookup_iocs(self, iocs: List[Dict[str, Any]]) -> List[str]:
        """Return IOC values that exist in the ``threatintel-iocs`` index."""
        values = sorted({str(i.get("value", "")) for i in iocs if i.get("value")})
        if not values:
            return []
        resp = await self._os_store._os.search(
            index="threatintel-iocs",
            body={
                "query": {"terms": {"value": values}},
                "size": min(len(values), 100),
                "_source": ["value"],
            },
        )
        return sorted({hit["_source"]["value"] for hit in resp["hits"]["hits"]})

    async def get_actor_profile(self, actor_id: str) -> Optional[ThreatActorProfile]:
        """Retrieve a threat actor profile by ID."""
        return self._actor_profiles.get(actor_id)

    async def list_actor_profiles(self) -> List[ThreatActorProfile]:
        """List all known threat actor profiles."""
        return list(self._actor_profiles.values())

    async def update_actor_profile(self, profile: ThreatActorProfile) -> None:
        """Add or replace a threat actor profile in the in-memory catalog."""
        self._actor_profiles[profile.id] = profile
        logger.info("Updated threat actor profile", actor_id=profile.id)
