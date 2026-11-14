"""
STIX 2.1 object parser — converts STIX objects to normalized IOC/actor dicts.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import hashlib
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# STIX types we care about as IOCs
_IOC_TYPES = {
    "ipv4-addr",
    "ipv6-addr",
    "domain-name",
    "url",
    "email-addr",
    "file",
    "autonomous-system",
    "network-traffic",
    "vulnerability",
}

# Mappings from STIX relationship types
_REL_USES = "uses"
_REL_INDICATES = "indicates"
_REL_ATTRIBUTED_TO = "attributed-to"
_REL_TARGETS = "targets"
_REL_MITIGATES = "mitigates"


class StixParser:
    """
    Parses a STIX 2.1 bundle into normalized dicts suitable for
    storage in OpenSearch/Qdrant/Neo4j.

    Usage:
        parser = StixParser(bundle_objects)
        iocs = parser.extract_iocs()
        actors = parser.extract_actors()
        relationships = parser.extract_relationships()
    """

    def __init__(self, objects: list[dict[str, Any]]) -> None:
        self._objects = objects
        self._by_id: dict[str, dict[str, Any]] = {o["id"]: o for o in objects if "id" in o}

    # ─── Indicators / IOCs ────────────────────────────────────────────────────

    def extract_iocs(self) -> list[dict[str, Any]]:
        """
        Extract all IOC-worthy objects from the STIX bundle.

        Handles:
        - indicator objects (with pattern parsing)
        - SCO (STIX Cyber Observable) objects
        """
        iocs: list[dict[str, Any]] = []

        for obj in self._objects:
            obj_type = obj.get("type", "")

            if obj_type == "indicator":
                parsed = self._parse_indicator(obj)
                if parsed:
                    iocs.extend(parsed)

            elif obj_type in _IOC_TYPES:
                ioc = self._observable_to_ioc(obj)
                if ioc:
                    iocs.append(ioc)

        return iocs

    def _parse_indicator(self, obj: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse a STIX indicator object into one or more IOC dicts."""
        pattern: str = obj.get("pattern", "")
        labels = obj.get("labels", [])
        name = obj.get("name", "")
        confidence = obj.get("confidence", 50)
        valid_from = obj.get("valid_from", "")
        valid_until = obj.get("valid_until", "")

        iocs: list[dict[str, Any]] = []

        # Extract values from STIX pattern  e.g. [ipv4-addr:value = '1.2.3.4']
        import re

        # Simple regex extraction
        for match in re.finditer(r"\[(\S+):(\S+)\s*=\s*'([^']+)'\]", pattern):
            obj_type, prop, value = match.groups()
            ioc_type = self._map_stix_type(obj_type, prop)
            if not ioc_type:
                continue
            iocs.append(
                {
                    "type": ioc_type,
                    "value": value,
                    "labels": labels,
                    "name": name,
                    "confidence": confidence,
                    "valid_from": valid_from,
                    "valid_until": valid_until,
                    "stix_id": obj.get("id"),
                    "source": "stix",
                    "source_ref": obj.get("id", ""),
                    "tags": labels,
                    "tlp": self._extract_marking(obj),
                }
            )
        return iocs

    def _observable_to_ioc(self, obj: dict[str, Any]) -> dict[str, Any] | None:
        """Convert a STIX SCO to a normalized IOC dict."""
        obj_type = obj.get("type", "")
        value = ""

        if obj_type == "ipv4-addr":
            value = obj.get("value", "")
            ioc_type = "ipv4-addr"
        elif obj_type == "ipv6-addr":
            value = obj.get("value", "")
            ioc_type = "ipv6-addr"
        elif obj_type == "domain-name":
            value = obj.get("value", "")
            ioc_type = "domain-name"
        elif obj_type == "url":
            value = obj.get("value", "")
            ioc_type = "url"
        elif obj_type == "email-addr":
            value = obj.get("value", "")
            ioc_type = "email-addr"
        elif obj_type == "file":
            hashes = obj.get("hashes", {})
            for hash_type in ("SHA-256", "SHA-1", "MD5"):
                if hash_type in hashes:
                    value = hashes[hash_type]
                    ioc_type = f"file-hash:{hash_type}"
                    break
            else:
                return None
        elif obj_type == "vulnerability":
            value = obj.get("name", "")
            ioc_type = "vulnerability"
        else:
            return None

        if not value:
            return None

        return {
            "type": ioc_type,
            "value": value,
            "stix_id": obj.get("id"),
            "source": "stix",
            "source_ref": obj.get("id", ""),
            "tags": [],
            "tlp": self._extract_marking(obj),
        }

    # ─── Threat Actors ────────────────────────────────────────────────────────

    def extract_actors(self) -> list[dict[str, Any]]:
        """Extract threat actor / intrusion set objects."""
        actors = []
        for obj in self._objects:
            if obj.get("type") in ("threat-actor", "intrusion-set"):
                actors.append(
                    {
                        "stix_id": obj.get("id"),
                        "type": obj.get("type"),
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                        "aliases": obj.get("aliases", []),
                        "goals": obj.get("goals", []),
                        "labels": obj.get("labels", []),
                        "sophistication": obj.get("sophistication", ""),
                        "resource_level": obj.get("resource_level", ""),
                        "primary_motivation": obj.get("primary_motivation", ""),
                        "first_seen": obj.get("first_seen", ""),
                        "last_seen": obj.get("last_seen", ""),
                        "source": "stix",
                        "tlp": self._extract_marking(obj),
                    }
                )
        return actors

    # ─── Relationships ────────────────────────────────────────────────────────

    def extract_relationships(self) -> list[dict[str, Any]]:
        """Extract STIX relationship objects for graph storage."""
        rels = []
        for obj in self._objects:
            if obj.get("type") != "relationship":
                continue
            rel_type = obj.get("relationship_type", "")
            if rel_type not in (_REL_USES, _REL_INDICATES, _REL_ATTRIBUTED_TO, _REL_TARGETS, _REL_MITIGATES):
                continue
            rels.append(
                {
                    "stix_id": obj.get("id"),
                    "rel_type": rel_type,
                    "source_ref": obj.get("source_ref", ""),
                    "target_ref": obj.get("target_ref", ""),
                    "description": obj.get("description", ""),
                    "start_time": obj.get("start_time", ""),
                    "stop_time": obj.get("stop_time", ""),
                }
            )
        return rels

    # ─── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _map_stix_type(obj_type: str, prop: str) -> str:
        mapping = {
            ("ipv4-addr", "value"): "ipv4-addr",
            ("ipv6-addr", "value"): "ipv6-addr",
            ("domain-name", "value"): "domain-name",
            ("url", "value"): "url",
            ("email-addr", "value"): "email-addr",
            ("file", "hashes.MD5"): "file-hash:MD5",
            ("file", "hashes.'SHA-256'"): "file-hash:SHA-256",
            ("file", "hashes.'SHA-1'"): "file-hash:SHA-1",
        }
        return mapping.get((obj_type, prop), obj_type)

    @staticmethod
    def _extract_marking(obj: dict[str, Any]) -> str:
        """Extract TLP marking from STIX object marking refs."""
        for ref in obj.get("object_marking_refs", []):
            ref_lower = ref.lower()
            if "tlp" in ref_lower:
                for level in ("red", "amber", "green", "white", "clear"):
                    if level in ref_lower:
                        return level
        return "white"


def generate_ioc_id(ioc_type: str, value: str, source: str) -> str:
    """Generate a stable, deduplication-friendly IOC ID."""
    key = f"{ioc_type}:{value}:{source}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]
