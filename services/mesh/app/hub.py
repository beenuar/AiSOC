"""In-memory mesh hub with hub-side privacy enforcement.

Privacy gates enforced here (defense-in-depth; the client also gates):

* **k-anonymity** — an artifact's consensus is only revealed/counted once
  ``>= k`` *distinct* (verified) instances have reported it. Default k=5.
* **Ed25519 verification** — an artifact is only counted after its signature
  verifies against the claimed instance public key, so one actor can't inflate
  consensus with sock-puppet instance IDs.
* **opt-out** — an instance (or the operator, per rule) can opt a public key out;
  the hub then refuses to accept or serve its contributions.
* **audit** — every accepted publish is appended to a receipts log, queryable
  per instance, so an operator can see exactly what left their instance.

The store is intentionally in-memory + simple; a production hub would back it
with a database, but the privacy logic is the part that matters and it's pure
and unit-tested.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.artifacts import IocSighting, VerdictSignature
from app.crypto import verify

DEFAULT_K = 5

#: Fixed domain string an instance signs to prove an opt-out withdrawal.
#: A distinct message from every artifact's ``signing_bytes()``, so an
#: opt-out signature cannot be replayed as a publish and vice versa.
OPT_OUT_DOMAIN = b"aisoc-mesh:opt-out:v1"

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class _IocRecord:
    ioc_type: str
    instances: set[str] = field(default_factory=set)
    severities: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class _SigRecord:
    category: str = ""
    connector_type: str = ""
    primary_technique: str = ""
    instances: set[str] = field(default_factory=set)
    verdict_counts: dict[str, int] = field(default_factory=dict)
    confidence_sum: float = 0.0
    confidence_n: int = 0


@dataclass
class Receipt:
    instance: str
    kind: str
    ref: str
    ts: str


class MeshHub:
    def __init__(self, k: int = DEFAULT_K) -> None:
        self.k = k
        self._iocs: dict[str, _IocRecord] = {}
        self._sigs: dict[str, _SigRecord] = {}
        self._optout: set[str] = set()
        self._receipts: list[Receipt] = []
        self._lock = threading.Lock()

    # -- opt-out ---------------------------------------------------------------

    def opt_out_signed(self, instance_pubkey: str, signature_b64: str) -> bool:
        """Withdraw an instance's participation, proven by its own key.

        Opt-out is a permanent publish denylist: every future artifact from
        the named pubkey is rejected, so an unauthenticated opt-out was a
        silent, permanent denial-of-service against any contributor — and it
        removes the instance from every k-anonymity cohort at once, quietly
        invalidating the privacy guarantee other instances were promised. An
        anonymous caller must not be able to do that: the withdrawal is
        signed with the instance's own Ed25519 key over ``OPT_OUT_DOMAIN``,
        and verification against the claimed pubkey fails for anyone who
        does not hold the private key. A bearer token would be the wrong
        shape here — foreign instances in a federation do not share this
        hub's platform secret, and proof-of-key works for exactly the party
        entitled to withdraw.
        """
        if not verify(instance_pubkey, OPT_OUT_DOMAIN, signature_b64):
            return False
        with self._lock:
            self._optout.add(instance_pubkey)
        return True

    def opt_out(self, instance_pubkey: str) -> None:
        """Unauthenticated denylist add. Internal/test use only — the HTTP
        route requires the signed form (:meth:`opt_out_signed`)."""
        with self._lock:
            self._optout.add(instance_pubkey)

    def is_opted_out(self, instance_pubkey: str) -> bool:
        return instance_pubkey in self._optout

    # -- publish ---------------------------------------------------------------

    def publish_ioc(self, instance_pubkey: str, sighting: IocSighting, signature_b64: str) -> bool:
        """Verify + record an IOC sighting. Returns False if rejected."""
        if self.is_opted_out(instance_pubkey):
            return False
        if not verify(instance_pubkey, sighting.signing_bytes(), signature_b64):
            return False
        with self._lock:
            rec = self._iocs.setdefault(sighting.ioc_hash, _IocRecord(ioc_type=sighting.ioc_type))
            rec.instances.add(instance_pubkey)
            rec.severities.append(sighting.severity)
            rec.first_seen = min(rec.first_seen or sighting.first_seen, sighting.first_seen)
            rec.last_seen = max(rec.last_seen, sighting.last_seen)
            self._receipts.append(Receipt(instance_pubkey, "ioc_sighting", sighting.ioc_hash, _now()))
        return True

    def publish_signature(self, instance_pubkey: str, sig: VerdictSignature, signature_b64: str) -> bool:
        if self.is_opted_out(instance_pubkey):
            return False
        if not verify(instance_pubkey, sig.signing_bytes(), signature_b64):
            return False
        with self._lock:
            rec = self._sigs.setdefault(
                sig.signature_key,
                _SigRecord(category=sig.category, connector_type=sig.connector_type, primary_technique=sig.primary_technique),
            )
            rec.instances.add(instance_pubkey)
            for verdict, n in sig.verdict_counts.items():
                rec.verdict_counts[verdict] = rec.verdict_counts.get(verdict, 0) + int(n)
            rec.confidence_sum += sig.mean_confidence
            rec.confidence_n += 1
            self._receipts.append(Receipt(instance_pubkey, "verdict_signature", sig.signature_key, _now()))
        return True

    # -- query (k-anonymity enforced) -----------------------------------------

    def query_ioc(self, ioc_hash: str) -> dict | None:
        """Return reputation ONLY if >= k distinct instances reported it (PSI + k-anon)."""
        rec = self._iocs.get(ioc_hash)
        if rec is None or len(rec.instances) < self.k:
            return None
        worst = max(rec.severities, key=lambda s: _SEVERITY_RANK.get(s, 0)) if rec.severities else "info"
        return {
            "ioc_hash": ioc_hash,
            "ioc_type": rec.ioc_type,
            "instances": len(rec.instances),
            "sightings": len(rec.severities),
            "max_severity": worst,
            "first_seen": rec.first_seen,
            "last_seen": rec.last_seen,
        }

    def query_signature(self, signature_key: str) -> dict | None:
        rec = self._sigs.get(signature_key)
        if rec is None or len(rec.instances) < self.k:
            return None
        total = sum(rec.verdict_counts.values()) or 1
        fp = rec.verdict_counts.get("false_positive", 0) + rec.verdict_counts.get("likely_benign", 0)
        return {
            "signature_key": signature_key,
            "category": rec.category,
            "connector_type": rec.connector_type,
            "primary_technique": rec.primary_technique,
            "instances": len(rec.instances),
            "verdict_counts": dict(rec.verdict_counts),
            "fp_rate": round(fp / total, 4),
            "mean_confidence": round(rec.confidence_sum / rec.confidence_n, 4) if rec.confidence_n else 0.0,
        }

    # -- stats + audit ---------------------------------------------------------

    def stats(self) -> dict:
        instances = {inst for r in self._iocs.values() for inst in r.instances} | {
            inst for r in self._sigs.values() for inst in r.instances
        }
        visible_iocs = sum(1 for r in self._iocs.values() if len(r.instances) >= self.k)
        visible_sigs = sum(1 for r in self._sigs.values() if len(r.instances) >= self.k)
        return {
            "instances_connected": len(instances),
            "ioc_hashes_total": len(self._iocs),
            "ioc_hashes_visible": visible_iocs,
            "verdict_signatures_total": len(self._sigs),
            "verdict_signatures_visible": visible_sigs,
            "k_anonymity_threshold": self.k,
            "artifacts_received": len(self._receipts),
        }

    def receipts_for(self, instance_pubkey: str) -> list[Receipt]:
        return [r for r in self._receipts if r.instance == instance_pubkey]


def _now() -> str:
    return datetime.now(UTC).isoformat()
