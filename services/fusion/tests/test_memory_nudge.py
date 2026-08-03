"""Wave 1 - live institutional-memory nudge in the confidence scorer.

Proves a distilled per-signature prior nudges new alerts of that signature
(benign history pulls down, confirmed history pushes up), that the nudge is
bounded (never dominates), that an unknown signature changes nothing, and that
the provider distils per-tenant priors from disposition history.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

import pytest
from app.memory.distill import SignaturePrior, signature_key
from app.memory.provider import MemoryPriorProvider
from app.memory.stage import MEMORY_CAP
from app.models.alert import AlertSeverity, FusedAlert, FusionDecision, RawAlert
from app.services.confidence import ConfidenceScorer

CONNECTOR = "crowdstrike_falcon"
TECH = "T1003"


def _fused() -> FusedAlert:
    raw = RawAlert(
        tenant_id=uuid.uuid4(),
        source="x",
        title="Credential dumping",
        severity=AlertSeverity.HIGH,
        connector_type=CONNECTOR,
        mitre_techniques=[TECH],
    )
    return FusedAlert(id=raw.id, tenant_id=raw.tenant_id, fusion_decision=FusionDecision.NEW_ALERT, alert=raw)


def _priors(prior_val: float, *, connector: str = CONNECTOR, tech: str = TECH, n: int = 20):
    sig = signature_key("", connector, tech)
    return {sig: SignaturePrior(signature_key=sig, category="", sample_count=n, fp_rate=round(1.0 - prior_val, 4), prior=prior_val)}


def test_benign_prior_nudges_confidence_down_bounded():
    scorer = ConfidenceScorer()
    base = scorer.score(_fused()).confidence_score
    nudged = scorer.score(_fused(), priors=_priors(0.0)).confidence_score  # always benign
    assert nudged < base
    assert (base - nudged) <= MEMORY_CAP + 1e-6  # bounded — never dominates


def test_confirmed_prior_nudges_confidence_up_bounded():
    scorer = ConfidenceScorer()
    base = scorer.score(_fused()).confidence_score
    nudged = scorer.score(_fused(), priors=_priors(1.0)).confidence_score  # always TP
    assert nudged > base
    assert (nudged - base) <= MEMORY_CAP + 1e-6


def test_unknown_signature_leaves_score_unchanged():
    scorer = ConfidenceScorer()
    base = scorer.score(_fused()).confidence_score
    # A prior for a *different* signature must not touch this alert.
    other = scorer.score(_fused(), priors=_priors(0.0, connector="okta", tech="T1078")).confidence_score
    assert other == base
    factors = {f.factor for f in scorer.score(_fused(), priors=_priors(0.0, connector="okta")).confidence_rationale}
    assert "institutional_memory" not in factors


class _FakeConn:
    def __init__(self, rows):
        self._rows = rows

    async def fetch(self, *_a):
        return self._rows


class _FakePool:
    def __init__(self, rows):
        self._conn = _FakeConn(rows)

    def acquire(self):
        @asynccontextmanager
        async def _cm():
            yield self._conn

        return _cm()


@pytest.mark.asyncio
async def test_provider_distils_per_tenant_priors():
    t1 = str(uuid.uuid4())
    t2 = str(uuid.uuid4())
    rows = [
        {"tenant_id": t1, "connector_type": CONNECTOR, "mitre_techniques": '["T1003"]', "disposition": "false_positive"},
        {"tenant_id": t1, "connector_type": CONNECTOR, "mitre_techniques": '["T1003"]', "disposition": "false_positive"},
        {"tenant_id": t2, "connector_type": "okta", "mitre_techniques": ["T1078"], "disposition": "true_positive"},
    ]
    provider = MemoryPriorProvider()
    await provider.refresh(_FakePool(rows))

    p1 = provider.get_priors(t1)
    assert p1  # tenant 1 has a benign prior for the cred-dump signature
    sig1 = signature_key("", CONNECTOR, "T1003")
    assert p1[sig1].fp_rate == 1.0
    # tenant isolation: tenant 2's priors never appear under tenant 1.
    assert sig1 not in provider.get_priors(t2)
