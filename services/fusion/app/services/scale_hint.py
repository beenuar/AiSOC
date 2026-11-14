"""Lag-based autoscaling hints (parity 6.9 / depth 4.4).

AiSOC publishes a signal. It does not scale itself.

That is a decision rather than an omission, and ADR-0012 records it: an
autoscaler belongs to the cluster, not to the application. A platform
that scaled its own deployments would need write access to the
orchestrator, would fight whatever HPA or KEDA scaler the operator
already runs, and could not honour the quota and cost policies that live
outside it. Publishing the signal is the whole of the job.

What the hint is
----------------
Consumer lag divided by a per-replica budget, rounded up, and clamped. It
answers "how many replicas would clear this backlog in the target time",
which is the input a KEDA ``ScaledObject`` or an HPA external metric
wants — not "scale up", which is a decision with more inputs than fusion
has.

Where the budget comes from
---------------------------
From a measurement, and from one that is published. The realistic-mix run
in ``apps/docs/docs/operations/performance.md`` is the reference, and the
constant below names it. A per-replica budget picked out of the air would
make the hint a number that relates to nothing — which is the defect this
repository has already measured on a performance gate whose floor sat
orders of magnitude below the figures it was supposed to protect.

The budget is overridable per deployment, because the published figure is
a laptop's and an operator's hardware is not. An override is read once and
logged, so a hint nobody can explain has a line that explains it.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass

import structlog

logger = structlog.get_logger()

#: Events per second one fusion replica drained in the published
#: realistic-mix run (docs/perf/results/2026-10-11-compose-realistic-mix.json:
#: 6,000 events accepted at 122.56 events/s through a single replica).
#:
#: Named rather than inlined so the derivation is greppable from the
#: figure: if the published run changes, this is the one place that has to
#: move, and the test that pins the two together fails until it does.
PUBLISHED_REPLICA_EPS = 122.56

#: How long a backlog should take to clear. Two minutes is a policy
#: choice and is stated as one: nothing measured says two minutes is
#: right. It is the window in which an operator would rather have added a
#: replica than waited.
DEFAULT_DRAIN_TARGET_SECONDS = 120.0

#: Bounds on the hint. A hint of zero would ask an autoscaler to remove
#: the last replica, and an unbounded one turns a stuck consumer — lag
#: that is not falling because nothing is consuming — into an unbounded
#: scale-out that cannot help.
MIN_REPLICAS = 1
MAX_REPLICAS = 20

_EPS_ENV = "AISOC_FUSION_REPLICA_EPS"
_TARGET_ENV = "AISOC_FUSION_DRAIN_TARGET_SECONDS"


def _positive_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.error("scale_hint.bad_override", variable=name, value=raw, using=default)
        return default
    if value <= 0:
        logger.error("scale_hint.non_positive_override", variable=name, value=value, using=default)
        return default
    logger.info("scale_hint.override", variable=name, value=value)
    return value


@dataclass(frozen=True)
class ScaleHint:
    """What an external autoscaler should read."""

    lag_messages: int
    replica_eps: float
    drain_target_seconds: float
    suggested_replicas: int
    #: True when the lag figure is unknown rather than zero. An autoscaler
    #: reading a hint built on an unknown lag is reading a guess, and the
    #: difference between "no backlog" and "we could not measure the
    #: backlog" is the whole of this field.
    lag_measured: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "lag_messages": self.lag_messages,
            "lag_measured": self.lag_measured,
            "replica_eps": self.replica_eps,
            "drain_target_seconds": self.drain_target_seconds,
            "suggested_replicas": self.suggested_replicas,
            "basis": (
                f"{self.lag_messages} message(s) backlog, cleared in "
                f"{self.drain_target_seconds:.0f}s at {self.replica_eps:.1f} events/s per replica"
                if self.lag_measured
                else "consumer lag could not be read; the hint is the floor, not a measurement"
            ),
        }


def compute(lag_messages: int | None) -> ScaleHint:
    """Turn a measured consumer lag into a replica count.

    ``None`` means the lag could not be read — a broker that did not
    answer, a consumer not yet assigned a partition. That returns the
    floor with ``lag_measured`` false, rather than zero lag: reporting an
    unreadable backlog as no backlog is how a stalled consumer looks
    healthy, which is the defect this service has shipped before.
    """
    replica_eps = _positive_float(_EPS_ENV, PUBLISHED_REPLICA_EPS)
    target = _positive_float(_TARGET_ENV, DEFAULT_DRAIN_TARGET_SECONDS)

    if lag_messages is None:
        return ScaleHint(
            lag_messages=0,
            replica_eps=replica_eps,
            drain_target_seconds=target,
            suggested_replicas=MIN_REPLICAS,
            lag_measured=False,
        )

    lag = max(0, int(lag_messages))
    per_replica = replica_eps * target
    suggested = MIN_REPLICAS if per_replica <= 0 else math.ceil(lag / per_replica)
    suggested = max(MIN_REPLICAS, min(MAX_REPLICAS, suggested))
    return ScaleHint(
        lag_messages=lag,
        replica_eps=replica_eps,
        drain_target_seconds=target,
        suggested_replicas=suggested,
        lag_measured=True,
    )
