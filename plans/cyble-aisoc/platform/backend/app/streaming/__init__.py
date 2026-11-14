"""Streaming detection runtime (t6-streaming).

A sub-second detection layer that sits in front of the existing
:mod:`app.detections.engine` to exercise *windowed* and
*correlation* rules — patterns the per-event matcher cannot express
on its own.

The runtime is an in-process simulation of the streaming primitives
a real Flink / Materialize / Bytewax pipeline would provide:

* **Watermarks** propagate forward as events arrive; late events
  beyond the lateness budget are dropped.
* **Tumbling and sliding windows** are advanced as the watermark
  passes their close boundary.
* **Stateful key partitioning** lets rules group by user, host, or
  tenant without leaking state across keys.

We pick this in-process approach because:

1. The detection rules and grading logic must work *inside* the
   FastAPI process today (the platform's whole point is fast time-
   to-detect on a single machine in an evaluation environment), but
   they must also lift cleanly into a real streaming engine
   tomorrow.
2. Modelling watermarks + windows explicitly here means we can write
   correlation rules that exactly match what we'll deploy to
   Flink/Bytewax/Materialize when the time comes — no algorithmic
   surprise on cutover.
3. Tests run deterministically on a synthetic clock, which is
   exactly the property a real-time detection layer needs.

Contract for callers:

* Push events with :func:`StreamingRuntime.ingest`.
* Subscribe to detections with :func:`StreamingRuntime.on_detection`.
* In production the ingest call is driven by the OCSF-normaliser
  (Theme 1: t1-realtime-data) reading from Kafka; in tests it is
  driven directly.
"""

from app.streaming.runtime import (
    BurstThresholdRule,
    CorrelationRule,
    Detection,
    StreamingRule,
    StreamingRuntime,
    WindowSpec,
)

__all__ = [
    "BurstThresholdRule",
    "CorrelationRule",
    "Detection",
    "StreamingRule",
    "StreamingRuntime",
    "WindowSpec",
]
