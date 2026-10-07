"""A stable name for one step execution, so repeating it is detectable.

Why a key at all
----------------
Three of the engine's behaviours can run the same step object twice:

* a resumed run replays from a stored index, and a decision that arrives
  twice is routine (a double-tap in the responder app, a retried webhook);
* ``loop`` runs its children once per item;
* ``parallel`` runs its branches concurrently, and a branch that is retried
  must not be confused with the branch beside it.

"The same step" is therefore not the same thing as "the same step id". The
key below is derived from the run, the step, and the *position* the step was
reached at — ``i2`` for the third loop iteration, ``b1`` for the second
parallel branch — so two executions collide exactly when they are the same
logical unit of work and never otherwise.

What it is not
--------------
This is not a distributed deduplication store. Nothing here remembers keys
across runs or across replicas; the key is a name, and the dedupe that uses
it is the engine's own "this step already has a result in this run" check
plus whatever the vendor does with it downstream (PagerDuty's ``dedup_key``
is the obvious one). Claiming more than that would be the kind of
exactly-once promise that needs a transaction log to keep.

Deterministic on purpose: the same step reached the same way in a resumed
run produces the same key, which is what makes a resume safe. That means it
must not read the clock, a UUID, or anything else that changes between the
first attempt and the retry.
"""

from __future__ import annotations

import hashlib

#: Separator that cannot appear in a run id, a step id or a coordinate, so
#: ``("a", "b:c")`` and ``("a:b", "c")`` cannot hash to the same key.
_SEP = "\x1f"


def step_key(*, run_id: str, step_id: str, path: tuple[str, ...] = ()) -> str:
    """The idempotency key for one step execution.

    ``path`` is the coordinates that got here: ``()`` at the top level,
    ``("i3",)`` inside the fourth loop iteration, ``("b1", "i0")`` for the
    first iteration of a loop inside the second parallel branch.

    Hashed rather than concatenated because the key travels to vendors in
    request bodies, and a raw join would leak the playbook's internal step
    ids and the run id into a third party's incident record. A hash is also
    a fixed length, which matters for the vendors that cap theirs —
    PagerDuty's ``dedup_key`` is 255 characters.
    """
    material = _SEP.join((run_id, step_id, *path))
    return "aisoc-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def child_path(path: tuple[str, ...], kind: str, index: int) -> tuple[str, ...]:
    """Extend a path by one coordinate.

    ``kind`` is a single letter — ``i`` for a loop iteration, ``b`` for a
    parallel branch — so a path reads as ``b1/i3`` in a log line and stays
    short in the hash material.
    """
    return (*path, f"{kind}{index}")
