"""Public-dataset fidelity benchmark (T5.3).

This package loads public network-security research datasets
(CICIDS-2017, CTU-13), normalises every flow into an OCSF-shaped
event, and runs a deterministic reference classifier through them so
the loader → OCSF → classifier path can be regression-tested end to
end.

Workspace rule we adhere to: numbers produced by this harness are
**substrate** (deterministic, no LLM) unless the runner is invoked
with ``--mode wet``. Substrate numbers are a fidelity floor of the
loader-and-rule pipeline; they are not a claim of agent accuracy.
The methodology page (``apps/docs/docs/benchmark-fidelity.md``)
spells out the substrate-vs-wet distinction in detail.

The full datasets are not redistributed in this repo. See
``scripts/datasets/download_cicids.py`` and
``scripts/datasets/download_ctu13.py`` for licensed-source download
flows. A 100-flow synthetic micro fixture
(``services/agents/tests/eval_data/cicids_micro.csv``) is committed so
CI can exercise the loader and runner without any network access.
"""

from __future__ import annotations

__all__ = [
    "cicids_loader",
    "ctu13_loader",
    "runner",
]
