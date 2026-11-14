"""Compounding Memory (v8 P4).

Nightly distillation compresses analyst overrides + verdict history into (a)
per-signature priors consumed by a deterministic ``memory`` verdict stage and
(b) a curated few-shot exemplar bank for the LLM band. The result: verdicts that
measurably improve the longer an instance runs — and a portable, signed memory
pack so an MSSP can bootstrap a new child tenant from a curated baseline.
"""

from app.memory.distill import MemoryPack, SignaturePrior, distill, signature_key
from app.memory.improvement import ImprovementCurve, precision_over_time
from app.memory.pack import export_pack, import_pack
from app.memory.stage import MEMORY_CAP, memory_contribution

__all__ = [
    "distill",
    "MemoryPack",
    "SignaturePrior",
    "signature_key",
    "memory_contribution",
    "MEMORY_CAP",
    "export_pack",
    "import_pack",
    "precision_over_time",
    "ImprovementCurve",
]
