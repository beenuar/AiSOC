"""What the local model is *actually* running on, asked rather than assumed.

Why this asks Ollama instead of reading configuration
-----------------------------------------------------
`infra/compose/docker-compose.gpu.yml` reserves an NVIDIA device, but a
reservation is a request. The model can still land on the CPU -- too little
VRAM for the layer count, a driver the runtime cannot use, another process
holding the card. Reading the compose file back would report the intent and
call it the outcome.

Ollama already knows, and publishes it. `GET /api/ps` lists each loaded model
with `size` and `size_vram`, and the ratio between them is the answer.
Verified against the pinned `ollama/ollama:0.6.7` image: a model loaded in a
container on an Apple Silicon host reports `size_vram: 0` against
`size: 820601088`, correctly CPU, while the same host's *native* Ollama
reports `size_vram == size` because it reaches Metal. Those are the two
configurations this feature exists to tell apart, and the field distinguishes
them.

The four states, and why "unknown" is one of them
-------------------------------------------------
`/api/ps` lists models that are loaded **right now**. Ollama unloads after a
few minutes idle, so an empty list is the ordinary state of a stack nobody has
asked anything of yet. It means *we have not been told*, which is not the same
as CPU -- and answering CPU there would be a fabricated verdict about the thing
an operator is deciding on.

A missing `size_vram` key is treated the same way, so a future Ollama that
renames or drops it degrades to "unknown" rather than silently reporting every
deployment as CPU.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx
import structlog

logger = structlog.get_logger(__name__)

Placement = Literal["gpu", "partial", "cpu", "unknown", "unreachable", "not_local"]

#: Where the bundled Ollama lives on the compose network. `make up-host-llm`
#: overrides this to the host's own Ollama, which is the configuration where
#: the answer is most likely to be "gpu" on a Mac.
DEFAULT_OLLAMA_URL = "http://ollama:11434"

#: Short. This runs behind a wizard step a human is waiting on, and a slow
#: probe would make the page feel broken. A timeout is reported as
#: `unreachable`, which is honest and actionable.
PROBE_TIMEOUT_SECONDS = 4.0


def ollama_url() -> str:
    """Where to ask. `AISOC_OLLAMA_URL` is set by the host-llm overlay."""
    return (os.getenv("AISOC_OLLAMA_URL") or DEFAULT_OLLAMA_URL).rstrip("/")


@dataclass
class RuntimeReport:
    """What is running, where, and how sure we are."""

    placement: Placement
    detail: str
    base_url: str
    model: str | None = None
    vram_bytes: int | None = None
    total_bytes: int | None = None
    #: The commands that would change the answer, for the surface that shows it.
    #: Populated by the endpoint, which knows the host; this module only knows
    #: what Ollama said.
    options: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "placement": self.placement,
            "detail": self.detail,
            "base_url": self.base_url,
            "options": self.options,
        }
        # Absent rather than null, matching the convention the performance
        # results follow: an unmeasured quantity carries no value key, so no
        # renderer downstream can turn an absence into `0`.
        if self.model is not None:
            out["model"] = self.model
        if self.vram_bytes is not None:
            out["vram_bytes"] = self.vram_bytes
        if self.total_bytes is not None:
            out["total_bytes"] = self.total_bytes
        return out


def classify(models: list[dict[str, Any]]) -> RuntimeReport:
    """Turn Ollama's `/api/ps` payload into a verdict.

    Pure, so the states can be tested without a container.
    """
    base = ollama_url()

    if not models:
        return RuntimeReport(
            placement="unknown",
            detail=(
                "No model is loaded right now, so Ollama cannot say where one would run. "
                "Ollama unloads after a few minutes idle; run a triage and check again."
            ),
            base_url=base,
        )

    # The largest resident model is the one that matters: it is what a triage
    # will use and what a GPU would have to hold.
    model = max(models, key=lambda m: int(m.get("size") or 0))
    name = str(model.get("name") or model.get("model") or "unknown")
    total = int(model.get("size") or 0)

    if "size_vram" not in model:
        return RuntimeReport(
            placement="unknown",
            detail=(
                f"Ollama is serving {name} but did not report VRAM usage, so where it runs cannot be determined from this version's API."
            ),
            base_url=base,
            model=name,
            total_bytes=total or None,
        )

    vram = int(model.get("size_vram") or 0)

    if vram <= 0:
        return RuntimeReport(
            placement="cpu",
            detail=f"{name} is running entirely on the CPU.",
            base_url=base,
            model=name,
            vram_bytes=0,
            total_bytes=total or None,
        )

    if total and vram < total:
        pct = round(100.0 * vram / total)
        return RuntimeReport(
            placement="partial",
            detail=(
                f"{name} is split: {pct}% of it is in VRAM and the rest is on the CPU. "
                "A card with more memory, or a smaller model, would hold all of it."
            ),
            base_url=base,
            model=name,
            vram_bytes=vram,
            total_bytes=total,
        )

    return RuntimeReport(
        placement="gpu",
        detail=f"{name} is running on the GPU ({_gib(vram)} in VRAM).",
        base_url=base,
        model=name,
        vram_bytes=vram,
        total_bytes=total or None,
    )


def _gib(n: int) -> str:
    return f"{n / (1024**3):.1f} GB"


async def probe() -> RuntimeReport:
    """Ask the local Ollama what it is doing.

    Never raises. Every failure becomes a reported state, because this is
    rendered on a setup page and an exception there is a blank panel with no
    explanation.
    """
    base = ollama_url()
    try:
        async with httpx.AsyncClient(timeout=PROBE_TIMEOUT_SECONDS) as client:
            resp = await client.get(f"{base}/api/ps")
    except Exception as exc:  # noqa: BLE001 - every failure is a state, not a crash
        logger.info("llm_runtime.unreachable", base_url=base, error=type(exc).__name__)
        return RuntimeReport(
            placement="unreachable",
            detail=(f"No Ollama answered at {base}. If this deployment uses a hosted provider that is expected and nothing is wrong."),
            base_url=base,
        )

    if resp.status_code != 200:
        return RuntimeReport(
            placement="unreachable",
            detail=f"Ollama at {base} answered HTTP {resp.status_code}.",
            base_url=base,
        )

    try:
        payload = resp.json()
    except ValueError:
        return RuntimeReport(
            placement="unknown",
            detail=f"Ollama at {base} returned a response that is not JSON.",
            base_url=base,
        )

    models = payload.get("models")
    return classify(models if isinstance(models, list) else [])


__all__ = ["Placement", "RuntimeReport", "classify", "ollama_url", "probe"]
