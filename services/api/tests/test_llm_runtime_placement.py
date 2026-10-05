"""Where the model runs is asked, and an absent answer stays absent.

The states, and the one that matters most
-----------------------------------------
`GET /api/v1/llm/runtime` exists because a GPU reservation is a *request*: a
model can still land on the CPU for want of VRAM or a usable driver, so
reading the compose file back would report the intent and call it the outcome.
Ollama knows and publishes it on `/api/ps`.

The payloads below are not invented. They were captured from real Ollama
instances while building this:

* **CPU** -- the pinned `ollama/ollama:0.6.7` image running in a container on
  an Apple Silicon host, which reports `size_vram: 0` against a real `size`.
  That is the configuration `make up` produces on a Mac.
* **GPU** -- the same host's *native* Ollama 0.30.7, which reaches Metal and
  reports `size_vram == size`. That is what `make up-host-llm` produces.

Those two are the configurations this whole feature exists to tell apart, so
the fixtures are the two it was measured on.

**`unknown` is a state, not a fallback.** `/api/ps` lists models loaded *right
now*, and Ollama unloads after a few minutes idle, so an empty list is the
ordinary condition of a stack nobody has asked anything of. Answering "CPU"
there would be a fabricated verdict about the exact thing an operator is
deciding on.
"""

from __future__ import annotations

import pytest

# Captured from `ollama/ollama:0.6.7` in a container on Apple Silicon.
CPU_PAYLOAD = [
    {
        "name": "qwen2.5:0.5b",
        "model": "qwen2.5:0.5b",
        "size": 820601088,
        "size_vram": 0,
        "digest": "a8b0c515",
        "details": {"family": "qwen2", "quantization_level": "Q4_K_M"},
    }
]

# Captured from a native Ollama 0.30.7 on the same host, using Metal.
GPU_PAYLOAD = [
    {
        "name": "qwen2.5:0.5b",
        "model": "qwen2.5:0.5b",
        "size": 928755219,
        "size_vram": 928755219,
        "digest": "a8b0c515",
        "details": {"family": "qwen2", "quantization_level": "Q4_K_M"},
    }
]


class TestTheFourStates:
    def test_nothing_loaded_is_unknown_not_cpu(self) -> None:
        """The state that must never be guessed."""
        from app.services.llm_runtime import classify

        report = classify([])

        assert report.placement == "unknown"
        assert "unloads" in report.detail or "not loaded" in report.detail.lower()
        # No fabricated measurement travels with a non-answer.
        assert report.vram_bytes is None
        assert "vram_bytes" not in report.as_dict()

    def test_a_containerised_model_on_a_mac_is_cpu(self) -> None:
        from app.services.llm_runtime import classify

        report = classify(CPU_PAYLOAD)

        assert report.placement == "cpu"
        assert report.vram_bytes == 0
        assert report.total_bytes == 820601088
        assert "CPU" in report.detail

    def test_a_native_metal_model_is_gpu(self) -> None:
        from app.services.llm_runtime import classify

        report = classify(GPU_PAYLOAD)

        assert report.placement == "gpu"
        assert report.vram_bytes == 928755219
        assert "GPU" in report.detail

    def test_a_split_model_is_partial_and_says_how_much(self) -> None:
        """A card too small for the layer count is the common half-measure, and
        reporting it as `gpu` would explain neither the latency nor the fix."""
        from app.services.llm_runtime import classify

        report = classify([{"name": "m", "size": 1000, "size_vram": 400}])

        assert report.placement == "partial"
        assert "40%" in report.detail


class TestItDegradesHonestly:
    def test_a_missing_size_vram_is_unknown_not_cpu(self) -> None:
        """Guards against a future Ollama renaming or dropping the field.

        Defaulting a missing key to `0` would silently report every deployment
        as CPU, which is the shape of wrongness that is hardest to notice: it
        looks like a measurement.
        """
        from app.services.llm_runtime import classify

        report = classify([{"name": "m", "size": 1000}])

        assert report.placement == "unknown"
        assert report.vram_bytes is None

    def test_the_largest_resident_model_is_the_one_reported(self) -> None:
        """Two models can be resident. The big one is what a triage will use
        and what a GPU would have to hold."""
        from app.services.llm_runtime import classify

        report = classify(
            [
                {"name": "small", "size": 100, "size_vram": 100},
                {"name": "big", "size": 9000, "size_vram": 0},
            ]
        )

        assert report.model == "big"
        assert report.placement == "cpu"


class TestTheEndpointOffersSomethingToDo:
    @pytest.mark.parametrize("placement", ["cpu", "partial", "unknown"])
    def test_a_cpu_answer_names_all_three_alternatives(self, placement: str) -> None:
        from app.api.v1.endpoints.llm_status import _placement_options

        options = _placement_options(placement)
        joined = " ".join(options)

        assert "make up-gpu" in joined
        assert "make up-host-llm" in joined
        assert "hosted provider" in joined

    def test_unreachable_does_not_read_as_a_fault_when_it_is_not(self) -> None:
        """A deployment on a hosted provider has no Ollama, and telling that
        operator something is broken sends them to debug a service they
        deliberately do not run."""
        from app.api.v1.endpoints.llm_status import _placement_options

        joined = " ".join(_placement_options("unreachable"))

        assert "expected" in joined

    def test_a_gpu_answer_does_not_nag(self) -> None:
        from app.api.v1.endpoints.llm_status import _placement_options

        options = _placement_options("gpu")

        assert not any("make up-gpu" in o for o in options)
