"""The GPU reservation is opt-in, and `make up` stays runnable everywhere.

The regression this exists to prevent
-------------------------------------
A contributed change once put an unconditional NVIDIA device reservation on
the `ollama` service in the **base** compose file. On a host without an NVIDIA
GPU and the container toolkit the daemon refuses to start the service at all:

    Error response from daemon: could not select device driver "nvidia" with
    capabilities: [[gpu]]

`make up` is the documented first-run path and CORE ships a model that runs
CPU-only in 8 GB, so that one line takes out first run for every Mac, every
CPU-only Linux box and every CI runner. The first test below is the guard, and
the second is its negative control: an assertion that only ever checked the
base file would also pass against a tree where the overlay had been deleted.

These parse the compose files rather than shelling out to `docker compose`, so
they run on a machine with no Docker at all -- which is where a CI lint job
usually is.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "docker-compose.yml"
GPU_OVERLAY = ROOT / "infra" / "compose" / "docker-compose.gpu.yml"
HOST_LLM_OVERLAY = ROOT / "infra" / "compose" / "docker-compose.host-llm.yml"


class _ComposeLoader(yaml.SafeLoader):
    """PyYAML plus Compose's merge tags.

    Compose 2.24+ understands `!reset` and `!override` on a value, and
    `yaml.safe_load` refuses them with `could not determine a constructor for
    the tag '!reset'`. They are merge *directives* rather than data, so the
    loader keeps the value and drops the tag -- which is the right shape for a
    test asserting on the resulting structure. Tests that care whether the tag
    is present read the raw text instead, because this loader deliberately
    throws that away.
    """


def _drop_tag(loader: yaml.Loader, node: yaml.Node) -> object:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


for _tag in ("!reset", "!override"):
    _ComposeLoader.add_constructor(_tag, _drop_tag)


def _load(path: Path) -> dict:
    assert path.is_file(), f"{path.relative_to(ROOT)} is missing"
    return yaml.load(path.read_text(encoding="utf-8"), Loader=_ComposeLoader) or {}


def _device_reservations(service: dict) -> list:
    return (((service.get("deploy") or {}).get("resources") or {}).get("reservations") or {}).get("devices") or []


class TestTheBaseFileStaysRunnableWithoutAGpu:
    def test_no_service_reserves_a_device(self) -> None:
        """The guard. Any device reservation here is a host requirement that
        `make up` does not otherwise have."""
        services = _load(BASE).get("services") or {}

        reserving = [name for name, svc in services.items() if _device_reservations(svc or {})]

        assert not reserving, (
            f"{reserving} reserve a device in the base compose file. That makes `make up` fail on "
            "any host without the matching driver, which is most of them. Put it in "
            "infra/compose/docker-compose.gpu.yml instead."
        )

    def test_no_service_pins_an_nvidia_runtime(self) -> None:
        """The other spelling of the same mistake."""
        services = _load(BASE).get("services") or {}

        pinned = [n for n, s in services.items() if (s or {}).get("runtime") == "nvidia"]

        assert not pinned, f"{pinned} pin runtime: nvidia in the base file"


class TestTheGpuOverlayDoesTheOppositeThing:
    """The negative control. Without this, deleting the overlay would leave the
    guard above passing and the feature gone."""

    def test_it_reserves_an_nvidia_device_for_ollama(self) -> None:
        services = _load(GPU_OVERLAY).get("services") or {}

        devices = _device_reservations(services.get("ollama") or {})

        assert devices, "the GPU overlay reserves nothing"
        assert any(d.get("driver") == "nvidia" for d in devices)
        assert any("gpu" in (d.get("capabilities") or []) for d in devices)

    def test_it_touches_only_ollama(self) -> None:
        """An overlay that quietly changed other services would be a second
        deployment shape nobody reviewed."""
        services = _load(GPU_OVERLAY).get("services") or {}

        assert set(services) == {"ollama"}, f"the GPU overlay also changes {sorted(set(services) - {'ollama'})}"


class TestTheHostLlmOverlayStopsTheBundledOne:
    def test_ollama_and_its_puller_move_into_a_profile(self) -> None:
        """A service with a profile is not started unless the profile is named,
        which is how the bundled pair is skipped without deleting it."""
        services = _load(HOST_LLM_OVERLAY).get("services") or {}

        for name in ("ollama", "ollama-pull"):
            assert (services.get(name) or {}).get("profiles"), f"{name} is still started by default"

    def test_litellm_stops_waiting_for_a_puller_that_will_not_run(self) -> None:
        """`!reset` and not an empty mapping: a plain override *merges*, so it
        can add a dependency and cannot remove one. Without this the gateway
        waits forever on a one-shot that never starts.

        Read from the raw text because PyYAML does not keep the compose tag.
        """
        text = HOST_LLM_OVERLAY.read_text(encoding="utf-8")

        assert "depends_on: !reset" in text, "litellm still depends on the bundled ollama-pull, which this overlay does not start"

    def test_the_gateway_is_pointed_at_the_host(self) -> None:
        services = _load(HOST_LLM_OVERLAY).get("services") or {}
        env = (services.get("litellm") or {}).get("environment") or {}

        assert "host.docker.internal" in str(env.get("AISOC_LLM_API_BASE", ""))

    @pytest.mark.parametrize("service", ["litellm", "api"])
    def test_linux_can_resolve_the_host_address(self, service: str) -> None:
        """Docker Desktop provides `host.docker.internal` and Linux does not,
        so without `extra_hosts` this works on a Mac and fails on a server --
        which is the worst place for it to fail, because the Mac is where it
        would have been tested."""
        services = _load(HOST_LLM_OVERLAY).get("services") or {}
        hosts = (services.get(service) or {}).get("extra_hosts") or []

        assert any("host.docker.internal" in str(h) and "host-gateway" in str(h) for h in hosts), f"{service} has no host-gateway mapping"


class TestTheMakefileWiresThemUp:
    def test_up_gpu_runs_the_preflight_before_compose(self) -> None:
        """The whole point of the preflight is to replace the daemon's
        `could not select device driver` with something actionable. Running it
        after compose would be decoration."""
        text = (ROOT / "Makefile").read_text(encoding="utf-8")

        line = next((ln for ln in text.splitlines() if ln.startswith("up-gpu:")), "")
        assert "_gpu_preflight" in line, "up-gpu does not depend on the preflight"
        assert "_gpu_preflight" in text.split("up-gpu:")[1].split("\n")[0]

    def test_both_targets_use_their_overlay(self) -> None:
        text = (ROOT / "Makefile").read_text(encoding="utf-8")

        assert "infra/compose/docker-compose.gpu.yml" in text
        assert "infra/compose/docker-compose.host-llm.yml" in text
