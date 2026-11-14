#!/usr/bin/env python3
"""Refuse `make up-gpu` with a cause, rather than letting Docker refuse it without one.

What this exists to prevent
---------------------------
`infra/compose/docker-compose.gpu.yml` reserves an NVIDIA device for the
bundled Ollama. On a host that cannot provide one, the daemon's answer is:

    Error response from daemon: could not select device driver "nvidia" with
    capabilities: [[gpu]]

That names no cause and no next command. It does not say whether the card, the
driver, the container toolkit or the daemon configuration is the missing piece,
and on a Mac it does not say that no amount of installing will help because
Docker Desktop cannot pass Metal into a Linux container at all.

So this runs first and answers the question the daemon does not: which of the
four things is missing, what installs it, and what to do instead when nothing
will.

Why it probes rather than reads configuration
---------------------------------------------
`docker info` listing `nvidia` under Runtimes is necessary and not sufficient:
the runtime can be registered while the driver is too old for the toolkit, or
while no device is visible to the daemon. The only answer that means anything
is whether a container can actually acquire a GPU, so the last check runs one.
It is a 4 MB image and a few seconds, which is cheaper than a failed stack
start.

Usage::

    python3 scripts/check_gpu_runtime.py            # verdict
    python3 scripts/check_gpu_runtime.py --self-test
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import self_test_if_requested  # noqa: E402

#: Small and already common on a developer machine. `busybox` would be smaller
#: but carries no CUDA stack, so it cannot answer the question that matters.
_PROBE_IMAGE = "nvidia/cuda:12.4.1-base-ubuntu22.04"

_APPLE_SILICON_ADVICE = """
This is an Apple Silicon Mac, and `make up-gpu` cannot help here.

Docker Desktop does not pass the Metal GPU into a Linux container. There is no
setting, driver or toolkit that changes this -- a container on this machine is
CPU-only whatever the compose file reserves.

What does work is running Ollama natively, where it uses Metal, and pointing
the stack at it:

    brew install ollama
    OLLAMA_HOST=0.0.0.0 ollama serve          # in its own terminal
    ollama pull llama3.2:3b-instruct-q4_K_M
    make up-host-llm

`make up` also remains correct: the bundled model runs on CPU and triage works,
just more slowly.
""".strip()

_NO_TOOLKIT_ADVICE = """
Install the NVIDIA Container Toolkit, which is what lets the daemon hand a GPU
to a container:

    https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html

On Debian/Ubuntu that is roughly:

    sudo apt-get install -y nvidia-container-toolkit
    sudo nvidia-ctk runtime configure --runtime=docker
    sudo systemctl restart docker

Then run `make up-gpu` again.

If you would rather not install it, `make up` runs the same model on CPU, and
`make up-host-llm` uses an Ollama you run outside Docker.
""".strip()


class Result:
    """One check's outcome, with the advice that belongs to it."""

    def __init__(self, ok: bool, detail: str, advice: str = "") -> None:
        self.ok = ok
        self.detail = detail
        self.advice = advice


def check_platform() -> Result:
    """Apple Silicon is a refusal, not a missing dependency."""
    if platform.system() == "Darwin":
        if platform.machine() in {"arm64", "aarch64"}:
            return Result(False, "Apple Silicon: Docker cannot pass Metal to a container", _APPLE_SILICON_ADVICE)
        return Result(
            False,
            "macOS on Intel: Docker Desktop exposes no GPU to Linux containers",
            _APPLE_SILICON_ADVICE,
        )
    return Result(True, f"{platform.system()} {platform.machine()}")


def _docker_info() -> dict:
    if not shutil.which("docker"):
        return {}
    try:
        done = subprocess.run(
            ["docker", "info", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if done.returncode != 0:
        return {}
    try:
        return json.loads(done.stdout or "{}")
    except json.JSONDecodeError:
        return {}


def check_daemon_runtime() -> Result:
    """Is `nvidia` registered as a runtime with the daemon?

    Necessary, not sufficient -- see the module docstring. A registered runtime
    with a too-old driver still fails at container start.
    """
    info = _docker_info()
    if not info:
        return Result(
            False,
            "could not read `docker info`",
            "Docker is not running, or this user cannot reach its socket. Start Docker and retry.",
        )
    runtimes = info.get("Runtimes") or {}
    if "nvidia" not in runtimes:
        return Result(
            False,
            f"the Docker daemon has no `nvidia` runtime (it has: {', '.join(sorted(runtimes)) or 'none'})",
            _NO_TOOLKIT_ADVICE,
        )
    return Result(True, "the daemon has an `nvidia` runtime registered")


def check_container_can_acquire(skip: bool = False) -> Result:
    """The only check whose answer means anything: run one.

    `docker info` can list the runtime while the driver is too old, or while
    the daemon sees no device. This asks the question the stack will ask.
    """
    if skip:
        return Result(True, "skipped (--no-probe)")
    try:
        done = subprocess.run(
            ["docker", "run", "--rm", "--gpus", "all", _PROBE_IMAGE, "nvidia-smi", "-L"],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return Result(
            False,
            "the probe container did not finish within 180s",
            "The image may still be downloading. Re-run, or pass --no-probe to skip this check.",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return Result(False, f"could not run the probe container ({type(exc).__name__}: {exc})", _NO_TOOLKIT_ADVICE)

    if done.returncode != 0:
        tail = (done.stderr or done.stdout or "").strip().splitlines()
        reason = tail[-1][:300] if tail else "no output"
        return Result(
            False,
            f"a container could not acquire a GPU: {reason}",
            _NO_TOOLKIT_ADVICE,
        )

    devices = [ln for ln in (done.stdout or "").splitlines() if ln.strip().startswith("GPU ")]
    if not devices:
        return Result(
            False,
            "the probe ran but reported no devices",
            "The toolkit is installed and the daemon sees no GPU. Check `nvidia-smi` on the host.",
        )
    return Result(True, f"{len(devices)} device(s): {devices[0].strip()[:80]}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--no-probe",
        action="store_true",
        help="Skip the container probe. Faster, and answers a weaker question.",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    checks = [
        ("host platform", check_platform()),
    ]
    if checks[-1][1].ok:
        checks.append(("docker daemon runtime", check_daemon_runtime()))
    if checks[-1][1].ok:
        checks.append(("a container can acquire a GPU", check_container_can_acquire(skip=args.no_probe)))

    print("check_gpu_runtime: can this host give a container an NVIDIA GPU?")
    for label, result in checks:
        print(f"  {'PASS' if result.ok else 'FAIL'}  {label}: {result.detail}")

    failed = next((r for _, r in checks if not r.ok), None)
    if failed is None:
        print("\nOK — `make up-gpu` will work on this host.")
        return 0

    print("\n" + failed.advice)
    return 1


def _self_test() -> int:
    """Prove the refusals fire and say something actionable.

    The platform check is the one that can be exercised deterministically here;
    the daemon and probe checks depend on the host, so they are asserted to
    carry advice rather than to reach a particular verdict.
    """
    checks: list[tuple[str, bool]] = []

    mac = check_platform
    import platform as _p

    real_system, real_machine = _p.system, _p.machine
    try:
        _p.system = lambda: "Darwin"  # type: ignore[assignment]
        _p.machine = lambda: "arm64"  # type: ignore[assignment]
        r = mac()
        checks.append(("apple silicon is refused", not r.ok))
        checks.append(("and the refusal names make up-host-llm", "make up-host-llm" in r.advice))
        checks.append(("and it says metal cannot be passed through", "Metal" in r.advice))

        _p.system = lambda: "Linux"  # type: ignore[assignment]
        _p.machine = lambda: "x86_64"  # type: ignore[assignment]
        checks.append(("linux passes the platform check", mac().ok))
    finally:
        _p.system, _p.machine = real_system, real_machine

    toolkit_advice = _NO_TOOLKIT_ADVICE
    checks.append(("the no-toolkit advice names the install guide", "nvidia-container-toolkit" in toolkit_advice))
    checks.append(("and offers both fallbacks", "make up" in toolkit_advice and "make up-host-llm" in toolkit_advice))

    for label, ok in checks:
        print(f"  {'[ok]' if ok else '[FAIL]'} {label}")
    failed = [label for label, ok in checks if not ok]
    if failed:
        print(f"\ncheck_gpu_runtime.py: self-test FAILED ({len(failed)})")
        return 1
    print("\ncheck_gpu_runtime.py: self-test OK")
    return 0


if __name__ == "__main__":
    self_test_if_requested("check_gpu_runtime.py")
    sys.exit(main())
