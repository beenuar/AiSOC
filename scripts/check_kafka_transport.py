#!/usr/bin/env python3
"""Every Kafka client resolves its transport, and production refuses cleartext.

Seven Python services, three Go files and one TypeScript service each
constructed a Kafka client, and not one passed a security protocol — so all
eleven spoke `PLAINTEXT`, which is the default in aiokafka, kafka-go and
kafkajs alike. The spine carries normalized security telemetry: raw event
bodies, usernames, hostnames, command lines, `alerts.entities`. The
commercial deployment made it concrete rather than theoretical, running MSK
as `TLS_PLAINTEXT`, unauthenticated, with every service pointed at the
plaintext `:9092` bootstrap while the TLS listener sat unused.

Checked in two directions, because one is not enough:

1. **Every construction site passes the resolver's output.** A site that
   omits it gets the library default, which is the defect.
2. **The resolver refuses cleartext in a protected environment.** Exercised
   by calling it, not by reading it — a resolver that returns a refusal
   nobody raises is the shape this whole batch keeps finding.

The second direction is the one that matters. A gate that only checked
call sites would pass a tree where every site dutifully calls a resolver
that always answers `PLAINTEXT`.
"""

from __future__ import annotations

import argparse
import ast
import pathlib
import re
import sys
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

#: The Python client classes.
PY_CLIENTS = ("AIOKafkaConsumer", "AIOKafkaProducer")

#: The call every Python site must make.
PY_RESOLVER = "kafka_client_kwargs"

#: Go and TypeScript sites, with the token that proves the transport was set.
#: Listed explicitly because each ecosystem spells it differently and a
#: generic search would either miss one or match a comment.
NON_PYTHON_SITES: dict[str, tuple[str, ...]] = {
    "services/ingest/internal/publisher/publisher.go": ("kafkatls.Resolve(",),
    "services/ingest/internal/graph_ws/kafka_source.go": ("kafkatls.Resolve(",),
    "services/realtime/src/index.ts": ("resolveKafkaTransport(",),
}


@dataclass
class Report:
    unwired: list[str] = field(default_factory=list)
    missing_non_python: list[str] = field(default_factory=list)
    sites_seen: int = 0
    files_seen: int = 0
    refusal_works: bool = False
    refusal_detail: str = ""


def _python_sites(root: pathlib.Path) -> list[tuple[str, int, bool]]:
    """Every aiokafka construction, and whether it passes the resolver."""
    out: list[tuple[str, int, bool]] = []
    services = root / "services"
    if not services.is_dir():
        return out
    for path in sorted(services.rglob("*.py")):
        if "test" in path.parts or path.name.startswith("test_"):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not any(client + "(" in source for client in PY_CLIENTS):
            continue
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            if name not in PY_CLIENTS:
                continue
            # The resolver arrives as `**kafka_client_kwargs()`, which is a
            # keyword with `arg=None`. Checked structurally rather than by
            # searching the line, so a mention in a comment cannot satisfy it.
            wired = any(
                keyword.arg is None
                and isinstance(keyword.value, ast.Call)
                and getattr(keyword.value.func, "id", getattr(keyword.value.func, "attr", "")) == PY_RESOLVER
                for keyword in node.keywords
            )
            out.append((path.relative_to(root).as_posix(), node.lineno, wired))
    return out


def _check_refusal(root: pathlib.Path) -> tuple[bool, str]:
    """Call the resolver and require it to refuse a cleartext production run.

    Loaded from the canonical copy by path. Importing it as a package would
    need the service on `sys.path`, and the question here is about the file
    this repository ships.
    """
    import importlib.util

    source = root / "services" / "fusion" / "app" / "core" / "kafka_security.py"
    if not source.is_file():
        return False, f"the canonical resolver is missing at {source}"

    spec = importlib.util.spec_from_file_location("_aisoc_kafka_security_probe", source)
    if spec is None or spec.loader is None:
        return False, "the resolver could not be loaded"
    module = importlib.util.module_from_spec(spec)
    # Registered before execution because `@dataclass` resolves annotations
    # through `sys.modules[cls.__module__]`, and a module loaded by path that
    # is not registered has no entry there.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    # Direction one: production + plaintext must raise.
    try:
        module.resolve_transport(environment="production", protocol="PLAINTEXT")
    except module.KafkaTransportError:
        pass
    except Exception as exc:  # noqa: BLE001 - any other failure is still a failure
        return False, f"production + PLAINTEXT raised {type(exc).__name__}, not KafkaTransportError"
    else:
        return False, "production + PLAINTEXT was accepted; the refusal does not fire"

    # Direction two, so this cannot pass by refusing everything.
    try:
        transport = module.resolve_transport(environment="development", protocol="PLAINTEXT")
    except Exception as exc:  # noqa: BLE001
        return False, f"development + PLAINTEXT was refused ({exc}); local compose has no broker TLS"
    if transport.protocol != "PLAINTEXT":
        return False, f"development resolved to {transport.protocol}, not PLAINTEXT"

    # Direction three: an unknown protocol is a refusal, not a fallback.
    try:
        module.resolve_transport(environment="development", protocol="TLS")
    except module.KafkaTransportError:
        pass
    else:
        return False, "an unknown protocol was accepted; the fallback is plaintext"

    return True, "refuses cleartext in production, allows it in development, refuses a typo"


def inspect(root: pathlib.Path) -> Report:
    report = Report()
    sites = _python_sites(root)
    report.sites_seen = len(sites)
    report.files_seen = len({s[0] for s in sites})
    report.unwired = [f"{path}:{line}" for path, line, wired in sites if not wired]

    for rel, tokens in NON_PYTHON_SITES.items():
        path = root / rel
        if not path.is_file():
            report.missing_non_python.append(f"{rel} (file not found)")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        # Comments stripped first, so a note about TLS cannot satisfy the check.
        stripped = re.sub(r"(?m)^\s*(//|#).*$", "", text)
        if not any(token in stripped for token in tokens):
            report.missing_non_python.append(f"{rel} (no {' or '.join(tokens)})")

    report.refusal_works, report.refusal_detail = _check_refusal(root)
    return report


def _verdict(report: Report) -> int:
    if report.sites_seen == 0:
        print(
            "check_kafka_transport: no aiokafka construction found anywhere — refusing to report a tree with nothing in it as clean",
            file=sys.stderr,
        )
        return 2

    failed = False
    if report.unwired:
        print(
            f"check_kafka_transport: {len(report.unwired)} Kafka client(s) do not resolve a "
            "transport, so they take the library default, which is PLAINTEXT:",
            file=sys.stderr,
        )
        for site in report.unwired:
            print(f"  {site}", file=sys.stderr)
        failed = True

    if report.missing_non_python:
        print("check_kafka_transport: non-Python client(s) with no transport:", file=sys.stderr)
        for site in report.missing_non_python:
            print(f"  {site}", file=sys.stderr)
        failed = True

    if not report.refusal_works:
        print(
            f"check_kafka_transport: the resolver itself is wrong — {report.refusal_detail}",
            file=sys.stderr,
        )
        failed = True

    if failed:
        return 1

    print(
        f"check_kafka_transport: OK — {report.sites_seen} Python client(s) across "
        f"{report.files_seen} module(s) plus {len(NON_PYTHON_SITES)} non-Python site(s) "
        f"resolve a transport, and the resolver {report.refusal_detail}."
    )
    return 0


# ── Self-test ───────────────────────────────────────────────────────────────


def self_test() -> int:
    import importlib.util
    import tempfile

    root = repo_root()
    extra: list[tuple[str, bool]] = []

    source = root / "services" / "fusion" / "app" / "core" / "kafka_security.py"
    spec = importlib.util.spec_from_file_location("_aisoc_kafka_probe", source)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules[spec.name] = module  # type: ignore[union-attr]
    spec.loader.exec_module(module)  # type: ignore[union-attr]

    def case(description: str, fn) -> None:
        try:
            extra.append((description, bool(fn())))
        except Exception as exc:  # noqa: BLE001
            extra.append((f"{description} — raised {exc}", False))

    case(
        "production + PLAINTEXT is refused",
        lambda: _raises(module, environment="production", protocol="PLAINTEXT"),
    )
    case(
        "staging + SASL_PLAINTEXT is refused — cleartext with a password is still cleartext",
        lambda: _raises(module, environment="staging", protocol="SASL_PLAINTEXT"),
    )
    case(
        "development + PLAINTEXT is allowed — local compose has no broker certificate",
        lambda: module.resolve_transport(environment="development", protocol="PLAINTEXT").protocol == "PLAINTEXT",
    )
    case(
        "an unknown protocol is refused, never silently defaulted",
        lambda: _raises(module, environment="development", protocol="TLS"),
    )
    case(
        "SASL without a mechanism is refused",
        lambda: _raises(module, environment="development", protocol="SASL_SSL"),
    )
    case(
        "the cleartext kwargs are explicit, so a chosen plaintext is distinguishable from a forgotten one",
        lambda: (
            module.resolve_transport(environment="development", protocol="PLAINTEXT").client_kwargs().get("security_protocol")
            == "PLAINTEXT"
        ),
    )

    # And the detector itself, in both directions.
    with tempfile.TemporaryDirectory(prefix="aisoc-kafka-gate-") as tmp:
        base = pathlib.Path(tmp) / "services" / "probe" / "app"
        base.mkdir(parents=True)
        (base / "unwired.py").write_text(
            "from aiokafka import AIOKafkaConsumer\ndef go():\n    return AIOKafkaConsumer('t', bootstrap_servers='b')\n",
            encoding="utf-8",
        )
        found = _python_sites(pathlib.Path(tmp))
        # `bool(...)` rather than the bare expression: `found and ...` is the
        # list itself when it is empty, which types as `list | bool` and is
        # also the wrong answer — an empty list is falsy, so the case would
        # have reported "did not detect" where the truth is "found nothing
        # to look at".
        extra.append(("detects a client that passes no transport", bool(found) and not found[0][2]))
        (base / "unwired.py").write_text(
            "from aiokafka import AIOKafkaConsumer\n"
            "from app.core.kafka_security import kafka_client_kwargs\n"
            "def go():\n    return AIOKafkaConsumer('t', **kafka_client_kwargs())\n",
            encoding="utf-8",
        )
        found = _python_sites(pathlib.Path(tmp))
        extra.append(("accepts a client that does", bool(found) and found[0][2]))

    return self_test_main(pathlib.Path(__file__).name, ["--check"], extra)


def _raises(module, **kwargs) -> bool:
    try:
        module.resolve_transport(**kwargs)
    except module.KafkaTransportError:
        return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", dest="self_test")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    return _verdict(inspect(repo_root()))


if __name__ == "__main__":
    raise SystemExit(main())
