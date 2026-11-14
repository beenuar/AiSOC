#!/usr/bin/env python3
"""A chart that installs CORE, a restore that covers the backup, one leader.

Depth plan 4.5 / parity 6.8. Three claims, each of which was false in a
way nothing could see.

**The chart did not install CORE.** `infra/helm/aisoc/values.yaml`
declared seven application services. CORE in `docker-compose.yml` is
sixteen, and the chart was missing response execution, every connector
poll, the threat-intel store, the LLM gateway, the local model and the
vector store. `helm install` produced a deployment that could not act,
could not collect and could not triage — and reported success, because
nothing compared the two files.

**A restore that does not cover the backup is a backup nobody can use.**
The two scripts are a pair, maintained separately, and a component added
to one and not the other is discovered during an incident. They happen to
agree today; nothing held them that way.

**Two scheduler replicas each polled every vendor.** The scheduler adds
one job per connector instance in process, so two replicas doubled every
vendor's call volume — and on a rate-limited API the second replica's
poll is the one that gets throttled, which looks exactly like expired
credentials.

Read statically rather than by installing anything. `helm` is not on a
lint runner and a Kubernetes cluster certainly is not, and a gate that
skips when it cannot find a toolchain is a gate that silently stops
checking.

Usage:
    python3 scripts/check_deployment_completeness.py
    python3 scripts/check_deployment_completeness.py --self-test
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import TREE_SHAPES, refuses_an_empty_tree, repo_root  # noqa: E402

REPO_ROOT = repo_root()

COMPOSE = Path("docker-compose.yml")
VALUES = Path("infra/helm/aisoc/values.yaml")
TEMPLATE_DIR = Path("infra/helm/aisoc/templates")
BACKUP_SH = Path("scripts/backup.sh")
RESTORE_SH = Path("scripts/restore.sh")
LEASE_PY = Path("services/connectors/app/leader_lease.py")
SCHEDULER_PY = Path("services/connectors/app/scheduler.py")
LEASE_MIGRATION = Path("services/api/migrations/115_scheduler_leases.sql")

#: Compose services the chart is not expected to render, with the reason.
#:
#: Each is a deliberate exclusion rather than an omission, and naming them
#: here is what stops this gate becoming a list someone appends to
#: whenever it fails.
CHART_EXEMPT: dict[str, str] = {
    "postgres": "a Bitnami subchart dependency, not a template of ours",
    "redis": "a Bitnami subchart dependency, not a template of ours",
    "zookeeper": "the chart's Kafka runs KRaft and needs no ZooKeeper",
    "ollama-pull": "a one-shot model pull; the StatefulSet's startup probe covers the same wait",
}

#: Workload components the chart renders that are not CORE compose
#: services. Also deliberate: these are `full`-profile or optional
#: surfaces the chart has always shipped.
COMPOSE_EXEMPT: dict[str, str] = {
    "alert-fusion": "the chart's name for the fusion worker, which compose calls `fusion`",
    "enrichment": "a full-profile service the chart has always shipped",
    "ueba": "a full-profile service with its own template and values block",
    "honeytokens": "a full-profile service with its own template",
    "purple-team": "a full-profile service with its own template",
    "backup": "a CronJob, not a long-running service",
    "kafka-topics": "a one-shot topic-creation Job",
    "migrations": (
        "a one-shot pre-upgrade hook Job behind `runMigrations`, with no compose "
        "counterpart by design: compose applies the chain through `make upgrade` on "
        "the host rather than as a service"
    ),
    "core-api": "an optional second API surface with its own template and values block",
    "kafka": "the chart ships its own StatefulSet; compose runs the Confluent image",
    "mcp": (
        "an opt-in surface on both sides: compose gates it behind `profiles: [mcp]` and the "
        "chart ships it `enabled: false` with an empty image repository the template `required`s "
        "— depth 9.1 (#1304) added both halves before 4.5's gate (#1326) existed, and the two "
        "merged in one train"
    ),
}

#: The compose service each chart component corresponds to where the two
#: use different names. Stated rather than guessed: a fuzzy match would
#: silently pair `fusion` with `alert-fusion` today and with something
#: else after a rename.
NAME_MAP = {"ingest-worker": "ingest", "fusion": "alert-fusion"}


def _read(root: Path, rel: Path) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8")
    except OSError:
        return ""


def core_compose_services(root: Path) -> set[str]:
    """Long-running CORE services: no `profiles:` key, and not one-shot."""
    raw = _read(root, COMPOSE)
    if not raw:
        return set()
    try:
        parsed = yaml.safe_load(raw) or {}
    except yaml.YAMLError:
        return set()
    out: set[str] = set()
    for name, body in (parsed.get("services") or {}).items():
        if isinstance(body, dict) and body.get("profiles"):
            continue
        out.add(name)
    return out


def chart_components(root: Path) -> set[str]:
    """Every workload the chart renders, from values and from templates.

    Values first, because `.Values.services` drives the generic
    Deployment template. Templates after, because the services that do
    not fit that loop — the ones with volumes or third-party tags — have
    their own files, and a gate that only read the values map would call
    them missing.
    """
    components: set[str] = set()
    raw = _read(root, VALUES)
    if raw:
        try:
            values = yaml.safe_load(raw) or {}
        except yaml.YAMLError:
            values = {}
        components.update((values.get("services") or {}).keys())

    directory = root / TEMPLATE_DIR
    if directory.is_dir():
        for path in sorted(directory.glob("*.yaml")):
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in re.finditer(r"app\.kubernetes\.io/component:\s*([a-z0-9-]+)", text):
                components.add(match.group(1))
    return components


def _shell_functions(source: str, prefix: str) -> set[str]:
    return {m.group(1) for m in re.finditer(rf"^{prefix}_([a-z0-9_]+)\(\)", source, flags=re.M)}


def evaluate(root: Path) -> list[str]:
    failures: list[str] = []

    # 1. The chart installs CORE.
    core = core_compose_services(root)
    if not core:
        failures.append(f"{COMPOSE} has no profile-less services, so there is no CORE set to compare against.")
    else:
        rendered = chart_components(root)
        if not rendered:
            failures.append(f"{VALUES} and {TEMPLATE_DIR} render no workloads at all.")
        missing = sorted(
            name for name in core if name not in CHART_EXEMPT and NAME_MAP.get(name, name) not in rendered and name not in rendered
        )
        for name in missing:
            failures.append(
                f"{name} is a CORE service in {COMPOSE} and the chart renders no workload for it. "
                f"`helm install` would bring up a deployment missing it and report success."
            )
        unexplained = sorted(
            name
            for name in rendered
            if name not in COMPOSE_EXEMPT
            and name not in core
            and name not in set(NAME_MAP.values())
            and name not in {NAME_MAP.get(c, c) for c in core}
        )
        for name in unexplained:
            failures.append(
                f"the chart renders {name}, which is neither a CORE compose service nor in the exempt "
                f"list with a reason. Add it to COMPOSE_EXEMPT saying why, or the two descriptions of "
                f"the platform have drifted."
            )

    # 2. Restore covers what backup covers.
    backup = _shell_functions(_read(root, BACKUP_SH), "backup")
    restore = _shell_functions(_read(root, RESTORE_SH), "restore")
    if not backup:
        failures.append(f"{BACKUP_SH} declares no backup_* component functions, so nothing is being backed up.")
    if not restore:
        failures.append(f"{RESTORE_SH} declares no restore_* component functions.")
    for component in sorted(backup - restore):
        failures.append(
            f"{BACKUP_SH} backs up {component!r} and {RESTORE_SH} cannot restore it. A backup nobody can "
            f"restore is discovered during an incident."
        )
    for component in sorted(restore - backup):
        failures.append(f"{RESTORE_SH} restores {component!r} and {BACKUP_SH} never backs it up, so the restore path has nothing to read.")

    # 3. One scheduler leads.
    lease = _read(root, LEASE_PY)
    if not lease:
        failures.append(
            f"{LEASE_PY} is missing, so two connector replicas each run every poll job and every vendor is polled twice on every cycle."
        )
    else:
        if "expires_at < now()" not in lease:
            failures.append(
                f"{LEASE_PY} acquires without checking the expiry in the same statement. Postgres has "
                f"nothing to re-evaluate after the row lock, and two replicas both become leader."
            )
        if "fenced_at" not in lease:
            failures.append(
                f"{LEASE_PY} records no term, so a log cannot say which generation of the leader wrote a line after a partition."
            )

    scheduler = _read(root, SCHEDULER_PY)
    if not scheduler:
        failures.append(f"{SCHEDULER_PY} is missing.")
    else:
        if "_is_leader" not in scheduler:
            failures.append(
                f"{SCHEDULER_PY} never asks whether it leads, so the lease is taken and ignored — which is "
                f"the same double-poll with a table to prove it was avoidable."
            )
        if "_remove_all_poll_jobs" not in scheduler:
            failures.append(
                f"{SCHEDULER_PY} does not drop its poll jobs when leadership is lost. A replica that "
                f"stops adding jobs but keeps the ones it had is still polling every vendor."
            )

    if not (root / LEASE_MIGRATION).is_file():
        failures.append(
            f"{LEASE_MIGRATION} is missing, so scheduler_leases exists in code and in no database and every acquisition raises."
        )

    return failures


_INJECTIONS = (
    ("CHART_MISSING_SERVICE", "a CORE service the chart does not render"),
    ("CHART_EXTRA_SERVICE", "a chart workload that is in neither compose nor the exempt list"),
    ("RESTORE_GAP", "a component backed up and not restorable"),
    ("BACKUP_GAP", "a component restorable and never backed up"),
    ("NO_LEASE", "a missing lease module"),
    ("RACY_ACQUIRE", "an acquire that does not re-check the expiry"),
    ("LEASE_IGNORED", "a scheduler that takes the lease and ignores it"),
    ("FOLLOWER_KEEPS_JOBS", "a follower that keeps the jobs it already had"),
    ("NO_LEASE_TABLE", "a lease table that exists in code and in no database"),
)


def _inject(tmp: Path, kind: str) -> None:
    values = tmp / VALUES
    if kind == "CHART_MISSING_SERVICE":
        text = values.read_text(encoding="utf-8")
        values.write_text(text.replace("\n  connectors:\n", "\n  connectors_disabled:\n", 1), encoding="utf-8")
    elif kind == "CHART_EXTRA_SERVICE":
        text = values.read_text(encoding="utf-8")
        values.write_text(
            text.replace("\n  actions:\n", "\n  invented-service:\n    image: {}\n  actions:\n", 1),
            encoding="utf-8",
        )
    elif kind == "RESTORE_GAP":
        path = tmp / RESTORE_SH
        path.write_text(path.read_text(encoding="utf-8").replace("restore_qdrant()", "_disabled_qdrant()", 1), encoding="utf-8")
    elif kind == "BACKUP_GAP":
        path = tmp / BACKUP_SH
        path.write_text(path.read_text(encoding="utf-8").replace("backup_qdrant()", "_disabled_qdrant()", 1), encoding="utf-8")
    elif kind == "NO_LEASE":
        (tmp / LEASE_PY).unlink(missing_ok=True)
    elif kind == "RACY_ACQUIRE":
        path = tmp / LEASE_PY
        path.write_text(path.read_text(encoding="utf-8").replace("expires_at < now()", "true"), encoding="utf-8")
    elif kind == "LEASE_IGNORED":
        path = tmp / SCHEDULER_PY
        path.write_text(path.read_text(encoding="utf-8").replace("_is_leader", "_unused_leader_check"), encoding="utf-8")
    elif kind == "FOLLOWER_KEEPS_JOBS":
        path = tmp / SCHEDULER_PY
        path.write_text(path.read_text(encoding="utf-8").replace("_remove_all_poll_jobs", "_noop_drop"), encoding="utf-8")
    elif kind == "NO_LEASE_TABLE":
        (tmp / LEASE_MIGRATION).unlink(missing_ok=True)
    else:  # pragma: no cover
        raise AssertionError(f"unknown injection {kind}")


def _self_test() -> int:
    print(f"{Path(__file__).name} self-test\n")
    results: list[tuple[str, bool]] = []

    clean = evaluate(REPO_ROOT)
    results.append(("reports the real tree clean", not clean))
    for line in clean[:6]:
        print(f"        unexpected: {line}")

    for kind, label in _INJECTIONS:
        tmp = Path(tempfile.mkdtemp(prefix="deployment-completeness-"))
        try:
            for rel in (COMPOSE, VALUES, BACKUP_SH, RESTORE_SH, LEASE_PY, SCHEDULER_PY, LEASE_MIGRATION):
                source = REPO_ROOT / rel
                if source.is_file():
                    (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, tmp / rel)
            if (REPO_ROOT / TEMPLATE_DIR).is_dir():
                shutil.copytree(REPO_ROOT / TEMPLATE_DIR, tmp / TEMPLATE_DIR)
            _inject(tmp, kind)
            results.append((f"catches {label}", bool(evaluate(tmp))))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    details: list[str] = []
    for shape in TREE_SHAPES:
        refused, detail = refuses_an_empty_tree(Path(__file__).name, shape=shape)
        results.append((f"refuses a {shape} tree rather than reporting it clean", refused))
        details.append(f"{shape}: {detail}")

    ok = True
    for description, passed in results:
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")
    for line in "\n".join(details).splitlines():
        print(f"        {line}")
    print()
    if not ok:
        print(f"{Path(__file__).name}: self-test FAILED")
        return 1
    print(f"{Path(__file__).name}: self-test OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="inject one violation per rule and require each to be caught")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()

    if not (REPO_ROOT / COMPOSE).is_file():
        print(f"check_deployment_completeness: {COMPOSE} is not there — nothing to render a verdict about.", file=sys.stderr)
        return 2

    failures = evaluate(REPO_ROOT)
    if failures:
        print("Deployment completeness (depth plan 4.5 / parity 6.8) is incomplete:\n", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        print(f"\n{len(failures)} problem(s).", file=sys.stderr)
        return 1

    core = core_compose_services(REPO_ROOT)
    backup = _shell_functions(_read(REPO_ROOT, BACKUP_SH), "backup")
    print(
        f"OK — the chart renders a workload for every one of the {len(core)} CORE services "
        f"(or names why not), restore covers all {len(backup)} components backup writes, and the "
        f"connector scheduler elects one leader with a predicate two replicas cannot both satisfy."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
