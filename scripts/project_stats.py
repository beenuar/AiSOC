#!/usr/bin/env python3
"""Recount every figure the README publishes, from the tree.

A number typed into a README is a number that goes stale silently. This
script is the single source for the project's quantitative claims, and
`--check` fails when the README disagrees with it — so a figure cannot drift
without a red build.

Each figure counts the thing the claim is *about*, which is not always the
obvious file count:

* **Connectors** come from the registry the service actually loads, not from
  the number of files in the connectors directory. A module that is not
  registered is not a connector a user can configure.
* **Detections** count what the *engine* loads. `detections/*.yaml` is a
  generated projection and includes thousands of quarantined imports the
  engine never evaluates; publishing that number would overstate coverage by
  an order of magnitude.
* **Services** count deployable compose services, split by profile, because
  "19 services" means something very different if 10 of them are optional.

Usage:
    python3 scripts/project_stats.py            # human-readable
    python3 scripts/project_stats.py --json     # machine-readable
    python3 scripts/project_stats.py --check    # fail if README disagrees
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()


def _connectors() -> int | None:
    """Registered connector classes, read from the registry literal."""
    init = ROOT / "services" / "connectors" / "app" / "connectors" / "__init__.py"
    if not init.is_file():
        return None
    text = init.read_text(encoding="utf-8")
    match = re.search(r"_CONNECTOR_CLASSES\s*[:=][^=]*=\s*[\(\[\{](.*?)[\)\]\}]\s*\n", text, re.S)
    if not match:
        return None
    # Count class references, not commas: a trailing comma would inflate it.
    return len(re.findall(r"\b[A-Z]\w*Connector\b", match.group(1)))


def _executable_detections() -> int | None:
    """Rules the fusion engine loads — the only ones that can fire.

    Both compiled rulesets count. The engine reads the native specs and the
    imported rules the Sigma compiler translated and proved fireable, so
    counting one of them reports a number no deployment runs.
    """
    data_dir = ROOT / "services" / "fusion" / "app" / "data"
    total: int | None = None
    for name in ("detection_ruleset.json", "detection_ruleset_imported.json"):
        path = data_dir / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            return None
        rules = data.get("rules") if isinstance(data, dict) else data
        if not isinstance(rules, list):
            return None
        total = len(rules) if total is None else total + len(rules)
    return total


def _threat_anomaly_detections() -> int | None:
    """Rules pairing a threat condition with a depth plan 3.4 baseline score.

    Depth plan 3.5 asks for these to be *"counted as their own family"*, and
    the reason is that the claim is genuinely different. An ordinary
    executable rule fires on a well-formed event of its log source. One of
    these additionally needs a warmed baseline for the principal — so a
    day-one install has the rule and does not yet have the signal, and
    folding them into the headline would overstate what it detects.

    They are a subset of `_executable_detections`, not an addition to it.
    """
    path = ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    rules = data.get("rules") if isinstance(data, dict) else data
    if not isinstance(rules, list):
        return None
    return sum(1 for r in rules if isinstance(r, dict) and r.get("category") == "threat-anomaly")


#: The four groups depth plan 3.6 counts, by the `product` each compiled rule
#: declares. Membership is listed rather than pattern-matched for two
#: reasons: the first depth plan re-derived this figure two ways and got 461
#: and 395, which is what a grouping nobody pinned produces; and a regex over
#: product names would silently absorb every new product into whichever group
#: its spelling resembled.
#:
#: The lists start from that re-derivation's grouping. Additions since are
#: deliberate and named here so a reader can see what moved the figure: `oci`
#: and `digitalocean` are public clouds the tree gained connectors for, and
#: the SaaS list is extended with the sources depth 3.6 names minimums for.
#: Nothing is in two groups and nothing matches by prefix.
SCENARIO_GROUPS: dict[str, frozenset[str]] = {
    "cloud": frozenset({"aws", "azure", "gcp", "kubernetes", "docker", "cloud", "multi-cloud", "oci", "digitalocean"}),
    "identity": frozenset({"identity", "okta", "active-directory", "auth0", "duo", "ping", "keycloak"}),
    "saas": frozenset(
        {
            "google-workspace",
            "m365",
            "slack",
            "email",
            "salesforce",
            "zoom",
            "atlassian",
            "confluence",
            "notion",
            "snowflake",
            "workday",
            "box",
            "dropbox",
            "onepassword",
            "servicenow",
        }
    ),
    "code": frozenset({"github", "gitlab"}),
}

#: Depth plan 3.6's target. The gate below does *not* enforce it — the tree
#: is short of it and a gate asserting a number the tree does not have would
#: simply be red. It enforces a ratchet at the measured figure so the count
#: cannot fall silently, and prints the shortfall every run so the gap is
#: published rather than quietly dropped. Raise `SCENARIO_FLOOR` in the PR
#: that raises the count; never lower it to make a build green.
SCENARIO_TARGET = 800

#: Measured on 2026-11-01 after the depth 2 wave 2 item 2.1 scenario
#: families landed (443 before them).
SCENARIO_FLOOR = 569

#: Windowed rules that declare a category and no product, so nothing can put
#: them in one of the four groups. The windowed ruleset has no `product`
#: field; a translated rule is attributed through the native rule it names in
#: `translated_from`, and these are the natively authored ones that name
#: none. Held so the unclassifiable set cannot grow silently — the honest
#: close is to give the windowed schema a product, which is a change to how
#: those rules are authored and is recorded as open rather than guessed at.
MAX_WINDOWED_UNCLASSIFIED = 26


def _scenario_conditions() -> dict[str, int | dict[str, int]]:
    """Executable cloud, identity, SaaS and code conditions (depth plan 3.6).

    Counts the rules the *engine* loads — both compiled native rulesets, the
    imported Sigma corpus and the windowed ruleset — grouped by the product
    each one declares. Anything outside the four groups (Windows, Linux,
    macOS, EDR, network and so on) is not part of this claim and is reported
    as `other` rather than dropped, so the four numbers and the total the
    headline publishes stay reconcilable.

    Windowed rules carry no `product` of their own: they are translations of
    a native rule and name it in `translated_from`. Their group is resolved
    through that link. One that cannot be resolved counts as `unclassified`
    and is printed — an unknown bucket that quietly passes as zero is the
    defect this repository keeps finding.
    """
    data_dir = ROOT / "services" / "fusion" / "app" / "data"
    by_group = dict.fromkeys(SCENARIO_GROUPS, 0)
    other = 0
    unclassified = 0

    def group_of(product: str | None) -> str | None:
        for name, products in SCENARIO_GROUPS.items():
            if product in products:
                return name
        return None

    product_by_slug: dict[str, str] = {}
    for name in ("detection_ruleset.json", "detection_ruleset_imported.json"):
        path = data_dir / name
        if not path.is_file():
            continue
        try:
            rules = (json.loads(path.read_text(encoding="utf-8")) or {}).get("rules") or []
        except ValueError:
            return {"total": 0, "groups": {}, "other": 0, "unclassified": 0}
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            product = rule.get("product") or None
            if isinstance(rule.get("slug"), str) and isinstance(product, str):
                product_by_slug[rule["slug"]] = product
            group = group_of(product)
            if group is None:
                other += 1
            else:
                by_group[group] += 1

    # A translated windowed rule names the native rule it came from, and that
    # rule is *absent* from the compiled artefact by design — translating it
    # is what retired it. So the product is resolved from the specs, which
    # still hold it, rather than from the artefact, which cannot.
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        from detection_specs_index import all_specs  # noqa: PLC0415 — scripts/ sibling

        for _category, spec in all_specs():
            log_source = spec.get("log_source") or {}
            if isinstance(spec.get("slug"), str) and log_source.get("product"):
                product_by_slug.setdefault(spec["slug"], str(log_source["product"]))
    except Exception:  # noqa: BLE001 — the artefact path above still works without it
        pass

    windowed = data_dir / "windowed_ruleset.json"
    if windowed.is_file():
        try:
            rules = (json.loads(windowed.read_text(encoding="utf-8")) or {}).get("rules") or []
        except ValueError:
            rules = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            origin = rule.get("translated_from")
            product = product_by_slug.get(str(origin)) if origin else None
            if product is None:
                # Natively authored windowed rules declare a category and no
                # product, so there is nothing to group them by. They are
                # counted here and held by a ratchet rather than folded into
                # a group they have not earned — but the number is printed
                # every run, because a bucket nobody can classify must not
                # pass quietly.
                unclassified += 1
                continue
            group = group_of(product)
            if group is None:
                other += 1
            else:
                by_group[group] += 1

    return {
        "total": sum(by_group.values()),
        "groups": by_group,
        "other": other,
        "unclassified": unclassified,
    }


#: Directories under `detections/` holding YAML that is not a detection rule.
#: Kept equal to `detection_truth_table.py`'s `SKIP_DIRS`, because a rule
#: count and a file count published under the same words is how two surfaces
#: come to disagree while both are right.
_NON_RULE_DIRS = {"fixtures", "playbooks"}


def _detection_files_on_disk() -> int:
    """Detection *rules* on disk, including the quarantine.

    Reported alongside the executable count so the gap is visible rather than
    conflated. The two numbers have been published interchangeably before.

    This used to count every YAML under `detections/` and print the result as
    "Detection files on disk", which put 7,016 against the README's 6,991
    under the same label. Both were right and they were counting different
    things: the extra 25 are the standalone response playbooks under
    `detections/playbooks/`, which are not detection rules. The rule count is
    now the one the truth table and the README publish, and the wider file
    count is printed beside it saying what it includes.
    """
    d = ROOT / "detections"
    if not d.is_dir():
        return 0
    return sum(1 for p in d.rglob("*.yaml") if not _NON_RULE_DIRS & set(p.relative_to(d).parts))


def _detection_yaml_files() -> int:
    """Every YAML under detections/, rules and playbooks alike."""
    d = ROOT / "detections"
    return sum(1 for _ in d.rglob("*.yaml")) if d.is_dir() else 0


def _compose_services() -> dict[str, int]:
    """Deployable services, split by profile."""
    try:
        import yaml
    except ImportError:
        return {}
    f = ROOT / "docker-compose.yml"
    if not f.is_file():
        return {}
    doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
    services = doc.get("services") or {}
    # One-shots are excluded, matching `scripts/check_profile_service_counts.py`,
    # which is the gate that holds every published figure to the compose file.
    #
    # This counted them, so it printed "17 core" against the 16 that gate
    # enforces and the README states. Two scripts disagreeing about one
    # number is how a reader learns not to trust either: "long-running
    # services" is the figure the documents publish, and `ollama-pull`
    # fetches the model and exits.
    one_shot = frozenset({"ollama-pull"})
    core = [n for n, svc in services.items() if not (svc or {}).get("profiles") and n not in one_shot]
    resident = [n for n in services if n not in one_shot]
    return {
        "core": len(core),
        "total": len(resident),
        "optional": len(resident) - len(core),
    }


def _claim_gate_rows() -> dict[str, int]:
    """Claim-to-gate matrix rows by status."""
    f = ROOT / "docs" / "audit" / "CLAIM_TO_GATE_MATRIX.md"
    if not f.is_file():
        return {}
    counts = {"GATED": 0, "PARTIAL": 0, "NO GATE": 0}

    # The status column is located by reading the header, not by index.
    # It was hardcoded to cells[3], and when a `Profile` column was
    # inserted ahead of it every row's status became "core" — so this
    # figure read **0 rows, 0 gated** against a real 278 for as long as
    # that column has existed. Nothing caught it because the README does
    # not publish this number, so no comparison existed to fail.
    status_idx: int | None = None
    for line in f.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| ") or line.startswith("| ---"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if status_idx is None:
            if "Status" in cells:
                status_idx = cells.index("Status")
            continue
        if len(cells) <= status_idx:
            continue
        status = cells[status_idx].upper()
        # `GATED (ratchet)` counts as gated; check NO GATE first so the
        # substring "GATE" does not swallow it.
        if "NO GATE" in status:
            counts["NO GATE"] += 1
        elif "PARTIAL" in status:
            counts["PARTIAL"] += 1
        elif "GATED" in status:
            counts["GATED"] += 1
    counts["total"] = counts["GATED"] + counts["PARTIAL"] + counts["NO GATE"]
    return counts


def _python_services() -> int:
    d = ROOT / "services"
    return sum(1 for p in d.iterdir() if p.is_dir() and not p.name.startswith(".")) if d.is_dir() else 0


def collect() -> dict:
    stats: dict = {
        "connectors": _connectors(),
        "detections_executable": _executable_detections(),
        "detections_threat_anomaly": _threat_anomaly_detections(),
        "scenario_conditions": _scenario_conditions(),
        "detections_files_on_disk": _detection_files_on_disk(),
        "detections_yaml_files": _detection_yaml_files(),
        "services_in_repo": _python_services(),
        "compose": _compose_services(),
        "claim_gate": _claim_gate_rows(),
    }
    version = ROOT / "VERSION"
    if version.is_file():
        stats["version"] = version.read_text(encoding="utf-8").strip()
    return stats


def _render(stats: dict) -> str:
    c = stats["compose"]
    g_claim = stats["claim_gate"]
    sc = stats["scenario_conditions"]
    g = sc["groups"]
    playbook_yaml = stats["detections_yaml_files"] - stats["detections_files_on_disk"]
    lines = [
        "",
        f"  AiSOC {stats.get('version', '?')} — figures recounted from the tree",
        "",
        f"  Connectors (registered)        {stats['connectors']}",
        f"  Detections (engine loads)      {stats['detections_executable']}",
        f"  … threat-and-anomaly family    {stats['detections_threat_anomaly']}"
        "  (a subset: each also needs a warmed baseline for the principal)",
        f"  Detection rules on disk        {stats['detections_files_on_disk']}  (includes quarantined imports the engine never evaluates)",
        f"  Cloud/identity/SaaS/code       {sc['total']}  "
        f"(cloud {g['cloud']}, identity {g['identity']}, saas {g['saas']}, code {g['code']}"
        f"; {sc['other']} rules are none of the four, {sc['unclassified']} windowed rules carry no product)"
        + (
            f"  [{SCENARIO_TARGET - sc['total']} short of the {SCENARIO_TARGET} target]"
            if sc["total"] < SCENARIO_TARGET
            else "  [target met]"
        ),
        f"  YAML files under detections/   {stats['detections_yaml_files']}  (the extra {playbook_yaml} are response playbooks, not rules)",
        f"  Services in repo               {stats['services_in_repo']}",
    ]
    if c:
        lines.append(f"  Compose services               {c['core']} core + {c['optional']} optional = {c['total']}")
    if g_claim:
        lines.append(
            f"  Claim-to-gate matrix           {g_claim['total']} rows — {g_claim['GATED']} gated, "
            f"{g_claim['PARTIAL']} partial, {g_claim['NO GATE']} ungated"
        )
    lines.append("")
    return "\n".join(lines)


#: README phrases that must agree with the counts above. Each is a
#: (regex, stat-path) pair; the regex must capture the number in group 1.
README_CLAIMS: list[tuple[str, tuple[str, ...]]] = [
    (r"\*\*(\d+) click-and-connect data connectors\*\*", ("connectors",)),
    (r"(\d+) executable detection", ("detections_executable",)),
    (r"(\d+) GATED", ("claim_gate", "GATED")),
]


def _lookup(stats: dict, path: tuple[str, ...]):
    cur = stats
    for key in path:
        cur = cur.get(key) if isinstance(cur, dict) else None
        if cur is None:
            return None
    return cur


def check(stats: dict) -> int:
    readme = ROOT / "README.md"
    if not readme.is_file():
        print("README.md not found", file=sys.stderr)
        return 1
    text = readme.read_text(encoding="utf-8")
    failures = []
    for pattern, path in README_CLAIMS:
        expected = _lookup(stats, path)
        if expected is None:
            continue
        for match in re.finditer(pattern, text):
            claimed = int(match.group(1))
            if claimed != expected:
                failures.append(f"README claims {claimed} for {'.'.join(path)}; the tree has {expected} (pattern: {pattern})")
    scenario = stats["scenario_conditions"]
    measured = int(scenario["total"])
    if measured < SCENARIO_FLOOR:
        failures.append(
            f"cloud/identity/SaaS/code conditions fell to {measured} against a floor of {SCENARIO_FLOOR}. "
            "A rule stopped being executable, or its product left the groups in SCENARIO_GROUPS. "
            "If the drop is a correction — a rule that could never fire being retired — lower SCENARIO_FLOOR "
            "in the same commit and say why; never lower it to make a build green."
        )
    unclassified = int(scenario["unclassified"])
    if unclassified > MAX_WINDOWED_UNCLASSIFIED:
        failures.append(
            f"{unclassified} windowed rules carry neither a product nor a resolvable `translated_from`, "
            f"against a ceiling of {MAX_WINDOWED_UNCLASSIFIED}. They are counted in none of the four groups "
            "and in no `other`, so the headline and the breakdown stop reconciling. Give the new windowed "
            "rule a `translated_from` that resolves, or a product."
        )

    if failures:
        print("project-stats: the tree disagrees with what is published\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        print("\nRe-run `make stats` and correct the README.\n", file=sys.stderr)
        return 1
    print("project-stats: OK — every checked README figure matches the tree")
    print(
        f"project-stats: cloud/identity/SaaS/code conditions {measured} "
        f"(floor {SCENARIO_FLOOR}, depth plan 3.6 target {SCENARIO_TARGET}"
        + (f", {SCENARIO_TARGET - measured} short)" if measured < SCENARIO_TARGET else ", met)")
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("--check", action="store_true", help="fail if the README disagrees")
    args = ap.parse_args()

    stats = collect()
    if args.check:
        return check(stats)
    print(json.dumps(stats, indent=2) if args.json else _render(stats))
    return 0


if __name__ == "__main__":
    sys.exit(main())
