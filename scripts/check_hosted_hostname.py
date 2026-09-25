#!/usr/bin/env python3
"""Keep the maintainers' hosted hostname out of open-source defaults.

A self-hoster must never meet another deployment's hostname presented as their
own product's URL. The canonical example was an OSS login page hard-coding
"back to <hosted domain>", which a self-hoster saw inside their own install.
Later examples were worse than cosmetic: published replay share links, tenant
invite emails, the Slack bot's case deep-links and the site's canonical/OG/
sitemap URLs all defaulted to the hosted host, so an unconfigured install
handed its users links into somebody else's console.

The hostname still appears legitimately in ~100 files — the managed-instance
deploy configs, the marketing pages that describe the hosted offering, and the
changelog. So this gate is not "the string must not appear"; it is "every
appearance is one somebody signed off on".

Bidirectional by construction
-----------------------------
The recurring failure mode in this repo is the one-directional check: it
compares A against B and never B against A, so drift in the direction things
actually change slips past while the check prints OK. A hostname allow-list
keyed only on "is this path allowed?" has exactly that shape — delete the line
that made a file legitimate and the file keeps its exemption forever, ready to
launder a real leak later.

So the allow-list stores an exact expected count per path and both directions
are errors:

  * tree -> allow-list : an occurrence in a path with no entry (a new leak), or
                         more occurrences than the entry allows.
  * allow-list -> tree : an entry whose path is gone, or that now has fewer
                         occurrences than recorded (a stale exemption).

Either way the fix is the same: look at the occurrence, decide whether it is
legitimate, and move the number deliberately.

Non-vacuity
-----------
A gate that can pass while inspecting nothing is worse than no gate, because it
launders the claim. Three guards:

  * The repo root comes from ``git rev-parse --show-toplevel`` evaluated in the
    *current working directory*, never from this file's location. A sibling
    gate resolved its root from ``__file__``, so a run launched from another
    worktree printed a confident OK about a tree it never inspected. The
    resolved root is verified against sentinel paths and always printed.
  * The scan must reach a plausible number of files and must still find the
    hostname somewhere. A scan that matches nothing means the pattern, the
    root or the file walk broke — that is reported as failure, not success.
  * ``--self-test`` runs the detector over a known-bad and a known-good sample
    and asserts it separates them, then asserts the comparison itself rejects
    an empty scan. Run in CI ahead of the real check.

It also pins the six vendored ``cors.py`` copies byte-identical to each other.
Nothing enforced that before, and a single drifted copy is precisely how one
service would quietly keep a hosted origin in its credentialed allow-list.

Usage:
    python3 scripts/check_hosted_hostname.py --self-test
    python3 scripts/check_hosted_hostname.py
    python3 scripts/check_hosted_hostname.py --repo-root /path/to/checkout
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

HOSTED_HOSTNAME = "tryaisoc.com"

# Paths that exist to detect or record the hostname. Scanning them would make
# the gate flag itself. Keep this set as small as it can possibly be.
SELF_REFERENTIAL = frozenset(
    {
        "scripts/check_hosted_hostname.py",
        ".github/workflows/hosted-hostname.yml",
    }
)

# Files that must exist for a directory to be this repository. Cheap insurance
# against pointing the scan at the wrong tree and reporting a clean result.
SENTINELS = ("services/api/app/core/cors.py", "apps/web/package.json", "CHANGELOG.md")

# The six byte-identical vendored copies of the shared CORS helper.
CORS_COPIES = (
    "services/api/app/core/cors.py",
    "services/agents/app/core/cors.py",
    "services/connectors/app/security/cors.py",
    "services/honeytokens/app/core/cors.py",
    "services/purple-team/app/core/cors.py",
    "services/ueba/app/core/cors.py",
)

# If the scan finds fewer tracked files than this, something is wrong with the
# walk rather than right with the tree.
MIN_FILES_SCANNED = 500

_MANAGED_DEPLOY = "deploy config for the maintainers' managed instance; the hostname is the thing being configured"
_MARKETING = "marketing page describing the hosted offering to a reader on that hosted site"
_HISTORY = "historical record — changelog, release notes, decision log or incident note"
_MANAGED_FEATURE = "docstring/comment on the managed-instance feature set (waitlist, tenant provisioning, hosted demo)"
_UUID_SEED = "opaque uuid5 namespace seed — changing the string changes every derived id, so it is a compatibility constant, not a URL"
_DOCS = "documentation about the managed instance, accurate as written"
_PLAN = "plan file — never edited by policy; reported instead"
_GATE_FIXTURE = "deliberate regression assertion that the hostname is absent"

# path -> (expected occurrences, why this one is allowed)
ALLOWED: dict[str, tuple[int, str]] = {
    # --- managed-instance deploy configs -----------------------------------
    "infra/fly/fly-demo-deploy.sh": (27, _MANAGED_DEPLOY),
    "infra/fly/README.md": (17, _MANAGED_DEPLOY),
    "infra/fly/web/fly.toml": (13, _MANAGED_DEPLOY),
    "infra/fly/api/fly.toml": (9, _MANAGED_DEPLOY),
    "infra/fly/realtime/fly.toml": (4, _MANAGED_DEPLOY),
    "infra/fly/managed/README.md": (1, _MANAGED_DEPLOY),
    "infra/cloudflare/README.md": (13, _MANAGED_DEPLOY),
    "infra/cloudflare/tunnel.sh": (10, _MANAGED_DEPLOY),
    "infra/terraform/environments/managed/README.md": (7, _MANAGED_DEPLOY),
    "infra/terraform/environments/managed/variables.tf": (6, _MANAGED_DEPLOY),
    "infra/terraform/environments/managed/main.tf": (6, _MANAGED_DEPLOY),
    "apps/web/fly.toml": (4, _MANAGED_DEPLOY),
    "scripts/demo-public.sh": (3, _MANAGED_DEPLOY),
    "scripts/adoption_snapshot.py": (1, _MANAGED_DEPLOY),
    ".github/FUNDING.yml": (1, _MANAGED_DEPLOY),
    ".github/ISSUE_TEMPLATE/benchmark_submission.yml": (2, _MANAGED_DEPLOY),
    "apps/web/e2e/demo/screencast.spec.ts": (1, _MANAGED_DEPLOY),
    # --- marketing surface, served from the hosted site --------------------
    "apps/web/src/app/(marketing)/about/page.tsx": (5, _MARKETING),
    "apps/web/src/app/(marketing)/sovereign/page.tsx": (5, _MARKETING),
    "apps/web/src/app/(marketing)/waitlist/page.tsx": (5, _MARKETING),
    "apps/web/src/app/(marketing)/privacy/page.tsx": (6, _MARKETING),
    "apps/web/src/app/(marketing)/contact/page.tsx": (4, _MARKETING),
    "apps/web/src/app/(marketing)/terms/page.tsx": (3, _MARKETING),
    "apps/web/src/app/(marketing)/blog/page.tsx": (2, _MARKETING),
    "apps/web/src/app/(marketing)/customers/page.tsx": (2, _MARKETING),
    "apps/web/src/app/(marketing)/press/page.tsx": (2, _MARKETING),
    "apps/web/src/app/(marketing)/pricing/page.tsx": (2, _MARKETING),
    "apps/web/src/app/(marketing)/blog/[slug]/page.tsx": (1, _MARKETING),
    "apps/web/src/app/(marketing)/customers/[slug]/page.tsx": (1, _MARKETING),
    "apps/web/src/app/(marketing)/mesh/page.tsx": (1, _MARKETING),
    "apps/web/src/app/why-open-source/page.tsx": (1, _MARKETING),
    # `apps/web/src/app/page.tsx` used to sit here for one occurrence: the
    # landing page's Open Graph description ended "join the managed waitlist
    # at tryaisoc.com". An OG description is what a crawler quotes when the
    # open-source project is shared, so that one reached far further than a
    # marketing paragraph. It was removed rather than exempted.
    "apps/web/src/app/not-found.tsx": (1, _MARKETING),
    "apps/web/src/app/r/[slug]/opengraph-image.tsx": (1, _MARKETING),
    "apps/web/src/app/api/badge/[kind]/route.ts": (1, _MARKETING),
    "apps/web/src/app/api/badge/[kind]/route.test.ts": (4, _MARKETING),
    "apps/web/src/components/landing/Hero.tsx": (2, _MARKETING),
    "apps/web/src/components/landing/Hero.test.tsx": (1, _MARKETING),
    "apps/web/src/components/landing/sections/Footer.tsx": (2, _MARKETING),
    "apps/web/src/components/landing/sections/DeployOptions.tsx": (1, _MARKETING),
    "apps/web/src/components/landing/sections/PricingTeaser.tsx": (1, _MARKETING),
    # Four entries used to sit here and were dropped rather than renumbered,
    # because their occurrences are gone rather than reduced:
    #   sections/Hero.tsx      (1) the fold's primary button, "Open the live
    #                              dashboard", pointing at the hosted host. The
    #                              repository is the conversion, so it is now
    #                              "Read the source on GitHub".
    #   sections/StickyNav.tsx (2) the same button in the site-wide nav, desktop
    #                              and mobile, on every marketing page.
    #   sections/Faq.tsx       (2) "What runs in production today?" answered with
    #                              beta deployments and a managed waitlist. The
    #                              question was replaced; the adopter claim it
    #                              asserted was not supported by anything.
    #   sections/DemoEmbed.tsx (1) a mocked console whose chrome displayed a
    #                              hosted URL. The file was deleted; its
    #                              replacement shows real captures taken on
    #                              localhost.
    "apps/web/content/blog/automation-maturity.mdx": (2, _MARKETING),
    "marketing/launch/blog-outlines.md": (2, _MARKETING),
    "marketing/launch/product-hunt.md": (1, _MARKETING),
    # --- history: changelog, releases, decision records, incident notes ----
    "CHANGELOG.md": (24, _HISTORY),
    "RELEASES.md": (4, _HISTORY),
    "AGENTS.md": (6, _HISTORY),
    "docs/decisions/0004-live-demo-strategy.md": (5, _HISTORY),
    "docs/decisions/0003-mssp-pricing-shape.md": (2, _HISTORY),
    "services/api/app/db/database.py": (1, _HISTORY),
    "services/api/app/scripts/serve.py": (1, _HISTORY),
    "services/api/Dockerfile": (1, _HISTORY),
    "apps/web/src/components/onboarding/OnboardingView.tsx": (1, _HISTORY),
    "apps/web/src/lib/api.ts": (2, _HISTORY),
    "apps/web/next.config.js": (1, _HISTORY),
    "services/api/migrations/042_waitlist.sql": (1, _HISTORY),
    "services/api/migrations/043_tenant_provision.sql": (1, _HISTORY),
    "services/api/migrations/045_published_replays.sql": (1, _HISTORY),
    # --- managed-instance feature docstrings -------------------------------
    "services/api/app/api/v1/router.py": (2, _MANAGED_FEATURE),
    "services/api/app/scripts/demo_seed.py": (2, _MANAGED_FEATURE),
    "services/api/app/api/v1/endpoints/tenant_provision.py": (1, _MANAGED_FEATURE),
    "services/api/app/core/config.py": (1, _MANAGED_FEATURE),
    "services/api/app/middleware/demo_mode.py": (1, _MANAGED_FEATURE),
    "services/api/app/models/published_replay.py": (1, _MANAGED_FEATURE),
    "services/api/app/models/waitlist.py": (1, _MANAGED_FEATURE),
    "services/api/app/services/tenant_provision/__init__.py": (1, _MANAGED_FEATURE),
    "services/api/app/services/waitlist/__init__.py": (1, _MANAGED_FEATURE),
    "services/api/app/services/waitlist/rate_limit.py": (1, _MANAGED_FEATURE),
    "services/mesh/app/main.py": (1, _MANAGED_FEATURE),
    # --- uuid5 namespace seeds: compatibility constants, not URLs ----------
    "services/agents/app/orchestrator/router.py": (2, _UUID_SEED),
    "services/agents/app/workers/fused_alert_consumer.py": (1, _UUID_SEED),
    # --- documentation about the managed instance --------------------------
    "apps/docs/docs/operations/managed-instance.md": (14, _DOCS),
    "apps/docs/docusaurus.config.ts": (2, _DOCS),
    "docs/operations/live-demo-runbook.md": (7, _DOCS),
    "docs/design/landing-page-brief.md": (3, _DOCS),
    "docs/design/landing-page-content.md": (3, _DOCS),
    "docs/architecture/mesh.md": (1, _DOCS),
    "docs/design/README.md": (1, _DOCS),
    "docs/managed-mode.md": (1, _DOCS),
    "docs/press/README.md": (1, _DOCS),
    "examples/lateral-movement.md": (1, _DOCS),
    "examples/phishing-payload.md": (1, _DOCS),
    "services/slack-bot/README.md": (1, _DOCS),
    ".env.example": (2, _DOCS),
    # --- plan files: never edited, reported instead ------------------------
    "plans/aisoc_v8.0_north_star_plan_1dee8c63.plan.md": (6, _PLAN),
    "plans/cyble-aisoc/AGENTS.md": (4, _PLAN),
    "plans/cyble-aisoc/index.html": (4, _PLAN),
    "plans/cyble-aisoc/platform/README.md": (2, _PLAN),
    "plans/cyble-aisoc/architecture/agent-topology.md": (1, _PLAN),
    "plans/cyble-aisoc/architecture/integration-matrix.md": (1, _PLAN),
    "plans/cyble-aisoc/platform/CONTRIBUTING-DETECTIONS.md": (1, _PLAN),
    "plans/cyble-aisoc/platform/backend/app/api/routes.py": (1, _PLAN),
    "plans/cyble-aisoc/platform/backend/app/marketplace/catalog.py": (16, _PLAN),
    # --- the regression assertion itself -----------------------------------
    "services/api/tests/test_tenant_provision.py": (1, _GATE_FIXTURE),
}


class GateError(RuntimeError):
    """Raised when the gate cannot trust its own inputs."""


def resolve_repo_root(explicit: str | None) -> Path:
    """Resolve the tree to inspect, never from this file's own location.

    Deriving the root from ``__file__`` makes the gate describe the checkout it
    happens to live in rather than the one being tested, so a run from another
    worktree reports OK about a tree it never opened.
    """
    if explicit:
        root = Path(explicit).resolve()
    else:
        try:
            out = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise GateError(f"cannot resolve a git repository from {Path.cwd()}: {exc}") from exc
        root = Path(out.stdout.strip()).resolve()

    missing = [s for s in SENTINELS if not (root / s).exists()]
    if missing:
        raise GateError(f"{root} does not look like the AiSOC repository (missing: {', '.join(missing)})")
    return root


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [p for p in out.stdout.split("\0") if p]


def count_in_text(text: str) -> int:
    return text.count(HOSTED_HOSTNAME)


def scan(root: Path, paths: list[str]) -> dict[str, int]:
    """Occurrences of the hostname per path, skipping self-referential files."""
    found: dict[str, int] = {}
    for rel in paths:
        if rel in SELF_REFERENTIAL:
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="ignore")
        except (OSError, ValueError):
            continue
        n = count_in_text(text)
        if n:
            found[rel] = n
    return found


def compare(found: dict[str, int], allowed: dict[str, tuple[int, str]]) -> list[str]:
    """Both directions. Returns a list of failure lines; empty means clean."""
    problems: list[str] = []

    # Direction 1: tree -> allow-list. New or grown leaks.
    for rel, n in sorted(found.items()):
        if rel not in allowed:
            problems.append(f"NEW LEAK          {rel}: {n} occurrence(s) of {HOSTED_HOSTNAME}, no allow-list entry")
        elif n > allowed[rel][0]:
            problems.append(f"GREW              {rel}: {n} occurrence(s), allow-list records {allowed[rel][0]}")

    # Direction 2: allow-list -> tree. Stale exemptions that would silently
    # grant permission to a file that could regain a leak later.
    for rel, (expected, _reason) in sorted(allowed.items()):
        actual = found.get(rel, 0)
        if actual == 0:
            problems.append(f"STALE EXEMPTION   {rel}: allow-list records {expected}, file has none (or is gone) — drop the entry")
        elif actual < expected:
            problems.append(f"SHRANK            {rel}: {actual} occurrence(s), allow-list records {expected} — lower the number")

    return problems


def check_cors_copies(root: Path) -> list[str]:
    """The vendored CORS helper must stay byte-identical across services."""
    digests: dict[str, str] = {}
    problems: list[str] = []
    for rel in CORS_COPIES:
        path = root / rel
        if not path.exists():
            problems.append(f"CORS COPY MISSING {rel}")
            continue
        digests[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    if len(set(digests.values())) > 1:
        problems.append(
            "CORS COPIES DIFFER — the shared helper is vendored byte-identical; "
            "a drifted copy lets one service keep a different origin allow-list:"
        )
        for rel, digest in sorted(digests.items()):
            problems.append(f"    {digest[:12]}  {rel}")
    return problems


def self_test() -> int:
    """Prove the gate detects a known-bad sample and rejects a vacuous pass."""
    failures: list[str] = []

    bad = f"const DEFAULT = 'https://{HOSTED_HOSTNAME}/api';"
    good = "const DEFAULT = 'http://localhost:3000/api';"

    if count_in_text(bad) != 1:
        failures.append(f"detector missed a known-bad sample: {bad!r}")
    if count_in_text(good) != 0:
        failures.append(f"detector flagged a known-good sample: {good!r}")

    # A known-bad file with no allow-list entry must be reported.
    if not compare({"some/new/file.ts": 1}, {}):
        failures.append("compare() passed a file containing the hostname with no allow-list entry")

    # A stale allow-list entry must be reported — the reverse direction that a
    # one-directional gate would miss.
    if not compare({}, {"gone/file.ts": (1, "stale")}):
        failures.append("compare() passed an allow-list entry with no matching occurrence")

    # Counts must be pinned in both directions, not just as a ceiling.
    if not compare({"f.ts": 2}, {"f.ts": (1, "x")}):
        failures.append("compare() passed an occurrence count above the allow-listed number")
    if not compare({"f.ts": 1}, {"f.ts": (2, "x")}):
        failures.append("compare() passed an occurrence count below the allow-listed number")

    # And the happy path must actually be reachable, or every check above is
    # satisfied by a function that just always fails.
    if compare({"f.ts": 1}, {"f.ts": (1, "x")}):
        failures.append("compare() failed an exactly-matching allow-list entry")

    if failures:
        print("self-test FAILED:")
        for line in failures:
            print(f"  - {line}")
        return 1

    print(f"self-test OK — detector separates known-bad from known-good and compare() is bidirectional ({HOSTED_HOSTNAME})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", default=None, help="tree to inspect (default: git toplevel of the working directory)")
    parser.add_argument("--self-test", action="store_true", help="prove the gate is not vacuous, then exit")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    try:
        root = resolve_repo_root(args.repo_root)
    except GateError as exc:
        print(f"FAIL: {exc}")
        return 2

    paths = tracked_files(root)
    # Print what was inspected. A gate that does not say which tree it read is
    # one worktree away from a confident, meaningless OK.
    print(f"scanning {len(paths)} tracked files under {root}")

    if len(paths) < MIN_FILES_SCANNED:
        print(f"FAIL: only {len(paths)} tracked files found (expected >= {MIN_FILES_SCANNED}); the scan is broken, not the tree clean")
        return 2

    found = scan(root, paths)
    if not found:
        print(f"FAIL: zero occurrences of {HOSTED_HOSTNAME} anywhere in {len(paths)} files.")
        print("      The managed-instance deploy configs legitimately contain it, so this")
        print("      means the pattern or the file walk broke — not that the tree is clean.")
        return 2

    problems = compare(found, ALLOWED) + check_cors_copies(root)

    if problems:
        print(f"\nFAIL: {len(problems)} problem(s).\n")
        for line in problems:
            print(f"  {line}")
        print(
            "\nIf an occurrence is a real leak, give it a deployment-neutral default.\n"
            "If it legitimately describes the managed offering, add or move its entry\n"
            "in ALLOWED with a reason. Never raise a number to make this pass without\n"
            "reading the occurrence it covers."
        )
        return 1

    total = sum(found.values())
    print(f"OK — {total} occurrence(s) across {len(found)} file(s), every one allow-listed with a reason")
    print(f"OK — {len(CORS_COPIES)} vendored cors.py copies are byte-identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
