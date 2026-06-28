#!/usr/bin/env python3
"""Validate every managed-mode tenant manifest before it lands on main.

Used by CI (and locally — ``python scripts/audit_managed_tenants.py``) to
guarantee that:

1. Every ``infra/fly/managed/tenants/*.yaml`` parses cleanly.
2. Each manifest carries the required fields (``slug``, ``display_name``,
   ``base_domain``, ``contact_email``, ``plan``).
3. The slug shape matches ``[a-z0-9-]{2,32}`` so it can be used as the
   Fly app suffix without breaking the ``aisoc-<slug>-<component>``
   convention.
4. The filename matches the manifest's slug.
5. The plan is one of the documented tiers.
6. The base_domain looks like a real DNS name.

Files prefixed with ``_`` (underscore) are treated as templates and
ignored.

Exit codes:
* 0 — every manifest passes.
* 1 — one or more manifests failed validation; details printed to
      stderr.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
TENANT_DIR = REPO_ROOT / "infra" / "fly" / "managed" / "tenants"

SLUG_RE = re.compile(r"^[a-z0-9-]{2,32}$")
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PLANS = {"starter", "standard", "enterprise"}
POSTGRES_PLANS = {"development", "ha", "production"}
VM_SIZE_RE = re.compile(r"^(shared|performance)-cpu-(\d+)x$")


def lint_manifest(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        body = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]
    if not isinstance(body, dict):
        return ["manifest body must be a YAML mapping"]

    for key in ("slug", "display_name", "base_domain", "contact_email", "plan"):
        if key not in body or not body[key]:
            errors.append(f"missing required field: {key}")

    slug = str(body.get("slug", ""))
    if slug and not SLUG_RE.match(slug):
        errors.append(f"slug {slug!r} must match {SLUG_RE.pattern}")
    if slug and path.stem != slug:
        errors.append(f"filename {path.name!r} does not match slug {slug!r} (rename one of them)")

    domain = str(body.get("base_domain", ""))
    if domain and not DOMAIN_RE.match(domain):
        errors.append(f"base_domain {domain!r} is not a valid DNS name")

    email = str(body.get("contact_email", ""))
    if email and not EMAIL_RE.match(email):
        errors.append(f"contact_email {email!r} is not a valid email")

    plan = str(body.get("plan", ""))
    if plan and plan not in PLANS:
        errors.append(f"plan {plan!r} must be one of {sorted(PLANS)}")

    pg_plan = body.get("postgres_plan")
    if pg_plan and pg_plan not in POSTGRES_PLANS:
        errors.append(f"postgres_plan {pg_plan!r} must be one of {sorted(POSTGRES_PLANS)}")

    for vm_key in ("api_vm_size", "agents_vm_size"):
        size = body.get(vm_key)
        if size and not VM_SIZE_RE.match(str(size)):
            errors.append(f"{vm_key} {size!r} must match {VM_SIZE_RE.pattern}")

    min_machines = body.get("realtime_min_machines")
    if min_machines is not None and (not isinstance(min_machines, int) or min_machines < 0 or min_machines > 10):
        errors.append(f"realtime_min_machines {min_machines!r} must be int in [0, 10]")

    return errors


def main() -> int:
    if not TENANT_DIR.is_dir():
        print(f"tenant dir not found: {TENANT_DIR}", file=sys.stderr)
        return 1

    failed = 0
    checked = 0
    for path in sorted(TENANT_DIR.glob("*.yaml")):
        # _example.yaml etc. are templates — treat them as advisory.
        if path.name.startswith("_"):
            continue
        checked += 1
        errs = lint_manifest(path)
        if errs:
            failed += 1
            print(f"FAIL {path.relative_to(REPO_ROOT)}", file=sys.stderr)
            for err in errs:
                print(f"  - {err}", file=sys.stderr)

    print(f"checked {checked} manifests; {failed} failed.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
