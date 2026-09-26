"""First-run defects that every test suite passed and a real deployment did not.

A live acceptance pass brought the CORE stack up from the published images,
ran the golden pipeline green, and then could not log in. Three separate
things had to be wrong at once for that to happen, and none of them was
visible to a unit test:

* migration 001 seeded `admin@aisoc.local`, an RFC 6761 special-use domain
  that `pydantic.EmailStr` rejects with a 422 before the password is compared;
* it seeded a bcrypt hash whose plaintext nobody knew, while four
  documentation pages published `changeme` for it;
* the published `aisoc-web:latest` image — the one `docker-compose.yml`
  pulls — was built with `NEXT_PUBLIC_DEMO_MODE=true`, and Next inlines that
  at build time, so a self-hoster's console called their real alerts demo
  data with no runtime way out.

Each check below is a file-content assertion because each defect lived in the
gap *between* files: a migration and a doc, a Dockerfile and a workflow. The
behavioural coverage is in `services/api/tests/test_bootstrap_admin.py`.
"""

from __future__ import annotations

import fnmatch
import pathlib
import re

import pytest
import yaml
from email_validator import EmailNotValidError, validate_email

REPO = pathlib.Path(__file__).resolve().parents[1]
MIGRATIONS = REPO / "services/api/migrations"
WEB_DOCKERFILE = REPO / "apps/web/Dockerfile"
DEMO_AUTOLOGIN = REPO / "apps/web/src/components/demo/DemoAutoLogin.tsx"
LOGIN_PAGE = REPO / "apps/web/src/app/login/page.tsx"
ROOT_COMPOSE = REPO / "docker-compose.yml"
DEMO_COMPOSE = REPO / "infra/compose/docker-compose.demo.yml"
PUBLISH_WORKFLOW = REPO / ".github/workflows/publish-images.yml"
RELEASE_WORKFLOW = REPO / ".github/workflows/release.yml"

# The address migration 001 seeded. It may still be named in places that
# explain why it was retired; what it may not do is appear as a credential a
# reader is told to use.
RETIRED_EMAIL = "admin@aisoc.local"

# Documentation whose job is to describe the defect rather than repeat it.
HISTORY_ALLOWED = {"CHANGELOG.md"}

# The only migration permitted to name the orphaned hash, because it has to
# match that exact row to retire it. Deliberately not extended to 001: an
# exemption there would let the seed come back under a gate reporting OK,
# which is the shape of the original defect rather than a guard against it.
HASH_ALLOWED = {"059_retire_unusable_seed_admin.sql"}

SKIP_DIRS = {".git", "node_modules", ".next", "dist", "build", "plans", ".venv-firstrun"}


def _docs() -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for path in REPO.rglob("*.md"):
        if SKIP_DIRS & set(path.relative_to(REPO).parts):
            continue
        out.append(path)
    for path in REPO.rglob("*.mdx"):
        if SKIP_DIRS & set(path.relative_to(REPO).parts):
            continue
        out.append(path)
    return out


# ─── The seeded credential ───────────────────────────────────────────────────


def test_no_migration_seeds_a_login() -> None:
    """A password hash committed here is a default credential everywhere."""
    offenders = []
    for path in sorted(MIGRATIONS.glob("*.sql")):
        text = path.read_text()
        if re.search(r"INSERT\s+INTO\s+users\b", text, flags=re.IGNORECASE):
            offenders.append(f"{path.name}: INSERT INTO users")
        if path.name not in HASH_ALLOWED and re.search(r"\$2[aby]\$\d\d\$", text):
            offenders.append(f"{path.name}: bcrypt hash literal")
    assert not offenders, (
        "migrations must not ship an account:\n  " + "\n  ".join(offenders) + "\nThe first administrator comes from `make bootstrap`."
    )


def test_no_page_tells_a_reader_to_sign_in_with_the_retired_address() -> None:
    offenders = [str(path.relative_to(REPO)) for path in _docs() if path.name not in HISTORY_ALLOWED and RETIRED_EMAIL in path.read_text()]
    assert not offenders, (
        f"{RETIRED_EMAIL} is published as a credential in:\n  "
        + "\n  ".join(offenders)
        + f"\nThe login route rejects {RETIRED_EMAIL} with a 422 — it is not a password problem, "
        "and a doc that merely agrees with the old seed is not fixed."
    )


@pytest.mark.parametrize("doc", _docs(), ids=lambda p: str(p.relative_to(REPO)))
def test_every_documented_login_uses_an_address_the_api_accepts(doc: pathlib.Path) -> None:
    """Run the validator the route runs, not a copy of its reserved-domain list.

    `"email":"admin@aisoc.local"` was copied into four pages. Each was
    self-consistent with the seed and every one of them was unusable.
    """
    text = doc.read_text()
    addresses = re.findall(r'"email"\s*:\s*\\?"([^"\\]+)\\?"', text)
    for address in addresses:
        if address.startswith("$") or address.startswith("<"):
            continue  # a placeholder for the reader to substitute
        try:
            validate_email(address, check_deliverability=False)
        except EmailNotValidError as exc:
            pytest.fail(
                f"{doc.relative_to(REPO)} documents a login as {address!r}, which "
                f"POST /api/v1/auth/login rejects with a 422 before checking the "
                f"password: {exc}"
            )


# ─── The published image ─────────────────────────────────────────────────────


def test_the_web_dockerfile_defaults_ship_no_demo_credential() -> None:
    """Next inlines NEXT_PUBLIC_* wherever referenced, default or not."""
    for line in WEB_DOCKERFILE.read_text().splitlines():
        match = re.match(r"\s*ARG\s+(NEXT_PUBLIC_DEMO_AUTOLOGIN_\w+)=(.*)$", line)
        if not match:
            continue
        value = match.group(2).strip().strip('"').strip("'")
        assert value == "", (
            f"{match.group(1)} defaults to {value!r}. Every build made without an explicit "
            "value — including a self-host build — would inline that into the client bundle."
        )


@pytest.mark.parametrize("source", [DEMO_AUTOLOGIN, LOGIN_PAGE], ids=lambda p: p.name)
def test_no_client_component_hardcodes_a_demo_credential(source: pathlib.Path) -> None:
    """Gating the render hides the panel; it does not remove the strings.

    Both of these declared `const DEMO_EMAIL = '…'` at module scope, so the
    pair was inlined into every bundle the project builds — the login page's
    even though the panel that shows it is already behind `isDemoMode()`.
    """
    text = source.read_text()
    for name in ("DEMO_EMAIL", "DEMO_PASSWORD"):
        literal = re.search(rf"const\s+{name}\s*(?::[^=]+)?=\s*['\"]([^'\"]+)['\"]", text)
        assert literal is None, (
            f"{source.name} assigns {name} the literal {literal.group(1)!r}. Read it from "
            "process.env.NEXT_PUBLIC_DEMO_AUTOLOGIN_* so only a demo build carries it."
        )
        fallback = re.search(
            r"process\.env\.NEXT_PUBLIC_DEMO_AUTOLOGIN_\w+[^;]*\|\|\s*['\"]([^'\"]+)['\"]",
            text,
        )
        assert fallback is None, (
            f"{source.name} falls back to the literal {fallback.group(1)!r}. A fallback is inlined into every build, demo or not."
        )


def _build_job(workflow: pathlib.Path) -> tuple[str, dict]:
    """The job that builds images, found by what it does rather than by name.

    Named lookup broke the moment the release workflow split its build in two:
    the test asked for `docker-push`, which no longer existed, and a gate that
    fails because a job was renamed says nothing about the property it guards.
    The demo build args are the structural signal — exactly one job sets them.
    """
    spec = yaml.safe_load(workflow.read_text())
    named = [
        (name, job)
        for name, job in spec["jobs"].items()
        if any("NEXT_PUBLIC_DEMO_MODE=true" in str(step.get("run", "")) for step in job.get("steps", []))
    ]
    assert len(named) == 1, f"{workflow.name}: expected exactly one job setting NEXT_PUBLIC_DEMO_MODE, found {[n for n, _ in named]}"
    return named[0]


def _matrix(workflow: pathlib.Path) -> list[dict]:
    return _build_job(workflow)[1]["strategy"]["matrix"]["include"]


def _demo_build_step(workflow: pathlib.Path) -> dict:
    for step in _build_job(workflow)[1]["steps"]:
        if "NEXT_PUBLIC_DEMO_MODE=true" in str(step.get("run", "")):
            return step
    raise AssertionError(f"{workflow.name}: no step sets NEXT_PUBLIC_DEMO_MODE")


@pytest.mark.parametrize(
    "workflow",
    [PUBLISH_WORKFLOW, RELEASE_WORKFLOW],
    ids=["publish-images", "release"],
)
def test_the_demo_bundle_is_built_by_its_own_matrix_entry(workflow: pathlib.Path) -> None:
    """The demo build must be a separate image, not a flag on the product one.

    It was a flag on the product one, which is how `latest` — what `make up`
    pulls — came to carry a bundle that disabled every write control.
    """
    demo_entries = [e for e in _matrix(workflow) if str(e.get("demo", "")) == "true"]
    assert len(demo_entries) == 1, f"{workflow.name}: expected exactly one matrix entry with `demo: 'true'`, found {len(demo_entries)}"
    assert demo_entries[0]["image"].endswith("aisoc-web")

    step = _demo_build_step(workflow)
    assert "matrix.demo" in str(step.get("if", "")), (
        f"{workflow.name}: the demo build args are not gated on `matrix.demo`, so a "
        f"product build can still receive them (if: {step.get('if')!r})"
    )


@pytest.mark.parametrize(
    "workflow",
    [PUBLISH_WORKFLOW, RELEASE_WORKFLOW],
    ids=["publish-images", "release"],
)
def test_one_image_cannot_collect_another_images_digests(workflow: pathlib.Path) -> None:
    """The per-architecture digest an image merges must be its own.

    `web` and `web-demo` push to the same repository and differ only in the
    bundle they contain, and the upload/download pair keyed them
    `digest-<service>-<platform>` with a `digest-<service>-*` pattern. So the
    console's merge job collected four digests — two of them the demo build —
    and would have published a mixed manifest under the tag `make up` pulls.
    The merge step's count check caught it, but only after both builds had run.

    This is the same question one step earlier: replay each service's download
    pattern against every service's upload name and require exactly its own.
    """
    build = _build_job(workflow)[1]
    merge = next(
        job
        for job in yaml.safe_load(workflow.read_text())["jobs"].values()
        if any("download-artifact" in str(step.get("uses", "")) for step in job.get("steps", []))
    )
    services = [e["service"] for e in build["strategy"]["matrix"]["include"]]
    platforms = build["strategy"]["matrix"]["platform"]

    upload = next(s for s in build["steps"] if "upload-artifact" in str(s.get("uses", "")))
    download = next(s for s in merge["steps"] if "download-artifact" in str(s.get("uses", "")))
    name_template = upload["with"]["name"]
    pattern_template = download["with"]["pattern"]

    def rendered(template: str, service: str, platform: str = "") -> str:
        return template.replace("${{ matrix.service }}", service).replace("${{ matrix.platform }}", platform).strip()

    uploaded = {rendered(name_template, s, p): (s, p) for s in services for p in platforms}
    for service in services:
        pattern = rendered(pattern_template, service)
        matched = {uploaded[name] for name in uploaded if fnmatch.fnmatch(name, pattern)}
        assert matched == {(service, p) for p in platforms}, (
            f"{workflow.name}: the pattern {pattern!r} for {service!r} collects "
            f"{sorted(matched)}. An image must merge only its own architectures."
        )


def test_publish_images_keeps_demo_off_the_moving_tags() -> None:
    text = PUBLISH_WORKFLOW.read_text()
    for tag in ("value=main", "value=latest"):
        line = next(ln for ln in text.splitlines() if tag in ln and "type=raw" in ln)
        assert "matrix.demo != 'true'" in line, f"publish-images.yml publishes `{tag}` without excluding the demo build: {line.strip()}"


def test_release_publishes_the_demo_under_its_own_tag() -> None:
    text = RELEASE_WORKFLOW.read_text()
    assert "-demo" in text, "release.yml has no demo-suffixed tag for the demo build"
    assert 'matrix.demo }}" = "true"' in text, (
        "release.yml does not branch its tag list on `matrix.demo`, so `vX.Y.Z` and `latest` could carry the demo bundle again"
    )


def test_each_compose_file_pulls_the_image_built_for_it() -> None:
    root = ROOT_COMPOSE.read_text()
    demo = DEMO_COMPOSE.read_text()

    root_ref = re.search(r"image:\s*(ghcr\.io/beenuar/aisoc-web:\S+)", root)
    demo_ref = re.search(r"image:\s*(ghcr\.io/beenuar/aisoc-web:\S+)", demo)
    assert root_ref and demo_ref

    assert "demo" not in root_ref.group(1), (
        f"docker-compose.yml (what `make up` starts) pulls {root_ref.group(1)} — a self-host stack must not pull a demo bundle"
    )
    assert "demo" in demo_ref.group(1), (
        f"the demo stack pulls {demo_ref.group(1)}, which is the product build: no banner, no auto-login, and a visitor bounced to /login"
    )
