"""The README advertises an API-docs URL only when the stack serves one.

Two eras, and the invariant spans both.

Originally the quick start told a new user to open
`http://localhost:8000/docs` while FastAPI mounted `/api/docs`, so the
second link in the quick start was a 404 on arrival.

Then `make up` became production-class, and the API disables its
interactive docs there by design. The corrected URL started returning 404
too, for a completely different reason, and live QA found `make up`,
`install.sh` and the README all still printing it.

So the rule is not "advertise the mounted URL". It is: **advertise one
only if the documented path serves one**, and if it does, advertise the
one it serves. Pinned as a test rather than fixed twice because the
document and the mount live in different files and neither mentions the
other.
"""

from __future__ import annotations

import pathlib
import re

from app.main import create_application

REPO = pathlib.Path(__file__).resolve().parents[3]
README = REPO / "README.md"

#: The three URLs that exist only when the interactive docs are mounted.
_INTERACTIVE_DOC_PATHS = frozenset({"/docs", "/redoc", "/openapi.json", "/api/docs", "/api/redoc", "/api/openapi.json"})


def _make_up_sets_production() -> bool:
    """Whether the stack `make up` starts runs in a production posture.

    Read from the compose file rather than from this process's settings,
    because the question is what a reader following the README gets, not
    what the test runner happens to be configured as.
    """
    compose = (REPO / "docker-compose.yml").read_text()
    # `ENVIRONMENT: ${ENVIRONMENT:-production}`, not a bare literal. It was
    # a bare literal once, which meant `.env` was ignored and setting
    # production did nothing; the default form is what the tree ships.
    return bool(
        re.search(r"^\s+ENVIRONMENT:\s*\$\{ENVIRONMENT:-production\}\s*$", compose, re.M)
        or re.search(r"^\s+ENVIRONMENT:\s*production\s*$", compose, re.M)
    )


_MAKE_UP_IS_PRODUCTION = _make_up_sets_production()

# Everything else that prints this URL at a user. The README was corrected on
# its own and these were not, so `make up` went on telling every new user to
# open a 404 — the fix reached the document and not the tool.
TOOL_OUTPUT = (
    "Makefile",
    "install.sh",
    "install.ps1",
    "scripts/lab.sh",
    "docs/runbooks/LOCAL_DEVELOPMENT.md",
    "apps/docs/docs/api/rest.md",
    "apps/docs/docs/architecture/overview.md",
)


def test_the_readme_advertises_only_what_the_documented_path_serves() -> None:
    app = create_application()
    text = README.read_text()
    advertised = set(re.findall(r"http://localhost:8000(/[\w/.-]*)", text))

    # `make up` starts a production-class stack. What this test is really
    # asking is what a reader following the README would get, so the
    # production posture is the one that matters even though the test
    # process itself may not be in it.
    docs_are_served_on_the_documented_path = not _MAKE_UP_IS_PRODUCTION

    if not docs_are_served_on_the_documented_path:
        offenders = {p for p in advertised if p in _INTERACTIVE_DOC_PATHS}
        assert not offenders, (
            "`make up` starts a production-class stack where the API disables its "
            f"interactive docs, and the README still advertises {sorted(offenders)}. "
            "A reader following the quick start gets a 404."
        )
        return

    docs_url = app.docs_url
    assert docs_url, "docs are unmounted; the README should not advertise them"
    for path in advertised:
        assert path in {docs_url, app.openapi_url, app.redoc_url, "/health"}, (
            f"README advertises http://localhost:8000{path}, which the app does not serve (docs are at {docs_url})"
        )


def test_nothing_the_tooling_prints_points_at_a_url_the_app_does_not_serve() -> None:
    """Only the interactive-docs URLs, not every route these files mention.

    `/docs`, `/redoc` and `/openapi.json` are the three that moved under
    `/api`, and the three that 404 when a file still names the old spelling.
    """
    app = create_application()
    served = {app.docs_url, app.openapi_url, app.redoc_url}
    doc_url = re.compile(r"http://localhost:8000((?:/api)?/(?:docs|redoc|openapi\.json))")

    offenders = []
    for relative in TOOL_OUTPUT:
        path = REPO / relative
        if not path.exists():
            continue
        for advertised in sorted(set(doc_url.findall(path.read_text()))):
            if advertised not in served:
                offenders.append(f"{relative}: http://localhost:8000{advertised}")

    assert not offenders, (
        "these print an API docs URL the app does not serve:\n  " + "\n  ".join(offenders) + f"\n(docs are mounted at {app.docs_url})"
    )
