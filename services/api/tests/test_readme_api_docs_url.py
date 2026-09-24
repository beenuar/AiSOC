"""The README's API-docs URL has to be the one the app serves.

The quick start told a new user to open `http://localhost:8000/docs`. FastAPI
is mounted with `docs_url="/api/docs"`, so that URL returned
`{"detail":"Not Found"}` on a freshly-started stack — the second link in the
quick start, 404 on arrival.

Pinned as a test rather than fixed once because the two live in different
files and neither mentions the other.
"""

from __future__ import annotations

import pathlib
import re

from app.core.config import settings
from app.main import create_application

REPO = pathlib.Path(__file__).resolve().parents[3]
README = REPO / "README.md"

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


def test_the_readme_points_at_the_url_the_app_mounts() -> None:
    app = create_application()
    assert not settings.is_production, "this test asserts the dev-mode mount"
    docs_url = app.docs_url
    assert docs_url, "docs are unmounted; the README should not advertise them"

    text = README.read_text()
    advertised = set(re.findall(r"http://localhost:8000(/[\w/.-]*)", text))
    assert advertised, "README no longer advertises an API docs URL"

    for path in advertised:
        assert path in {docs_url, app.openapi_url, app.redoc_url, "/health"}, (
            f"README advertises http://localhost:8000{path}, which the app does not serve " f"(docs are at {docs_url})"
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
