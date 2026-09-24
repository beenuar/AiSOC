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

README = pathlib.Path(__file__).resolve().parents[3] / "README.md"


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
