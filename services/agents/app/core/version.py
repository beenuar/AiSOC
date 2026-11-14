"""One answer to "which version of AiSOC is this process running".

Vendored, like ``cors.py`` and ``_health.py`` beside it: services do not
share a Python path, so each ships its own byte-identical copy under
``services/<svc>/app/core/version.py``. ``services/api`` holds the copy to
edit; the others are kept equal to it.

The defect this replaces
------------------------
``Settings.APP_VERSION`` was the literal ``"0.1.0"`` and nothing ever
populated it. A v22.2.0 deployment therefore reported ``0.1.0`` on
``/health``, published ``0.1.0`` as ``info.version`` in its OpenAPI document
and logged it at startup — three surfaces, one wrong number, perfectly
consistent with each other. ``telemetry.py`` had a second stale literal
(``4.0.0``) reached through ``AISOC_VERSION``'s default, so traces and the
health endpoint disagreed as well.

Where the number comes from
---------------------------
Two sources, in order:

1. ``AISOC_VERSION`` in the environment. Images stamp it from the
   ``AISOC_VERSION`` build arg (see each service's ``Dockerfile``), which
   ``.github/workflows/publish-images.yml`` fills from the repo-root
   ``VERSION`` file at build time. A container has no repository to read, so
   this is the only path that can work there.
2. The repo-root ``VERSION`` file, found by walking up from this module.
   This is the source-checkout path: ``python -m app.scripts.serve`` from a
   clone, the test suite, and ``scripts/export_openapi.py``.

...and an explicit unknown
--------------------------
When neither answers, the result is the string ``"unknown"``.

That is the whole point of this module, so it is worth stating plainly: a
default like ``0.1.0`` or ``0.0.0`` is not a neutral placeholder. It parses
as a version, sorts below every tag that has ever shipped, and renders in a
console tile and a Prometheus label as though it were measured. An operator
comparing a deployment against a release tag cannot distinguish "this is
very old" from "nobody told me". ``"unknown"`` cannot be mistaken for
either, and it is what ``apps/web``'s ``/api/runtime-config`` route already
answers when the console's build-time value is absent.

The bounded upward walk
-----------------------
The walk stops after ``_MAX_WALK_PARENTS`` directories and only believes a
``VERSION`` file whose contents look like a release. Both guards exist
because the walk can leave the project: from ``/app/app/core`` inside a
container it reaches ``/``, and ``/VERSION`` is a real file on some base
images meaning something entirely unrelated. Reporting that string as the
running release would be a fabricated answer dressed as a measured one,
which is the failure mode this module exists to remove rather than relocate.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path

#: What this module answers when no source declares a version. Asserted
#: against in ``tests/test_running_version.py`` so a later edit cannot
#: quietly reinstate a numeric default.
UNKNOWN_VERSION = "unknown"

#: Environment variable the image stamps from its ``AISOC_VERSION`` build arg.
VERSION_ENV_VAR = "AISOC_VERSION"

#: Environment variable the image stamps from its ``AISOC_REVISION`` build
#: arg. The release workflow already writes the same value into the
#: ``org.opencontainers.image.revision`` OCI label, but a label is metadata on
#: the manifest — a process cannot read its own. This is the runtime half.
REVISION_ENV_VAR = "AISOC_REVISION"

#: How far up to look for the repo-root ``VERSION`` file. This module sits at
#: ``services/<svc>/app/core/version.py``, so the repository root is four
#: directories up; the extra headroom covers a checkout nested one deeper
#: without letting the walk reach the filesystem root from a container.
_MAX_WALK_PARENTS = 6

#: A release looks like ``MAJOR.MINOR.PATCH`` with an optional pre-release or
#: build suffix. Anything else in a ``VERSION`` file belongs to a different
#: project and is ignored rather than reported.
_RELEASE_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?$")


def _declared(value: str | None) -> str | None:
    """Return *value* stripped, or ``None`` when it declares nothing.

    ``ARG AISOC_VERSION`` with no ``--build-arg`` puts an empty string in the
    image's environment rather than leaving the variable unset, so "present"
    and "declared" are different questions and only the second one matters.
    """
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def version_from_file(start: Path) -> str | None:
    """The nearest plausible repo-root ``VERSION`` at or above *start*."""
    here = start if start.is_dir() else start.parent
    for directory in [here, *list(here.parents)[:_MAX_WALK_PARENTS]]:
        candidate = directory / "VERSION"
        try:
            if not candidate.is_file():
                continue
            text = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            # An unreadable candidate is not a version. Keep walking rather
            # than failing: a permission error on one directory says nothing
            # about the one above it.
            continue
        if _RELEASE_RE.match(text):
            return text
    return None


def resolve_version(
    *,
    env: Mapping[str, str] | None = None,
    start: Path | None = None,
) -> str:
    """Resolve the running version: build arg, then the tree, then unknown.

    Both arguments are injectable so the precedence can be tested without
    mutating process state or the filesystem the test itself runs from.
    """
    environ = os.environ if env is None else env
    stamped = _declared(environ.get(VERSION_ENV_VAR))
    if stamped is not None:
        return stamped

    from_tree = version_from_file(start if start is not None else Path(__file__).resolve().parent)
    return from_tree if from_tree is not None else UNKNOWN_VERSION


def resolve_revision(env: Mapping[str, str] | None = None) -> str | None:
    """The commit this build came from, or ``None`` when it was not stamped.

    ``None`` rather than ``"unknown"`` because this one has a natural absent
    value in JSON and the consumer is a machine as often as a person. The
    rule is the same either way: nothing is invented. There is deliberately
    no ``git rev-parse`` fallback — a source checkout's working tree is not
    the commit an image was built from, and answering with the former while
    the question is the latter is the kind of plausible-but-wrong answer this
    module exists to stop.
    """
    return _declared((os.environ if env is None else env).get(REVISION_ENV_VAR))
