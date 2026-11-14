#!/usr/bin/env python3
"""The PEP 508 marker environment of whatever interpreter runs this file.

Why this is its own file
------------------------
``check_install_completeness.py`` decides which packages a lock declares for
a given environment, and the only honest source for "a given environment" is
the thing under test. Asking the *runner* which platform it is would answer a
question nobody asked: the runner is ubuntu-latest, the image is
``python:3.11-slim``, and markers like ``sys_platform == "win32"`` or
``python_full_version < "3.11.3"`` are exactly where those two disagree.

So the environment is read out of the image:

    docker run --rm -i --entrypoint python aisoc-api:first - \\
        < scripts/marker_environment.py > env.json

That works because this file imports nothing outside the standard library and
has no siblings to find. A service image carries no ``scripts/`` directory and
no third-party packaging library, so anything heavier could not be piped into
it, and a helper that cannot run inside the image would have to guess.

The keys and their spellings are PEP 508's, and the expressions below are the
ones ``packaging.markers.default_environment()`` uses. ``packaging`` is not
imported here for the reason above — this half must run anywhere — and the
evaluation half, where the version-comparison semantics actually live, uses
the reference implementation rather than a second opinion.

One known narrowing: ``implementation_version`` here is the plain dotted
release. ``packaging`` additionally encodes a prerelease interpreter as, for
example, ``3.13.0rc1``. No marker in any lock in this repository reads
``implementation_version`` at all, and the gate refuses a marker it cannot
evaluate rather than guessing, so the narrowing cannot silently change a
verdict.
"""

from __future__ import annotations

import json
import os
import platform
import sys


def marker_environment() -> dict[str, str]:
    """This interpreter's PEP 508 marker variables."""
    return {
        "implementation_name": sys.implementation.name,
        "implementation_version": ".".join(str(part) for part in sys.implementation.version[:3]),
        "os_name": os.name,
        "platform_machine": platform.machine(),
        "platform_python_implementation": platform.python_implementation(),
        "platform_release": platform.release(),
        "platform_system": platform.system(),
        "platform_version": platform.version(),
        "python_full_version": platform.python_version(),
        "python_version": ".".join(platform.python_version_tuple()[:2]),
        "sys_platform": sys.platform,
    }


if __name__ == "__main__":
    print(json.dumps(marker_environment(), indent=2, sort_keys=True))
