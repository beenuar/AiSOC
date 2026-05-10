"""Dual-stack uvicorn entrypoint.

Why this exists:
    uvicorn's ``--host`` accepts a single string. If we pass ``::`` Python's
    asyncio explicitly sets ``IPV6_V6ONLY=1`` on the socket
    (see ``Lib/asyncio/base_events.py``), so the listener only accepts IPv6
    connections. On Fly.io we need both:

    * IPv6 — for 6PN private traffic (``aisoc-demo-api.internal:8000`` from
      sibling apps like the web Next.js rewriter), which routes via IPv6.
    * IPv4 — for ``fly-proxy``'s public health checks against
      ``api.tryaisoc.com/health``, which speak IPv4 to ``127.0.0.1:8000``.

    If we ``--host 0.0.0.0`` we lose 6PN reachability; if we ``--host ::``
    we lose the public health check (returns 503). The clean fix is to
    pre-bind a dual-stack socket with ``IPV6_V6ONLY=0`` and hand the file
    descriptor to uvicorn via ``--fd``.

This wrapper is the production CMD for the API container.
"""

from __future__ import annotations

import os
import socket
import sys


def main() -> None:
    port = int(os.environ.get("PORT", "8000"))

    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    # Allow IPv4-mapped IPv6 connections (dual-stack).
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("::", port))
    sock.listen(128)
    # Sockets created via socket.socket() in Python 3.4+ are non-inheritable
    # (close-on-exec). uvicorn re-opens the fd after exec, so we must mark
    # the descriptor as inheritable before handing off.
    os.set_inheritable(sock.fileno(), True)

    os.execvp(
        sys.executable,
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--fd",
            str(sock.fileno()),
        ],
    )


if __name__ == "__main__":
    main()
