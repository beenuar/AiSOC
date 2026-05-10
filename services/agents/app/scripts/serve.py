"""Dual-stack uvicorn entrypoint for the agents service.

See ``services/api/app/scripts/serve.py`` for the full rationale. Short
version: Python's asyncio sets ``IPV6_V6ONLY=1`` on IPv6 sockets, which
breaks Fly.io health checks (IPv4) when we bind to ``::``. Pre-binding a
dual-stack socket and handing the fd to uvicorn fixes both 6PN (IPv6)
and the fly-proxy edge (IPv4) at once.
"""

from __future__ import annotations

import os
import socket
import sys


def main() -> None:
    port = int(os.environ.get("PORT", "8084"))

    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("::", port))
    sock.listen(128)
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
