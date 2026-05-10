"""Dual-stack uvicorn entrypoint for the connectors service.

See ``services/api/app/scripts/serve.py`` for the full rationale.
"""

from __future__ import annotations

import os
import socket
import sys


def main() -> None:
    port = int(os.environ.get("PORT", "8087"))

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
