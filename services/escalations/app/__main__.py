"""Entry point: `python -m app` (and the container CMD) start the bridge here.

Named `__main__.py` so the module-reachability gate recognises it as a
service entry point the way it does every other service's — the bridge is
started by a command, not imported, so without this the gate reads bridge.py
as dead code (it has no production importer).
"""

from app.bridge import main

if __name__ == "__main__":
    main()
