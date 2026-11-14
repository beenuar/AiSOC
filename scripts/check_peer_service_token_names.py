#!/usr/bin/env python3
"""The credential a service presents must be the one its peer accepts.

Why this gate exists
--------------------
``AISOC_<SERVICE>_SERVICE_TOKEN`` means "the token that service accepts". Read
that way it is consistent; read as "my token" it is backwards, and the agents
service read it both ways at once. Six modules under ``services/agents/app``
resolved a credential for an outbound call to the API: four got the order right
(``AISOC_API_SERVICE_TOKEN`` then ``AISOC_SERVICE_TOKEN``) and two presented
``AISOC_AGENTS_SERVICE_TOKEN`` — the token the *agents* service accepts, which
the API has never validated — so ``GET /graph/incident-context`` and
``POST /approvals`` answered 401 on every deployment. One concept declared six
times had already diverged.

``scripts/check_service_token_wiring.py`` could not see it: that gate asks
whether a call carries *a* credential, which all six did.

Three arms, each failing in both directions:

1. **No backwards name.** Nothing under ``services/agents/app`` may put this
   service's own token into an ``Authorization: Bearer`` header. That is the
   defect shape exactly, and it is statically decidable.

2. **One resolution order.** The names ``peer_tokens.token_for("API")`` reads
   must be the names ``resolve_service_token()`` in the API's ``deps.py``
   validates, in the same order. A change to either side reds the build.

3. **The recorded deviation stays recorded.** ``alert_writeback.service_token_valid``
   guards the ``X-AiSOC-Service-Token`` header against ``AISOC_AGENTS_SERVICE_TOKEN``
   — the caller's name rather than its own. Nine agents call sites present that
   header and work, so it is load-bearing where it stands. Pinned here so it
   reads as a known exception; if somebody changes it, this says so rather than
   passing in silence.

Run ``--self-test`` to see each arm injected and caught.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root  # noqa: E402

#: The tree git says we are in, not whatever sits two levels above this
#: file. A gate run from a copied `scripts/` directory would otherwise
#: judge a tree it never opened.
ROOT = repo_root()

AGENTS_APP = ROOT / "services" / "agents" / "app"
PEER_TOKENS = AGENTS_APP / "security" / "peer_tokens.py"
API_DEPS = ROOT / "services" / "api" / "app" / "api" / "v1" / "deps.py"
ALERT_WRITEBACK = ROOT / "services" / "api" / "app" / "api" / "v1" / "endpoints" / "alert_writeback.py"

#: This service's own name, as the vendored ``tenant_scope`` spells it.
SELF_TOKEN_ENV = "AISOC_AGENTS_SERVICE_TOKEN"

#: The order the API validates in, asserted against both implementations
#: rather than assumed by either.
EXPECTED_API_ORDER = ["AISOC_API_SERVICE_TOKEN", "AISOC_SERVICE_TOKEN"]

#: Arm 3. The one place the caller's own name is legitimately the accepted one.
RECORDED_DEVIATION = {
    "path": "services/api/app/api/v1/endpoints/alert_writeback.py",
    "symbol": "_SERVICE_TOKEN_ENV",
    "value": SELF_TOKEN_ENV,
    "reason": (
        "guards the X-AiSOC-Service-Token header, which nine agents call sites already present; renaming it would 401 all nine at once"
    ),
}

_BEARER = re.compile(r"Authorization\"?\s*:\s*f?\"Bearer")


def _show(path: Path) -> str:
    """Repo-relative when it is in the repo, absolute otherwise (self-test temp dirs)."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _getenv_names(node: ast.AST) -> list[str]:
    """Every ``os.getenv("NAME")`` literal inside ``node``, in source order."""
    names: list[str] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        fn = child.func
        attr = getattr(fn, "attr", None) or getattr(fn, "id", None)
        if attr not in {"getenv", "environ"}:
            continue
        if child.args and isinstance(child.args[0], ast.Constant) and isinstance(child.args[0].value, str):
            names.append(child.args[0].value)
    return names


def _function(tree: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _arm_one_no_backwards_name(agents_app: Path) -> list[str]:
    """No outbound Bearer call may carry this service's own token."""
    problems: list[str] = []
    for path in sorted(agents_app.rglob("*.py")):
        if path == PEER_TOKENS or path.name.startswith("tenant_scope"):
            # `peer_tokens.self_token` and the vendored request-side guard both
            # name it on purpose: one to label it, the other to *accept* it.
            continue
        text = path.read_text(encoding="utf-8")
        if SELF_TOKEN_ENV not in text or not _BEARER.search(text):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if SELF_TOKEN_ENV in line and "getenv" in line:
                problems.append(
                    f"{_show(path)}:{lineno} resolves {SELF_TOKEN_ENV} in a module that sends "
                    f"`Authorization: Bearer` — that is the token this service *accepts*. "
                    f"Use app.security.peer_tokens.token_for(<peer>)."
                )
    return problems


def _arm_two_one_resolution_order(peer_tokens: Path, api_deps: Path) -> list[str]:
    """Both sides of the API contract must read the same names in the same order."""
    problems: list[str] = []

    if not peer_tokens.is_file():
        return [f"{_show(peer_tokens)} is missing; nothing defines which credential a peer is given"]

    tree = ast.parse(peer_tokens.read_text(encoding="utf-8"))
    token_for = _function(tree, "token_for")
    if token_for is None:
        problems.append(f"{_show(peer_tokens)} defines no token_for(); the peer-directed resolver is gone")
    else:
        # `AISOC_{peer}_SERVICE_TOKEN` is an f-string, so only the shared
        # fallback appears as a literal. Both halves are checked: the template
        # by source shape, the fallback by name.
        source = ast.unparse(token_for)
        if "AISOC_{peer.upper()}_SERVICE_TOKEN" not in source.replace("'", '"').replace('f"', '"'):
            problems.append("peer_tokens.token_for no longer derives the per-peer name from its argument")
        if _getenv_names(token_for) != [EXPECTED_API_ORDER[1]]:
            problems.append(f"peer_tokens.token_for falls back to {_getenv_names(token_for)}, expected [{EXPECTED_API_ORDER[1]!r}]")

    api_tree = ast.parse(api_deps.read_text(encoding="utf-8"))
    resolver = _function(api_tree, "resolve_service_token")
    if resolver is None:
        problems.append(f"{_show(api_deps)} defines no resolve_service_token(); the accepting side moved")
    else:
        accepted = _getenv_names(resolver)
        if accepted != EXPECTED_API_ORDER:
            problems.append(
                f"the API accepts {accepted} but peer_tokens presents {EXPECTED_API_ORDER}; "
                "the two sides of one call name different variables"
            )
    return problems


def _arm_three_recorded_deviation(writeback: Path) -> list[str]:
    """The one legitimate use of the caller's name, pinned in both directions."""
    if not writeback.is_file():
        return [f"{RECORDED_DEVIATION['path']} is gone; re-derive the recorded deviation"]
    text = writeback.read_text(encoding="utf-8")
    expected = f'{RECORDED_DEVIATION["symbol"]} = "{RECORDED_DEVIATION["value"]}"'
    if expected not in text:
        return [
            f"the recorded deviation in {RECORDED_DEVIATION['path']} changed: expected `{expected}`. "
            f"It was recorded because it {RECORDED_DEVIATION['reason']}. "
            "If it moved deliberately, update RECORDED_DEVIATION in this gate in the same commit."
        ]
    return []


def run(
    *,
    agents_app: Path = AGENTS_APP,
    peer_tokens: Path = PEER_TOKENS,
    api_deps: Path = API_DEPS,
    writeback: Path = ALERT_WRITEBACK,
) -> list[str]:
    return (
        _arm_one_no_backwards_name(agents_app)
        + _arm_two_one_resolution_order(peer_tokens, api_deps)
        + _arm_three_recorded_deviation(writeback)
    )


def _self_test() -> int:
    """Inject each drift and require the gate to name it.

    A gate proven only against a clean tree is a gate nobody has seen work.
    """
    failures: list[str] = []

    def expect(label: str, problems: list[str], *, want: bool) -> None:
        if bool(problems) != want:
            failures.append(f"{label}: expected {'a finding' if want else 'none'}, got {problems or 'none'}")

    expect("clean tree", run(), want=False)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        # Arm 1: a module that presents this service's own token.
        app = root / "app"
        (app / "context").mkdir(parents=True)
        (app / "context" / "leaky.py").write_text(
            "import os\n"
            "def headers(t):\n"
            '    token = os.getenv("AISOC_AGENTS_SERVICE_TOKEN", "")\n'
            '    return {"Authorization": f"Bearer {token}"}\n'
        )
        expect("arm 1 — backwards name", _arm_one_no_backwards_name(app), want=True)

        # ...and the same module routed through the resolver is clean.
        (app / "context" / "leaky.py").write_text(
            "from app.security import peer_tokens\ndef headers(t):\n    return peer_tokens.api_bearer_headers(t)\n"
        )
        expect("arm 1 — resolver used", _arm_one_no_backwards_name(app), want=False)

        # Arm 2: the accepting side renamed.
        drifted = root / "deps.py"
        drifted.write_text(
            'import os\ndef resolve_service_token():\n    return os.getenv("AISOC_PLATFORM_TOKEN") or os.getenv("AISOC_SERVICE_TOKEN")\n'
        )
        expect("arm 2 — accepting side renamed", _arm_two_one_resolution_order(PEER_TOKENS, drifted), want=True)

        # Arm 2: the presenting side deleted.
        expect("arm 2 — resolver missing", _arm_two_one_resolution_order(root / "nope.py", API_DEPS), want=True)

        # Arm 3: the recorded deviation moved.
        moved = root / "alert_writeback.py"
        moved.write_text('_SERVICE_TOKEN_ENV = "AISOC_SOMETHING_ELSE"\n')
        expect("arm 3 — deviation moved", _arm_three_recorded_deviation(moved), want=True)

    if failures:
        print("SELF-TEST FAILED")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("SELF-TEST OK — every arm was injected and caught, and the clean tree passes")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="inject each drift and assert the gate names it")
    args = parser.parse_args()

    if args.self_test:
        return _self_test()

    problems = run()
    if problems:
        print("FAIL — the credential presented is not the one the peer accepts:")
        for p in problems:
            print(f"  - {p}")
        return 1

    print(
        f"OK — peer-directed credentials: agents presents {EXPECTED_API_ORDER[0]} then {EXPECTED_API_ORDER[1]} "
        f"to the API, which accepts exactly those; 1 recorded deviation, unchanged"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
