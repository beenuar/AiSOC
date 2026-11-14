"""Neither SSO handler can ever mint an identity nobody authenticated.

`saml.py` issued a signed token for `stub-saml-user` whenever `python3-saml`
failed to import, and `python3-saml` is declared in no manifest — so on a
stock install the `ImportError` branch was the *only* reachable path through
the assertion consumer. `oidc.py` did the same for `oidc-stub-user` whenever
`OIDC_ISSUER` or `OIDC_CLIENT_ID` was unset, which is the default.

Both set `aisoc_token` as a cookie. The API verifies a bearer token and does
not read that cookie, which is the only reason this was not already a full
authentication bypass — and a cookie the API ignores today is a cookie the
API might read tomorrow, which is exactly the change Phase 4 of the parity
plan makes. The stubs had to go before SSO was made to work, not after.

Asserted three ways, because deleting the branch is not the same as proving
no path reaches it:

* neither identity appears anywhere in the tree;
* the handlers answer 501 rather than a token when unconfigured;
* no response from either module sets the session cookie on that path.
"""

from __future__ import annotations

import pathlib

import pytest

SERVICE_ROOT = pathlib.Path(__file__).resolve().parents[1]

#: The two identities. Spelled here so the assertion names what it forbids.
FORBIDDEN_SUBJECTS = ("stub-saml-user", "oidc-stub-user")


def _auth_sources() -> list[pathlib.Path]:
    return sorted((SERVICE_ROOT / "app" / "auth").rglob("*.py"))


class TestNeitherIdentityExists:
    @pytest.mark.parametrize("subject", FORBIDDEN_SUBJECTS)
    def test_no_module_mentions_it(self, subject: str) -> None:
        offenders = [
            f"{path.relative_to(SERVICE_ROOT)}:{number}"
            for path in _auth_sources()
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if subject in line and not line.lstrip().startswith("#")
        ]
        assert not offenders, (
            f"{subject!r} is still constructible at {offenders}. It was minted whenever a "
            "library failed to import or a variable was unset, which on a stock install is "
            "every time"
        )

    def test_the_sources_were_actually_read(self) -> None:
        """A glob that matches nothing makes every assertion above vacuous."""
        sources = _auth_sources()
        assert len(sources) >= 2, f"expected the auth modules, found {sources}"
        assert any(p.name == "saml.py" for p in sources)
        assert any(p.name == "oidc.py" for p in sources)


class TestAnUnconfiguredHandlerRefuses:
    def test_saml_declares_the_dependency_it_needs(self) -> None:
        """The `ImportError` branch existed because nothing installed it.

        Deleting the branch without declaring the dependency would turn a
        silent stub into a 501 nobody can clear, which is more honest but
        still unusable.
        """
        manifest = (SERVICE_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        assert "python3-saml" in manifest, (
            "python3-saml is still declared in no install path, so the SAML routes cannot work on any deployment"
        )

    @pytest.mark.parametrize("module", ["saml", "oidc"])
    def test_an_unconfigured_path_answers_501_not_a_token(self, module: str) -> None:
        source = (SERVICE_ROOT / "app" / "auth" / f"{module}.py").read_text(encoding="utf-8")
        assert "501" in source, (
            f"{module}.py no longer answers 501 anywhere. An unconfigured identity provider "
            "must refuse, and refusing with a status that says 'not implemented' is what "
            "tells an operator the difference between a misconfiguration and a rejection"
        )

    @pytest.mark.parametrize("module", ["saml", "oidc"])
    def test_no_cookie_is_set_outside_a_verified_assertion(self, module: str) -> None:
        """Every `set_cookie` must sit downstream of a real verification.

        Counted rather than inspected for context, because the two that
        existed were both in `except` blocks: one on `ImportError` and one on
        a missing configuration variable. Neither had verified anything.
        """
        source = (SERVICE_ROOT / "app" / "auth" / f"{module}.py").read_text(encoding="utf-8")
        lines = source.splitlines()
        # Parsed by indentation rather than by a flag. A first draft set a
        # boolean on `except` and cleared it only at column zero, so once a
        # handler appeared anywhere in a function every later line in that
        # file counted as inside it — and the two legitimate `set_cookie`
        # calls downstream of a verified assertion were reported as the
        # defect.
        except_indent: int | None = None
        offenders = []
        for number, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue
            indent = len(line) - len(line.lstrip())
            if except_indent is not None and indent <= except_indent:
                except_indent = None
            if stripped.startswith(("except ", "except:")):
                except_indent = indent
                continue
            if except_indent is not None and "set_cookie" in stripped:
                offenders.append(f"{module}.py:{number}")
        assert not offenders, (
            f"a session cookie is set from an exception handler at {offenders}, which is where both stub identities were minted"
        )
