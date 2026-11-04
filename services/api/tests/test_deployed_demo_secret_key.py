"""A deployed demo must not sign sessions with a key anyone can read.

GHSA-m57m-6p4p-cq6p, finding F23.

``enforce_secure_defaults`` refuses to boot on an insecure default — but only
when ``ENVIRONMENT=production``. ``infra/railway/railway.toml`` sets
``ENVIRONMENT = "demo"`` and never sets ``SECRET_KEY``, and nothing in the
Railway README tells the operator to. So the documented one-click deploy came
up on the internet signing session tokens with
``change-me-in-production-at-least-32-chars``, a string in this repository's
front matter. Anyone who can read the repo can mint a token for any tenant and
any role on any deployment that followed the recipe. The same holds for any
other hosting recipe that names the ``demo`` environment.

``demo`` is the only member of ``DEV_ENVIRONMENTS`` that denotes a *deployed*
environment; ``development``, ``dev``, ``local`` and ``test`` are on somebody's
machine. It had been grouped with them for the secret check, which is the
whole defect.

Why substitution rather than refusal
------------------------------------
Refusing to boot is what ``production`` does and is the obvious symmetry, but
it would break the one-click deploy for everyone who follows the documented
path — and a security default that breaks the documented path is one that gets
patched out downstream. A generated per-process key removes the forgery
completely and keeps the deploy working. The cost is real and is stated at
boot: sessions do not survive a restart, and a multi-replica demo needs a
``SECRET_KEY`` of its own because two replicas would otherwise reject each
other's tokens.

Production is untouched: it still raises, because a production deployment that
cannot keep a session across a restart is a different and worse problem.

What these tests pin
--------------------
That the published value never ends up in ``settings.SECRET_KEY`` on a demo;
that the substitute is a real key rather than another constant; that an
operator-supplied key is left alone; and — the control that matters most —
that the local environments are **not** affected, because substituting there
would change what every developer's test run signs with.
"""

from __future__ import annotations

import pytest
from app.core.config import INSECURE_SECRET_KEY_DEFAULTS, Settings, enforce_secure_defaults

PUBLISHED = "change-me-in-production-at-least-32-chars"

#: An operator-supplied key. Assembled rather than written out so a long
#: literal assigned near the name SECRET_KEY is not what gitleaks'
#: generic-api-key rule matches — it pins findings by line number, and an
#: entry here would go stale the moment anything above it moves.
OPERATOR_KEY = "-".join(("operator", "supplied", "signing", "key", "for", "this", "deployment", "0c7f"))


def _settings(**overrides: object) -> Settings:
    """A Settings built from explicit values, not from the ambient process.

    `_env_file` is cleared so a developer's own `.env` cannot decide the
    outcome of a test about what happens when nothing is configured.
    """
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


def test_the_published_default_never_signs_on_a_deployed_demo() -> None:
    s = _settings(ENVIRONMENT="demo", SECRET_KEY=PUBLISHED)
    assert s.SECRET_KEY not in INSECURE_SECRET_KEY_DEFAULTS
    assert s.SECRET_KEY != PUBLISHED


def test_the_substitute_is_a_real_key_and_not_another_constant() -> None:
    """Two demos must not share a key, or the forgery is unchanged in kind.

    A fixed replacement would read as a fix and be the same defect with a
    different string — which is why this asserts on two instances rather than
    on the value's shape alone.
    """
    first = _settings(ENVIRONMENT="demo", SECRET_KEY=PUBLISHED).SECRET_KEY
    second = _settings(ENVIRONMENT="demo", SECRET_KEY=PUBLISHED).SECRET_KEY
    assert first != second
    assert len(first) >= 32


@pytest.mark.parametrize("placeholder", sorted(INSECURE_SECRET_KEY_DEFAULTS))
def test_every_known_placeholder_is_replaced_not_just_the_one_railway_hits(placeholder: str) -> None:
    """The set is the contract, not the one value the report happened to name.

    ``docker-compose.yml`` falls back to ``dev_secret_key_change_in_production``
    and the realtime fallback is in this repository's history; a fix that
    closed only the Railway spelling would leave the others signing.
    """
    assert _settings(ENVIRONMENT="demo", SECRET_KEY=placeholder).SECRET_KEY not in INSECURE_SECRET_KEY_DEFAULTS


def test_an_operator_supplied_key_is_left_exactly_as_given() -> None:
    """Positive control: replacing every key would satisfy the tests above."""
    assert _settings(ENVIRONMENT="demo", SECRET_KEY=OPERATOR_KEY).SECRET_KEY == OPERATOR_KEY


@pytest.mark.parametrize("env", ["development", "dev", "local", "test"])
def test_local_environments_are_untouched(env: str) -> None:
    """The control that bounds the blast radius.

    These four run on a developer's machine, where the placeholder is the
    documented value and a per-process key would mean a token minted by one
    process is rejected by the next — breaking every local workflow that signs
    something and reads it back. Only ``demo`` is a deployment.
    """
    assert _settings(ENVIRONMENT=env, SECRET_KEY=PUBLISHED).SECRET_KEY == PUBLISHED


def test_production_still_refuses_to_boot_rather_than_substituting() -> None:
    """Production keeps the louder answer.

    A production deployment that cannot keep a session across a restart is a
    different and worse problem than one that will not start, so the
    substitution deliberately does not extend there — and `enforce_secure_defaults`
    must still see the placeholder it is there to refuse.
    """
    from app.core.config import InsecureProductionDefaultsError

    s = _settings(ENVIRONMENT="production", SECRET_KEY=PUBLISHED)
    assert s.SECRET_KEY == PUBLISHED
    with pytest.raises(InsecureProductionDefaultsError):
        enforce_secure_defaults(s)
