"""A service must not pin its environment to a dev-class literal.

`.env.example` tells an operator that setting `ENVIRONMENT=production` is
enough, and `docker-compose.yml` reads that value. That promise only holds if
every service takes the variable rather than hardcoding a value.

One did not. `ingest-worker` carried `ENV: development` as a literal, and
`envmode.Current()` reads `ENV` *before* `ENVIRONMENT`
(`services/ingest/internal/envmode/envmode.go`), so the operator's setting was
shadowed on the one service that accepts events off the network — leaving
`JWT_SECRET must be set in non-development environments`
(`services/ingest/internal/config/config.go`) unreachable.

The failure shape is worth naming, because it is the one this repository keeps
finding: the escape hatch was documented, and the documentation was true of
every service but one. Nothing compared the two.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]

#: Mirrors DEV_ENVIRONMENTS in services/api/app/core/config.py and
#: devEnvironments in services/ingest/internal/envmode/envmode.go. A value in
#: this set relaxes an auth or secret requirement somewhere in the stack.
DEV_ENVIRONMENTS = frozenset({"development", "dev", "local", "demo", "test"})

#: The keys any service reads to decide whether it is in a dev-class
#: environment. `current_env_from_os()` reads ENV or ENVIRONMENT; the Go
#: mirror reads the same two; APP_ENV is checked by the realtime edge.
ENV_KEYS = ("ENV", "ENVIRONMENT", "APP_ENV")

COMPOSE_FILES = [
    REPO / "docker-compose.yml",
    REPO / "infra" / "compose" / "docker-compose.dev.yml",
]


def _services(path: pathlib.Path) -> dict:
    if not path.is_file():
        return {}
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("services") or {}


def _literal_dev_envs(path: pathlib.Path) -> list[str]:
    """Services pinning a dev-class environment as a literal, not a variable."""
    offenders: list[str] = []
    for name, service in _services(path).items():
        env = (service or {}).get("environment") or {}
        if not isinstance(env, dict):
            continue
        for key in ENV_KEYS:
            value = str(env.get(key, "")).strip()
            # `${...}` is interpolated and therefore follows the operator's
            # .env; only a bare value shadows it.
            if value and "${" not in value and value.lower() in DEV_ENVIRONMENTS:
                offenders.append(f"{path.name}:{name}:{key}={value}")
    return offenders


class TestTheDocumentedSwitchReachesEveryService:
    def test_the_shipped_compose_pins_no_dev_environment(self) -> None:
        offenders = _literal_dev_envs(REPO / "docker-compose.yml")
        assert not offenders, (
            f"these services hardcode a dev-class environment, so `ENVIRONMENT=production` in .env does not reach them: {offenders}"
        )

    #: The one file whose job is to be development, so the one file allowed
    #: to pin it. Everything else must interpolate, or an operator's
    #: `ENVIRONMENT=production` does not reach the service.
    DEV_OVERLAY_NAME = "docker-compose.dev.yml"

    @pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
    def test_no_tracked_compose_file_pins_one(self, path: pathlib.Path) -> None:
        """Every compose file except the developer overlay interpolates.

        Included because the next service to hardcode one is as likely to land
        in an overlay as in the root file, and a gate that reads one file is
        the shape that let this through.

        The developer overlay is exempt, and pins the literal deliberately.
        This assertion used to exempt it on the grounds that it interpolated
        too, which was true only because the file was a fifteen-line `include`
        alias that set nothing at all. Now that it carries the switch, an
        interpolated value there would let a stray `ENVIRONMENT=production` in
        `.env` silently defeat the overlay an operator passed on purpose.
        """
        if path.name == self.DEV_OVERLAY_NAME:
            offenders = _literal_dev_envs(path)
            assert offenders, (
                f"{path.name} is the developer overlay and no longer pins a dev-class "
                "environment, so `make up-dev` would produce the same posture as `make up` "
                "and this suite would still be green"
            )
            return
        assert not _literal_dev_envs(path)

    def test_the_gate_detects_the_literal_it_was_written_for(self, tmp_path: pathlib.Path) -> None:
        """Proven against the defect, not only against the fixed tree.

        Without this, a refactor that stopped reading `environment:` at all
        would report every file clean.
        """
        broken = tmp_path / "docker-compose.yml"
        broken.write_text(
            yaml.safe_dump({"services": {"ingest-worker": {"environment": {"ENV": "development"}}}}),
            encoding="utf-8",
        )
        assert _literal_dev_envs(broken) == ["docker-compose.yml:ingest-worker:ENV=development"]

    def test_an_interpolated_default_is_not_an_offender(self, tmp_path: pathlib.Path) -> None:
        """`${ENVIRONMENT:-development}` is the fix, so it must pass.

        A gate that rejected the default too would force the dev stack to
        require a variable nobody sets locally, and would be reverted.
        """
        ok = tmp_path / "docker-compose.yml"
        ok.write_text(
            yaml.safe_dump({"services": {"api": {"environment": {"ENVIRONMENT": "${ENVIRONMENT:-development}"}}}}),
            encoding="utf-8",
        )
        assert _literal_dev_envs(ok) == []
