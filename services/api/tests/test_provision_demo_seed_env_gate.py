"""SEC-2: tenant provisioning must not seed demo identities outside dev."""

from __future__ import annotations

import inspect

import pytest


@pytest.mark.parametrize("env", ["production", "prod", "staging", "", None])
def test_env_not_dev(env):
    from app.core.config import is_dev_env

    assert is_dev_env(env) is False


@pytest.mark.parametrize("env", ["development", "dev", "local", "demo", "test"])
def test_env_dev(env):
    from app.core.config import is_dev_env

    assert is_dev_env(env) is True


def test_provisioner_gates_seed_on_env():
    from app.services.tenant_provision import provisioner

    src = inspect.getsource(provisioner.provision_from_waitlist)
    assert "is_dev_env" in src, "SEC-2 gate missing from provisioner"
