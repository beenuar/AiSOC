"""A ChatOps verification prompt gets one reply, across a restart.

GHSA-vf98-8367-45mp, F04. Replay protection for these prompts was a
module-level ``set[str]`` in ``api/router.py``, under a comment saying
"anything more durable belongs in Redis once we move off the in-memory action
store" -- a future that had already arrived, since the store has been
Postgres-backed for several versions.

A set in process memory is not replay protection. It is empty after every
restart and was never populated on the second replica, so the same signed
payload -- inside its own expiry window, so the HMAC and the expiry both still
pass -- was accepted again. A single-use control enforced nothing across
either boundary.
"""

from __future__ import annotations

import importlib

import pytest
from app.services import action_store

#: Two tenants, because a claim keyed only on the action id is claimable
#: by whoever names the id. The id is a UUID in production, but how a row
#: is addressed is not an authorization control.
TENANT_A = "aaaaaaaa-0000-0000-0000-00000000000a"
TENANT_B = "bbbbbbbb-0000-0000-0000-00000000000b"


@pytest.fixture(autouse=True)
def _clean():
    action_store.clear()
    yield
    action_store.clear()


async def _seed(action_id: str) -> None:
    await action_store.save(
        {
            "id": action_id,
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "tenant_id": "22222222-2222-2222-2222-222222222222",
            "action_type": "notify_slack",
            "target": "#soc",
            "rationale": "verification prompt",
            "status": "awaiting_approval",
        }
    )


@pytest.mark.asyncio
async def test_the_first_reply_is_claimed():
    """Positive control, and it is the one that matters most here.

    Replay protection that refuses the *first* reply would pass every test
    below and silently discard every genuine answer an analyst gives -- which
    reads to them as a broken link rather than as a control.
    """
    await _seed("act-1")
    assert await action_store.claim_chatops_reply("act-1", tenant_id=TENANT_A) is True


@pytest.mark.asyncio
async def test_a_second_reply_to_the_same_prompt_is_refused():
    await _seed("act-2")
    assert await action_store.claim_chatops_reply("act-2", tenant_id=TENANT_A) is True
    assert await action_store.claim_chatops_reply("act-2", tenant_id=TENANT_A) is False


@pytest.mark.asyncio
async def test_two_different_prompts_do_not_collide():
    """Second positive control: the claim is per action, not a global latch."""
    await _seed("act-3")
    await _seed("act-4")
    assert await action_store.claim_chatops_reply("act-3", tenant_id=TENANT_A) is True
    assert await action_store.claim_chatops_reply("act-4", tenant_id=TENANT_A) is True


@pytest.mark.asyncio
async def test_the_claim_survives_the_router_module_being_reimported():
    """The restart, as far as a test can reach it.

    The defect was that the record of a reply lived in the module's own
    globals, so re-importing it -- which is what a process restart does to
    every module -- lost it. Re-importing `api.router` here and finding the
    claim still refused is the property; the durable half is proved against
    real Postgres by the row predicate in `claim_chatops_reply`.

    Note the direction of the check: `_chatops_replied` must not come back.
    A reimported module that re-creates the set would pass a test that only
    asked "is the second reply refused", because the *store* would refuse it
    anyway -- so this asserts the weak path is gone as well as that the
    strong one works.
    """
    await _seed("act-5")
    assert await action_store.claim_chatops_reply("act-5", tenant_id=TENANT_A) is True

    router_module = importlib.import_module("app.api.router")
    importlib.reload(router_module)
    assert not hasattr(router_module, "_chatops_replied"), (
        "the in-memory replay set is back; it is empty after a restart and was never populated on the second replica"
    )

    assert await action_store.claim_chatops_reply("act-5", tenant_id=TENANT_A) is False


@pytest.mark.asyncio
async def test_another_tenant_cannot_claim_the_reply() -> None:
    """The claim is scoped by tenant as well as by id.

    `claim_for_execution` has always matched on `id AND tenant_id AND status`;
    this claim shipped matching on the id alone, which the tenant-predicate
    gate caught. The tenant is not caller-settable -- it comes from `tid` in
    the signed ChatOps token -- so the predicate closes the gap rather than
    relying on a UUID being hard to guess.
    """

    assert await action_store.claim_chatops_reply("act-9", tenant_id=TENANT_A) is True
    # Tenant B names the same action id. Its claim must not be treated as the
    # same prompt, and must not consume tenant A's single reply.
    assert await action_store.claim_chatops_reply("act-9", tenant_id=TENANT_B) is True
    # Tenant A's prompt is still spent exactly once.
    assert await action_store.claim_chatops_reply("act-9", tenant_id=TENANT_A) is False
