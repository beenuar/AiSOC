"""No raw hostname, user, IP, domain or email reaches a hosted model.

Parity plan 2.4, and the gate claim-matrix row 19 now rests on.

The point of this file
----------------------
Row 19 ("no data exfiltration") used to be gated by
`test_privacy_redactor.py`, which calls the redactor directly and asserts it
redacts. That is a true statement about a function. It said nothing about
the product, because **no LLM call site invoked the redactor**, and parity
1.1 had to retract the claim for exactly that reason.

So these tests drive `safe_ainvoke`, the function every LLM call in
`services/agents` passes through, and inspect what the fake provider
actually received. A test that calls the redactor cannot tell a wired
control from an unwired one; a test that inspects the outbound payload can.
"""

from __future__ import annotations

import pytest
from app.llm import egress_privacy
from app.llm.contract import safe_ainvoke


class _Message:
    """Minimal message with the attribute the contract reads."""

    def __init__(self, content: str, role: str = "user") -> None:
        self.content = content
        self.type = role
        self.role = role

    def model_copy(self, *, update: dict) -> _Message:
        return _Message(update.get("content", self.content), self.role)


class _Recorder:
    """A fake provider that records exactly what it was sent."""

    def __init__(self, *, model: str, base_url: str | None = None, reply: str = "ok") -> None:
        self.model_name = model
        self.base_url = base_url
        self.reply = reply
        self.seen: list[str] = []

    async def ainvoke(self, messages, **_kwargs):  # noqa: ANN001
        self.seen = [getattr(m, "content", "") for m in messages]
        return _Message(self.reply, "assistant")


#: Customer-identifying evidence, which must never reach a hosted model.
#: Realistic shapes, because a redactor tuned on `example.com` and
#: `10.0.0.1` can pass while missing what a real alert carries.
EVIDENCE = {
    "hostname": "FIN-WKSTN-04782.corp.internal",
    "username": "priya.raghavan",
    "internal_ip": "10.42.17.9",
    "email": "priya.raghavan@acme-corp.com",
    "path": "C:\\Users\\priya.raghavan\\AppData\\payroll.xlsx",
}

#: Public threat indicators, which are **deliberately not** redacted. They
#: are IOCs rather than customer PII and the agent needs them to reason, so
#: this is a documented trade-off (`services/agents/app/privacy/redactor.py`
#: and `docs/trust/`) rather than a gap. Asserted explicitly below, so the
#: trade-off is pinned and a future change to it is a visible decision.
PUBLIC_IOCS = {
    "c2_domain": "update-delivery-cdn.xyz",
    # A genuinely globally-routable address. The RFC 5737 documentation
    # ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are the
    # obvious choice for a test and the wrong one here: `ipaddress`
    # classifies them as not-global, so the redactor treats them as
    # internal and a test using one measures the opposite of what it says.
    "c2_ip": "8.8.8.8",
}

PROMPT = (
    "Triage this alert. Host {hostname} running as {username} connected to "
    "{c2_ip} resolving {c2_domain}. Internal source {internal_ip}. "
    "The account's address is {email} and it opened {path}."
).format(**EVIDENCE, **PUBLIC_IOCS)


@pytest.mark.asyncio
class TestHostedEgress:
    async def test_no_raw_evidence_reaches_a_hosted_provider(self) -> None:
        """The claim, tested through the path the product uses."""
        provider = _Recorder(model="gpt-4o-mini", base_url="https://api.openai.com/v1")
        await safe_ainvoke(provider, [_Message(PROMPT)])

        assert provider.seen, "the provider was never called, so this proves nothing"
        sent = "\n".join(provider.seen)
        leaked = {name: value for name, value in EVIDENCE.items() if value in sent}
        assert not leaked, f"these reached a hosted provider unredacted: {sorted(leaked)}. Payload was: {sent[:400]}"

    async def test_public_iocs_are_deliberately_left_alone(self) -> None:
        """The documented trade-off, pinned.

        A C2 domain and a public IP are threat intelligence, not customer
        data. Redacting them would leave the model unable to reason about
        the thing the alert is actually about, and they identify an attacker
        rather than the customer. If this ever changes it should be a
        decision somebody made, not a silent drift, which is why it is a
        test rather than a comment.
        """
        provider = _Recorder(model="gpt-4o-mini", base_url="https://api.openai.com/v1")
        await safe_ainvoke(provider, [_Message(PROMPT)])
        sent = "\n".join(provider.seen)
        for name, value in PUBLIC_IOCS.items():
            assert value in sent, f"{name} was redacted; the agent cannot reason about it"

    async def test_the_model_still_gets_usable_structure(self) -> None:
        """Redaction that destroys the prompt is not a win.

        The model has to be able to tell that two mentions of the same host
        are the same host, or the verdict degrades and the control gets
        turned off.
        """
        provider = _Recorder(model="gpt-4o-mini", base_url="https://api.openai.com/v1")
        text = f"Host {EVIDENCE['hostname']} alerted. Host {EVIDENCE['hostname']} again."
        await safe_ainvoke(provider, [_Message(text)])

        sent = provider.seen[0]
        assert EVIDENCE["hostname"] not in sent
        # Whatever token replaced it must appear twice, consistently.
        tokens = [word for word in sent.split() if word.isupper() and "_" in word]
        assert tokens, f"no pseudonym token in: {sent}"
        assert len(set(tokens)) == 1, f"the same host got two different tokens: {set(tokens)}"
        assert len(tokens) == 2, f"expected the token twice, saw {len(tokens)}: {sent}"

    async def test_the_answer_comes_back_re_identified(self) -> None:
        """An analyst reads about their host, not about HOST_1."""
        provider = _Recorder(model="gpt-4o-mini", base_url="https://api.openai.com/v1")
        result = await safe_ainvoke(provider, [_Message(PROMPT)])
        # The fake echoes a fixed reply, so drive the restore directly on a
        # session that has seen the evidence.
        session = egress_privacy.open_session(model="gpt-4o-mini", base_url="https://api.openai.com/v1")
        session.redact_messages([_Message(PROMPT)])
        redacted_host = session.pseudonymizer.redact(EVIDENCE["hostname"])
        restored = session.restore(_Message(f"Isolate {redacted_host} immediately."))
        assert EVIDENCE["hostname"] in restored.content, (
            "the answer came back still pseudonymized, which makes this a degradation rather than a privacy control"
        )
        assert result is not None


@pytest.mark.asyncio
class TestLocalProviders:
    async def test_a_local_model_sees_the_real_evidence_by_default(self) -> None:
        """A local model is inside the same trust boundary as the evidence.

        Pseudonymizing it costs the model the context it reasons with and
        buys nothing, because the data never leaves the deployment.
        """
        provider = _Recorder(model="llama3.2:3b", base_url="http://ollama:11434")
        await safe_ainvoke(provider, [_Message(PROMPT)])
        assert EVIDENCE["hostname"] in provider.seen[0]

    async def test_an_unrecognised_provider_is_treated_as_hosted(self) -> None:
        """The safe default. A provider nobody has reasoned about is one
        whose network path nobody has reasoned about."""
        provider = _Recorder(model="some-new-model", base_url="https://inference.example.net")
        await safe_ainvoke(provider, [_Message(PROMPT)])
        assert EVIDENCE["hostname"] not in provider.seen[0]


class TestTheDecision:
    @pytest.mark.parametrize(
        ("model", "base_url", "expected"),
        [
            ("gpt-4o", "https://api.openai.com/v1", True),
            ("claude-3-5-sonnet", "https://api.anthropic.com", True),
            ("llama3.2:3b", "http://ollama:11434", False),
            ("aisoc-triage", "http://litellm:4000", False),
            ("mistral", "http://localhost:8080", False),
            ("anything", None, True),
        ],
    )
    def test_hosted_and_local_are_told_apart(self, model, base_url, expected) -> None:  # noqa: ANN001
        assert egress_privacy.should_pseudonymize(model=model, base_url=base_url) is expected

    def test_a_tenant_setting_overrides_the_default_in_both_directions(self) -> None:
        assert egress_privacy.should_pseudonymize(model="llama3.2:3b", base_url="http://ollama:11434", tenant_setting=True) is True
        assert egress_privacy.should_pseudonymize(model="gpt-4o", base_url="https://api.openai.com/v1", tenant_setting=False) is False


@pytest.mark.asyncio
class TestTheGateCannotPassVacuously:
    async def test_removing_the_redaction_makes_the_leak_test_fail(self, monkeypatch) -> None:  # noqa: ANN001
        """Proves this file would catch the regression it exists for.

        Without this, a refactor that quietly stopped calling
        `redact_messages` would leave every assertion above passing on a
        provider that was never handed anything to leak.
        """
        monkeypatch.setattr(egress_privacy.EgressSession, "redact_messages", lambda self, messages: messages)
        provider = _Recorder(model="gpt-4o-mini", base_url="https://api.openai.com/v1")
        await safe_ainvoke(provider, [_Message(PROMPT)])
        assert EVIDENCE["hostname"] in provider.seen[0], (
            "the control was disabled and the evidence still did not reach the provider, "
            "which means this file is not measuring what it claims to"
        )
