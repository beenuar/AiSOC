"""The AI-chat classifier keeps labels and loses the content.

Depth plan wave 2, Phase 7.1.

The load-bearing assertion in this file is not "the classifier finds an AWS
key". It is that **the key is not in what the classifier returns**. A
minimisation feature whose evidence field contains the value it claims to
have minimised is worse than no feature: it creates a new copy of the
secret, in a table an operator believes is safe to keep, and labels it so an
attacker can find it.
"""

from __future__ import annotations

import pytest
from app._vendor.ai_redaction import _SECRET_PATTERNS
from app.services.ai_chat_compliance.classifier import (
    _SDK_LABEL,
    LABELS,
    SNIPPET_MAX,
    classify_chat,
    classify_message,
)

# Values with the right shape and no real credential behind them. The AWS
# and GitHub shapes are documented prefixes plus filler.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "a" * 36
VISA = "4111111111111111"  # the vendor's own documentation card; passes Luhn
NOT_A_CARD = "4111111111111112"  # one digit changed: fails Luhn


def test_every_shared_shape_is_classified():
    """A shape the SDK adds cannot arrive here unclassified.

    `classify_message` skips a shape it has no class for rather than
    guessing, which is the safe direction — guessing would put a credential
    in the personal-data bucket. This test is what stops "skipped" becoming
    permanent and silent.
    """
    missing = sorted({name for name, _ in _SECRET_PATTERNS} - set(_SDK_LABEL))
    assert not missing, f"shapes in the vendored SDK list with no class here: {missing}"
    assert set(_SDK_LABEL.values()) <= set(LABELS)


@pytest.mark.parametrize(
    ("text", "expected_label", "expected_shape"),
    [
        (f"here is the key AWS_SECRET={AWS_KEY} use it", "secrets", "aws_access_key"),
        (f"token {GH_TOKEN} for the runner", "secrets", "github_token"),
        ("mail me at alice@example.com please", "personal_data", "email"),
        ("call me on +44 20 7946 0958 tomorrow", "personal_data", "phone_number"),
        ("the patient SSN is 123-45-6789 on file", "regulated", "us_ssn"),
        ("passport number X1234567 expires soon", "regulated", "passport_number"),
        (f"card {VISA} expiry 01/30", "financial", "credit_card"),
        ("IBAN GB82WEST12345698765432 for the transfer", "financial", "iban"),
    ],
)
def test_each_class_is_recognised(text: str, expected_label: str, expected_shape: str):
    labels, shapes, spans = classify_message(text)
    assert expected_label in labels
    assert expected_shape in shapes
    assert spans


def test_a_digit_string_that_fails_luhn_is_not_payment_data():
    """The negative twin, differing in exactly one decisive character.

    The shared card shape is digits-only, so it also matches order ids and
    reference numbers. Without the Luhn check this classifier labels most
    conversations `financial` and nobody believes any of its labels.
    """
    labels, shapes, _ = classify_message(f"order reference {NOT_A_CARD} shipped")
    assert "financial" not in labels
    assert "credit_card" not in shapes


def test_the_snippet_never_contains_the_secret_it_reports():
    """The assertion this table's safety rests on."""
    result = classify_chat([f"deploy with AWS_SECRET_ACCESS_KEY={AWS_KEY} and {GH_TOKEN}"])

    assert "secrets" in result.labels
    assert result.snippet is not None
    assert AWS_KEY not in result.snippet
    assert GH_TOKEN not in result.snippet
    # And it is still useful: the reviewer can see what was found and where.
    assert "[aws_access_key]" in result.snippet
    assert "[github_token]" in result.snippet


@pytest.mark.parametrize(("name", "pattern"), list(_SECRET_PATTERNS))
def test_no_shared_shape_survives_into_the_snippet(name: str, pattern):
    """Every shape in the shared list, not just the two above.

    A per-pattern sweep rather than a couple of examples, because the
    failure mode is one unmasked pattern and a spot check would not find
    it.
    """
    samples = {
        "aws_access_key": AWS_KEY,
        "github_token": GH_TOKEN,
        "openai_key": "sk-" + "b" * 32,
        "slack_token": "xoxb-" + "1" * 20,
        "private_key": "-----BEGIN RSA PRIVATE KEY-----",
        "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
        "email": "alice@example.com",
        "credit_card": VISA,
    }
    value = samples[name]
    result = classify_chat([f"context before the value {value} and context after"])

    assert result.snippet is not None, f"{name}: nothing matched, so the mask was never exercised"
    assert value not in result.snippet, f"{name}: the matched value survived into the snippet"
    assert f"[{name}]" in result.snippet


def test_the_snippet_is_bounded_even_for_a_very_long_message():
    """The column is VARCHAR(280); the cut happens here.

    A conversation pasted into one message is the realistic case, and it is
    exactly the one where an unbounded snippet becomes a copy of the
    conversation.
    """
    long_message = ("lorem ipsum dolor sit amet " * 400) + f" key={AWS_KEY} " + ("tail " * 400)
    result = classify_chat([long_message])

    assert result.snippet is not None
    assert len(result.snippet) <= SNIPPET_MAX
    assert result.snippet_truncated is True
    # The window is centred on the match, so the evidence survived the cut
    # rather than being replaced by 280 characters of lorem ipsum.
    assert "[aws_access_key]" in result.snippet


def test_a_clean_conversation_produces_no_labels_and_no_snippet():
    """The other direction. A row with an empty label set and a snippet
    would be a stored fragment of a conversation that evidenced nothing,
    which is the exact thing this feature must not accumulate."""
    result = classify_chat(["what is the capital of France?", "Paris."])

    assert result.labels == ()
    assert result.shapes == ()
    assert result.snippet is None
    assert result.snippet_truncated is False
    assert result.messages_examined == 2
    assert result.messages_matched == 0


def test_counts_are_independent_of_the_labels():
    """Counted against messages this test wrote, not against a second call
    to the classifier. Four shipped meters in this repository read zero for
    four different reasons, and the common cause was asserting a meter
    against the thing being measured."""
    messages = [
        "hello",
        f"key {AWS_KEY}",
        "nothing here",
        "mail alice@example.com",
        "",
    ]
    result = classify_chat(messages)

    assert result.messages_examined == 5
    assert result.messages_matched == 2
    assert set(result.labels) == {"secrets", "personal_data"}
    assert result.secret_kinds == ("aws_access_key",)
