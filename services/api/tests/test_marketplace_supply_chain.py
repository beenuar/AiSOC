"""Plugins run in-process. What gets installed has to be what was reviewed.

Three claims the documentation made that the code did not:

**"verify signed manifests"** — `_get_registered_pub_key` returned `None`
unconditionally, so `publish_plugin` skipped verification entirely and stored
`verified: False`. The rejection branch was unreachable: a plugin could not
be refused for a bad signature, ever.

**"against an allow-list"** — there was no allow-list. There was a deny list
of three cloud-metadata hostnames, which answers a much smaller question.

**"pin image digests at install time"** — nothing resolved a tag to a digest
or recorded one. `:latest` stayed mutable after install, so what a deployment
was running had no answer after the fact.

The signature gate does not close the digest hole, which is the subtle part:
it verifies whatever arrived, and cannot tell you that what arrived is what
was reviewed.
"""

from __future__ import annotations

import pytest
from app.services.marketplace_publishers import (
    PublisherKeyError,
    RegisteredKey,
    parse_public_key,
    verify_against,
)
from app.services.plugin_manager import PluginError, _registry_of, _require_pinned, _validate_oci_ref
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

PINNED = "ghcr.io/example/plugin@sha256:" + "a" * 64
TAGGED = "ghcr.io/example/plugin:latest"


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    private = Ed25519PrivateKey.generate()
    pem = (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private, pem


def _registered(pem: str, fingerprint: str = "fp") -> RegisteredKey:
    import uuid

    return RegisteredKey(
        id=uuid.uuid4(),
        publisher_id=uuid.uuid4(),
        public_key_pem=pem,
        fingerprint=fingerprint,
        label="",
    )


class TestPublisherKeys:
    def test_an_ed25519_key_parses_and_fingerprints_stably(self):
        _, pem = _keypair()
        key, fingerprint = parse_public_key(pem)
        assert isinstance(key, Ed25519PublicKey)
        assert len(fingerprint) == 64
        assert parse_public_key(pem)[1] == fingerprint

    def test_two_keys_have_different_fingerprints(self):
        assert parse_public_key(_keypair()[1])[1] != parse_public_key(_keypair()[1])[1]

    def test_a_non_ed25519_key_is_refused_at_registration(self):
        """Rejecting here rather than at verification means a publisher finds
        out while registering, not when their first release is silently
        unverifiable."""
        rsa = generate_private_key(public_exponent=65537, key_size=2048)
        pem = (
            rsa.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        with pytest.raises(PublisherKeyError, match="Ed25519"):
            parse_public_key(pem)

    def test_garbage_is_refused(self):
        with pytest.raises(PublisherKeyError):
            parse_public_key("not a pem")


class TestSignatureVerification:
    def test_a_good_signature_names_the_key_that_verified(self):
        private, pem = _keypair()
        payload = b"tarball-bytes"
        assert verify_against([_registered(pem, "fp-1")], payload, private.sign(payload)) == "fp-1"

    def test_a_signature_from_an_unregistered_key_verifies_against_nothing(self):
        # This is the branch that was unreachable. Before the publisher tables
        # existed, no key was ever found, so this case could not be detected.
        _, registered_pem = _keypair()
        other, _ = _keypair()
        payload = b"tarball-bytes"
        assert verify_against([_registered(registered_pem)], payload, other.sign(payload)) is None

    def test_a_tampered_payload_does_not_verify(self):
        private, pem = _keypair()
        signature = private.sign(b"original")
        assert verify_against([_registered(pem)], b"tampered", signature) is None

    def test_every_active_key_is_tried_so_a_rotation_does_not_break_publishing(self):
        """Forcing a publisher to re-sign everything during a rotation is how
        rotations get skipped."""
        old, old_pem = _keypair()
        _, new_pem = _keypair()
        payload = b"signed-with-the-old-key"

        result = verify_against(
            [_registered(new_pem, "fp-new"), _registered(old_pem, "fp-old")],
            payload,
            old.sign(payload),
        )
        assert result == "fp-old"

    def test_no_registered_keys_verifies_nothing(self):
        private, _ = _keypair()
        assert verify_against([], b"x", private.sign(b"x")) is None


class TestDigestPinning:
    def test_a_pinned_reference_is_accepted(self):
        assert _require_pinned(PINNED) == PINNED

    def test_a_mutable_tag_is_refused(self):
        # :latest resolves to one image today and another tomorrow, so what a
        # deployment is running has no answer after the fact.
        with pytest.raises(PluginError, match="pinned to a digest"):
            _require_pinned(TAGGED)

    def test_a_bare_repo_with_no_tag_is_refused(self):
        with pytest.raises(PluginError):
            _require_pinned("ghcr.io/example/plugin")

    def test_the_opt_out_exists_because_requiring_it_would_break_upgrades(self, monkeypatch: pytest.MonkeyPatch):
        """A control an operator has to disable wholesale is worse than one
        they can adopt."""
        monkeypatch.setenv("AISOC_PLUGIN_ALLOW_UNPINNED", "1")
        assert _require_pinned(TAGGED) == TAGGED

    def test_a_short_or_malformed_digest_is_not_a_pin(self):
        with pytest.raises(PluginError):
            _require_pinned("ghcr.io/example/plugin@sha256:abc")


class TestRegistryAllowlist:
    def test_any_registry_when_unset_so_upgrades_do_not_break(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("AISOC_PLUGIN_REGISTRY_ALLOWLIST", raising=False)
        assert _validate_oci_ref(PINNED) == PINNED

    def test_an_allowed_registry_passes(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AISOC_PLUGIN_REGISTRY_ALLOWLIST", "ghcr.io, registry.internal")
        assert _validate_oci_ref(PINNED) == PINNED

    def test_a_registry_not_on_the_list_is_refused(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AISOC_PLUGIN_REGISTRY_ALLOWLIST", "registry.internal")
        with pytest.raises(PluginError, match="not in AISOC_PLUGIN_REGISTRY_ALLOWLIST"):
            _validate_oci_ref(PINNED)

    def test_an_implicit_docker_hub_reference_fails_a_list_rather_than_passing_it(self, monkeypatch: pytest.MonkeyPatch):
        """`library/thing:1.0` names no host. Treating that as "matches
        everything" is how an allow-list silently stops applying."""
        monkeypatch.setenv("AISOC_PLUGIN_REGISTRY_ALLOWLIST", "ghcr.io")
        with pytest.raises(PluginError):
            _validate_oci_ref("library/thing@sha256:" + "b" * 64)

    @pytest.mark.parametrize(
        ("ref", "expected"),
        [
            ("ghcr.io/x/y:1", "ghcr.io"),
            ("localhost:5000/x/y:1", "localhost:5000"),
            ("registry.internal/x@sha256:" + "c" * 64, "registry.internal"),
            ("library/thing:1", ""),
        ],
    )
    def test_registry_extraction(self, ref: str, expected: str):
        assert _registry_of(ref) == expected

    def test_the_metadata_deny_list_still_applies(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("AISOC_PLUGIN_REGISTRY_ALLOWLIST", raising=False)
        with pytest.raises(PluginError, match="deny list"):
            _validate_oci_ref("169.254.169.254/x@sha256:" + "d" * 64)
