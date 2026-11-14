"""Neither Postgres nor Kafka carries platform data in the clear by default.

Two transports, one defect: nobody set a protocol, and the library default
for both is cleartext.

**Kafka.** Seven Python services, three Go files and one TypeScript service
each built their own client and not one passed a security protocol, so all
of them spoke `PLAINTEXT` — aiokafka's, kafka-go's and kafkajs' default
alike. The spine carries raw event bodies, usernames, hostnames, command
lines and `alerts.entities`. The commercial deployment made it concrete:
MSK provisioned `TLS_PLAINTEXT`, unauthenticated, every service pointed at
the plaintext `:9092` bootstrap, with the TLS listener sitting unused.

**Postgres.** `sslmode` unset means `prefer` in libpq — TLS when the server
offers it, cleartext when it does not, and no way to tell which happened. A
server that stops offering TLS downgrades every connection without a log
line. `docker-compose.yml` shipped `sslmode=disable` outright.

The Kafka resolver is exercised by `scripts/check_kafka_transport.py`, which
calls it rather than reading it. These cases cover the Postgres half and the
property that ties them together: production refuses, development does not.
"""

from __future__ import annotations

import warnings

import pytest
from app.core.config import Settings, warn_if_insecure_defaults


def _transport_warnings(dsn: str) -> list[str]:
    settings = Settings(DATABASE_URL=dsn)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        emitted = warn_if_insecure_defaults(settings)
    return [m for m in emitted if "sslmode" in m or "DATABASE_URL" in m]


class TestPostgresTransport:
    @pytest.mark.parametrize("mode", ["disable", "allow", "false", "0"])
    def test_a_cleartext_mode_is_reported(self, mode: str) -> None:
        found = _transport_warnings(f"postgresql+asyncpg://u:p@h/db?sslmode={mode}")
        assert found, f"sslmode={mode} puts every query on the wire in the clear and was not reported"

    def test_an_unset_mode_is_reported(self) -> None:
        """Because `prefer` is indistinguishable from `require` in a log.

        This is the case that matters most: `disable` at least says what it
        does, while an unset mode looks like nobody made a choice and in
        fact silently accepts a downgrade.
        """
        found = _transport_warnings("postgresql+asyncpg://u:p@h/db")
        assert found, "an unset sslmode means 'prefer', which tolerates a silent downgrade"
        assert "prefer" in found[0]

    @pytest.mark.parametrize("mode", ["require", "verify-ca", "verify-full"])
    def test_a_protecting_mode_is_accepted(self, mode: str) -> None:
        """The other direction, so this cannot pass by warning about everything."""
        assert not _transport_warnings(f"postgresql+asyncpg://u:p@h/db?sslmode={mode}")


class TestKafkaTransport:
    """The resolver's own behaviour, from the copy this service vendors.

    Loaded through the service's own import path rather than the canonical
    file, so a vendored copy that drifted would fail here even though the
    sync gate compares bytes — two different questions, and the second one
    is what this service actually runs.
    """

    def test_production_refuses_cleartext(self) -> None:
        from app.core.kafka_security import KafkaTransportError, resolve_transport

        with pytest.raises(KafkaTransportError) as exc:
            resolve_transport(environment="production", protocol="PLAINTEXT")
        assert "clear" in str(exc.value)

    def test_cleartext_with_a_password_is_still_cleartext(self) -> None:
        from app.core.kafka_security import KafkaTransportError, resolve_transport

        with pytest.raises(KafkaTransportError):
            resolve_transport(environment="production", protocol="SASL_PLAINTEXT")

    def test_development_allows_plaintext(self) -> None:
        """The compose broker has no certificate.

        Refusing here would make `make up` fail on a machine where there is
        nothing to fix, which is how a security default gets patched out.
        """
        from app.core.kafka_security import resolve_transport

        assert resolve_transport(environment="development", protocol="PLAINTEXT").protocol == "PLAINTEXT"

    def test_an_unrecognised_protocol_refuses_rather_than_defaulting(self) -> None:
        from app.core.kafka_security import KafkaTransportError, resolve_transport

        with pytest.raises(KafkaTransportError):
            resolve_transport(environment="development", protocol="TLS")

    def test_plaintext_is_passed_explicitly(self) -> None:
        """So a chosen plaintext is distinguishable from a forgotten one.

        Returning `{}` would have been equivalent at runtime and useless to
        the gate, which has no way to tell a site that decided from a site
        that never asked.
        """
        from app.core.kafka_security import resolve_transport

        kwargs = resolve_transport(environment="development", protocol="PLAINTEXT").client_kwargs()
        assert kwargs["security_protocol"] == "PLAINTEXT"
