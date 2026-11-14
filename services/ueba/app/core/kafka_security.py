"""Transport settings for every Kafka client in the platform.

Canonical copy. `scripts/sync_vendored_kafka_security.py` keeps the copies in
the other Python services byte-identical, and a CI gate runs it with
`--check`.

Why this exists
---------------
Seven Python services, three Go files and one TypeScript service each
constructed their own Kafka client, and not one of them passed a security
protocol — so every client spoke `PLAINTEXT`, which is aiokafka's,
kafka-go's and kafkajs' default. The spine carries normalized security
telemetry: raw event bodies, usernames, hostnames, command lines and
`alerts.entities`. Anyone on the broker's network path could read all of it
and inject onto the topics, and nothing in the platform would notice,
because an unauthenticated plaintext broker accepts whatever arrives.

The commercial deployment makes this concrete rather than theoretical: MSK
is provisioned `TLS_PLAINTEXT`, unauthenticated, and every service is
pointed at the plaintext `:9092` bootstrap. The TLS listener was already
there and nothing used it.

The shape of the fix
--------------------
One resolver, three rules:

* **Production refuses plaintext.** Not a warning — a refusal at startup,
  because a warning in a log nobody reads is how this lasted as long as it
  did.
* **Development defaults to plaintext**, because the local compose broker
  has no certificate and demanding one would make `make up` fail on a
  machine with nothing to fix.
* **The protocol is read once, here**, so eleven call sites cannot drift
  into eleven different answers. That is the same reasoning behind the
  single CORS module, and the same failure it prevents.

Deliberately not a transport the caller can override per client. A
per-client override is how one consumer ends up plaintext on a TLS
deployment, and the one that drifts is never the one anybody tests.
"""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass, field
from typing import Any, Final

#: The protocols aiokafka accepts. Spelled out rather than passed through,
#: so a typo in an environment variable is a refusal at startup and not a
#: silent fallback to the library default.
VALID_PROTOCOLS: Final[frozenset[str]] = frozenset({"PLAINTEXT", "SSL", "SASL_PLAINTEXT", "SASL_SSL"})

#: Protocols that put the bytes on the wire in the clear.
CLEARTEXT_PROTOCOLS: Final[frozenset[str]] = frozenset({"PLAINTEXT", "SASL_PLAINTEXT"})

#: Environments where a cleartext broker is a defect rather than a choice.
PROTECTED_ENVIRONMENTS: Final[frozenset[str]] = frozenset({"production", "prod", "staging"})

PROTOCOL_VAR: Final[str] = "KAFKA_SECURITY_PROTOCOL"
CA_VAR: Final[str] = "KAFKA_SSL_CAFILE"
CERT_VAR: Final[str] = "KAFKA_SSL_CERTFILE"
KEY_VAR: Final[str] = "KAFKA_SSL_KEYFILE"
MECHANISM_VAR: Final[str] = "KAFKA_SASL_MECHANISM"
USERNAME_VAR: Final[str] = "KAFKA_SASL_USERNAME"
PASSWORD_VAR: Final[str] = "KAFKA_SASL_PASSWORD"
ENV_VAR: Final[str] = "ENVIRONMENT"

#: Set to any truthy value to run a protected environment on a cleartext
#: broker. It exists because a private VPC with its own encryption is a real
#: deployment, and because a refusal with no escape hatch gets patched out
#: downstream, which is worse than an escape hatch that is named and logged.
OVERRIDE_VAR: Final[str] = "AISOC_ALLOW_CLEARTEXT_KAFKA"

_TRUTHY: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})


class KafkaTransportError(RuntimeError):
    """Refusal to build a client whose transport is wrong for this environment."""


@dataclass(frozen=True)
class KafkaTransport:
    """Resolved transport, ready to splat into a client constructor."""

    protocol: str
    ssl_context: ssl.SSLContext | None = None
    sasl_mechanism: str | None = None
    sasl_username: str | None = None
    sasl_password: str | None = field(default=None, repr=False)

    @property
    def is_cleartext(self) -> bool:
        return self.protocol in CLEARTEXT_PROTOCOLS

    def client_kwargs(self) -> dict[str, Any]:
        """Keyword arguments for `AIOKafkaConsumer` and `AIOKafkaProducer`.

        Returns `{"security_protocol": "PLAINTEXT"}` rather than `{}` in the
        cleartext case. Passing it explicitly is what makes the gate able to
        tell "this call site chose plaintext" from "this call site forgot",
        and those were indistinguishable before.
        """
        kwargs: dict[str, Any] = {"security_protocol": self.protocol}
        if self.ssl_context is not None:
            kwargs["ssl_context"] = self.ssl_context
        if self.sasl_mechanism:
            kwargs["sasl_mechanism"] = self.sasl_mechanism
            kwargs["sasl_plain_username"] = self.sasl_username
            kwargs["sasl_plain_password"] = self.sasl_password
        return kwargs


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _build_ssl_context() -> ssl.SSLContext:
    """A verifying context, with an optional client certificate.

    `create_default_context` verifies the hostname and the chain. Neither is
    made optional here: a TLS connection that verifies nothing authenticates
    nothing, and an operator who needs a private CA should pass it in
    `KAFKA_SSL_CAFILE` rather than turn verification off.
    """
    cafile = _env(CA_VAR) or None
    context = ssl.create_default_context(cafile=cafile)
    certfile, keyfile = _env(CERT_VAR), _env(KEY_VAR)
    if certfile:
        context.load_cert_chain(certfile, keyfile or None)
    return context


def resolve_transport(
    *,
    environment: str | None = None,
    protocol: str | None = None,
) -> KafkaTransport:
    """Resolve the transport, or raise if it is wrong for this environment.

    Arguments exist for the tests. In a running service both come from the
    environment, because a caller that can choose its own protocol is a
    caller that can choose plaintext.
    """
    env = (environment if environment is not None else _env(ENV_VAR)).lower()
    resolved = (protocol if protocol is not None else _env(PROTOCOL_VAR)) or "PLAINTEXT"
    resolved = resolved.upper()

    if resolved not in VALID_PROTOCOLS:
        raise KafkaTransportError(
            f"{PROTOCOL_VAR}={resolved!r} is not one of {sorted(VALID_PROTOCOLS)}. "
            "Refusing rather than falling back, because the fallback is plaintext."
        )

    if resolved in CLEARTEXT_PROTOCOLS and env in PROTECTED_ENVIRONMENTS:
        if _env(OVERRIDE_VAR).lower() not in _TRUTHY:
            raise KafkaTransportError(
                f"{ENV_VAR}={env!r} with {PROTOCOL_VAR}={resolved!r} would put normalized "
                "security telemetry — raw event bodies, usernames, hostnames, command "
                "lines — on the wire in the clear, on a broker that accepts whatever "
                f"arrives. Set {PROTOCOL_VAR}=SSL or SASL_SSL, or set {OVERRIDE_VAR}=1 if "
                "the broker is reachable only over a network you already encrypt."
            )

    context = _build_ssl_context() if resolved in {"SSL", "SASL_SSL"} else None
    mechanism = _env(MECHANISM_VAR) or None
    if resolved.startswith("SASL_") and not mechanism:
        raise KafkaTransportError(f"{PROTOCOL_VAR}={resolved!r} requires {MECHANISM_VAR} (for example PLAIN or SCRAM-SHA-512).")

    return KafkaTransport(
        protocol=resolved,
        ssl_context=context,
        sasl_mechanism=mechanism,
        sasl_username=_env(USERNAME_VAR) or None,
        sasl_password=_env(PASSWORD_VAR) or None,
    )


def kafka_client_kwargs(*, environment: str | None = None) -> dict[str, Any]:
    """The one call every client site makes."""
    return resolve_transport(environment=environment).client_kwargs()
