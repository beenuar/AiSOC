"""Reversible pseudonymization of evidence before it leaves the process.

Phase 1.4 of the world-class program. The README promises "no data
exfiltration", yet the default path sends raw evidence to a third-party LLM.
This module pseudonymizes the *customer's* identifying data — internal IPs,
emails, file paths, secrets, internal hostnames, usernames — through a per-run,
per-tenant, in-memory-only bidirectional map. The LLM reasons over ``USER_1``,
``HOST_2``, ``IP_3``; the ledger and console re-hydrate the real values locally
via :meth:`Pseudonymizer.rehydrate`.

Public threat indicators (external domains/IPs) are intentionally *not*
redacted by default: they are IOCs, not customer PII, and the agent needs them
to reason. This is a deliberate, documented trade-off (see docs/trust/).

Pure/synchronous, stdlib only, so it is unit-testable offline and gated: a
golden-corpus test asserts zero raw customer PII survives redaction.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

__all__ = ["RedactionConfig", "Pseudonymizer", "default_pseudonymizer"]

# Field-name hints whose *values* are treated as usernames when redacting
# structured evidence.
_USER_FIELD_HINTS = frozenset({"user", "username", "user_name", "account", "actor", "principal", "samaccountname", "upn", "subject"})

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# Windows (C:\...), UNC (\\host\share), and multi-segment unix paths.
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"']+")
_UNC_PATH_RE = re.compile(r"\\\\[^\s\"']+")
_UNIX_PATH_RE = re.compile(r"(?:/[A-Za-z0-9._\-]+){2,}/?")
# DOMAIN\user (down-level logon name).
_DOMAIN_USER_RE = re.compile(r"\b[A-Za-z0-9.\-]+\\[A-Za-z0-9._\-]+")
# Common secret shapes: AWS keys, OpenAI-style, bearer/JWT, private key headers.
_SECRET_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),  # JWT
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
# FQDNs; only redacted when the suffix is in the internal set.
_FQDN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b")

_DEFAULT_INTERNAL_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".intranet", ".home.arpa")


@dataclass(frozen=True)
class RedactionConfig:
    """What to pseudonymize. Defaults are on (fail-safe for the no-exfil claim)."""

    redact_internal_ips: bool = True
    redact_emails: bool = True
    redact_paths: bool = True
    redact_secrets: bool = True
    redact_internal_hostnames: bool = True
    redact_usernames: bool = True
    # Extra domain suffixes considered internal (customer-configurable).
    internal_domain_suffixes: tuple[str, ...] = _DEFAULT_INTERNAL_SUFFIXES


def _is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


class Pseudonymizer:
    """Per-run, per-tenant reversible entity map held only in memory."""

    def __init__(self, *, tenant_id: str = "", config: RedactionConfig | None = None) -> None:
        self.tenant_id = tenant_id
        self.config = config or RedactionConfig()
        self._to_token: dict[str, str] = {}
        self._to_original: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    # -- public API ------------------------------------------------------------

    @property
    def mapping(self) -> dict[str, str]:
        """token -> original, for local (never-egress) re-hydration."""
        return dict(self._to_original)

    def redact(self, text: str) -> str:
        if not text or not isinstance(text, str):
            return text if isinstance(text, str) else ""
        out = text
        # Order matters: secrets/emails/paths/domain-user before bare IPs/hosts,
        # so a token like EMAIL_1 is never re-matched by a later pattern.
        if self.config.redact_secrets:
            for pat in _SECRET_RES:
                out = pat.sub(lambda m: self._token("SECRET", m.group(0)), out)
        if self.config.redact_emails:
            out = _EMAIL_RE.sub(lambda m: self._token("EMAIL", m.group(0)), out)
        # Paths before DOMAIN\user: a Windows path (C:\Users\alice\...) contains
        # backslash-separated segments that would otherwise be mis-matched as a
        # down-level logon name and fragment the path.
        if self.config.redact_paths:
            out = _WIN_PATH_RE.sub(lambda m: self._token("PATH", m.group(0)), out)
            out = _UNC_PATH_RE.sub(lambda m: self._token("PATH", m.group(0)), out)
            out = _UNIX_PATH_RE.sub(lambda m: self._token("PATH", m.group(0)), out)
        if self.config.redact_usernames:
            out = _DOMAIN_USER_RE.sub(lambda m: self._token("USER", m.group(0)), out)
        if self.config.redact_internal_hostnames:
            out = _FQDN_RE.sub(self._maybe_internal_host, out)
        if self.config.redact_internal_ips:
            out = _IPV4_RE.sub(self._maybe_internal_ip, out)
        return out

    def redact_value(self, value: Any, *, _key: str | None = None) -> Any:
        """Recursively redact a JSON-like value. Values under user-ish keys are
        pseudonymized as usernames even if they are plain identifiers."""
        if isinstance(value, str):
            if _key and self.config.redact_usernames and _key.lower() in _USER_FIELD_HINTS and "@" not in value:
                return self._token("USER", value)
            return self.redact(value)
        if isinstance(value, Mapping):
            return {k: self.redact_value(v, _key=str(k)) for k, v in value.items()}
        if isinstance(value, Sequence) and not isinstance(value, str | bytes):
            return [self.redact_value(v) for v in value]
        return value

    def rehydrate(self, text: str) -> str:
        """Reverse redaction locally (never send the result to the LLM)."""
        if not text:
            return text
        out = text
        # Replace longer tokens first to avoid USER_1 clobbering USER_10.
        for token in sorted(self._to_original, key=len, reverse=True):
            out = out.replace(token, self._to_original[token])
        return out

    # -- internals -------------------------------------------------------------

    def _token(self, kind: str, original: str) -> str:
        if original in self._to_token:
            return self._to_token[original]
        self._counters[kind] = self._counters.get(kind, 0) + 1
        token = f"{kind}_{self._counters[kind]}"
        self._to_token[original] = token
        self._to_original[token] = original
        return token

    def _maybe_internal_ip(self, m: re.Match[str]) -> str:
        val = m.group(0)
        return self._token("IP", val) if _is_internal_ip(val) else val

    def _maybe_internal_host(self, m: re.Match[str]) -> str:
        host = m.group(0)
        lowered = host.lower()
        if any(lowered.endswith(sfx) for sfx in self.config.internal_domain_suffixes):
            return self._token("HOST", host)
        return host


def default_pseudonymizer(tenant_id: str = "") -> Pseudonymizer:
    """A pseudonymizer with all redaction on (the safe default for no-exfil)."""
    return Pseudonymizer(tenant_id=tenant_id, config=RedactionConfig())
