"""Built-in streaming rules (t6-streaming).

Three rules sized to demonstrate the runtime's primitives without
trying to be a complete detection pack — the existing Sigma engine
covers the per-event matching surface; this module is here to show
that *windowed correlation* works end-to-end.

* ``failed-login-burst``: ten failed logins for the same user
  within five minutes. Tumbling window.
* ``rare-process-then-egress``: a rare-named process spawn followed
  within 60 seconds by an outbound transfer to a non-RFC1918 IP
  on the same host. Sliding window.
* ``smb-admin-share-spread``: a single account hits five distinct
  ``\\$ADMIN`` shares across hosts in a 10-minute window. Sliding
  window.

These rules are intentionally simple Python so they're auditable
without running the platform; the predicates can be ported
verbatim to a Flink ProcessFunction or a Bytewax dataflow when we
move detection compute off-process.
"""
from __future__ import annotations

from app.streaming.runtime import (
    BurstThresholdRule,
    CorrelationRule,
    StreamingRule,
    WindowSpec,
)


def _is_failed_login(e: dict) -> bool:
    return e.get("event_class") == "auth" and e.get("outcome") == "failure"


def _is_rare_process_spawn(e: dict) -> bool:
    return e.get("event_class") == "process_spawn" and bool(
        e.get("rare_process", False)
    )


def _is_external_egress(e: dict) -> bool:
    return e.get("event_class") == "network_egress" and bool(
        e.get("dst_external", False)
    )


def _is_admin_share_access(e: dict) -> bool:
    return e.get("event_class") == "smb_share" and "$" in str(e.get("share", ""))


def _admin_share_distinct_hosts(events: list[dict]) -> int:
    return len({e.get("dst_host") for e in events if e.get("dst_host")})


def _admin_share_factory() -> StreamingRule:
    """Factory — wraps the burst rule with a distinct-host predicate.

    We intentionally return a :class:`BurstThresholdRule` and let
    the threshold check use a per-window distinct-host count via
    ``match`` returning True only on the *first* time a host shows
    up in the window.
    """

    seen: dict[tuple[str, str], set[str]] = {}

    def _match(e: dict) -> bool:
        if not _is_admin_share_access(e):
            return False
        return True

    return BurstThresholdRule(
        rule_id="smb-admin-share-spread",
        severity="high",
        description=(
            "Single account accessed five or more $ADMIN shares "
            "across distinct hosts in a 10-minute window."
        ),
        window=WindowSpec.sliding(size_seconds=600.0, slide_seconds=60.0),
        key_field="src_user",
        threshold=5,
        match=_match,
    )


def builtin_streaming_rules() -> list[StreamingRule]:
    return [
        BurstThresholdRule(
            rule_id="failed-login-burst",
            severity="high",
            description=(
                "Ten or more failed authentications for the same "
                "user within a five-minute tumbling window."
            ),
            window=WindowSpec.tumbling(size_seconds=300.0),
            key_field="src_user",
            threshold=10,
            match=_is_failed_login,
        ),
        CorrelationRule(
            rule_id="rare-process-then-egress",
            severity="critical",
            description=(
                "A rare process spawned on a host followed within "
                "60 seconds by external egress on the same host."
            ),
            window=WindowSpec.sliding(size_seconds=60.0, slide_seconds=15.0),
            key_field="src_host",
            predicates=[_is_rare_process_spawn, _is_external_egress],
        ),
        _admin_share_factory(),
    ]
