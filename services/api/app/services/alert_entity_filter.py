"""Exact entity predicates for the alert list, its count and its facets."""

from typing import Final, Literal

from sqlalchemy import or_
from sqlalchemy.sql.elements import ColumnElement

from app.models.alert import Alert

AlertEntityType = Literal["host", "user", "ip", "domain", "asset", "url"]

# The canonical kinds and import aliases also recognized by the investigation
# rail. Each containment operand carries both fields so a type on one entity
# cannot match a value on a different entity in the same alert.
_ENTITY_ALIASES: Final[dict[str, tuple[str, ...]]] = {
    "host": ("host", "hostname", "device"),
    "user": ("user", "username", "account"),
    "ip": ("ip", "ip_address", "src_ip"),
    "domain": ("domain",),
    "asset": ("asset",),
    "url": ("url",),
}


def entity_filter(value: str, kind: AlertEntityType | None) -> ColumnElement[bool]:
    """Match exact, case-sensitive values in stored entity fields.

    Fusion writes hosts/users to ``entities`` and IPs/domains/URLs to ``iocs``.
    Its denormalized arrays and older imported alerts are covered too. JSONB
    containment treats wildcard characters as data and uses bound parameters.
    """
    kinds = (kind,) if kind is not None else tuple(_ENTITY_ALIASES)
    predicates = [Alert.entities.contains([{"type": alias, "value": value}]) for canonical in kinds for alias in _ENTITY_ALIASES[canonical]]
    affected = {
        "host": Alert.affected_hosts,
        "user": Alert.affected_users,
        "ip": Alert.affected_ips,
        "asset": Alert.affected_assets,
    }
    predicates.extend(affected[canonical].contains([value]) for canonical in kinds if canonical in affected)
    predicates.extend(
        Alert.iocs.contains([{"type": canonical, "value": value}]) for canonical in kinds if canonical in {"ip", "domain", "url"}
    )
    return or_(*predicates)
