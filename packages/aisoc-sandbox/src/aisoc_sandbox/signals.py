"""Facts the sandbox can actually derive from a scenario's events.

Why this module exists
----------------------
Everything the sandbox prints about an alert used to be keyed on two
strings the *input file* declared: the MITRE technique and the severity.
``DeterministicReasoner`` held one fixed sentence per technique, so a
``T1078`` tag always produced "the geo pivot between sequential events is
physically impossible" — on two sign-ins by the same user from the same
address in the same city eight hours apart, which is the opposite of
impossible travel. The confidence score was ``{severity} + 4 x techniques``
and the automation tier was a dict keyed on severity, so relabelling a
genuine impossible-travel alert ``info`` returned "L4 — fully autonomous
closure". A community reviewer found all three by typing a benign login
into the demo and reading what came back.

The rule this module exists to enforce is the repository's standing one:
**state only what was computed.** Impossible travel between two
timestamped, geolocated sign-ins is ordinary arithmetic — a distance
divided by an elapsed time — so the sandbox computes it, and the verdict
follows the events. Where there is nothing to compute, the caller emits
:class:`~aisoc_sandbox.ledger.NotComputed` rather than a plausible figure.

Three properties keep that honest, and each is pinned by a test:

* A signal has three outcomes, not two. ``not_computable`` is distinct
  from ``does_not_hold``: "the city is not in the table" and "the user did
  not move" are different facts and only one of them is about the alert.
* An unresolvable location is named, never defaulted. Substituting a
  country centroid for a city the table does not carry would invent the
  precision the whole measurement rests on.
* ``does_not_hold`` is not a benign verdict. A signal that fails to fire
  says the sandbox found no support for the tag, which is not evidence the
  alert is harmless. Callers must not round it to one.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

__all__ = ["CONTAINER_ONLY_SPELLINGS", "FIELD_CONTAINERS", "FIELD_VOCABULARY", "Signal", "compute_signals", "technique_support"]


#: Fastest sustained ground speed a human being can plausibly achieve
#: between two sign-ins. Commercial aircraft cruise around 900 km/h; the
#: ceiling is set above that so a long-haul flight plus a generous clock
#: skew cannot be reported as impossible.
MAX_PLAUSIBLE_KMH = 1000.0

#: Distances below this are not evidence of anything. Both endpoints are
#: city centroids, so two sign-ins from opposite ends of one metropolitan
#: area can be tens of kilometres apart without anybody travelling, and a
#: short enough elapsed time turns that into a large implied speed.
MIN_SIGNIFICANT_KM = 100.0


# ---------------------------------------------------------------------------
# A deliberately small gazetteer.
#
# The live stack resolves coordinates through a geo-IP provider. The sandbox
# has no network, so it ships a table — and a table has an edge. The edge is
# surfaced rather than papered over: a city that is not here produces
# `not_computable` naming the city, because a wrong coordinate would not look
# wrong, it would look like a measurement.
#
# Keyed on (city, country) because city names are not unique. Saint
# Petersburg is in the table twice on purpose: a lookup with no country that
# matches two entries is refused rather than resolved to whichever one was
# listed first.
# ---------------------------------------------------------------------------
_GAZETTEER: dict[tuple[str, str], tuple[float, float]] = {
    ("amsterdam", "nl"): (52.3676, 4.9041),
    ("austin", "us"): (30.2672, -97.7431),
    ("beijing", "cn"): (39.9042, 116.4074),
    ("bengaluru", "in"): (12.9716, 77.5946),
    ("berlin", "de"): (52.5200, 13.4050),
    ("boston", "us"): (42.3601, -71.0589),
    ("buenos aires", "ar"): (-34.6037, -58.3816),
    ("cairo", "eg"): (30.0444, 31.2357),
    ("chicago", "us"): (41.8781, -87.6298),
    ("delhi", "in"): (28.6139, 77.2090),
    ("dubai", "ae"): (25.2048, 55.2708),
    ("dublin", "ie"): (53.3498, -6.2603),
    ("frankfurt", "de"): (50.1109, 8.6821),
    ("hong kong", "hk"): (22.3193, 114.1694),
    ("istanbul", "tr"): (41.0082, 28.9784),
    ("jakarta", "id"): (-6.2088, 106.8456),
    ("johannesburg", "za"): (-26.2041, 28.0473),
    ("kyiv", "ua"): (50.4501, 30.5234),
    ("lagos", "ng"): (6.5244, 3.3792),
    ("lisbon", "pt"): (38.7223, -9.1393),
    ("london", "gb"): (51.5074, -0.1278),
    ("los angeles", "us"): (34.0522, -118.2437),
    ("madrid", "es"): (40.4168, -3.7038),
    ("mexico city", "mx"): (19.4326, -99.1332),
    ("milan", "it"): (45.4642, 9.1900),
    ("moscow", "ru"): (55.7558, 37.6173),
    ("mumbai", "in"): (19.0760, 72.8777),
    ("nairobi", "ke"): (-1.2921, 36.8219),
    ("new york", "us"): (40.7128, -74.0060),
    ("paris", "fr"): (48.8566, 2.3522),
    ("saint petersburg", "ru"): (59.9311, 30.3609),
    ("saint petersburg", "us"): (27.7676, -82.6403),
    ("san francisco", "us"): (37.7749, -122.4194),
    ("seattle", "us"): (47.6062, -122.3321),
    ("seoul", "kr"): (37.5665, 126.9780),
    ("shanghai", "cn"): (31.2304, 121.4737),
    ("singapore", "sg"): (1.3521, 103.8198),
    ("stockholm", "se"): (59.3293, 18.0686),
    ("sydney", "au"): (-33.8688, 151.2093),
    ("sao paulo", "br"): (-23.5505, -46.6333),
    ("tel aviv", "il"): (32.0853, 34.7818),
    ("tokyo", "jp"): (35.6762, 139.6503),
    ("toronto", "ca"): (43.6532, -79.3832),
    ("warsaw", "pl"): (52.2297, 21.0122),
    ("zurich", "ch"): (47.3769, 8.5417),
}

#: Spellings that denote a city already in the table. Normalised, not
#: guessed: each one is the same place under a different transliteration or
#: abbreviation, never a near-miss resolved to its closest neighbour.
_CITY_ALIASES: dict[str, str] = {
    "bangalore": "bengaluru",
    "kiev": "kyiv",
    "new york city": "new york",
    "nyc": "new york",
    "sankt-peterburg": "saint petersburg",
    "st petersburg": "saint petersburg",
    "st. petersburg": "saint petersburg",
    "são paulo": "sao paulo",
}


@dataclass(frozen=True)
class Signal:
    """One thing the sandbox tried to compute from the events.

    Attributes:
        name: Stable identifier (``geo_velocity``, ``event_burst``, ...).
        status: ``holds`` | ``does_not_hold`` | ``not_computable``.
            ``not_computable`` means the inputs were absent or
            unresolvable, which is a statement about the payload rather
            than about the alert.
        summary: One sentence carrying the arithmetic that produced the
            status, so a reader can check it without re-running anything.
        inputs: The exact values used. Rounded at this boundary so the
            rendered ledger is byte-stable across runs and platforms.
        bears_on: ATT&CK techniques this signal can corroborate. A
            declared technique that appears in no signal's ``bears_on``
            is one the sandbox cannot speak to at all, and says so.
    """

    name: str
    status: str
    summary: str
    inputs: dict[str, Any] = field(default_factory=dict)
    bears_on: tuple[str, ...] = ()

    @property
    def holds(self) -> bool:
        return self.status == "holds"


# ---------------------------------------------------------------------------
# What a field may be called.
#
# Each reader used to carry its own inline list, and they drifted apart in
# the direction that matters: timestamps accepted exactly two spellings
# (`published`, `timestamp`) while actors and addresses accepted four each.
# That is backwards — a timestamp has *more* ordinary spellings than an
# actor, not fewer — and the cost was not cosmetic. A reader who wrote
# `ts`, `_time` or `@timestamp` got `not_computable` on geo-velocity *and*
# on event-burst, concluded the sandbox computes nothing, and would have
# been right to.
#
# It survived review because the bundled corpus is written in the parser's
# own dialect: every fixture says `published`, so replaying the fixtures
# could only ever confirm that `published` works. The vocabulary is
# declared here as data so `scripts/check_sandbox_honesty.py` can enumerate
# it, rewrite a scenario into each spelling, and require every one to
# compute — a test the corpus cannot supply from inside its own dialect.
#
# Order is preference, most event-specific first, because a payload can
# carry several: an Elastic document with both `@timestamp` and
# `created_at` means the first.
# ---------------------------------------------------------------------------

FIELD_VOCABULARY: dict[str, tuple[str, ...]] = {
    "timestamp": (
        "published",
        "@timestamp",
        "_time",
        "timestamp",
        "eventTime",
        "event_time",
        "eventTimestamp",
        "observedTimestamp",
        "occurred_at",
        "occurredAt",
        "time",
        "ts",
        "datetime",
        "created_at",
        "createdAt",
        "date",
    ),
    "actor": (
        "actor",
        "user",
        "username",
        "user_name",
        "userName",
        "userPrincipalName",
        "principal",
        "subject",
        "account",
        "accountName",
        "src_user",
        "srcUser",
        "alternateId",
        "email",
    ),
    "address": (
        "client_ip",
        "clientIp",
        "ipAddress",
        "ip_address",
        "source_ip",
        "sourceIp",
        "src_ip",
        "srcIp",
        "srcip",
        "remote_ip",
        "remoteIp",
        "client_address",
        "ip",
    ),
    "city": ("city", "city_name", "cityName", "locality"),
    "country": (
        "country",
        "country_code",
        "countryCode",
        "country_iso_code",
        "countryOrRegion",
        "country_or_region",
        "country_name",
        "countryName",
    ),
    "latitude": ("lat", "latitude"),
    "longitude": ("lon", "long", "lng", "longitude"),
    "domain_age_days": ("domain_age_days", "domainAgeDays", "domain_age"),
    "destination": ("domain", "destination_domain", "destinationDomain", "dest_domain", "url", "uri"),
}

#: Spellings honoured **only** inside a container, never at the top level
#: of an event. ``user.name`` is how Elastic Common Schema names the actor
#: and reading it is necessary; a bare top-level ``name`` is far more
#: likely to be the name of the *event* than of the person, and guessing
#: wrong there puts an event type in the actor column. The distinction
#: costs one table and removes the need to choose between missing ECS and
#: mislabelling everything else.
CONTAINER_ONLY_SPELLINGS: dict[str, tuple[str, ...]] = {
    "actor": ("name", "displayName", "emailAddress", "upn"),
    "address": ("address",),
}

#: Nested objects a position may be found inside. Okta ships
#: ``client.geographicalContext.geolocation.{lat,lon}``, Entra ships
#: ``location.geoCoordinates.{latitude,longitude}`` and Elastic ships
#: ``source.geo.location.{lat,lon}``, so a flat read finds none of them.
_GEO_CONTAINERS = (
    "geo",
    "geoip",
    "geo_location",
    "geoLocation",
    "geolocation",
    "geographicalContext",
    "geoCoordinates",
    "coordinates",
    "location",
    "client",
    "source",
    "src",
    "clientGeo",
    "client_geo",
    "source_geo",
)

#: Which nested objects each concept may also be read from, searched after
#: the top level and in this order.
#:
#: ``timestamp`` is deliberately **empty**, and that is the one entry worth
#: explaining. Descending into arbitrary objects for a time would let
#: ``user.created_at`` — the age of the *account* — be read as the time of
#: the event, which is not a near-miss but a wrong answer that looks right.
#: An event's own time belongs at the top of the event.
FIELD_CONTAINERS: dict[str, tuple[str, ...]] = {
    "timestamp": (),
    "actor": ("actor", "user", "account", "identity", "subject", "principal", "client"),
    "address": ("client", "source", "src", "network", "request", "http", "connection"),
    "city": _GEO_CONTAINERS,
    "country": _GEO_CONTAINERS,
    "latitude": _GEO_CONTAINERS,
    "longitude": _GEO_CONTAINERS,
    "domain_age_days": ("destination", "dest", "url", "dns", "http"),
    "destination": ("destination", "dest", "http", "url", "request"),
}

#: How far the nested search descends. Three levels reaches Okta's
#: ``client.geographicalContext.geolocation``; the bound exists so a
#: pathological payload cannot make a 30-second demo walk a deep tree.
_MAX_CONTAINER_DEPTH = 3

#: Epoch bounds, so a numeric timestamp can be read without guessing its
#: unit. 1e8 s is 1973 and 1e11 s is the year 5138; the millisecond window
#: is the same two dates. The ranges do not overlap for any date a log
#: could plausibly carry, which is what makes this a rule rather than a
#: guess — a value outside both is refused rather than coerced.
_EPOCH_SECONDS_RANGE = (1e8, 1e11)
_EPOCH_MILLIS_RANGE = (1e11, 1e14)


def _read(event: dict[str, Any], concept: str) -> tuple[Any, str | None]:
    """The first value ``event`` carries for ``concept``, and where it was.

    Breadth-first: every spelling at the top level before any container,
    then containers in declared order. Returns ``(None, None)`` when the
    payload says nothing about the concept — which callers must report as
    "not computed", never fill in.
    """

    top_level = FIELD_VOCABULARY[concept]
    nested = top_level + CONTAINER_ONLY_SPELLINGS.get(concept, ())
    containers = FIELD_CONTAINERS.get(concept, ())
    level: list[tuple[dict[str, Any], str]] = [(event, "")]
    visited: set[int] = {id(event)}

    for depth in range(_MAX_CONTAINER_DEPTH + 1):
        spellings = top_level if depth == 0 else nested
        for node, prefix in level:
            for spelling in spellings:
                value = node.get(spelling)
                # A dict under an actor-shaped key is a container to
                # descend, not a value to return.
                if value is not None and not isinstance(value, (dict, list)):
                    return value, f"{prefix}{spelling}"
        deeper: list[tuple[dict[str, Any], str]] = []
        for node, prefix in level:
            for name in containers:
                child = node.get(name)
                if isinstance(child, dict) and id(child) not in visited:
                    visited.add(id(child))
                    deeper.append((child, f"{prefix}{name}."))
        if not deeper:
            break
        level = deeper
    return None, None


def _read_str(event: dict[str, Any], concept: str) -> tuple[str | None, str | None]:
    value, where = _read(event, concept)
    if isinstance(value, str) and value.strip():
        return value.strip(), where
    return None, None


def _read_number(event: dict[str, Any], concept: str) -> tuple[float | None, str | None]:
    value, where = _read(event, concept)
    # `bool` is an `int` in Python and `True` is not a latitude.
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value), where
    if isinstance(value, str):
        try:
            return float(value.strip()), where
        except ValueError:
            return None, None
    return None, None


# ---------------------------------------------------------------------------
# Parsing helpers. Each returns None rather than a default: a default here
# would be a fabricated input to a real measurement.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Instant:
    """A parsed event time, and how much of one it actually was.

    ``date_only`` carries the thing a bare ``datetime`` would lose. Two
    events whose payload gives only ``2026-05-14`` both parse to midnight,
    so their elapsed time is zero — and a distance over a zero time is an
    infinite speed, which the velocity signal would otherwise report as
    physically impossible travel. The finding would be an artefact of
    precision the payload never had, which is the same defect as reading a
    verdict off a label, arriving by a different road.
    """

    when: datetime
    key: str
    date_only: bool


def _parse_timestamp(value: Any) -> tuple[datetime, bool] | None:
    """A value to an aware UTC datetime plus whether it carried a time.

    Accepts ISO-8601 and epoch seconds / milliseconds. ``fromisoformat``
    only learned to accept a trailing ``Z`` in 3.11 and the package
    supports 3.10, so the suffix is normalised here rather than relied on.
    """

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if _EPOCH_SECONDS_RANGE[0] <= number < _EPOCH_SECONDS_RANGE[1]:
            return datetime.fromtimestamp(number, tz=timezone.utc), False
        if _EPOCH_MILLIS_RANGE[0] <= number < _EPOCH_MILLIS_RANGE[1]:
            return datetime.fromtimestamp(number / 1000.0, tz=timezone.utc), False
        return None

    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    aware = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    return aware, len(text) == 10 and text.count("-") == 2


def _instant_of(event: dict[str, Any]) -> _Instant | None:
    """The event's own time, read through the declared vocabulary."""

    value, where = _read(event, "timestamp")
    if value is None or where is None:
        return None
    parsed = _parse_timestamp(value)
    return None if parsed is None else _Instant(when=parsed[0], key=where, date_only=parsed[1])


def _normalise_city(name: str) -> str:
    key = " ".join(name.strip().lower().split())
    return _CITY_ALIASES.get(key, key)


def _actor_of(event: dict[str, Any]) -> str | None:
    return _read_str(event, "actor")[0]


def _address_of(event: dict[str, Any]) -> str | None:
    return _read_str(event, "address")[0]


@dataclass(frozen=True)
class _Point:
    lat: float
    lon: float
    label: str
    #: How the position was resolved — "coordinates (`client.geo.lat`)" or
    #: "the built-in city table". Carried so the ledger can say which,
    #: since a centroid and a real fix are different kinds of input to the
    #: same arithmetic and a reader is entitled to know which they got.
    source: str


def _coordinates(event: dict[str, Any]) -> tuple[_Point | None, str | None]:
    """Explicit coordinates from the payload, or why they were refused.

    ``(None, None)`` means the payload carries none and the caller should
    fall through to the city table. A non-empty reason means it carried
    something coordinate-shaped that could not be trusted.
    """

    lat, lat_at = _read_number(event, "latitude")
    lon, lon_at = _read_number(event, "longitude")
    if lat is None and lon is None:
        return None, None
    if lat is None or lon is None:
        half = f"a longitude at `{lon_at}`" if lat is None else f"a latitude at `{lat_at}`"
        return None, f"carries {half} without its pair"
    if not (-90.0 <= lat <= 90.0) or not (-180.0 <= lon <= 180.0):
        return None, f"carries out-of-range coordinates ({lat}, {lon})"
    if lat == 0.0 and lon == 0.0:
        return None, "carries the 0,0 null-island sentinel, which is how several sources spell 'unknown'"

    city, _ = _read_str(event, "city")
    country, _ = _read_str(event, "country")
    label = ", ".join(part for part in (city, country) if part) or f"{lat:.4f},{lon:.4f}"
    return _Point(lat, lon, label, f"coordinates at `{lat_at}`/`{lon_at}`"), None


def _locate(event: dict[str, Any]) -> tuple[_Point | None, str | None]:
    """Resolve an event to a position, or explain why it could not be.

    Precedence is explicit coordinates, then the built-in city table.
    Coordinates win because they are not a weaker input than a centroid
    but a strictly better one: the table answers "somewhere in this city",
    a payload's own ``lat``/``lon`` answers where. The reasoning that keeps
    the table narrow — that deriving a country centroid for an unknown
    city would invent the precision the whole measurement rests on — is
    about *manufacturing* a position, and reading one the payload already
    carries is the opposite of that.

    Returns ``(point, None)`` on success and ``(None, reason)`` otherwise.
    """

    point, coordinate_problem = _coordinates(event)
    if point is not None:
        return point, None

    city, city_at = _read_str(event, "city")
    if city is None:
        if coordinate_problem is not None:
            return None, f"{coordinate_problem}, and carries no city to fall back to"
        return None, "carries neither coordinates nor a city"

    trailer = f" (it {coordinate_problem})" if coordinate_problem is not None else ""
    key = _normalise_city(city)
    country, _ = _read_str(event, "country")
    country_key = country.lower() if country else ""

    if country_key:
        coords = _GAZETTEER.get((key, country_key))
        if coords is None:
            return None, f"{city!r} in {country} is not in the sandbox's built-in city table{trailer}"
        return _Point(coords[0], coords[1], f"{city}, {country}", f"the built-in city table, via `{city_at}`"), None

    matches = [(k, v) for k, v in _GAZETTEER.items() if k[0] == key]
    if not matches:
        return None, f"{city!r} is not in the sandbox's built-in city table{trailer}"
    if len(matches) > 1:
        countries = ", ".join(sorted(k[1].upper() for k, _ in matches))
        return None, f"{city!r} is ambiguous without a country ({countries}) and was not guessed{trailer}"
    (_, _), coords = matches[0]
    return _Point(coords[0], coords[1], city, f"the built-in city table, via `{city_at}`"), None


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular}" if count == 1 else f"{count} {plural or singular + 's'}"


def _haversine_km(a: _Point, b: _Point) -> float:
    radius_km = 6371.0088
    lat1, lon1, lat2, lon2 = map(math.radians, (a.lat, a.lon, b.lat, b.lon))
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * radius_km * math.asin(math.sqrt(h))


# ---------------------------------------------------------------------------
# The signals themselves.
# ---------------------------------------------------------------------------


def _geo_velocity(events: list[dict[str, Any]]) -> Signal:
    """Implied travel speed between consecutive located sign-ins per actor.

    This is the one the reported defect was about. The old code asserted
    "physically impossible" from the technique tag alone; this divides a
    great-circle distance by an elapsed time and reports the quotient.
    """

    bears_on = ("T1078", "T1078.004", "T1021", "T1133")
    by_actor: dict[str, list[tuple[_Instant, _Point]]] = {}
    unresolved: list[str] = []
    untimed = 0

    for event in events:
        actor, instant = _actor_of(event), _instant_of(event)
        if actor is None:
            continue
        if instant is None:
            untimed += 1
            continue
        point, reason = _locate(event)
        if point is None:
            if reason is not None and "carries neither coordinates nor a city" not in reason:
                unresolved.append(reason)
            continue
        by_actor.setdefault(actor, []).append((instant, point))

    usable = {actor: sorted(points, key=lambda pair: pair[0].when) for actor, points in by_actor.items() if len(points) >= 2}

    # Legs the payload's own precision cannot support. Two events whose time
    # is a bare date both land at midnight, so the elapsed time is zero and
    # the implied speed infinite — which would be published as impossible
    # travel on the strength of precision the payload never carried. That is
    # the same defect as reading a verdict off a label, arriving by a
    # different road, so the pair is excluded and counted rather than measured.
    legs: list[tuple[float, str, str, str, float, float, str, str]] = []
    precision_skipped = 0
    for actor, points in sorted(usable.items()):
        for (i0, p0), (i1, p1) in zip(points, points[1:], strict=False):
            hours = (i1.when - i0.when).total_seconds() / 3600.0
            if hours == 0.0 and (i0.date_only or i1.date_only):
                precision_skipped += 1
                continue
            km = _haversine_km(p0, p1)
            legs.append((km / hours if hours > 0 else math.inf, actor, p0.label, p1.label, km, hours, p0.source, p1.source))

    if not legs:
        if precision_skipped:
            detail = (
                f"{_plural(precision_skipped, 'event pair')} carried a date with no time of day, so the"
                " elapsed time between them is zero and there is no speed to compute"
            )
        elif unresolved:
            detail = "; ".join(sorted(set(unresolved)))
        elif untimed:
            detail = f"{_plural(untimed, 'event')} carried no timestamp the sandbox could read"
        else:
            detail = "no actor has two timestamped, geolocated events"
        return Signal(
            name="geo_velocity",
            status="not_computable",
            summary=(
                f"Travel speed could not be computed: {detail}. The live stack resolves coordinates"
                " through a geo-IP provider; the sandbox prefers coordinates the payload carries, falls"
                " back to a small built-in city table, and refuses to substitute one it does not have."
            ),
            inputs={
                "located_event_pairs": 0,
                "unresolved": sorted(set(unresolved)),
                "events_without_a_readable_timestamp": untimed,
                "pairs_skipped_for_date_only_precision": precision_skipped,
            },
            bears_on=bears_on,
        )

    speed, actor, origin, destination, km, hours, from_source, to_source = max(legs, key=lambda leg: leg[0])
    inputs: dict[str, Any] = {
        "actor": actor,
        "from": origin,
        "to": destination,
        # A centroid and a real fix are different inputs to the same
        # arithmetic, and a reader is entitled to know which they got.
        "position_source": from_source if from_source == to_source else f"{from_source}; {to_source}",
        "distance_km": round(km, 1),
        "elapsed_hours": round(hours, 3),
        "implied_speed_kmh": round(speed, 1) if math.isfinite(speed) else "unbounded",
        "threshold_kmh": MAX_PLAUSIBLE_KMH,
        "minimum_significant_km": MIN_SIGNIFICANT_KM,
        "unresolved": sorted(set(unresolved)),
        "pairs_skipped_for_date_only_precision": precision_skipped,
    }
    if math.isfinite(speed):
        movement = f"{actor} appears at {destination} {hours:.2f} h after {origin} — {km:,.1f} km apart, implied speed {speed:,.1f} km/h"
    else:
        movement = (
            f"{actor} appears at {origin} and at {destination} on one timestamp — {km:,.1f} km apart with no"
            " time between them, so one actor was in two places at once"
        )

    if km >= MIN_SIGNIFICANT_KM and speed > MAX_PLAUSIBLE_KMH:
        return Signal(
            name="geo_velocity",
            status="holds",
            summary=(
                f"{movement}, above the {MAX_PLAUSIBLE_KMH:,.0f} km/h threshold."
                " Computed from the events, not assumed: this is physically impossible travel."
            ),
            inputs=inputs,
            bears_on=bears_on,
        )
    why = (
        "the same place, or close enough that city-centroid error dominates"
        if km < MIN_SIGNIFICANT_KM
        else f"at or below the {MAX_PLAUSIBLE_KMH:,.0f} km/h threshold"
    )
    return Signal(
        name="geo_velocity",
        status="does_not_hold",
        summary=f"{movement} — {why}. These events do not show impossible travel.",
        inputs=inputs,
        bears_on=bears_on,
    )


def _event_burst(events: list[dict[str, Any]]) -> Signal:
    """How tightly the events cluster in time."""

    bears_on = ("T1110", "T1110.003", "T1567", "T1552", "T1486", "T1496")
    instants = [i for i in (_instant_of(e) for e in events) if i is not None]
    # A bare date cannot answer a question about a 60-second window. Events
    # timed only to the day all land on midnight, which would read as the
    # tightest possible burst from a payload that said nothing about the
    # hour. Dropped and counted rather than folded in.
    dated_only = sum(1 for i in instants if i.date_only)
    stamps = sorted(i.when for i in instants if not i.date_only)
    if len(stamps) < 2:
        if dated_only:
            detail = (
                f"{_plural(dated_only, 'event')} carried a date with no time of day, and a 60-second window cannot be assessed from that"
            )
        else:
            detail = f"{len(stamps)} of {_plural(len(events), 'event')} carried a timestamp the sandbox could read"
        return Signal(
            name="event_burst",
            status="not_computable",
            summary=f"Event rate needs two timestamps resolved to at least the second: {detail}.",
            inputs={"timestamped_events": len(stamps), "date_only_events": dated_only, "total_events": len(events)},
            bears_on=bears_on,
        )

    span = (stamps[-1] - stamps[0]).total_seconds()
    window = 60.0
    densest = max(sum(1 for other in stamps if 0 <= (other - start).total_seconds() <= window) for start in stamps)
    inputs = {
        "events": len(stamps),
        "date_only_events_excluded": dated_only,
        "span_seconds": round(span, 3),
        "densest_60s_window_events": densest,
        "threshold_events_per_60s": 3,
    }
    sentence = f"{_plural(len(stamps), 'timestamped event')} span {span:.1f} s; the densest 60 s window holds {densest}."
    if densest >= 3:
        return Signal(
            name="event_burst",
            status="holds",
            summary=f"{sentence} That is a burst by the sandbox's 3-per-60 s rule.",
            inputs=inputs,
            bears_on=bears_on,
        )
    return Signal(
        name="event_burst", status="does_not_hold", summary=f"{sentence} Below the 3-per-60 s burst rule.", inputs=inputs, bears_on=bears_on
    )


def _source_diversity(events: list[dict[str, Any]]) -> Signal:
    """Whether the payload shows more than one origin for the activity.

    Origin means a source address or a country. Actors are counted and
    reported, but a payload that names actors and no origin at all makes
    this ``not_computable`` rather than "a single origin" — the earlier
    phrasing would have turned *no observation* into an observation of
    sameness, which is the shape this whole module exists to avoid.
    """

    bears_on = ("T1078", "T1078.004", "T1133", "T1021")
    actors = sorted({a for a in (_actor_of(e) for e in events) if a})
    addresses = sorted({a for a in (_address_of(e) for e in events) if a})
    # Read through the shared vocabulary rather than a literal `geo.country`
    # path: that path is one dialect of several, and an Okta payload putting
    # the country under `client.geographicalContext` scored zero countries
    # while plainly carrying two.
    countries = sorted({c.upper() for c in (_read_str(e, "country")[0] for e in events) if c})
    inputs = {"actors": actors, "source_addresses": addresses, "countries": countries, "events": len(events)}
    counted = (
        f"{_plural(len(actors), 'actor')}, {_plural(len(addresses), 'source address', 'source addresses')}"
        f" and {_plural(len(countries), 'country', 'countries')} across {_plural(len(events), 'event')}."
    )

    if not addresses and not countries:
        return Signal(
            name="source_diversity",
            status="not_computable",
            summary=f"{counted} No event carries a source address or a country, so there is no origin to compare.",
            inputs=inputs,
            bears_on=bears_on,
        )
    if len(addresses) > 1 or len(countries) > 1:
        return Signal(
            name="source_diversity",
            status="holds",
            summary=f"{counted} More than one origin, which is the part worth a human's attention.",
            inputs=inputs,
            bears_on=bears_on,
        )
    return Signal(
        name="source_diversity", status="does_not_hold", summary=f"{counted} A single origin throughout.", inputs=inputs, bears_on=bears_on
    )


def _recorded_domain_age(events: list[dict[str, Any]]) -> Signal:
    """A domain age the payload states. Read, never estimated.

    The retired rationale for ``T1566`` asserted "the destination domain
    registered less than 14 days ago" whether or not anything in the
    payload said so. When an event does carry the field the sandbox can
    repeat it; when none does, it says nothing.
    """

    bears_on = ("T1566", "T1566.001", "T1566.002", "T1071")
    ages: list[tuple[str, int]] = []
    for event in events:
        days, _ = _read_number(event, "domain_age_days")
        if days is None or days != int(days):
            continue
        destination, _ = _read_str(event, "destination")
        ages.append((destination or "(unnamed destination)", int(days)))
    if not ages:
        return Signal(
            name="recorded_domain_age",
            status="not_computable",
            summary=(
                "No event records a domain age under any spelling the sandbox reads"
                f" ({', '.join(FIELD_VOCABULARY['domain_age_days'])}), and it has no network to look one up."
            ),
            inputs={"events_with_domain_age": 0, "spellings_read": list(FIELD_VOCABULARY["domain_age_days"])},
            bears_on=bears_on,
        )
    where, youngest = min(ages, key=lambda pair: pair[1])
    inputs = {"youngest_domain": str(where), "domain_age_days": youngest, "threshold_days": 14}
    sentence = f"The event payload records domain_age_days={youngest} for {where}."
    if youngest < 14:
        return Signal(
            name="recorded_domain_age",
            status="holds",
            summary=f"{sentence} Under the 14-day newly-registered threshold.",
            inputs=inputs,
            bears_on=bears_on,
        )
    return Signal(
        name="recorded_domain_age",
        status="does_not_hold",
        summary=f"{sentence} At or over the 14-day threshold.",
        inputs=inputs,
        bears_on=bears_on,
    )


_COMPUTERS = (_geo_velocity, _event_burst, _source_diversity, _recorded_domain_age)


def compute_signals(events: list[dict[str, Any]]) -> list[Signal]:
    """Every signal the sandbox knows how to compute, over ``events``.

    Returns one :class:`Signal` per computation attempted — including the
    ones that could not be computed, because "we did not look" and "we
    looked and found nothing" are different answers and the caller needs
    to be able to tell them apart.
    """

    return [compute(list(events)) for compute in _COMPUTERS]


def technique_support(techniques: list[str], signals: list[Signal]) -> dict[str, list[str]]:
    """Which declared techniques the computed signals speak to, and how.

    Buckets a technique as ``supported`` (a signal bearing on it holds),
    ``unsupported`` (a signal bearing on it was computed and did not
    hold), or ``no_signal`` (the sandbox computes nothing that bears on
    it at all). The three are kept apart deliberately: ``unsupported`` is
    not a benign verdict, and ``no_signal`` is not even a statement about
    the alert.
    """

    buckets: dict[str, list[str]] = {"supported": [], "unsupported": [], "no_signal": []}
    for technique in techniques:
        parent = technique.split(".", 1)[0]
        relevant = [s for s in signals if technique in s.bears_on or parent in s.bears_on]
        computed = [s for s in relevant if s.status != "not_computable"]
        if any(s.holds for s in computed):
            buckets["supported"].append(technique)
        elif computed:
            buckets["unsupported"].append(technique)
        else:
            buckets["no_signal"].append(technique)
    return buckets
