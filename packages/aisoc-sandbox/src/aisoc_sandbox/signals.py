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

__all__ = ["Signal", "compute_signals", "technique_support"]


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
# Parsing helpers. Each returns None rather than a default: a default here
# would be a fabricated input to a real measurement.
# ---------------------------------------------------------------------------


def _parse_timestamp(value: Any) -> datetime | None:
    """ISO-8601 to an aware UTC datetime, or None.

    ``datetime.fromisoformat`` only learned to accept a trailing ``Z`` in
    3.11 and the package supports 3.10, so the suffix is normalised here
    rather than relied on.
    """

    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _normalise_city(name: str) -> str:
    key = " ".join(name.strip().lower().split())
    return _CITY_ALIASES.get(key, key)


def _actor_of(event: dict[str, Any]) -> str | None:
    for key in ("actor", "user", "username", "principal"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _address_of(event: dict[str, Any]) -> str | None:
    for key in ("client_ip", "source_ip", "src_ip", "ip"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


@dataclass(frozen=True)
class _Point:
    lat: float
    lon: float
    label: str


def _locate(event: dict[str, Any]) -> tuple[_Point | None, str | None]:
    """Resolve an event to coordinates, or explain why it could not be.

    Returns ``(point, None)`` on success and ``(None, reason)`` otherwise.
    Explicit coordinates on the event win over the table, so a user
    scenario can carry any location on earth without the gazetteer
    needing to know about it.
    """

    geo = event.get("geo")
    if not isinstance(geo, dict):
        return None, "carries no `geo` object"

    lat, lon = geo.get("lat", geo.get("latitude")), geo.get("lon", geo.get("longitude"))
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)) and not isinstance(lat, bool) and not isinstance(lon, bool):
        label = str(geo.get("city") or geo.get("country") or f"{float(lat):.4f},{float(lon):.4f}")
        return _Point(float(lat), float(lon), label), None

    city = geo.get("city")
    if not isinstance(city, str) or not city.strip():
        return None, "`geo` carries neither coordinates nor a city"

    key = _normalise_city(city)
    country = geo.get("country")
    country_key = country.strip().lower() if isinstance(country, str) else ""

    if country_key:
        point = _GAZETTEER.get((key, country_key))
        if point is None:
            return None, f"{city!r} in {country} is not in the sandbox's built-in city table"
        return _Point(point[0], point[1], f"{city}, {country}"), None

    matches = [(k, v) for k, v in _GAZETTEER.items() if k[0] == key]
    if not matches:
        return None, f"{city!r} is not in the sandbox's built-in city table"
    if len(matches) > 1:
        countries = ", ".join(sorted(k[1].upper() for k, _ in matches))
        return None, f"{city!r} is ambiguous without a country ({countries}) and was not guessed"
    (_, _), coords = matches[0]
    return _Point(coords[0], coords[1], city), None


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
    by_actor: dict[str, list[tuple[datetime, _Point]]] = {}
    unresolved: list[str] = []

    for event in events:
        actor, when = _actor_of(event), _parse_timestamp(event.get("published") or event.get("timestamp"))
        if actor is None or when is None:
            continue
        point, reason = _locate(event)
        if point is None:
            if reason is not None and "carries no `geo` object" not in reason:
                unresolved.append(reason)
            continue
        by_actor.setdefault(actor, []).append((when, point))

    usable = {actor: sorted(points, key=lambda pair: pair[0]) for actor, points in by_actor.items() if len(points) >= 2}
    if not usable:
        detail = "; ".join(sorted(set(unresolved))) if unresolved else "no actor has two timestamped, geolocated events"
        return Signal(
            name="geo_velocity",
            status="not_computable",
            summary=(
                f"Travel speed could not be computed: {detail}. The live stack resolves coordinates"
                " through a geo-IP provider; the sandbox ships a small built-in city table and"
                " refuses to substitute a coordinate it does not have."
            ),
            inputs={"located_event_pairs": 0, "unresolved": sorted(set(unresolved))},
            bears_on=bears_on,
        )

    legs: list[tuple[float, str, str, str, float, float]] = []
    for actor, points in sorted(usable.items()):
        for (t0, p0), (t1, p1) in zip(points, points[1:], strict=False):
            hours = (t1 - t0).total_seconds() / 3600.0
            km = _haversine_km(p0, p1)
            legs.append((km / hours if hours > 0 else math.inf, actor, p0.label, p1.label, km, hours))

    speed, actor, origin, destination, km, hours = max(legs, key=lambda leg: leg[0])
    speed_text = f"{speed:,.1f}" if math.isfinite(speed) else "unbounded (the two events share a timestamp)"
    inputs: dict[str, Any] = {
        "actor": actor,
        "from": origin,
        "to": destination,
        "distance_km": round(km, 1),
        "elapsed_hours": round(hours, 3),
        "implied_speed_kmh": round(speed, 1) if math.isfinite(speed) else "unbounded",
        "threshold_kmh": MAX_PLAUSIBLE_KMH,
        "minimum_significant_km": MIN_SIGNIFICANT_KM,
        "unresolved": sorted(set(unresolved)),
    }
    movement = f"{actor} appears at {destination} {hours:.2f} h after {origin} — {km:,.1f} km apart, implied speed {speed_text} km/h"

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
    stamps = sorted(t for t in (_parse_timestamp(e.get("published") or e.get("timestamp")) for e in events) if t is not None)
    if len(stamps) < 2:
        return Signal(
            name="event_burst",
            status="not_computable",
            summary=f"Event rate needs two parsable timestamps; {len(stamps)} of {_plural(len(events), 'event')} carried one.",
            inputs={"timestamped_events": len(stamps), "total_events": len(events)},
            bears_on=bears_on,
        )

    span = (stamps[-1] - stamps[0]).total_seconds()
    window = 60.0
    densest = max(sum(1 for other in stamps if 0 <= (other - start).total_seconds() <= window) for start in stamps)
    inputs = {
        "events": len(stamps),
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
    countries = sorted(
        {
            str(e["geo"]["country"]).strip().upper()
            for e in events
            if isinstance(e.get("geo"), dict) and isinstance(e["geo"].get("country"), str) and e["geo"]["country"].strip()
        }
    )
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
    ages = [
        (e.get("domain") or e.get("url") or "(unnamed destination)", int(e["domain_age_days"]))
        for e in events
        if isinstance(e.get("domain_age_days"), int) and not isinstance(e.get("domain_age_days"), bool)
    ]
    if not ages:
        return Signal(
            name="recorded_domain_age",
            status="not_computable",
            summary="No event records a `domain_age_days` field, and the sandbox has no network to look one up.",
            inputs={"events_with_domain_age": 0},
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
