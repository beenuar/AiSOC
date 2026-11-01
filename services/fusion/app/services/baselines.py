"""Per-principal behavioural baselines, computed in CORE.

Depth plan 3.4: *"Behavioural scoring needs the `full`-profile UEBA service
today. Move its scoring core into fusion as a module, or add UEBA to CORE
behind an ADR that measures it."* ADR-0011 records why this is the module
and not the service.

What a baseline answers
-----------------------
Three questions, each about one principal and each a **typed signal rather
than an alert**:

* **Rarity.** Of everything this principal has done, how unusual is this
  action, this resource, this client family, this location? Reported in
  [0, 1], where 0.98 means "this principal has done this on 2% of their
  observed activity".
* **Peer deviation.** Against the principals who share their group, how far
  from the group's own normal is this volume? Reported as a bounded z-score.
* **Volume.** Against this principal's own hourly history — and separately
  against each OAuth application's — is this hour unusual?

None of these is a finding. A rare action is a rare action; an engineer who
has never touched IAM before touching IAM for the first time scores
identically to an attacker doing the same thing. They become findings only
when a rule pairs them with a threat condition, which is depth plan 3.5.

Why Redis and not Postgres
--------------------------
The scoring that `services/ueba` performs is a Welford mean and variance per
feature, kept in a Postgres JSONB column. The arithmetic is three lines; the
reason UEBA is a `full`-profile service is the table, the Alembic chain and
the Kafka consumer around it, not the statistics. Fusion already holds a
Redis for the windowed engine's sliding windows and for the Phase 3.3
first-seen store, so the counting state has a home in CORE that costs
nothing new. The service keeps its richer per-entity history for `full`; this
module gives CORE the signals that rules read.

Absent, not zero
----------------
The rule the rest of this package follows, and the one that matters most
here. An unreadable store, or a principal with too little history to say
anything, contributes **no key at all**. A rarity of `0.0` is a confident
statement that the principal does this routinely, and publishing that for an
account nobody has ever observed would silence exactly the rules that exist
to catch a new account behaving badly. A missing key means the clause does
not match and the rule stays quiet, which is the safe direction.

Bounded by construction
-----------------------
A principal's value set is attacker-influenceable: a resource name can be
anything, so an unbounded hash is a memory-exhaustion primitive aimed at the
detection path. Each `(principal, attribute)` hash stops admitting *new*
members at `MAX_DISTINCT_VALUES`. Past the cap the total still advances and
known values still score, so the baseline degrades into "we stopped learning
new values for this principal" rather than into a wrong answer or an outage.
"""

from __future__ import annotations

import math
import os
import time
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger()

#: How long a principal's baseline remembers. Matches the first-seen store
#: and the lake's default retention, so "normal for this principal" means
#: the same span everywhere a reader might compare them.
TTL_SECONDS = int(os.getenv("AISOC_BASELINE_TTL_SECONDS", str(90 * 86400)))

#: Observations a principal needs before any rarity is reported. Below this
#: every value looks rare, because every value *is* new — the first event a
#: principal ever produces is 100% of their history. Twenty is the point at
#: which "2% of their activity" stops being an artefact of a short history.
MIN_OBSERVATIONS = int(os.getenv("AISOC_BASELINE_MIN_OBSERVATIONS", "20"))

#: Hourly buckets a principal needs before a volume z-score is reported, and
#: the matching floor for a peer group. Welford over three points is not a
#: distribution.
MIN_VOLUME_SAMPLES = int(os.getenv("AISOC_BASELINE_MIN_VOLUME_SAMPLES", "12"))
MIN_PEER_MEMBERS = int(os.getenv("AISOC_BASELINE_MIN_PEER_MEMBERS", "5"))

#: Distinct values tracked per `(principal, attribute)` before the hash
#: stops admitting new members. See "Bounded by construction" above.
MAX_DISTINCT_VALUES = int(os.getenv("AISOC_BASELINE_MAX_DISTINCT", "512"))

#: The field holding the running total of observations for an attribute.
#: Prefixed so it cannot collide with a vendor value — a resource genuinely
#: named `__total__` would otherwise corrupt the denominator.
_TOTAL_FIELD = "__total__"

#: `<derived field a rule reads>` → the event fields naming its subject, in
#: the order they are trusted.
#:
#: Rarity is always *of a value, for a principal*, so each entry needs both.
#: The principal is resolved once per event by :func:`resolve_principal`.
#:
#: **Every chain must contain at least one name a connector actually emits**,
#: and a test asserts it against the same namespace
#: `scripts/check_detection_fields.py` builds. The first draft of this table
#: failed that for `baseline_client_family_rarity`: it listed
#: `client_family`, `user_agent_family` and `client_app`, and **no connector
#: emits any of the three**, so that rarity could never have been computed on
#: any deployment. It would have been a published signal that was structurally
#: incapable of firing — the exact shape this repository keeps finding, and
#: worse here than a missing feature because the field name reads as working.
RARITY_FIELDS: dict[str, tuple[str, ...]] = {
    "baseline_action_rarity": ("event_name", "eventName", "action", "event_type"),
    "baseline_resource_rarity": ("resource", "Resource", "resource_name", "target"),
    "baseline_client_family_rarity": ("user_agent", "userAgent", "clientAppUsed", "client_family"),
    "baseline_location_rarity": ("country", "ClientCountry", "countryOrRegion", "src_country"),
}

#: Event fields naming the principal whose baseline is being read, in trust
#: order. A service account and a human are both principals here; what makes
#: a baseline useful is that it is *per subject*, not that the subject is a
#: person.
PRINCIPAL_FIELDS: tuple[str, ...] = (
    "user",
    "user_name",
    "actor_email",
    "actor",
    "principal",
    "user_arn",
    "userPrincipalName",
)

#: Event fields naming the OAuth application acting, for the per-application
#: volume baseline the plan asks for. Distinct from the principal: a rogue
#: OAuth grant acts *as* a user, so the user's own volume looks normal while
#: the application's does not.
OAUTH_APP_FIELDS: tuple[str, ...] = (
    "application",
    "applicationName",
    "app_name",
    "client_id",
    "oauth_app",
)

#: Event fields naming the peer group a principal belongs to. Depth plan 3.4
#: names the Phase 2.5 posture snapshot as the source; until that lands, the
#: group is taken from whatever the identity provider already puts on the
#: event, which is what Workspace, Entra and Okta all emit. Resolving to
#: nothing yields no peer signal rather than a group of one.
PEER_GROUP_FIELDS: tuple[str, ...] = (
    "group",
    "groups",
    "role",
    "ROLE_NAME",
    "department",
)

#: The kinds of actor that get a baseline of their own (depth plan wave 2,
#: 1.4). Every one of these acts *on a human's behalf*, which is why folding
#: them into the human's baseline is backwards for the case these baselines
#: exist to catch: a stolen token acts as the user, so the user's own volume
#: and rarity stay normal while the token's do not.
#:
#: `oauth_app` is listed here as well as keeping its older volume-only
#: baseline, so the two namespaces do not collide: the old one is keyed
#: `vol:oauth_app` on the app name, the new one is keyed on
#: `sub:<kind>:<id>` and carries rarity too.
SUB_PRINCIPAL_KINDS: tuple[str, ...] = ("oauth_app", "api_token", "service_account", "ai_agent")

#: Vendor fields that name a token, per connector. Order is precedence.
#:
#: `hashed_token` is GitHub's own SHA-256 of the credential and is the join
#: key `services/ingest/internal/activity/session.go` writes into the
#: session projection. It is read **verbatim** -- see
#: :func:`resolve_sub_principal` for why that matters.
TOKEN_FIELDS: tuple[str, ...] = (
    "hashed_token",
    "token_id",
    "access_key_id",
    "accessKeyId",
    "api_key_id",
)

#: Fields naming a service account or workload identity.
SERVICE_ACCOUNT_FIELDS: tuple[str, ...] = (
    "service_account",
    "serviceAccountEmail",
    "service_account_email",
    "workload_identity",
)

#: Fields naming an AI agent acting for a person. Kept distinct from a
#: service account: an agent's cadence is interactive by nature, so folding
#: it into the service-account baseline would make every agent look like a
#: cron job that went rogue.
AI_AGENT_FIELDS: tuple[str, ...] = (
    "agent_id",
    "ai_agent",
    "assistant_id",
    "agent_name",
)

#: Every derived field this module can produce. Asserted against the gate's
#: own table in `services/fusion/tests/test_baselines.py`, in both
#: directions, so the two cannot drift the way the matcher's operator list
#: did (see depth plan deviation D9).
DERIVED_FIELDS: frozenset[str] = frozenset(
    set(RARITY_FIELDS)
    | {
        "baseline_principal_volume_z",
        "baseline_oauth_app_volume_z",
        "baseline_peer_deviation",
        # Depth plan wave 2, 1.4.
        "baseline_sub_principal_kind",
        "baseline_sub_principal_rarity",
        "baseline_sub_principal_volume_z",
        "baseline_token_cadence",
        "baseline_token_cadence_shift",
        "baseline_token_reactivated_after_idle",
        "baseline_token_new_asn_after_creation",
    }
)

#: A token silent for this long and then active again is worth a signal.
#: Sixty days from the plan; it is also comfortably longer than any leave
#: pattern, so a returning holidaymaker's token does not fire it.
IDLE_REACTIVATION_SECONDS = 60 * 24 * 3600

#: How soon after a token first appears a new ASN is suspicious. A token
#: created and used from somewhere else within the hour is the shape of a
#: credential that left the building before its first legitimate use.
NEW_TOKEN_ASN_WINDOW_SECONDS = 3600

#: Calls needed before a cadence claim is made. Three calls do not
#: establish a rhythm, and `scripted` returned for an unwatched token would
#: make the cadence-shift signal fire on the fourth call of every new token
#: in the estate.
CADENCE_MIN_SAMPLES = 8


def _first_present(event: dict[str, Any], candidates: tuple[str, ...]) -> str | None:
    """The first candidate field carrying a non-empty value, normalised."""
    for name in candidates:
        value = event.get(name)
        if value is None or value == "":
            continue
        text = str(value).strip().lower()
        if text:
            return text
    return None


def resolve_principal(event: dict[str, Any]) -> str | None:
    """The principal this event is about, or None if it names none."""
    return _first_present(event, PRINCIPAL_FIELDS)


@dataclass(frozen=True)
class SubPrincipal:
    """A token, app, service account or agent acting on a human's behalf."""

    kind: str
    id: str
    #: The human it acts for, where the event names one. Carried so a
    #: signal about the token can be attributed to a person without a
    #: second lookup, and left empty rather than guessed when it does not.
    on_behalf_of: str = ""

    @property
    def subject(self) -> str:
        """The baseline key. Namespaced by kind so two vendors' ids cannot collide."""
        return f"sub:{self.kind}:{self.id}"


def _verbatim(event: dict[str, Any], candidates: tuple[str, ...]) -> str | None:
    """First present candidate, trimmed and **not** case-folded.

    This exists because of one field. ``hashed_token`` is GitHub's SHA-256
    of the credential, and it is the join key
    ``services/ingest/internal/activity/session.go`` writes into the
    session projection using ``strings.TrimSpace`` and no case folding.

    Every other field in this module goes through :func:`_first_present`,
    which lowercases — correct for a username, wrong for a digest. Routing
    the token through the usual helper would produce a key that never joins
    to the session the Go side wrote, on every GitHub event, silently and
    with no error anywhere. ``test_sub_principal_baselines_reproduction.py``
    pins the two sides against each other.
    """
    for name in candidates:
        value = event.get(name)
        # A string, not anything stringifiable. Go's `str()` is
        # `if s, ok := v.(string); ok`, so a numeric `hashed_token` yields
        # no key there — and a Python side that coerced it to "12345" would
        # mint a baseline key Go never writes. The shared fixture caught
        # exactly this; `test_github_token_key_parity.py` keeps it caught.
        if not isinstance(value, str):
            continue
        text = value.strip()
        if text:
            return text
    return None


def resolve_sub_principal(event: dict[str, Any]) -> SubPrincipal | None:
    """The sub-principal acting, or ``None`` when the event names only a human.

    Precedence is narrowest-first: a token is more specific than the app it
    belongs to, which is more specific than the service account. An event
    naming several gets the narrowest, because that is the subject whose
    baseline a compromise would move.
    """
    on_behalf_of = resolve_principal(event) or ""

    token = _verbatim(event, TOKEN_FIELDS)
    if token:
        return SubPrincipal(kind="api_token", id=token, on_behalf_of=on_behalf_of)

    agent = _first_present(event, AI_AGENT_FIELDS)
    if agent:
        return SubPrincipal(kind="ai_agent", id=agent, on_behalf_of=on_behalf_of)

    app = _first_present(event, OAUTH_APP_FIELDS)
    if app:
        return SubPrincipal(kind="oauth_app", id=app, on_behalf_of=on_behalf_of)

    account = _first_present(event, SERVICE_ACCOUNT_FIELDS)
    if account:
        return SubPrincipal(kind="service_account", id=account, on_behalf_of=on_behalf_of)

    return None


def classify_cadence(hours: list[int]) -> str:
    """``scheduled`` | ``scripted`` | ``interactive`` | ``unknown``.

    From the hours-of-day a token has been seen at. The three classes are
    separated by *regularity* and *spread*, which is what the signal needs:
    the interesting transition is a token that behaved like a machine
    starting to behave like a person at a keyboard.

    * **scheduled** — even intervals across the clock. A cron job is the
      canonical case, and the tell is that the gaps between successive
      active hours barely vary.
    * **interactive** — concentrated inside a working day, with repeats
      within the same hour. A person.
    * **scripted** — regular but not evenly spaced, or spread without the
      within-hour clustering of a human.
    * **unknown** below :data:`CADENCE_MIN_SAMPLES`. Returning a class for
      a token nobody has watched would make the cadence-shift signal fire
      on the ninth call of every new token in the estate.
    """
    if len(hours) < CADENCE_MIN_SAMPLES:
        return "unknown"

    distinct = sorted(set(h % 24 for h in hours))
    if len(distinct) < 2:
        # Everything in one hour of the day, repeatedly: a daily job.
        return "scheduled"

    spread = len(distinct)
    repeats = len(hours) - spread

    # Interactive is tested **first**, and the order is the whole
    # classifier. A person working 09:00-17:00 produces consecutive active
    # hours whose gaps are almost all 1, which is indistinguishable from an
    # hourly cron by regularity alone. What separates them is that a person
    # calls several times within the same hour and a timer does not, so the
    # repeat count has to be consulted before the regularity is.
    if repeats >= 2 and max(distinct) - min(distinct) <= 12 and spread <= 12:
        return "interactive"

    # Gaps between consecutive active hours. The wrap-around gap is
    # deliberately excluded: an hourly job that runs only through the
    # morning has one 13-hour gap at the end of its day, and counting it
    # would make every part-time schedule look irregular.
    gaps = [b - a for a, b in zip(distinct, distinct[1:], strict=False)]
    mean_gap = sum(gaps) / len(gaps)
    variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)

    if variance <= 1.0 and spread >= 6:
        return "scheduled"
    return "scripted"


@dataclass(frozen=True)
class AnomalySignal:
    """One typed behavioural observation. Never an alert by itself.

    `kind` is the family (`rarity`, `volume`, `peer`), `subject` is what the
    baseline is held for, and `score` is in that family's own units —
    rarity in [0, 1], volume and peer as bounded z-scores. `observations`
    travels with the score because a z-score of 3 over 12 samples and one
    over 12,000 are different claims, and a consumer that cannot see the
    count cannot tell them apart.
    """

    kind: str
    subject: str
    attribute: str
    value: str
    score: float
    observations: int


def welford_add(stats: dict[str, float], value: float) -> dict[str, float]:
    """Advance a running mean and variance by one observation.

    Returns a new dict and mutates nothing. That is not a style preference:
    `services/ueba`'s copy of this edited its argument in place, the caller
    handed it the object SQLAlchemy had loaded, and the comparison that
    decides whether a JSONB column is dirty then found the two equal — so
    no baseline in that service ever advanced past its first event. Keeping
    the function pure is what makes that class of bug impossible here.
    """
    count = stats.get("count", 0.0) + 1
    mean = stats.get("mean", 0.0)
    m2 = stats.get("m2", 0.0)
    delta = value - mean
    mean += delta / count
    m2 += delta * (value - mean)
    return {"count": count, "mean": mean, "m2": m2}


def z_score(stats: dict[str, float], value: float, *, min_samples: int) -> float | None:
    """Deviations from the mean, or None when the baseline cannot say.

    None means *unknown* and never *normal*. Three cases produce it, and the
    third is the one that bites in production: service accounts and batch
    jobs converge on a constant, their standard deviation collapses to zero,
    and every subsequent value — however extreme — then sits exactly zero
    deviations from the mean. Returning 0.0 there would make the most
    automated account in the estate the least suspicious one it is possible
    to be.
    """
    count = stats.get("count", 0.0)
    if count < min_samples:
        return None
    variance = stats.get("m2", 0.0) / (count - 1) if count > 1 else 0.0
    std = math.sqrt(variance)
    if std < 1e-9:
        return None
    return abs(value - stats.get("mean", 0.0)) / std


class BaselineStore:
    """Per-principal behavioural state, in the Redis fusion already runs.

    Every method is fail-soft in the direction that keeps a novelty rule
    quiet: an unreachable Redis contributes no key, never a confident zero.
    """

    def __init__(
        self,
        redis: Any,
        *,
        key_prefix: str = "aisoc:bl",
        ttl_seconds: int | None = None,
        min_observations: int | None = None,
    ) -> None:
        self._redis = redis
        self._prefix = key_prefix
        self._ttl = ttl_seconds if ttl_seconds is not None else TTL_SECONDS
        self._min_observations = min_observations if min_observations is not None else MIN_OBSERVATIONS

    def _key(self, tenant: str, *parts: str) -> str:
        return ":".join((self._prefix, tenant, *parts))

    # -- rarity -----------------------------------------------------------

    async def observe_value(self, tenant: str, subject: str, attribute: str, value: str) -> tuple[int, int] | None:
        """Count one sighting; return (times seen, total for this attribute).

        None means the store could not answer. The pair is returned rather
        than a rarity so the caller can apply its own floor and so a test
        can assert on the counts instead of on a float derived from them.
        """
        key = self._key(tenant, subject, attribute)
        try:
            total = await self._redis.hincrby(key, _TOTAL_FIELD, 1)
            seen = await self._redis.hget(key, value)
            if seen is None:
                # Admit a new member only below the cap. Past it the total
                # still advances, so known values keep scoring correctly and
                # the baseline degrades into "stopped learning" rather than
                # into a wrong denominator.
                size = await self._redis.hlen(key)
                if size > MAX_DISTINCT_VALUES:
                    await self._redis.expire(key, self._ttl)
                    return None
                count = await self._redis.hincrby(key, value, 1)
            else:
                count = await self._redis.hincrby(key, value, 1)
            await self._redis.expire(key, self._ttl)
        except Exception as exc:  # noqa: BLE001 — see the class docstring
            logger.debug("baselines.unavailable", attribute=attribute, error=str(exc))
            return None
        return int(count), int(total)

    @staticmethod
    def rarity(count: int, total: int) -> float:
        """Share of this principal's history that is *not* this value.

        `count` includes the sighting being scored, which is deliberate: a
        value seen for the very first time scores `1 - 1/total` rather than
        a flat 1.0, so a rarity can never claim more confidence than the
        length of the history supports.
        """
        if total <= 0:
            return 0.0
        return max(0.0, min(1.0, 1.0 - (count / total)))

    # -- volume -----------------------------------------------------------

    async def observe_volume(self, tenant: str, subject: str, kind: str, *, now: float | None = None) -> float | None:
        """Count one event into this hour; return the z-score of the *previous* hour.

        Scoring the hour in progress would compare a partial count against
        a history of complete ones and call every event at :01 anomalous.
        When the hour rolls over, the completed bucket is folded into the
        running statistics and scored once.
        """
        when = now if now is not None else time.time()
        bucket = int(when // 3600)
        key = self._key(tenant, subject, f"vol:{kind}")
        try:
            state = await self._redis.hgetall(key)
            stats = _decode_stats(state)
            current_bucket = int(float(_field(state, "bucket") or bucket))
            current_count = float(_field(state, "count_in_bucket") or 0.0)

            if current_bucket == bucket:
                await self._redis.hset(key, "count_in_bucket", str(current_count + 1))
                await self._redis.hset(key, "bucket", str(bucket))
                await self._redis.expire(key, self._ttl)
                return None

            # The hour rolled over: the previous bucket is complete.
            score = z_score(stats, current_count, min_samples=MIN_VOLUME_SAMPLES)
            advanced = welford_add(stats, current_count)
            await self._redis.hset(key, "count", str(advanced["count"]))
            await self._redis.hset(key, "mean", str(advanced["mean"]))
            await self._redis.hset(key, "m2", str(advanced["m2"]))
            await self._redis.hset(key, "count_in_bucket", "1")
            await self._redis.hset(key, "bucket", str(bucket))
            await self._redis.expire(key, self._ttl)
        except Exception as exc:  # noqa: BLE001
            logger.debug("baselines.volume_unavailable", kind=kind, error=str(exc))
            return None
        return score

    # -- peer group -------------------------------------------------------

    async def observe_peer(self, tenant: str, group: str, subject: str, value: float) -> float | None:
        """Fold one member's observation into the group; return its deviation.

        The member count is tracked as a set rather than inferred from the
        observation count, because a group of one principal producing a
        thousand events is not a peer group — it is that principal's own
        baseline wearing a group's name, and comparing them would report
        every one of its events as perfectly typical.
        """
        key = self._key(tenant, "peer", group)
        members_key = f"{key}:members"
        try:
            await self._redis.sadd(members_key, subject)
            await self._redis.expire(members_key, self._ttl)
            members = int(await self._redis.scard(members_key) or 0)
            state = await self._redis.hgetall(key)
            stats = _decode_stats(state)
            score = z_score(stats, value, min_samples=MIN_PEER_MEMBERS) if members >= MIN_PEER_MEMBERS else None
            advanced = welford_add(stats, value)
            await self._redis.hset(key, "count", str(advanced["count"]))
            await self._redis.hset(key, "mean", str(advanced["mean"]))
            await self._redis.hset(key, "m2", str(advanced["m2"]))
            await self._redis.expire(key, self._ttl)
        except Exception as exc:  # noqa: BLE001
            logger.debug("baselines.peer_unavailable", group=group, error=str(exc))
            return None
        return score

    # -- the engine's entry point ----------------------------------------

    async def derived_fields(self, tenant: str, event: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
        """The baseline fields this event produces, for the detection engine.

        Mirrors `FirstSeenStore.derived_fields` deliberately: one awaited
        call per event, every key optional, and nothing raised into the
        pipeline. An event naming no principal produces nothing, because a
        baseline with no subject is not a baseline.
        """
        if not tenant:
            return {}
        principal = resolve_principal(event)
        if not principal:
            return {}

        out: dict[str, Any] = {}

        for field, candidates in RARITY_FIELDS.items():
            value = _first_present(event, candidates)
            if value is None:
                continue
            counted = await self.observe_value(tenant, principal, field, value)
            if counted is None:
                continue
            count, total = counted
            if total < self._min_observations:
                continue
            out[field] = round(self.rarity(count, total), 4)

        volume = await self.observe_volume(tenant, principal, "principal", now=now)
        if volume is not None:
            out["baseline_principal_volume_z"] = round(volume, 4)

        app = _first_present(event, OAUTH_APP_FIELDS)
        if app is not None:
            app_volume = await self.observe_volume(tenant, app, "oauth_app", now=now)
            if app_volume is not None:
                out["baseline_oauth_app_volume_z"] = round(app_volume, 4)

        # Depth plan wave 2, 1.4. The sub-principal gets a baseline of its
        # own, on the same store, so a stolen token moves a number even
        # while the human it acts for looks entirely normal.
        out.update(await self._sub_principal_fields(tenant, event, now=now))

        group = _first_present(event, PEER_GROUP_FIELDS)
        if group is not None:
            # The member's own hourly volume is the quantity compared across
            # the group. Rarity is not comparable between principals — one
            # person's rare action is another's routine — but "how much does
            # this account do in an hour" is the same question for everyone
            # in a department.
            deviation = await self.observe_peer(tenant, group, principal, 1.0)
            if deviation is not None:
                out["baseline_peer_deviation"] = round(deviation, 4)

        return out

    async def _sub_principal_fields(self, tenant: str, event: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
        """The four 1.4 signals for whichever sub-principal acted.

        Every one is fail-soft the same way the rest of the store is: an
        unreachable Redis contributes no key. A missing key reads as "no
        observation", never as a zero, because the consumers are detection
        rules and a zero would be a claim.
        """
        subject = resolve_sub_principal(event)
        if subject is None:
            return {}

        when = now if now is not None else time.time()
        out: dict[str, Any] = {"baseline_sub_principal_kind": subject.kind}

        # Rarity of this action for *this token*, which is the question the
        # human's own rarity cannot answer.
        action = _first_present(event, RARITY_FIELDS["baseline_action_rarity"])
        if action is not None:
            counted = await self.observe_value(tenant, subject.subject, "action", action)
            if counted is not None:
                count, total = counted
                if total >= self._min_observations:
                    out["baseline_sub_principal_rarity"] = round(self.rarity(count, total), 4)

        volume = await self.observe_volume(tenant, subject.subject, subject.kind, now=when)
        if volume is not None:
            out["baseline_sub_principal_volume_z"] = round(volume, 4)

        state = await self._advance_token_state(tenant, subject, event, when)
        out.update(state)
        return out

    async def _advance_token_state(
        self,
        tenant: str,
        subject: SubPrincipal,
        event: dict[str, Any],
        when: float,
    ) -> dict[str, Any]:
        """Cadence, idle reactivation and first-ASN-after-creation, in one hash.

        One Redis hash per sub-principal holding the hours it has been seen
        at, its last-seen timestamp, its first-seen timestamp and the ASNs
        it has used. Three signals out of one round trip, because this runs
        on the fusion hot path.
        """
        key = self._key(tenant, subject.subject, "token")
        hour = int((when % 86400) // 3600)
        asn = _first_present(event, ("asn", "src_asn", "autonomous_system", "as_number"))

        try:
            state = await self._redis.hgetall(key)
            previous_cadence = _field(state, "cadence") or "unknown"
            last_seen = float(_field(state, "last_seen") or 0.0)
            first_seen = float(_field(state, "first_seen") or 0.0)
            seen_hours = [int(h) for h in (_field(state, "hours") or "").split(",") if h.strip().isdigit()]
            known_asns = {a for a in (_field(state, "asns") or "").split(",") if a}

            seen_hours = (seen_hours + [hour])[-48:]
            cadence = classify_cadence(seen_hours)

            updates: dict[str, Any] = {
                "hours": ",".join(str(h) for h in seen_hours),
                "last_seen": repr(when),
                "cadence": cadence,
            }
            if first_seen <= 0:
                first_seen = when
                updates["first_seen"] = repr(when)
            if asn:
                updates["asns"] = ",".join(sorted({*known_asns, asn}))

            await self._redis.hset(key, mapping=updates)
            await self._redis.expire(key, self._ttl)
        except Exception as exc:  # noqa: BLE001 — see the class docstring
            logger.debug("baselines.token_state_unavailable", error=str(exc))
            return {}

        out: dict[str, Any] = {"baseline_token_cadence": cadence}

        # A machine identity that starts behaving like a person. Only
        # claimed when *both* classes are known: a shift out of `unknown`
        # is the token being watched long enough, not the token changing.
        if previous_cadence in {"scheduled", "scripted"} and cadence == "interactive" and previous_cadence != cadence:
            out["baseline_token_cadence_shift"] = f"{previous_cadence}->{cadence}"

        if last_seen > 0 and (when - last_seen) >= IDLE_REACTIVATION_SECONDS:
            out["baseline_token_reactivated_after_idle"] = round((when - last_seen) / 86400.0, 2)

        # A new ASN *shortly after the token first appeared*. Not "a new ASN
        # ever": tokens legitimately move networks, and a signal that fires
        # on every office-to-home switch is one that gets tuned out. The
        # window makes this the specific shape of a credential that left
        # the building before its first legitimate use.
        if asn and asn not in known_asns and known_asns and (when - first_seen) <= NEW_TOKEN_ASN_WINDOW_SECONDS:
            out["baseline_token_new_asn_after_creation"] = asn

        return out

    async def signals(self, tenant: str, event: dict[str, Any], *, now: float | None = None) -> list[AnomalySignal]:
        """The same observations as typed signals, for consumers that want them.

        Depth plan 3.4 requires each anomaly to be *a typed signal, not an
        alert on its own*. `derived_fields` serves the detection engine,
        which wants a flat namespace; this serves everything that wants to
        know what kind of observation it is holding.
        """
        fields = await self.derived_fields(tenant, event, now=now)
        principal = resolve_principal(event) or ""
        out: list[AnomalySignal] = []
        for field, score in fields.items():
            if field in RARITY_FIELDS:
                kind, attribute = "rarity", field
                value = _first_present(event, RARITY_FIELDS[field]) or ""
            elif field == "baseline_peer_deviation":
                kind, attribute = "peer", field
                value = _first_present(event, PEER_GROUP_FIELDS) or ""
            else:
                kind, attribute = "volume", field
                value = principal if field == "baseline_principal_volume_z" else (_first_present(event, OAUTH_APP_FIELDS) or "")
            out.append(
                AnomalySignal(
                    kind=kind,
                    subject=principal,
                    attribute=attribute,
                    value=value,
                    score=float(score),
                    observations=self._min_observations,
                )
            )
        return out


def _field(state: Any, name: str) -> str | None:
    """Read one field from a Redis hash whose keys may be bytes or str."""
    if not isinstance(state, dict):
        return None
    raw = state.get(name)
    if raw is None:
        raw = state.get(name.encode("utf-8"))
    if raw is None:
        return None
    return raw.decode("utf-8") if isinstance(raw, bytes | bytearray) else str(raw)


def _decode_stats(state: Any) -> dict[str, float]:
    """Welford state from a Redis hash, defaulting to an empty baseline."""
    out: dict[str, float] = {}
    for name in ("count", "mean", "m2"):
        raw = _field(state, name)
        if raw is None:
            continue
        try:
            out[name] = float(raw)
        except ValueError:
            continue
    return out
