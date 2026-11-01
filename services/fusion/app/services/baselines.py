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
    # The human an AI agent acted for. The `ai-runtime` template maps it to
    # `actor.user.name`, which is to say the vendor and the schema already
    # agree it is the principal; this module simply could not see it.
    "on_behalf_of",
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

#: Sub-principals: the things that act *as* a principal without being one.
#:
#: The OAuth application was the only one of these for a while, special-cased
#: inside `derived_fields`. Wave-2 Phase 1.4 asks for baselines per
#: sub-principal (OAuth app, personal access token, service account, and an
#: AI agent acting for a human) and wave-2 Phase 7.3 asks for per-agent
#: baselines. Those are the same mechanism with different subjects, so this
#: is a table and not four blocks of code: a new kind is one entry, and the
#: console cannot end up with two ways of saying the same thing.
#:
#: **The key is the field prefix.** `oauth_app` produces
#: `baseline_oauth_app_volume_z`, which is already published and must not
#: move; `agent` produces `baseline_agent_volume_z`. Deriving the name from
#: the key rather than from a second mapping means a reader can tell which
#: entry produced a field without consulting anything.
#:
#: Every chain must name at least one field a connector really emits — the
#: rule above `RARITY_FIELDS`, for the same reason. `agent_id`, `agent_name`
#: and `gateway_key` all come from `ai_gateway.normalize()` and the
#: `ai-runtime` ingest template.
SUB_PRINCIPAL_FIELDS: dict[str, tuple[str, ...]] = {
    "oauth_app": OAUTH_APP_FIELDS,
    "agent": ("agent_id", "agent_name"),
    # The gateway key a request was billed to. A compromised key used by a
    # well-behaved agent and a misbehaving agent on a normal key are
    # different incidents; only a baseline per subject separates them.
    "gateway_key": ("gateway_key",),
}

#: Per-kind rarity attributes: which of this subject's choices are worth
#: scoring for novelty. Keyed `kind -> {attribute: field chain}` and producing
#: `baseline_{kind}_{attribute}_rarity`.
#:
#: Rarity is per subject, never global, and for an agent that is the whole
#: value: `execute_command` is routine for a deployment bot and alarming for
#: a summariser, and a global count cannot tell them apart.
SUB_PRINCIPAL_RARITY: dict[str, dict[str, tuple[str, ...]]] = {
    "agent": {
        "tool": ("tool_name",),
        "model": ("model",),
    },
}

#: Kinds whose hour-of-day is baselined, producing
#: `baseline_{kind}_hour_rarity`. Computed from the event clock rather than
#: read from a field, because no connector emits an hour — stated here so it
#: does not look like an omission from `SUB_PRINCIPAL_RARITY`.
#:
#: An agent that has only ever run inside a nightly window and suddenly runs
#: at midday is the signal. A human's working hours are already covered by
#: the principal baseline, so this is deliberately not every kind.
HOUR_BASELINE_KINDS: frozenset[str] = frozenset({"agent"})

#: Kinds whose spend is baselined, producing
#: `baseline_{kind}_token_spend_z`. Depth 6.4 asks for token spend per agent;
#: wave-2 7.4 asks for it per key as well.
SPEND_BASELINE_KINDS: frozenset[str] = frozenset({"agent", "gateway_key"})

#: Where the cost of one request is read from. The gateway's own figure, in
#: dollars, promoted by `ai_gateway.normalize()`. Not recomputed here from
#: token counts and a price table: that would be a second meter disagreeing
#: with the one that is actually billed.
SPEND_VALUE_FIELDS: tuple[str, ...] = ("request_cost_usd",)

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

#: Every derived field this module can produce. Asserted against the gate's
#: own table in `services/fusion/tests/test_baselines.py`, in both
#: directions, so the two cannot drift the way the matcher's operator list
#: did (see depth plan deviation D9).
DERIVED_FIELDS: frozenset[str] = frozenset(
    set(RARITY_FIELDS)
    | {"baseline_principal_volume_z", "baseline_peer_deviation"}
    # Generated from the tables above rather than listed again. A hand-kept
    # second list is how a field comes to be computed and undeclared, or
    # declared and never computed — and the gate compares this set against
    # the one `scripts/check_detection_fields.py` builds, so either
    # direction of drift would be a false verdict rather than a loud one.
    | {f"baseline_{kind}_volume_z" for kind in SUB_PRINCIPAL_FIELDS}
    | {f"baseline_{kind}_{attribute}_rarity" for kind, attributes in SUB_PRINCIPAL_RARITY.items() for attribute in attributes}
    | {f"baseline_{kind}_hour_rarity" for kind in HOUR_BASELINE_KINDS}
    | {f"baseline_{kind}_token_spend_z" for kind in SPEND_BASELINE_KINDS}
)


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


def resolve_sub_principals(event: dict[str, Any]) -> list[tuple[str, str]]:
    """Every sub-principal this event names, as ``(kind, subject)``.

    A list rather than one value, because a single gateway span names both
    the agent that acted and the key it was billed to, and those are
    different incidents when they go wrong.

    An event naming none — which is every ordinary cloud and identity
    event — returns empty, and the caller emits nothing. A baseline with no
    subject is not a baseline, and inventing a placeholder would give every
    such event one shared subject and an unbounded Redis key space.
    """
    out: list[tuple[str, str]] = []
    for kind, chain in SUB_PRINCIPAL_FIELDS.items():
        subject = _first_present(event, chain)
        if subject is not None:
            out.append((kind, subject))
    return out


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

    # -- continuous amounts -----------------------------------------------

    async def observe_amount(self, tenant: str, subject: str, kind: str, value: float) -> float | None:
        """Fold one measured amount into this subject's history; return its z-score.

        Distinct from `observe_volume`, which counts events into an hourly
        bucket. Spend is a quantity carried by the event itself, so there is
        nothing to bucket: each request's cost is one observation.

        Scored against the history *before* this observation, so a value
        cannot flatten the distribution it is being judged against — the
        first large spend scores against what came before it rather than
        against a mean it has already moved.
        """
        key = self._key(tenant, subject, f"amt:{kind}")
        try:
            state = await self._redis.hgetall(key)
            stats = _decode_stats(state)
            score = z_score(stats, float(value), min_samples=MIN_VOLUME_SAMPLES)
            advanced = welford_add(stats, float(value))
            await self._redis.hset(key, "count", str(advanced["count"]))
            await self._redis.hset(key, "mean", str(advanced["mean"]))
            await self._redis.hset(key, "m2", str(advanced["m2"]))
            await self._redis.expire(key, self._ttl)
        except Exception as exc:  # noqa: BLE001 — see the class docstring
            logger.debug("baselines.amount_unavailable", kind=kind, error=str(exc))
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
        sub_principals = resolve_sub_principals(event)
        if not principal and not sub_principals:
            # Previously this returned on `not principal` alone, and that
            # skipped the whole module for any event naming a non-human
            # subject. A gateway span names an agent and a key and often no
            # person at all — an agent running on a schedule acts for
            # nobody — so every per-agent baseline was computed for exactly
            # zero events, while the field names read as working.
            #
            # "No subject of any kind" is still nothing to baseline, which
            # is what this now says.
            return {}

        out: dict[str, Any] = {}

        for field, candidates in RARITY_FIELDS.items():
            if not principal:
                break
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

        if principal:
            volume = await self.observe_volume(tenant, principal, "principal", now=now)
            if volume is not None:
                out["baseline_principal_volume_z"] = round(volume, 4)

        # Every sub-principal this event names, through one loop. The OAuth
        # application used to be special-cased here; it is now the first
        # entry in SUB_PRINCIPAL_FIELDS and produces the same published
        # field name, because the name is derived from the key.
        for kind, subject in sub_principals:
            sub_volume = await self.observe_volume(tenant, subject, kind, now=now)
            if sub_volume is not None:
                out[f"baseline_{kind}_volume_z"] = round(sub_volume, 4)

            for attribute, candidates in SUB_PRINCIPAL_RARITY.get(kind, {}).items():
                value = _first_present(event, candidates)
                if value is None:
                    continue
                counted = await self.observe_value(tenant, subject, f"{kind}:{attribute}", value)
                if counted is None:
                    continue
                count, total = counted
                if total < self._min_observations:
                    continue
                out[f"baseline_{kind}_{attribute}_rarity"] = round(self.rarity(count, total), 4)

            if kind in HOUR_BASELINE_KINDS:
                hour = time.strftime("%H", time.gmtime(now if now is not None else time.time()))
                counted = await self.observe_value(tenant, subject, f"{kind}:hour", hour)
                if counted is not None:
                    count, total = counted
                    if total >= self._min_observations:
                        out[f"baseline_{kind}_hour_rarity"] = round(self.rarity(count, total), 4)

            if kind in SPEND_BASELINE_KINDS:
                cost = _amount(event, SPEND_VALUE_FIELDS)
                # Absent stays absent. A gateway that did not price a
                # request must not teach the baseline the request was free:
                # a spend baseline fed zeros learns this agent costs nothing
                # and then never flags anything again.
                if cost is not None:
                    spend = await self.observe_amount(tenant, subject, f"spend:{kind}", cost)
                    if spend is not None:
                        out[f"baseline_{kind}_token_spend_z"] = round(spend, 4)

        group = _first_present(event, PEER_GROUP_FIELDS) if principal else None
        # `principal` is re-tested rather than relied on through `group`:
        # the implication holds, but it holds three lines away and a type
        # checker cannot see it — and neither can the next reader.
        if group is not None and principal:
            # The member's own hourly volume is the quantity compared across
            # the group. Rarity is not comparable between principals — one
            # person's rare action is another's routine — but "how much does
            # this account do in an hour" is the same question for everyone
            # in a department.
            deviation = await self.observe_peer(tenant, group, principal, 1.0)
            if deviation is not None:
                out["baseline_peer_deviation"] = round(deviation, 4)

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
            elif field.endswith("_rarity"):
                kind, attribute = "rarity", field
                value = _signal_subject(event, field)
            elif field == "baseline_peer_deviation":
                kind, attribute = "peer", field
                value = _first_present(event, PEER_GROUP_FIELDS) or ""
            else:
                kind = "spend" if field.endswith("_token_spend_z") else "volume"
                attribute = field
                value = principal if field == "baseline_principal_volume_z" else _signal_subject(event, field)
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


def _amount(event: dict[str, Any], candidates: tuple[str, ...]) -> float | None:
    """The first candidate carrying a genuinely numeric value, or None.

    `None`, the empty string and anything unparseable all mean "not
    measured", and all stay `None`. Coercing them to `0.0` is the shape
    that has produced four separate meters in this repository reading zero
    for four different reasons.
    """
    for name in candidates:
        value = event.get(name)
        if value is None or value == "":
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return None


def _signal_subject(event: dict[str, Any], field: str) -> str:
    """Which subject produced a generated sub-principal field.

    Derived by matching the field's prefix against the table that generated
    it, rather than by a second mapping that could disagree with the first.
    """
    for kind in SUB_PRINCIPAL_FIELDS:
        if field.startswith(f"baseline_{kind}_"):
            return _first_present(event, SUB_PRINCIPAL_FIELDS[kind]) or ""
    return ""
