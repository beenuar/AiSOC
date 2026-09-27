"""Which lake column an indicator of each type is actually recorded in.

Gap-closure Phase 8.1.

This module is where a retro-hunt silently fails if it is wrong, so it is
worth saying what it is for before what it does.

A retro-hunt sweeps a tenant's recorded history for an indicator somebody
else published. The sweep is only as good as the answer to "which column of
``aisoc.raw_events`` would this indicator be sitting in". Get that wrong and
every sweep returns zero, which reads to an operator as "we were never
exposed" rather than as "we never looked". That is the single most dangerous
way for this surface to fail, and it has already happened twice in this
repository at scale: 663 of 825 loaded detection rules matched on fields that
were never visible because the matcher read a flat namespace while connectors
nested the payload, and every Windows Sigma rule was unreachable because the
payload sits one level below what the engine flattened. Both passed their
tests throughout.

So the mapping below is not a reviewed table of plausible field names. Every
column is annotated with the OCSF path that
``services/fusion/app/services/lake_writer.py::event_to_row`` reads to
populate it, and ``scripts/check_ioc_lake_mapping.py`` reads that writer's
source and the ClickHouse DDL and fails when a column here is not one the
writer writes, or is not one the table has. The writer is the only thing that
puts a row in the lake, so agreeing with it is the same as agreeing with
recorded data. ``tests/isolation/test_retro_hunt_live.py`` then closes the
loop against a live warehouse: it drives a real OCSF event through the real
writer, inserts the row, and runs the sweep this module builds.

Three findings from reading the writer that a plausible-looking table would
have got wrong:

**A SHA-1 or an MD5 lands in the column called ``hash_sha256``.** ``_first_hash``
takes ``file.fingerprints[0].value`` whatever algorithm produced it, and only
falls back to a key literally named ``hash_sha256``. Mapping ``md5`` to a
``hash_md5`` column would have been reasonable, and would have matched nothing,
because no such column exists.

**An IPv4 address is stored as its IPv4-mapped IPv6 form.** The columns are
``IPv6``-typed and ``_to_ip_obj`` maps ``1.2.3.4`` to ``::ffff:1.2.3.4``, so a
predicate has to go through ``toIPv6()`` rather than compare to the string the
feed published.

**A URL has no column at all.** The writer records no URL anywhere except
inside ``raw_payload``, an unindexed ZSTD blob whose contents are
connector-dependent. Rather than emit a substring scan that costs a full table
read and returns a confident zero on connectors that do not populate it, the
type is declared unmapped with a reason. An unmapped type is reported to the
caller as a coverage gap, never as an absence of the indicator, which is the
same distinction ``app.services.agent_tools.siem_search`` draws for a backend
with no field mapping.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "LAKE_TABLE",
    "SWEEPABLE_TYPES",
    "UNMAPPED_TYPES",
    "LakeFieldMapping",
    "UnmappedIndicator",
    "mapping_for",
]

#: The one table a retro-hunt reads. Named here rather than imported from
#: ``lake_hunt`` so the mapping gate has a single symbol to check.
LAKE_TABLE = "aisoc.raw_events"


@dataclass(frozen=True)
class LakeColumn:
    """One lake column an indicator of some type could be recorded in.

    ``ocsf_paths`` is the load-bearing field. It names where
    ``event_to_row`` reads the value from, in the dotted form that function
    uses, and the mapping gate checks each one appears in that function's
    source. A column with no path is a column nothing populates.
    """

    #: Column name in ``aisoc.raw_events``.
    name: str
    #: OCSF paths ``event_to_row`` reads to fill this column.
    ocsf_paths: tuple[str, ...]
    #: True when the column is ``Array(String)`` and needs ``has()`` rather
    #: than ``=``.
    is_array: bool = False
    #: True when the column is ``IPv6``-typed, so the bound value has to go
    #: through ``toIPv6()`` to compare against a stored IPv4-mapped address.
    is_ip: bool = False


@dataclass(frozen=True)
class LakeFieldMapping:
    """Every column a sweep for one indicator type should read."""

    indicator_type: str
    columns: tuple[LakeColumn, ...]

    @property
    def column_names(self) -> tuple[str, ...]:
        return tuple(c.name for c in self.columns)


@dataclass(frozen=True)
class UnmappedIndicator:
    """An indicator type the lake genuinely cannot answer for, and why.

    Carried as data rather than as an omission so a sweep can say which
    types it did not check. An omission would be indistinguishable from a
    type nobody thought about.
    """

    indicator_type: str
    reason: str


#: The value written into ``iocs`` is the raw string from the OCSF endpoint
#: blocks, not the IPv6-normalised form the typed columns hold, so this is a
#: genuinely second path to the same event rather than a restatement of the
#: first. It is also the only bloom-indexed column among them.
_IOCS = LakeColumn(
    name="iocs",
    ocsf_paths=("src_endpoint.ip", "dst_endpoint.ip"),
    is_array=True,
)

_IOCS_HASH = LakeColumn(name="iocs", ocsf_paths=("file.fingerprints",), is_array=True)

#: Keyed by the Phase 4 indicator type, so an agent, the federated SIEM search
#: and a retro-hunt all speak one vocabulary. ``scripts/check_ioc_lake_mapping.py``
#: asserts this covers every type in ``app.services.agent_tools.indicators``
#: either here or in :data:`UNMAPPED_TYPES`, so a type added there cannot
#: quietly become a sweep that checks nothing.
SWEEPABLE_TYPES: dict[str, LakeFieldMapping] = {
    "ip": LakeFieldMapping(
        indicator_type="ip",
        columns=(
            LakeColumn(name="source_ip", ocsf_paths=("src_endpoint.ip",), is_ip=True),
            LakeColumn(name="dest_ip", ocsf_paths=("dst_endpoint.ip",), is_ip=True),
            _IOCS,
        ),
    ),
    "domain": LakeFieldMapping(
        indicator_type="domain",
        columns=(
            # `src_hostname` is deliberately absent. The writer fills it from
            # `device.name`, the reporting host, which is the tenant's own
            # asset rather than a name the event reached out to. Sweeping a
            # published malicious domain against it would only ever match a
            # customer who named a machine after the domain.
            LakeColumn(name="dst_hostname", ocsf_paths=("dst_endpoint.hostname",)),
        ),
    ),
    "hostname": LakeFieldMapping(
        indicator_type="hostname",
        columns=(
            LakeColumn(name="src_hostname", ocsf_paths=("device.name", "src_endpoint.hostname")),
            LakeColumn(name="dst_hostname", ocsf_paths=("dst_endpoint.hostname",)),
        ),
    ),
    "sha256": LakeFieldMapping(
        indicator_type="sha256",
        columns=(
            LakeColumn(name="hash_sha256", ocsf_paths=("file.fingerprints", "hash_sha256")),
            _IOCS_HASH,
        ),
    ),
    # sha1 and md5 read the same column as sha256, and that is the writer's
    # behaviour rather than an approximation of it: `_first_hash` returns
    # `file.fingerprints[0].value` without inspecting the algorithm, so a
    # connector whose first fingerprint is an MD5 puts an MD5 there. The
    # value's own shape (32 or 40 hex characters, checked by
    # `indicators.validate_value`) is what keeps the match unambiguous.
    "sha1": LakeFieldMapping(
        indicator_type="sha1",
        columns=(
            LakeColumn(name="hash_sha256", ocsf_paths=("file.fingerprints", "hash_sha256")),
            _IOCS_HASH,
        ),
    ),
    "md5": LakeFieldMapping(
        indicator_type="md5",
        columns=(
            LakeColumn(name="hash_sha256", ocsf_paths=("file.fingerprints", "hash_sha256")),
            _IOCS_HASH,
        ),
    ),
    "username": LakeFieldMapping(
        indicator_type="username",
        columns=(LakeColumn(name="user_name", ocsf_paths=("actor.user.name",)),),
    ),
    "process_name": LakeFieldMapping(
        indicator_type="process_name",
        columns=(LakeColumn(name="process_name", ocsf_paths=("process.name",)),),
    ),
}

#: Types the lake cannot answer for. Each reason names the column that does
#: not exist, so a reader can tell a deliberate refusal from an oversight.
UNMAPPED_TYPES: dict[str, UnmappedIndicator] = {
    "url": UnmappedIndicator(
        indicator_type="url",
        reason=(
            "The event lake records no URL column. A URL appears only inside raw_payload, "
            "which is an unindexed compressed blob that many connectors leave empty, so a "
            "substring scan would cost a full table read and return zero on the connectors "
            "that do not populate it. URLs are swept through the federated SIEM search "
            "instead, where the backends do carry a URL field."
        ),
    ),
}


def mapping_for(indicator_type: str) -> LakeFieldMapping | UnmappedIndicator | None:
    """Return the lake mapping for ``indicator_type``.

    Three outcomes rather than two. A :class:`LakeFieldMapping` means the lake
    can answer; an :class:`UnmappedIndicator` means it cannot and says why;
    ``None`` means the type is not one AiSOC knows at all, which is a caller
    error rather than a coverage gap.
    """
    mapping = SWEEPABLE_TYPES.get(indicator_type)
    if mapping is not None:
        return mapping
    return UNMAPPED_TYPES.get(indicator_type)
