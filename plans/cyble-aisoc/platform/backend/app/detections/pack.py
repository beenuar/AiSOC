"""RulePack: load and manage a directory of Sigma YAML rules.

A RulePack is the unit of distribution. We ship the built-in pack at
``app/detections/rules/`` and consumers can also load tenant-specific
packs from arbitrary paths (used by Theme 3d "vertical packs").

The pack does not own the event stream; it is a passive collection.
Wire it into ``DetectionEngine`` to actually evaluate events.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from .sigma import SigmaParseError, SigmaRule

logger = logging.getLogger(__name__)


@dataclass
class RulePack:
    """An ordered, de-duplicated collection of Sigma rules."""

    name: str = "default"
    rules: list[SigmaRule] = field(default_factory=list)

    # --- loaders --------------------------------------------------------

    @classmethod
    def load_directory(
        cls,
        path: str | Path,
        *,
        name: str | None = None,
        strict: bool = False,
        exclude_subdirs: Iterable[str] = (),
    ) -> "RulePack":
        """Load every ``*.yml`` / ``*.yaml`` rule under ``path`` recursively.

        Args:
            path: Root directory of the pack.
            name: Optional pack name; defaults to the directory name.
            strict: If True, the first ``SigmaParseError`` aborts the
                load. If False (default), broken rules are logged and
                skipped — production runs prefer this because one bad
                rule shouldn't take the whole pack offline. CI should
                set ``strict=True``.
            exclude_subdirs: Names of immediate subdirectories under
                ``path`` whose contents should be skipped. The built-in
                pack uses this to exclude ``verticals/`` so vertical
                packs are only delivered to tenants explicitly
                assigned to them by the registry layer.
        """
        root = Path(path)
        if not root.exists() or not root.is_dir():
            raise FileNotFoundError(f"rule pack directory not found: {root}")

        # Resolve excluded subdirs to absolute paths so the membership
        # check below is a simple ``is_relative_to`` comparison.
        excluded_roots = [
            (root / sub).resolve() for sub in exclude_subdirs
        ]

        pack = cls(name=name or root.name)
        loaded = 0
        skipped = 0
        for yml in sorted(root.rglob("*.y*ml")):
            if yml.is_dir():
                continue
            resolved = yml.resolve()
            if any(_is_under(resolved, ex) for ex in excluded_roots):
                continue
            try:
                rule = SigmaRule.from_file(yml)
            except SigmaParseError as e:
                skipped += 1
                if strict:
                    raise
                logger.warning("rule_pack:skip path=%s err=%s", yml, e)
                continue
            pack.add(rule)
            loaded += 1
        logger.info(
            "rule_pack:loaded name=%s loaded=%d skipped=%d",
            pack.name,
            loaded,
            skipped,
        )
        return pack

    # --- mutation -------------------------------------------------------

    def add(self, rule: SigmaRule) -> None:
        """Append a rule. Later additions of the same id win."""
        for i, existing in enumerate(self.rules):
            if existing.id == rule.id:
                # Replacement: later definitions override earlier ones.
                # This lets a tenant override a built-in rule by id.
                self.rules[i] = rule
                return
        self.rules.append(rule)

    def extend(self, rules: Iterable[SigmaRule]) -> None:
        for r in rules:
            self.add(r)

    # --- accessors ------------------------------------------------------

    def __iter__(self) -> Iterator[SigmaRule]:
        return iter(self.rules)

    def __len__(self) -> int:
        return len(self.rules)

    def by_id(self, rule_id: str) -> SigmaRule | None:
        for r in self.rules:
            if r.id == rule_id:
                return r
        return None

    def filter_by_tag(self, tag: str) -> "RulePack":
        """Return a new pack containing only rules with ``tag``.

        Matching is case-insensitive and substring-based on tags,
        so ``"attack.t1078"`` and ``"attack.T1078"`` both match.
        """
        needle = tag.lower()
        return RulePack(
            name=f"{self.name}:{tag}",
            rules=[r for r in self.rules if any(needle in t.lower() for t in r.tags)],
        )

    def filter_by_severity(self, *levels: str) -> "RulePack":
        wanted = {s.lower() for s in levels}
        return RulePack(
            name=f"{self.name}:{'-'.join(sorted(wanted))}",
            rules=[r for r in self.rules if r.severity.value in wanted],
        )


def _is_under(child: Path, parent: Path) -> bool:
    """Return True if ``child`` is the same as or nested under ``parent``.

    ``Path.is_relative_to`` only exists on 3.9+. We use ``relative_to``
    in a try/except for broader compatibility and to gracefully handle
    paths on different drives (Windows).
    """
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False
