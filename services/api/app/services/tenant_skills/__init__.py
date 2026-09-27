"""Tenant-authored investigation skills: parsing, tool validation, lifecycle.

Gap-closure Phase 6.1 and 6.2. Read ``models.py`` for the document shape,
``tools.py`` for what "a tool the tenant does not have" means, and
``store.py`` for the draft to backtested to active ladder and the refusals
that make it worth having.
"""

from app.services.tenant_skills.models import (
    SkillMatch,
    SkillParseError,
    TenantSkill,
    parse_skill_yaml,
    skill_from_body,
)
from app.services.tenant_skills.store import (
    SkillLifecycleError,
    SkillNotFound,
    activate_skill,
    attach_backtest,
    delete_skill,
    get_skill,
    list_skills,
    list_versions,
    resolve_active_skills,
    retire_skill,
    save_skill,
    validate_yaml,
)
from app.services.tenant_skills.tools import (
    BUILTIN_PIVOTS,
    ToolInventory,
    tool_inventory_for_tenant,
    validate_expected_pivots,
)

__all__ = [
    "BUILTIN_PIVOTS",
    "SkillLifecycleError",
    "SkillMatch",
    "SkillNotFound",
    "SkillParseError",
    "TenantSkill",
    "ToolInventory",
    "activate_skill",
    "attach_backtest",
    "delete_skill",
    "get_skill",
    "list_skills",
    "list_versions",
    "parse_skill_yaml",
    "resolve_active_skills",
    "retire_skill",
    "save_skill",
    "skill_from_body",
    "tool_inventory_for_tenant",
    "validate_expected_pivots",
    "validate_yaml",
]
