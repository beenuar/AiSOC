"""
Plugin management endpoints.

GET    /plugins                   – list all loaded plugins
GET    /plugins/{plugin_id}       – get single plugin detail
POST   /plugins/{plugin_id}/enable
POST   /plugins/{plugin_id}/disable
POST   /plugins/{plugin_id}/reload
DELETE /plugins/{plugin_id}       – unload (does not delete from disk)
POST   /plugins/{plugin_id}/run   – invoke plugin directly (enricher/action)
POST   /plugins/discover          – re-scan AISOC_PLUGINS_DIR

MIT License — Cyble Open-Source AiSOC
"""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.api.v1.deps import AuthUser, CurrentUser, require_permission
from app.services.plugin_manager import (
    LoadedPlugin,
    PluginError,
    get_plugin_manager,
    PluginManager,
)

router = APIRouter(prefix="/plugins", tags=["plugins"])


# ── Response schemas ──────────────────────────────────────────────────────────

class PluginManifestOut(BaseModel):
    id: str
    name: str
    version: str
    plugin_type: str
    description: str
    author: str
    tags: list[str]
    config_schema: dict[str, Any]


class PluginOut(BaseModel):
    id: str
    manifest: PluginManifestOut
    enabled: bool
    loaded_at: float
    error: str | None


class RunRequest(BaseModel):
    payload: dict[str, Any] = {}
    context: dict[str, Any] = {}


class RunResponse(BaseModel):
    plugin_id: str
    result: dict[str, Any]


class DiscoverResponse(BaseModel):
    discovered: list[str]


def _to_plugin_out(lp: LoadedPlugin) -> PluginOut:
    m = lp.manifest
    return PluginOut(
        id=lp.plugin_id,
        manifest=PluginManifestOut(
            id=m.id,
            name=m.name,
            version=m.version,
            plugin_type=m.plugin_type,
            description=m.description,
            author=m.author,
            tags=m.tags,
            config_schema=m.config_schema,
        ),
        enabled=lp.enabled,
        loaded_at=lp.loaded_at,
        error=lp.error,
    )


def _mgr() -> PluginManager:
    return get_plugin_manager()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("", response_model=list[PluginOut])
async def list_plugins(
    plugin_type: str | None = None,
    _: Annotated[AuthUser, Depends(require_permission("plugins:read"))] = None,
) -> list[PluginOut]:
    """List all currently loaded plugins, optionally filtered by type."""
    return [_to_plugin_out(p) for p in _mgr().list_plugins(plugin_type=plugin_type)]


@router.post("/discover", response_model=DiscoverResponse)
async def discover_plugins(
    _: Annotated[AuthUser, Depends(require_permission("plugins:admin"))] = None,
) -> DiscoverResponse:
    """Re-scan the plugins directory and load any new plugins found."""
    discovered = await _mgr().discover()
    return DiscoverResponse(discovered=discovered)


@router.get("/{plugin_id}", response_model=PluginOut)
async def get_plugin(
    plugin_id: str,
    _: Annotated[AuthUser, Depends(require_permission("plugins:read"))] = None,
) -> PluginOut:
    """Get details for a specific plugin."""
    p = _mgr().get_plugin(plugin_id)
    if p is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Plugin '{plugin_id}' not found")
    return _to_plugin_out(p)


@router.post("/{plugin_id}/enable", response_model=PluginOut)
async def enable_plugin(
    plugin_id: str,
    _: Annotated[AuthUser, Depends(require_permission("plugins:admin"))] = None,
) -> PluginOut:
    """Enable a loaded plugin."""
    try:
        await _mgr().enable(plugin_id)
    except PluginError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return _to_plugin_out(_mgr().get_plugin(plugin_id))  # type: ignore[arg-type]


@router.post("/{plugin_id}/disable", response_model=PluginOut)
async def disable_plugin(
    plugin_id: str,
    _: Annotated[AuthUser, Depends(require_permission("plugins:admin"))] = None,
) -> PluginOut:
    """Disable a loaded plugin (keeps it in memory but blocks invocations)."""
    try:
        await _mgr().disable(plugin_id)
    except PluginError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return _to_plugin_out(_mgr().get_plugin(plugin_id))  # type: ignore[arg-type]


@router.post("/{plugin_id}/reload", response_model=PluginOut)
async def reload_plugin(
    plugin_id: str,
    _: Annotated[AuthUser, Depends(require_permission("plugins:admin"))] = None,
) -> PluginOut:
    """Unload and re-import a plugin from disk (hot-reload)."""
    try:
        await _mgr().reload(plugin_id)
    except PluginError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return _to_plugin_out(_mgr().get_plugin(plugin_id))  # type: ignore[arg-type]


@router.delete("/{plugin_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unload_plugin(
    plugin_id: str,
    _: Annotated[AuthUser, Depends(require_permission("plugins:admin"))] = None,
) -> None:
    """Unload a plugin from memory (does not remove files from disk)."""
    try:
        await _mgr().unload(plugin_id)
    except PluginError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/{plugin_id}/run", response_model=RunResponse)
async def run_plugin(
    plugin_id: str,
    body: RunRequest,
    _: Annotated[AuthUser, Depends(require_permission("plugins:execute"))] = None,
) -> RunResponse:
    """
    Directly invoke a plugin.
    Supports enrichers, actions, and connectors.
    """
    try:
        result = await _mgr().run_any(plugin_id, body.payload, body.context)
    except PluginError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return RunResponse(plugin_id=plugin_id, result=result)
