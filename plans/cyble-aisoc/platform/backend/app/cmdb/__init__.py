"""Asset/CMDB intelligence (todo ``t2i-asset-cmdb``).

Public surface:

* :func:`resolve_asset` – fuzzy lookup by hostname / user / IP / alias.
* :func:`get_asset_context` – the rich asset profile every agent reads.
* :func:`upsert_asset` – idempotent connector-friendly write path.
* :func:`mirror_asset_into_graph` – keep the threat graph in sync.
"""
from app.cmdb.intel import (  # noqa: F401
    AssetContext,
    AssetRef,
    get_asset_context,
    list_assets,
    mirror_asset_into_graph,
    resolve_asset,
    upsert_asset,
)
