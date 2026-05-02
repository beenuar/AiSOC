"""
Connectors service REST API.
"""
from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException

logger = structlog.get_logger()
router = APIRouter()


@router.get("/connectors")
async def list_connectors():
    """List all available connectors."""
    return {
        "connectors": [
            {"id": "crowdstrike", "name": "CrowdStrike Falcon", "category": "EDR"},
            {"id": "splunk", "name": "Splunk SIEM", "category": "SIEM"},
            {"id": "aws_security_hub", "name": "AWS Security Hub", "category": "Cloud"},
            {"id": "okta", "name": "Okta Identity", "category": "IAM"},
            {"id": "microsoft_sentinel", "name": "Microsoft Sentinel", "category": "SIEM"},
        ]
    }


@router.get("/connectors/{connector_id}/schema")
async def get_connector_schema(connector_id: str):
    """Get configuration schema for a connector."""
    schemas = {
        "crowdstrike": {
            "fields": [
                {"name": "client_id", "type": "string", "required": True, "label": "Client ID"},
                {"name": "client_secret", "type": "secret", "required": True, "label": "Client Secret"},
                {"name": "base_url", "type": "string", "required": False, "label": "Base URL", "default": "https://api.crowdstrike.com"},
            ]
        },
        "splunk": {
            "fields": [
                {"name": "base_url", "type": "string", "required": True, "label": "Splunk URL"},
                {"name": "token", "type": "secret", "required": True, "label": "HEC Token"},
                {"name": "saved_search", "type": "string", "required": False, "label": "Saved Search Name"},
            ]
        },
        "aws_security_hub": {
            "fields": [
                {"name": "region", "type": "string", "required": True, "label": "AWS Region", "default": "us-east-1"},
                {"name": "access_key", "type": "string", "required": False, "label": "Access Key ID"},
                {"name": "secret_key", "type": "secret", "required": False, "label": "Secret Access Key"},
            ]
        },
        "okta": {
            "fields": [
                {"name": "domain", "type": "string", "required": True, "label": "Okta Domain", "placeholder": "https://yourorg.okta.com"},
                {"name": "api_token", "type": "secret", "required": True, "label": "API Token"},
            ]
        },
        "microsoft_sentinel": {
            "fields": [
                {"name": "tenant_id", "type": "string", "required": True, "label": "Tenant ID"},
                {"name": "client_id", "type": "string", "required": True, "label": "Client ID"},
                {"name": "client_secret", "type": "secret", "required": True, "label": "Client Secret"},
                {"name": "subscription_id", "type": "string", "required": True, "label": "Subscription ID"},
                {"name": "resource_group", "type": "string", "required": True, "label": "Resource Group"},
                {"name": "workspace", "type": "string", "required": True, "label": "Workspace Name"},
            ]
        },
    }
    schema = schemas.get(connector_id)
    if not schema:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found")
    return schema


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-connectors"}
