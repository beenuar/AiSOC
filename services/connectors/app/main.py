"""
AiSOC Connectors Service
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import router

app = FastAPI(
    title="AiSOC Connectors",
    description="Security source connectors: CrowdStrike, Splunk, AWS Security Hub, Okta, Microsoft Sentinel",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")
