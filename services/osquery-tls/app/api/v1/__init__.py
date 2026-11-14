"""API v1 router for the osquery TLS service."""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    config,
    distributed_enqueue,
    distributed_read,
    distributed_status,
    distributed_write,
    enroll,
    fim,
    log,
    packs,
)

router = APIRouter(prefix="/api/v1/osquery")
router.include_router(enroll.router)
router.include_router(config.router)
router.include_router(log.router)
router.include_router(distributed_read.router)
router.include_router(distributed_write.router)
router.include_router(distributed_enqueue.router)
router.include_router(distributed_status.router)
router.include_router(packs.router)
router.include_router(fim.router)
