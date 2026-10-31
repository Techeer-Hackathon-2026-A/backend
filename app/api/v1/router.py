from fastapi import APIRouter, Depends

from app.api.v1.endpoints import fixes, pull_requests, reports, scans
from app.core.auth import verify_service_key

api_router = APIRouter(prefix="/api/v1", dependencies=[Depends(verify_service_key)])
api_router.include_router(scans.router)
api_router.include_router(reports.router)
api_router.include_router(fixes.router)
api_router.include_router(pull_requests.router)
