from fastapi import APIRouter

from backend.api.alerts import router as alerts_router
from backend.api.websocket import router as websocket_router


api_router = APIRouter()


api_router.include_router(
    alerts_router
)


api_router.include_router(
    websocket_router
)