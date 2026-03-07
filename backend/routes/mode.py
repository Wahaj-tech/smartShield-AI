"""
SmartShield Backend — Mode Routes

GET / POST endpoints for switching between filtering modes:
  - free:     all sites allowed
  - exam:     ai_tool, writing_assistant, development blocked
  - parental: adult, social_media blocked
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services import mode_service
from utils.logger import get_logger

log = get_logger("mode_routes")

router = APIRouter(tags=["Mode"])


class ModeRequest(BaseModel):
    mode: str = Field(..., examples=["free", "exam", "parental"])


@router.get("/mode")
async def get_mode():
    """Return the current active filtering mode."""
    try:
        result = mode_service.get_mode()
        return result
    except Exception as exc:
        log.error("Failed to get mode: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/mode")
async def set_mode(body: ModeRequest):
    """Switch the active filtering mode."""
    try:
        result = mode_service.set_mode(body.mode)
        if result.get("status") == "error":
            raise HTTPException(status_code=400, detail=result.get("message"))
        return result
    except HTTPException:
        raise
    except Exception as exc:
        log.error("Failed to set mode: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
