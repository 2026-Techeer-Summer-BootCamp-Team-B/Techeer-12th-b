"""
담당: 윤재영 (중앙 로깅) — 대시보드(서동영)가 호출하는 API
"""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app.models.schemas import AttackType, RiskLevel
from app.storage.log_store import get_log_by_id, get_logs

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.get("")
def list_logs(
    attack_type: Optional[AttackType] = None,
    source_ip: Optional[str] = None,
    risk_level: Optional[RiskLevel] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
):
    """노션 API 명세의 GET /api/logs 구현체."""
    logs, total = get_logs(
        attack_type=attack_type,
        source_ip=source_ip,
        risk_level=risk_level,
        start_date=start_date,
        end_date=end_date,
        page=page,
        page_size=page_size,
    )
    return {"total": total, "page": page, "results": logs}


@router.get("/{log_id}")
def get_log_detail(log_id: str):
    """노션 API 명세의 GET /api/logs/{id} 구현체."""
    log = get_log_by_id(log_id)
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log