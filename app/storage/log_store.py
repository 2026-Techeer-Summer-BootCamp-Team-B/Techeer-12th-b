"""
담당: 심다움 (로그 마스터)

AttackLog 저장소. 초기 뼈대는 인메모리 리스트로 구현.
app/api/logs.py가 이 모듈의 get_logs / get_log_by_id를 호출한다.
"""
from datetime import datetime
from typing import List, Optional, Tuple

from app.models.schemas import AttackLog, AttackType, RiskLevel

_logs: List[AttackLog] = []


def add_log(log: AttackLog) -> None:
    _logs.append(log)


def get_logs(
    *,
    attack_type: Optional[AttackType] = None,
    source_ip: Optional[str] = None,
    risk_level: Optional[RiskLevel] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    page: int = 1,
    page_size: int = 20,
) -> Tuple[List[AttackLog], int]:
    filtered = _logs
    if attack_type is not None:
        filtered = [log for log in filtered if log.attack_type == attack_type]
    if source_ip is not None:
        filtered = [log for log in filtered if log.source_ip == source_ip]
    if risk_level is not None:
        filtered = [log for log in filtered if log.risk_level == risk_level]
    if start_date is not None:
        filtered = [log for log in filtered if log.timestamp >= start_date]
    if end_date is not None:
        filtered = [log for log in filtered if log.timestamp <= end_date]

    total = len(filtered)
    start = (page - 1) * page_size
    end = start + page_size
    return filtered[start:end], total


def get_log_by_id(log_id: str) -> Optional[AttackLog]:
    return next((log for log in _logs if log.id == log_id), None)
