"""
담당: 심다움 (로그 집계) — 서동영(대시보드)의 차트/카드가 이 API들을 바로 사용
"""
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Query

from app.storage.log_store import get_logs

router = APIRouter(prefix="/api/stats", tags=["stats"])

_INTERVAL_TO_MINUTES = {"5m": 5, "1h": 60, "1d": 60 * 24}


@router.get("/summary")
def get_summary():
    """대시보드 상단 요약 카드용. GET /api/stats/summary"""
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    logs_today, total_today = get_logs(start_date=today_start, page=1, page_size=10_000)

    blocked_count = sum(1 for log in logs_today if log.blocked)
    type_counter = Counter(log.attack_type for log in logs_today)
    ip_counter = Counter(log.source_ip for log in logs_today)

    top_attack_type = type_counter.most_common(1)[0][0] if type_counter else None
    top_attack_ips = [{"ip": ip, "count": count} for ip, count in ip_counter.most_common(5)]

    return {
        "total_attacks_today": total_today,
        "blocked_count": blocked_count,
        "top_attack_type": top_attack_type,
        "top_attack_ips": top_attack_ips,
    }


@router.get("/timeline")
def get_timeline(
    interval: str = Query(default="1h", pattern="^(5m|1h|1d)$"),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
):
    """실시간 공격 타임라인 차트용. GET /api/stats/timeline"""
    logs, _ = get_logs(start_date=start_date, end_date=end_date, page=1, page_size=10_000)

    bucket_minutes = _INTERVAL_TO_MINUTES[interval]
    buckets: dict[datetime, dict] = defaultdict(lambda: {"count": 0, "critical_count": 0})

    for log in logs:
        # 타임스탬프를 버킷 단위로 내림
        epoch_minutes = int(log.timestamp.timestamp() // 60)
        bucket_epoch_minutes = epoch_minutes - (epoch_minutes % bucket_minutes)
        bucket_time = datetime.utcfromtimestamp(bucket_epoch_minutes * 60)

        buckets[bucket_time]["count"] += 1
        if log.risk_level == "CRITICAL":
            buckets[bucket_time]["critical_count"] += 1

    sorted_buckets = [
        {"time": time.isoformat() + "Z", **data}
        for time, data in sorted(buckets.items())
    ]
    return {"interval": interval, "buckets": sorted_buckets}


@router.get("/attack-type-distribution")
def get_attack_type_distribution():
    """공격 유형별 비율 파이차트용. GET /api/stats/attack-type-distribution"""
    logs, _ = get_logs(page=1, page_size=10_000)
    counter = Counter(log.attack_type for log in logs)
    total = sum(counter.values()) or 1
    return [
        {"attack_type": attack_type, "count": count, "ratio": round(count / total, 3)}
        for attack_type, count in counter.most_common()
    ]