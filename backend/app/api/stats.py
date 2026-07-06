"""
담당: 심다움/서동영 (대시보드)

대시보드 시각화용 통계 API. Elasticsearch의 집계(aggregation) 쿼리를 사용해서
매번 전체 로그를 애플리케이션 레벨에서 훑지 않고, ES 안에서 바로 계산한다.
"""
from datetime import datetime, timedelta
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.dependencies import get_current_user
from app.detection.mitre_mapping import ATTACK_TYPE_TO_MITRE
from app.models.schemas import AttackType
from app.storage.es_client import ATTACK_LOG_INDEX, es_client
from app.storage.blacklist_store import list_blocked

router = APIRouter(prefix="/api/stats", tags=["stats"])

_RANGE_TO_TIMEDELTA = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


def _range_start(range_key: str) -> str:
    delta = _RANGE_TO_TIMEDELTA.get(range_key, _RANGE_TO_TIMEDELTA["24h"])
    return (datetime.utcnow() - delta).isoformat()


def _range_query(range_key: str) -> dict:
    return {"range": {"timestamp": {"gte": _range_start(range_key)}}}


class SummaryResponse(BaseModel):
    total_blocked: int
    active_blacklist_ips: int
    critical_count: int
    top_attack_type: Optional[str] = None


@router.get("/summary", response_model=SummaryResponse)
def get_summary(
    range: Literal["24h", "7d", "30d"] = Query(default="24h"),
    current_user: dict = Depends(get_current_user),
):
    response = es_client.search(
        index=ATTACK_LOG_INDEX,
        body={
            "query": _range_query(range),
            "size": 0,
            "aggs": {
                "critical_count": {"filter": {"term": {"risk_level": "CRITICAL"}}},
                "by_attack_type": {"terms": {"field": "attack_type", "size": 1}},
            },
        },
    )

    total_blocked = response["hits"]["total"]["value"]
    critical_count = response["aggregations"]["critical_count"]["doc_count"]
    top_buckets = response["aggregations"]["by_attack_type"]["buckets"]
    top_attack_type = top_buckets[0]["key"] if top_buckets else None

    return SummaryResponse(
        total_blocked=total_blocked,
        active_blacklist_ips=len(list_blocked()),
        critical_count=critical_count,
        top_attack_type=top_attack_type,
    )


class TimelinePoint(BaseModel):
    timestamp: str
    count: int


class TimelineResponse(BaseModel):
    points: List[TimelinePoint]


@router.get("/timeline", response_model=TimelineResponse)
def get_timeline(
    range: Literal["24h", "7d", "30d"] = Query(default="24h"),
    interval: Literal["1h", "1d"] = Query(default="1h"),
    current_user: dict = Depends(get_current_user),
):
    calendar_interval = "hour" if interval == "1h" else "day"

    response = es_client.search(
        index=ATTACK_LOG_INDEX,
        body={
            "query": _range_query(range),
            "size": 0,
            "aggs": {
                "over_time": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": calendar_interval,
                    }
                }
            },
        },
    )

    buckets = response["aggregations"]["over_time"]["buckets"]
    points = [TimelinePoint(timestamp=b["key_as_string"], count=b["doc_count"]) for b in buckets]
    return TimelineResponse(points=points)


class AttackTypeCount(BaseModel):
    attack_type: str
    count: int
    mitre_technique_id: Optional[str] = None


class ByAttackTypeResponse(BaseModel):
    items: List[AttackTypeCount]


@router.get("/by-attack-type", response_model=ByAttackTypeResponse)
def get_by_attack_type(
    range: Literal["24h", "7d", "30d"] = Query(default="24h"),
    current_user: dict = Depends(get_current_user),
):
    response = es_client.search(
        index=ATTACK_LOG_INDEX,
        body={
            "query": _range_query(range),
            "size": 0,
            "aggs": {
                "by_type": {"terms": {"field": "attack_type", "size": 25}},
            },
        },
    )

    buckets = response["aggregations"]["by_type"]["buckets"]
    items = []
    for b in buckets:
        attack_type_value = b["key"]
        mapping = ATTACK_TYPE_TO_MITRE.get(AttackType(attack_type_value))
        items.append(
            AttackTypeCount(
                attack_type=attack_type_value,
                count=b["doc_count"],
                mitre_technique_id=mapping["technique_id"] if mapping else None,
            )
        )
    return ByAttackTypeResponse(items=items)


class TopIpEntry(BaseModel):
    source_ip: str
    count: int
    is_blocked: bool


class TopIpsResponse(BaseModel):
    items: List[TopIpEntry]


@router.get("/top-ips", response_model=TopIpsResponse)
def get_top_ips(
    range: Literal["24h", "7d", "30d"] = Query(default="24h"),
    limit: int = Query(default=10, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
):
    response = es_client.search(
        index=ATTACK_LOG_INDEX,
        body={
            "query": _range_query(range),
            "size": 0,
            "aggs": {
                "top_ips": {"terms": {"field": "source_ip", "size": limit}},
            },
        },
    )

    blocked_ips = {entry["ip"] for entry in list_blocked()}
    buckets = response["aggregations"]["top_ips"]["buckets"]
    items = [
        TopIpEntry(source_ip=b["key"], count=b["doc_count"], is_blocked=b["key"] in blocked_ips)
        for b in buckets
    ]
    return TopIpsResponse(items=items)


class MitreCoverageEntry(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    detected_count: int


class MitreCoverageResponse(BaseModel):
    items: List[MitreCoverageEntry]


@router.get("/mitre-coverage", response_model=MitreCoverageResponse)
def get_mitre_coverage(current_user: dict = Depends(get_current_user)):
    """전체 기간 기준으로 attack_type별 탐지 건수를 집계하고, ATT&CK 매핑 정보를 붙여서 반환."""
    response = es_client.search(
        index=ATTACK_LOG_INDEX,
        body={
            "size": 0,
            "aggs": {"by_type": {"terms": {"field": "attack_type", "size": 30}}},
        },
    )

    counts_by_type = {b["key"]: b["doc_count"] for b in response["aggregations"]["by_type"]["buckets"]}

    items = []
    for attack_type, mapping in ATTACK_TYPE_TO_MITRE.items():
        items.append(
            MitreCoverageEntry(
                tactic=mapping["tactic"],
                technique_id=mapping["technique_id"],
                technique_name=mapping["technique_name"],
                detected_count=counts_by_type.get(attack_type.value, 0),
            )
        )
    return MitreCoverageResponse(items=items)