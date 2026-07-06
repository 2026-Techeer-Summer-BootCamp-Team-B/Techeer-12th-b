"""
담당: 심다움 (로그 마스터)

AttackLog 저장소. 기존에는 인메모리 리스트(_logs)였지만 Elasticsearch로 전환했다.
app/api/logs.py가 이 모듈의 get_logs / get_log_by_id를 호출하는 방식은 그대로 유지.

비정규화 저장 방침 (ERD 참고):
Elasticsearch는 관계형 조인이 없으므로, 저장 시점에 mitre_technique_id를
미리 조회해서 문서 안에 통째로 넣는다 (매번 조회 시 별도 매핑 테이블을 다시
찾지 않아도 되게). target_name은 다중 타겟 지원 시 Target 테이블 조회로 채울 예정 -
지금은 단일 타겟(Juice Shop) 단계라 호출부에서 직접 넘겨주지 않으면 비워둔다.
"""
from datetime import datetime
from typing import List, Optional, Tuple

from app.detection.mitre_mapping import get_mitre_mapping
from app.models.schemas import AttackLog, AttackType, RiskLevel
from app.storage.es_client import ATTACK_LOG_INDEX, es_client


def add_log(log: AttackLog) -> None:
    """공격 로그 하나를 Elasticsearch에 저장. 저장 전에 ATT&CK 매핑을 채워 넣는다."""
    if log.mitre_technique_id is None:
        mapping = get_mitre_mapping(log.attack_type)
        if mapping is not None:
            log.mitre_technique_id = mapping["technique_id"]

    doc = log.model_dump(mode="json")
    es_client.index(index=ATTACK_LOG_INDEX, id=log.id, document=doc)


def _build_filter_query(
    attack_type: Optional[AttackType],
    source_ip: Optional[str],
    risk_level: Optional[RiskLevel],
    start_date: Optional[datetime],
    end_date: Optional[datetime],
) -> dict:
    must = []
    if attack_type is not None:
        must.append({"term": {"attack_type": attack_type.value}})
    if source_ip is not None:
        must.append({"term": {"source_ip": source_ip}})
    if risk_level is not None:
        must.append({"term": {"risk_level": risk_level.value}})
    if start_date is not None or end_date is not None:
        date_range = {}
        if start_date is not None:
            date_range["gte"] = start_date.isoformat()
        if end_date is not None:
            date_range["lte"] = end_date.isoformat()
        must.append({"range": {"timestamp": date_range}})

    return {"query": {"bool": {"must": must}}} if must else {"query": {"match_all": {}}}


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
    query = _build_filter_query(attack_type, source_ip, risk_level, start_date, end_date)

    response = es_client.search(
        index=ATTACK_LOG_INDEX,
        body={
            **query,
            "sort": [{"timestamp": {"order": "desc"}}],
            "from": (page - 1) * page_size,
            "size": page_size,
        },
    )

    hits = response["hits"]["hits"]
    total = response["hits"]["total"]["value"]
    logs = [AttackLog(**hit["_source"]) for hit in hits]
    return logs, total


def get_log_by_id(log_id: str) -> Optional[AttackLog]:
    try:
        response = es_client.get(index=ATTACK_LOG_INDEX, id=log_id)
    except Exception:
        return None
    return AttackLog(**response["_source"])