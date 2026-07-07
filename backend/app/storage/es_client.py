"""
담당: 심다움 (로그 마스터)

Elasticsearch 연결 클라이언트. AttackLog 저장/조회는 이 클라이언트를 통해 이뤄진다.
"""
from elasticsearch import Elasticsearch

from app.config import settings

es_client = Elasticsearch(settings.elasticsearch_url)

ATTACK_LOG_INDEX = "attack_logs"

# AttackLog 인덱스 매핑 - 검색/집계가 잦은 필드는 keyword로, 자유 텍스트는 text로 지정
ATTACK_LOG_MAPPING = {
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "source_ip": {"type": "keyword"},
            "attack_type": {"type": "keyword"},
            "target_endpoint": {"type": "keyword"},
            "target_name": {"type": "keyword"},
            "http_method": {"type": "keyword"},
            "payload_snippet": {"type": "text"},
            "user_agent": {"type": "text"},
            "matched_rule_name": {"type": "keyword"},
            "mitre_technique_id": {"type": "keyword"},
            "blocked": {"type": "boolean"},
            "risk_level": {"type": "keyword"},
        }
    }
}


def ensure_index_exists() -> None:
    """앱 시작 시 한 번 호출 - 인덱스가 없으면 매핑과 함께 생성."""
    if not es_client.indices.exists(index=ATTACK_LOG_INDEX):
        es_client.indices.create(index=ATTACK_LOG_INDEX, body=ATTACK_LOG_MAPPING)
