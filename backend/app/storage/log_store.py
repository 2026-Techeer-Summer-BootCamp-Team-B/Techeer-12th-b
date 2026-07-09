"""
담당: 심다움 (로그 마스터)

AttackLog 저장소. Elasticsearch 색인은 제거하고, OTel(OTLP)로 otel-collector에 실시간
전송하는 방식으로 전환했다 (조회/보관은 이제 Central SIEM 쪽 책임이라 이 파일에는
get_logs/get_log_by_id 같은 조회 함수가 더 이상 없다).

app/api/logs.py, app/api/stats.py(ES 조회 API)도 같은 이유로 삭제됨.
"""
from app.detection.mitre_mapping import get_mitre_mapping
from app.models.schemas import AttackLog
from app.otel.logger import emit_attack_log


def add_log(log: AttackLog) -> None:
    """공격 로그 하나를 OTel Collector로 전송. 전송 전에 ATT&CK 매핑을 채워 넣는다."""
    if log.mitre_technique_id is None:
        mapping = get_mitre_mapping(log.attack_type)
        if mapping is not None:
            log.mitre_technique_id = mapping["technique_id"]

    emit_attack_log(log)
