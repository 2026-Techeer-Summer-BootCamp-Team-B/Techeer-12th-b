"""
담당: 심다움 (로그 마스터) — ES 색인을 OTel(OTLP) 전송으로 교체

WAF가 탐지한 WafAlert를 Elasticsearch에 직접 색인하던 방식 대신, OpenTelemetry Logs SDK로
로그 레코드를 만들어 OTLP(HTTP)로 otel-collector에 push한다. Falco(stdout)/K8s Audit(파일)도
같은 Collector가 tail해서 한 곳(otel-collector)으로 모이므로, 이 파일이 WAF 계층에서
"중앙 수집"으로 들어가는 유일한 진입점이 된다.

resource의 log.source=waf 로 태깅해서, Collector/Central SIEM에서 Falco(log.source=falco),
K8s Audit(log.source=k8s-audit)과 구분할 수 있게 한다.
"""
from datetime import datetime, timezone

from opentelemetry._logs import SeverityNumber
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs import LoggerProvider, LogRecord
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.trace import TraceFlags

from app.config import settings
from app.models.schemas import RiskLevel, WafAlert

# risk_level(우리 프로젝트 3단계) -> OTel 표준 심각도. OTel Collector/백엔드 SIEM 대부분이
# severity_number 기준으로 필터링/알림을 걸므로 숫자값도 함께 채워준다.
_RISK_TO_SEVERITY = {
    RiskLevel.LOW: (SeverityNumber.INFO, "INFO"),
    RiskLevel.MEDIUM: (SeverityNumber.WARN, "WARN"),
    RiskLevel.CRITICAL: (SeverityNumber.ERROR, "ERROR"),
}

_resource = Resource.create({"service.name": "waf-gateway", "log.source": "waf"})
_logger_provider = LoggerProvider(resource=_resource)
# OTLPLogExporter는 endpoint를 생성자로 명시하면 그 값을 그대로 쓰고, env var에서 읽을 때만
# 자동으로 /v1/logs를 붙인다 - 그래서 여기서는 직접 붙여줘야 한다 (안 붙이면 Collector가 404를
# 던지는 걸 실제로 재현 확인함). settings.otel_exporter_otlp_endpoint 자체는 다른 곳(Collector
# ConfigMap, backend-deployment.yaml 등)과 맞춘 "base endpoint"만 담아 표준 OTel 환경변수
# 의미(OTEL_EXPORTER_OTLP_ENDPOINT)를 그대로 유지한다.
_logger_provider.add_log_record_processor(
    BatchLogRecordProcessor(
        OTLPLogExporter(endpoint=f"{settings.otel_exporter_otlp_endpoint.rstrip('/')}/v1/logs")
    )
)
_logger = _logger_provider.get_logger("waf-gateway")


def _to_nanos(dt: datetime) -> int:
    """naive datetime(WafAlert.timestamp는 datetime.utcnow() 기준)을 UTC로 간주해 ns로 변환."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1_000_000_000)


def emit_waf_alert(log: WafAlert) -> None:
    """탐지된 WafAlert 하나를 OTel 로그 레코드로 변환해 Collector로 전송."""
    severity_number, severity_text = _RISK_TO_SEVERITY[log.risk_level]

    # observed_timestamp와 body(바로 아래)는 파이프라인 계약 v1.0의
    # event.id = sha256_hex(observedTimeUnixNano + "|" + body) 해시 입력값이다.
    # SIEM 정규화 워커가 이 둘을 그대로 가져다 event.id를 계산하므로, 두 값의 계산/직렬화
    # 방식(타임스탬프 인코딩, JSON 직렬화 등)을 바꿀 땐 반드시 SIEM 쪽 계약도 함께 갱신할 것.
    _logger.emit(
        LogRecord(
            timestamp=_to_nanos(log.timestamp),
            observed_timestamp=_to_nanos(datetime.now(timezone.utc)),
            # 이 로그는 트레이스 컨텍스트 없이 단독으로 발생하므로 0으로 명시해야 한다 -
            # None으로 두면 OTLP 인코더가 span_id/trace_id를 bytes로 변환하다 죽는다
            # (실제로 otlp-proto-http 익스포터에서 AttributeError로 재현 확인함).
            trace_id=0,
            span_id=0,
            trace_flags=TraceFlags(TraceFlags.DEFAULT),
            severity_number=severity_number,
            severity_text=severity_text,
            body=log.model_dump_json(),
            attributes={
                "attack_type": log.attack_type.value,
                "source_ip": log.source_ip,
                "target_endpoint": log.target_endpoint,
                "target_name": log.target_name or "",
                "http_method": log.http_method,
                "matched_rule_id": log.matched_rule_id or "",
                "mitre_technique_id": log.mitre_technique_id or "",
                "blocked": log.blocked,
            },
        )
    )


def shutdown() -> None:
    """앱 종료 시 배치 큐에 남은 로그를 마저 내보내고 익스포터를 정리."""
    _logger_provider.shutdown()
