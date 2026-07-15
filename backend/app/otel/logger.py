"""
담당: 심다움 (로그 마스터) — ES 색인을 OTel(OTLP) 전송으로 교체

WAF가 탐지한 WafAlert를 Elasticsearch에 직접 색인하던 방식 대신, OpenTelemetry Logs SDK로
로그 레코드를 만들어 OTLP(HTTP)로 otel-collector에 push한다. Falco(stdout)/K8s Audit(파일)도
같은 Collector가 tail해서 한 곳(otel-collector)으로 모이므로, 이 파일이 WAF 계층에서
"중앙 수집"으로 들어가는 유일한 진입점이 된다.

resource의 log.source=waf 로 태깅해서, Collector/Central SIEM에서 Falco(log.source=falco),
K8s Audit(log.source=k8s-audit)과 구분할 수 있게 한다.

⚠️ 배치 유실 주의: app/storage/log_store.py의 add_log()가 이제 로컬에 아무것도 남기지
않고 이 파일(emit_attack_log)만 거쳐서 나가므로, 여기서 잃어버리면 그 AttackLog는
어디에도 남지 않는다(완전 유실). BatchLogRecordProcessor는 exporter.export()가
LogExportResult.FAILURE를 반환해도(예외를 던지지 않는 한) 재시도나 로그 없이 그
배치를 그냥 버리는 게 기본 동작이다(opentelemetry-sdk의 _export_batch() 실측 확인 -
반환값 자체를 안 봄). otel-collector가 잠깐이라도 다운되면 그 사이의 AttackLog가
조용히 사라지는 이유. _ResilientLogExporter가 반환값을 직접 체크해서 실패 시
경고 로그 + 로컬 fallback 파일 저장으로 최소한의 안전망을 둔다.
"""
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Sequence

from opentelemetry._logs import SeverityNumber
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs import LoggerProvider, LogData, LogRecord
from opentelemetry.sdk._logs.export import (
    BatchLogRecordProcessor,
    LogExporter,
    LogExportResult,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.trace import TraceFlags

from app.config import settings
from app.models.schemas import RiskLevel, WafAlert

_logger_module = logging.getLogger(__name__)

# risk_level(우리 프로젝트 3단계) -> OTel 표준 심각도. OTel Collector/백엔드 SIEM 대부분이
# severity_number 기준으로 필터링/알림을 걸므로 숫자값도 함께 채워준다.
_RISK_TO_SEVERITY = {
    RiskLevel.LOW: (SeverityNumber.INFO, "INFO"),
    RiskLevel.MEDIUM: (SeverityNumber.WARN, "WARN"),
    RiskLevel.CRITICAL: (SeverityNumber.ERROR, "ERROR"),
}


class _ResilientLogExporter(LogExporter):
    """OTLPLogExporter를 감싸서 export() 반환값을 직접 확인한다.

    BatchLogRecordProcessor._export_batch()는 exporter.export()의 반환값
    (LogExportResult.SUCCESS/FAILURE)을 아예 읽지 않는다 - 예외가 나야만
    _logger.exception()으로 남는다. 그래서 otel-collector가 살아있는 것처럼
    응답하되 처리에 실패하는 경우는 물론, 커넥션 자체가 안 되는 경우도 조용히
    사라진다. 여기서 FAILURE를 감지해 경고 로그를 남기고, 원본을 로컬 파일에
    append해서 최소한 나중에 복구할 수 있게 한다(자동 재전송은 아님 - 사람이
    fallback 파일을 보고 수동으로 재적재해야 함).
    """

    def __init__(self, inner: LogExporter, fallback_path: str):
        self._inner = inner
        self._fallback_path = fallback_path

    def export(self, batch: Sequence[LogData]):
        result = self._inner.export(batch)
        if result == LogExportResult.FAILURE:
            _logger_module.warning(
                "OTel 로그 export 실패 - %d건을 로컬 fallback(%s)에 저장",
                len(batch),
                self._fallback_path,
            )
            self._write_fallback(batch)
        return result

    def _write_fallback(self, batch: Sequence[LogData]) -> None:
        try:
            with open(self._fallback_path, "a", encoding="utf-8") as f:
                for log_data in batch:
                    f.write(
                        json.dumps(
                            {
                                "timestamp": log_data.log_record.timestamp,
                                "severity_text": log_data.log_record.severity_text,
                                "body": log_data.log_record.body,
                            }
                        )
                        + "\n"
                    )
        except OSError:
            _logger_module.exception(
                "fallback 파일 쓰기도 실패 - 이 배치(%d건)는 복구 불가", len(batch)
            )

    def shutdown(self):
        self._inner.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        force_flush = getattr(self._inner, "force_flush", None)
        return force_flush(timeout_millis) if force_flush else True


_resource = Resource.create({"service.name": "waf-gateway", "log.source": "waf"})
_logger_provider = LoggerProvider(resource=_resource)
# 재전송 루프(retry_fallback_loop)가 fallback 파일을 다시 내보낼 때도 이 인스턴스를
# 직접 쓴다 - _ResilientLogExporter를 거치면 재시도가 또 실패했을 때 지금 막
# 읽어서 지우려는 그 fallback 파일에 다시 append하게 되어 파일을 손상시킨다
# (아래 _retry_fallback_once 참고).
_otlp_exporter = OTLPLogExporter(
    endpoint=f"{settings.otel_exporter_otlp_endpoint.rstrip('/')}/v1/logs"
)
# OTLPLogExporter는 endpoint를 생성자로 명시하면 그 값을 그대로 쓰고, env var에서 읽을 때만
# 자동으로 /v1/logs를 붙인다 - 그래서 여기서는 직접 붙여줘야 한다 (안 붙이면 Collector가 404를
# 던지는 걸 실제로 재현 확인함). settings.otel_exporter_otlp_endpoint 자체는 다른 곳(Collector
# ConfigMap, backend-deployment.yaml 등)과 맞춘 "base endpoint"만 담아 표준 OTel 환경변수
# 의미(OTEL_EXPORTER_OTLP_ENDPOINT)를 그대로 유지한다.
_logger_provider.add_log_record_processor(
    BatchLogRecordProcessor(
        _ResilientLogExporter(_otlp_exporter, fallback_path=settings.otel_export_fallback_path),
        # [실측 확인, 2026-07-14] schedule_delay_millis 기본값(5000ms)을 그대로 뒀더니
        # WAF 탐지 시점부터 Kafka에 실제로 나가기까지 이 배치 큐 하나가 최대 5초를
        # 잡아먹는 게 파이프라인 전체 지연의 90% 이상을 차지하는 걸 otel-collector
        # 로그로 직접 확인함(이벤트 여러 건이 5초 간격으로 뭉쳐서 나가는 패턴).
        # 나머지 구간(collector batch/Kafka/normalizer/correlation-engine/Postgres)은
        # 전부 합쳐도 0.3초 안팎이라, 중앙 otel-collector의 batch.timeout과 동일하게
        # 500ms로 낮춰서 이 단일 병목을 없앤다.
        schedule_delay_millis=500,
        # 기본 max_queue_size(2048)로도 대부분은 충분하지만, 짧은 outage 동안 유실
        # 창을 조금 더 넉넉히 벌려둔다 - 그래도 무한정 버텨주는 건 아니라서(큐가
        # 꽉 차면 deque가 오래된 항목을 자동으로 조용히 버림, exporter FAILURE
        # 여부와 별개 문제) 위 fallback 파일이 실질적인 안전망이다.
        max_queue_size=8192,
    )
)
_logger = _logger_provider.get_logger("waf-gateway")

_RETRY_INTERVAL_SECONDS = 60


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
            resource=_resource,
            body=log.model_dump_json(),
            attributes={
                "attack_type": log.attack_type.value,
                "source_ip": log.source_ip,
                "target_endpoint": log.target_endpoint,
                "target_name": log.target_name or "",
                "http_method": log.http_method,
                "matched_rule_id": log.matched_rule_id or "",
                "matched_rule_name": log.matched_rule_name or "",
                "mitre_technique_id": log.mitre_technique_id or "",
                "blocked": log.blocked,
            },
        )
    )


def shutdown() -> None:
    """앱 종료 시 배치 큐에 남은 로그를 마저 내보내고 익스포터를 정리."""
    _logger_provider.shutdown()


def _retry_fallback_once() -> None:
    """fallback 파일에 쌓인 실패 배치를 한 번 재전송 시도한다.

    동시에 새로 실패하는 배치가 지금 읽고 있는 파일에 또 append되는 걸 막기
    위해, 먼저 파일 내용을 읽고 즉시 비운 다음(원자적이진 않지만 이 프로세스
    안에서 재전송은 항상 이 함수 하나만 돌기 때문에 충분하다) 실패분만 나중에
    다시 쓴다. _ResilientLogExporter가 아니라 내부 _otlp_exporter를 직접 써서
    재시도 실패가 이 함수가 방금 비운 파일에 또 append되는 재귀적 상황을
    피한다 - 실패분은 이 함수가 끝에서 직접 다시 쓴다.
    """
    path = settings.otel_export_fallback_path
    if not os.path.exists(path):
        return

    with open(path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    if not lines:
        return

    open(path, "w", encoding="utf-8").close()

    recovered = 0
    still_failed: list = []
    for line in lines:
        try:
            entry = json.loads(line)
            record = LogRecord(
                timestamp=entry["timestamp"],
                observed_timestamp=_to_nanos(datetime.now(timezone.utc)),
                trace_id=0,
                span_id=0,
                trace_flags=TraceFlags(TraceFlags.DEFAULT),
                severity_text=entry.get("severity_text"),
                resource=_resource,
                body=entry["body"],
            )
        except (json.JSONDecodeError, KeyError):
            _logger_module.exception("fallback 파일의 손상된 줄을 버림: %s", line[:200])
            continue

        result = _otlp_exporter.export([LogData(log_record=record, instrumentation_scope=None)])
        if result == LogExportResult.SUCCESS:
            recovered += 1
        else:
            still_failed.append(line)

    if still_failed:
        with open(path, "a", encoding="utf-8") as f:
            for line in still_failed:
                f.write(line + "\n")

    if recovered or still_failed:
        _logger_module.info(
            "fallback 재전송 시도 - 복구 %d건, 여전히 실패 %d건", recovered, len(still_failed)
        )


async def retry_fallback_loop() -> None:
    """앱 시작 시 백그라운드 태스크로 띄워서, otel-collector가 복구된 뒤
    fallback 파일에 쌓인 실패 배치를 주기적으로 자동 재전송한다(수동 재적재
    불필요하게 만드는 부분). export()는 블로킹 호출이라 asyncio.to_thread로
    돌려서 이벤트 루프를 막지 않는다."""
    while True:
        await asyncio.sleep(_RETRY_INTERVAL_SECONDS)
        try:
            await asyncio.to_thread(_retry_fallback_once)
        except Exception:
            _logger_module.exception("fallback 재전송 루프에서 처리되지 않은 예외 발생")
