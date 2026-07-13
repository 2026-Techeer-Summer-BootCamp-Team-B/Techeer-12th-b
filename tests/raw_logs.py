"""
otel-collector가 gRPC로 Central SIEM에 내보내기 "전" 단계의 원본 로그를 직접 읽어온다.
IDS-COLLECTOR의 platform-api 같은 외부 API는 전혀 안 건드린다 - otel-collector
DaemonSet 자체가 이 프로젝트(Techeer-12th-b)가 k3d 클러스터에 배포한 것이므로
"우리가 자체적으로 생성한 로그"의 일부다.

두 갈래로 나뉜다:
- k8s_audit/falco/was: otel-collector가 hostPath로 마운트해서 읽는 것과 완전히
  같은 파일(/var/log/kubernetes/audit, /var/log/pods)을 읽는다. otel-collector
  자신은 배포 이미지에 shell이 없어(distroless 계열) `kubectl exec`으로 못
  들어가므로, hostPath가 실제로 가리키는 k3d 노드 컨테이너(도커 컨테이너 자체)에
  `docker exec`으로 들어가서 tail한다 - 파일 경로가 100% 동일(hostPath 마운트 원본).
- waf: 디스크에 파일이 없다(백엔드가 OTel SDK로 otel-collector에 OTLP를 직접
  push) - 대신 otel-collector 자신의 표준출력(otel-collector-config.yaml의 debug
  exporter, verbosity: detailed)에 수신한 그대로 찍히므로 `kubectl logs`로 그
  원문을 읽어서 파싱한다. gRPC(otlp exporter, Central SIEM행)가 성공하든 실패하든
  이 debug 출력은 항상 남으므로 정확히 "gRPC로 바뀌기 전" 원본이다.
"""
import json
import re
import subprocess
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

K3D_NODES = ["k3d-techeer-ids-server-0", "k3d-techeer-ids-agent-0", "k3d-techeer-ids-agent-1"]
OTEL_NAMESPACE = "default"
OTEL_LABEL_SELECTOR = "app=otel-collector"

_AUDIT_LOG_GLOB = "/var/log/kubernetes/audit/audit*.log"
_WAS_LOG_GLOB = "/var/log/pods/default_juice-shop-*/nginx-was-logger/*.log"
_FALCO_LOG_GLOB = "/var/log/pods/falco_falco-*/falco/*.log"

_TAIL_LINES = 4000  # audit.log가 수십MB라 노드당 최근 N줄만 - 전체 tail은 느림
_DOCKER_EXEC_TIMEOUT_SECONDS = 8
_KUBECTL_TIMEOUT_SECONDS = 8

_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?")


def _parse_ts(text: Optional[str]) -> float:
    """다양한 포맷(ISO8601 나노초, Go time.Time 문자열 등)에서 UTC epoch초를 뽑는다.
    실패하면 0.0(필터에서 자연히 제외됨)."""
    if not text:
        return 0.0
    m = _TS_RE.search(text)
    if not m:
        return 0.0
    date_part = m.group(1).replace(" ", "T")
    frac = (m.group(2) or ".0")[:7]  # 소수점 포함 최대 6자리(마이크로초)로 절삭
    try:
        dt = datetime.fromisoformat(f"{date_part}{frac}+00:00")
        return dt.timestamp()
    except ValueError:
        return 0.0


def _docker_exec_tail(node: str, glob_pattern: str) -> str:
    try:
        result = subprocess.run(
            ["docker", "exec", node, "sh", "-c", f"tail -n {_TAIL_LINES} {glob_pattern} 2>/dev/null"],
            capture_output=True, text=True, timeout=_DOCKER_EXEC_TIMEOUT_SECONDS,
        )
        return result.stdout or ""
    except (subprocess.SubprocessError, OSError):
        return ""


def _parse_cri_content(line: str) -> Optional[str]:
    """CRI 로그 한 줄(`<timestamp> <stream> <F|P> <content>`)에서 content만 뽑는다."""
    parts = line.split(" ", 3)
    if len(parts) < 4:
        return None
    return parts[3]


def fetch_audit_logs(since_ts: float, until_ts: float, needle: str = "dummy",
                      extra_needle: Optional[str] = None) -> List[Dict[str, Any]]:
    """k8s_audit 원본(JSON 한 줄씩) - needle(기본 "dummy")이 포함된 줄만 골라서
    시스템 전체 컨트롤러 트래픽 노이즈를 피한다. extra_needle을 추가로 주면(예:
    이 회차가 만든 정확한 리소스 이름 "dummy-cm-19cd66ae") 같은 시간창에서 실행된
    다른 액션과 안 섞이게 더 좁혀서 찾는다(개별 액션 카드 클릭용)."""
    out: List[Dict[str, Any]] = []
    seen_ids = set()
    for node in K3D_NODES:
        text = _docker_exec_tail(node, _AUDIT_LOG_GLOB)
        for line in text.splitlines():
            if needle not in line:
                continue
            if extra_needle and extra_needle not in line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            audit_id = entry.get("auditID")
            if audit_id and audit_id in seen_ids:
                continue
            ts = _parse_ts(entry.get("requestReceivedTimestamp") or entry.get("stageTimestamp"))
            if not (since_ts <= ts <= until_ts):
                continue
            if audit_id:
                seen_ids.add(audit_id)
            out.append({"log_source": "k8s_audit", "timestamp": ts, "raw": entry})
    out.sort(key=lambda e: e["timestamp"])
    return out


def _fetch_cri_logs(glob_pattern: str, log_source: str, since_ts: float, until_ts: float,
                     needle: Optional[str] = None, extra_needle: Optional[str] = None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for node in K3D_NODES:
        text = _docker_exec_tail(node, glob_pattern)
        for line in text.splitlines():
            content = _parse_cri_content(line)
            if content is None:
                continue
            if needle and needle not in content:
                continue
            if extra_needle and extra_needle not in content:
                continue
            ts = _parse_ts(line)
            if not (since_ts <= ts <= until_ts):
                continue
            try:
                parsed: Any = json.loads(content)
            except json.JSONDecodeError:
                parsed = content
            out.append({"log_source": log_source, "timestamp": ts, "raw": parsed})
    out.sort(key=lambda e: e["timestamp"])
    return out


def fetch_was_logs(since_ts: float, until_ts: float, extra_needle: Optional[str] = None) -> List[Dict[str, Any]]:
    """WAS(nginx-was-logger 사이드카) 접근 로그 원본 - waf_actions.py가
    python-requests로 보내므로 그 User-Agent로 우리 트래픽만 골라낸다. extra_needle을
    주면(예: 요청 경로) 개별 액션 카드 클릭 시 그 회차의 다른 요청과 안 섞이게 더
    좁힌다."""
    return _fetch_cri_logs(_WAS_LOG_GLOB, "was", since_ts, until_ts, needle="python-requests",
                            extra_needle=extra_needle)


def fetch_falco_logs(since_ts: float, until_ts: float, extra_needle: Optional[str] = None) -> List[Dict[str, Any]]:
    """Falco 원본 stdout - 시간창으로만 거른다(우리 dummy pod 이름이 output에
    안 섞여 나올 수도 있어서 needle 없이 전부 포함)."""
    return _fetch_cri_logs(_FALCO_LOG_GLOB, "falco", since_ts, until_ts, extra_needle=extra_needle)


_LOG_SOURCE_RE = re.compile(r"^\s*->\s*log\.source:\s*Str\((.+)\)\s*$")
_SCOPE_RE = re.compile(r"^InstrumentationScope\s+(\S+)")
_TIMESTAMP_RE = re.compile(r"^Timestamp:\s*(.+)$")
_BODY_RE = re.compile(r"^Body:\s*Str\((.*)\)\s*$")

# app/otel/logger.py가 Resource(log.source=waf)를 명시적으로 설정하는데도 실제
# 덤프에는 그 리소스 속성 자체가 안 찍히는(service.name도 unknown_service로
# 나오는) 별개의 기존 버그가 있다(실측 확인, 2026-07-13) - 대신
# LoggerProvider.get_logger("waf-gateway")가 남기는 InstrumentationScope 이름은
# 항상 정확히 찍히므로 이걸로 waf 판별을 보강한다. filelog 수신기(k8s_audit/
# falco/was)는 InstrumentationScope를 안 채우므로(빈 문자열) 서로 안 겹친다.
_SCOPE_TO_SOURCE = {"waf-gateway": "waf"}


def _parse_debug_dump(text: str) -> List[Dict[str, Any]]:
    """otel-collector debug exporter(verbosity: detailed) 콘솔 텍스트 덤프에서
    LogRecord 단위로 (log.source, timestamp, body)를 뽑는다. ResourceLog 블록
    안에서 log.source/InstrumentationScope 한 줄이 그 블록의 모든 LogRecord에
    적용되는 순서를 그대로 선형 스캔으로 따라간다."""
    records = []
    current_source = None
    current_ts = None
    for line in text.splitlines():
        m = _LOG_SOURCE_RE.match(line)
        if m:
            current_source = m.group(1)
            continue
        m = _SCOPE_RE.match(line)
        if m and m.group(1) in _SCOPE_TO_SOURCE:
            current_source = _SCOPE_TO_SOURCE[m.group(1)]
            continue
        m = _TIMESTAMP_RE.match(line)
        if m:
            current_ts = m.group(1).strip()
            continue
        m = _BODY_RE.match(line)
        if m and current_source:
            records.append({"log_source": current_source, "timestamp_text": current_ts, "body": m.group(1)})
    return records


def _otel_pod_names() -> List[str]:
    try:
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", OTEL_NAMESPACE, "-l", OTEL_LABEL_SELECTOR,
             "-o", "jsonpath={.items[*].metadata.name}"],
            capture_output=True, text=True, timeout=_KUBECTL_TIMEOUT_SECONDS,
        )
        return result.stdout.split()
    except (subprocess.SubprocessError, OSError):
        return []


def fetch_waf_logs(since_ts: float, until_ts: float, extra_needle: Optional[str] = None) -> List[Dict[str, Any]]:
    """WAF는 원본 파일이 없어서 otel-collector의 debug 콘솔 출력을 파싱한다 -
    WAF의 OTLP push는 k8s Service로 로드밸런싱되므로 collector pod 3개 전부
    확인해야 한다."""
    since_seconds = max(1, int(round(time.time() - since_ts)) + 5)
    out: List[Dict[str, Any]] = []
    for pod in _otel_pod_names():
        try:
            result = subprocess.run(
                ["kubectl", "logs", pod, "-n", OTEL_NAMESPACE, f"--since={since_seconds}s"],
                capture_output=True, text=True, timeout=_KUBECTL_TIMEOUT_SECONDS,
            )
        except (subprocess.SubprocessError, OSError):
            continue
        for rec in _parse_debug_dump(result.stdout):
            if rec["log_source"] != "waf":
                continue
            if extra_needle and extra_needle not in rec["body"]:
                continue
            ts = _parse_ts(rec["timestamp_text"])
            if not (since_ts <= ts <= until_ts):
                continue
            try:
                parsed: Any = json.loads(rec["body"])
            except json.JSONDecodeError:
                parsed = rec["body"]
            out.append({"log_source": "waf", "timestamp": ts, "raw": parsed})
    out.sort(key=lambda e: e["timestamp"])
    return out


def fetch_raw_logs(since_ts: float, until_ts: float,
                    extra_needle: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """시간창(since_ts~until_ts) 안에 든 4가지 원본 로그를 전부 모아서 돌려준다.
    extra_needle을 주면(개별 액션 카드 클릭) 그 액션의 식별자(리소스 이름/요청
    경로)로 추가로 좁혀서, 같은 회차 안 다른 액션의 로그와 안 섞이게 한다. 어느
    것 하나가 실패해도(예: docker/kubectl 접근 불가) 나머지는 최대한 반환한다."""
    result: Dict[str, List[Dict[str, Any]]] = {}
    fetchers = {
        "k8s_audit": fetch_audit_logs,
        "waf": fetch_waf_logs,
        "falco": fetch_falco_logs,
        "was": fetch_was_logs,
    }
    for key, fn in fetchers.items():
        try:
            result[key] = fn(since_ts, until_ts, extra_needle=extra_needle)
        except Exception as e:
            result[key] = [{"error": str(e)}]
    return result
