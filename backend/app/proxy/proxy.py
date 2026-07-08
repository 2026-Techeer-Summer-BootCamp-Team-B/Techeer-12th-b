"""
담당: 이용욱 (게이트웨이 & 트래픽 컨트롤러)

/proxy/{path} 라우터의 실제 구현.

흐름:
    브라우저 요청
        -> GatewayMiddleware (블랙리스트/RateLimit/BadBot, 이미 통과한 상태)
        -> 여기 (/proxy/{path})
              1) decoder.py로 body/헤더를 정규화 (인코딩 우회 방지)
              2) engine.py의 inspect_request로 SQLi/XSS/JWT위조 등 탐지
              3) 공격으로 판정되면
                   -> AttackLog 저장 (Elasticsearch, mitre_technique_id 자동 채움)
                   -> WebSocket으로 대시보드에 실시간 알림 발송
                   -> 403으로 즉시 차단
              4) 안전하면 -> settings.target_service_url(Juice Shop)로 그대로 전달하고
                 받은 응답을 브라우저에 그대로 돌려줌
"""
import httpx
from fastapi import APIRouter, Request, Response

from app.config import settings
from app.detection.engine import inspect_request
from app.middleware.decoder import normalize_query_params, normalize_text
from app.models.schemas import AttackLog, AttackType, RiskLevel
from app.storage.log_store import add_log as save_log
from app.websocket.manager import manager

router = APIRouter()

# 탐지 대상으로 삼을 헤더 화이트리스트.
#
# 왜 전체 헤더를 다 검사하지 않는가:
# Accept, Accept-Encoding 같은 헤더는 브라우저/curl이 "정상적으로" 자동 부착하는
# 표준 헤더인데, 예를 들어 "Accept: */*"의 "/*" 부분이 SQL 주석 종료 패턴과
# 우연히 일치해서 오탐(false positive)을 일으킨다.
# 실제 공격이 실리는 헤더(인증/추적/커스텀 헤더)만 골라서 검사 대상에 넣는다.
_INSPECTED_HEADER_NAMES = {
    "authorization",
    "cookie",
    "x-forwarded-for",
    "referer",
    "origin",
    "user-agent",
    "content-type",
    "x-api-key",
}

# 백엔드(Juice Shop)로 그대로 전달하면 안 되는 hop-by-hop 헤더
# (RFC 7230 기준, 프록시가 자체적으로 관리해야 하는 헤더들)
_EXCLUDED_RESPONSE_HEADERS = {
    "content-encoding",
    "content-length",
    "transfer-encoding",
    "connection",
}


@router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
async def proxy_request(path: str, request: Request):
    body_bytes = await request.body()
    body_text = normalize_text(body_bytes.decode("utf-8", errors="ignore"))

    # 헤더는 dict로 펼쳐서 탐지 대상 문자열로 만듦 (JWT alg:none 탐지가 여길 봄).
    # 단, Accept/Accept-Encoding 같은 브라우저 표준 헤더는 제외 - 시그니처 오탐 방지.
    headers_text = "\n".join(
        f"{k}: {v}"
        for k, v in request.headers.items()
        if k.lower() in _INSPECTED_HEADER_NAMES
    )

    client_ip = request.client.host if request.client else "unknown"

    attack_log = inspect_request(
        source_ip=client_ip,
        target_endpoint=f"/{path}",
        http_method=request.method,
        body_text=body_text,
        headers_text=headers_text,
        user_agent=request.headers.get("user-agent"),
    )

    if attack_log is not None:
        save_log(attack_log)

        # 실시간 알림 발송 - CRITICAL은 별도 이벤트 타입으로 구분해서
        # 대시보드가 팝업 등으로 더 눈에 띄게 처리할 수 있게 함
        event_type = "critical_alert" if attack_log.risk_level == RiskLevel.CRITICAL else "attack_detected"
        await manager.broadcast({"event": event_type, "data": attack_log.model_dump(mode="json")})

        return Response(
            content='{"detail": "Request blocked by security gateway"}',
            status_code=403,
            media_type="application/json",
        )

    # 쿼리 파라미터도 정규화 (HTTP Parameter Pollution 방어)
    raw_query_params: dict = {}
    for key in request.query_params.keys():
        raw_query_params[key] = request.query_params.getlist(key)

    # HPP (HTTP Parameter Pollution) 탐지 — 같은 이름의 파라미터가 여러 번 오는 것 자체가
    # WAF 우회 시도(첫 번째 값은 정상, 뒤에 숨긴 값에 실제 공격 페이로드)로 흔히 쓰인다.
    # normalize_query_params()가 첫 번째 값만 채택해서 실제 요청은 안전하게 무력화되므로
    # 여기서는 강제 차단(403)까지는 하지 않고 시도 자체만 기록한다.
    polluted_params = {key: values for key, values in raw_query_params.items() if len(values) > 1}
    if polluted_params:
        hpp_log = AttackLog(
            source_ip=client_ip,
            attack_type=AttackType.HPP,
            target_endpoint=f"/{path}",
            http_method=request.method,
            payload_snippet=str(polluted_params)[:200],
            user_agent=request.headers.get("user-agent"),
            matched_rule_id="hpp_duplicate_query_param",
            blocked=False,
            risk_level=RiskLevel.MEDIUM,
        )
        save_log(hpp_log)
        await manager.broadcast({"event": "attack_detected", "data": hpp_log.model_dump(mode="json")})

    clean_query_params = normalize_query_params(raw_query_params)

    target_url = f"{settings.target_service_url}/{path}"

    # 클라이언트가 보낸 헤더 중 Host는 제외 (타겟 서버 기준으로 새로 설정되어야 함)
    forward_headers = {
        k: v for k, v in request.headers.items() if k.lower() != "host"
    }

    async with httpx.AsyncClient() as client:
        upstream_response = await client.request(
            method=request.method,
            url=target_url,
            params=clean_query_params,
            headers=forward_headers,
            content=body_bytes,
            follow_redirects=False,
            timeout=30.0,
        )

    response_headers = {
        k: v
        for k, v in upstream_response.headers.items()
        if k.lower() not in _EXCLUDED_RESPONSE_HEADERS
    }

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get("content-type"),
    )