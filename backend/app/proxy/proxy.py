"""
담당: 이용욱 (게이트웨이 & 트래픽 컨트롤러)

/proxy/{path} 라우터의 실제 구현.

흐름:
    브라우저 요청
        -> GatewayMiddleware (Bad Bot/RateLimit/BruteForce/CORS 위반 탐지, 로그만 남기고 통과)
        -> 여기 (/proxy/{path})
              1) decoder.py로 body/헤더를 정규화 (인코딩 우회 방지)
              2) engine.py의 inspect_request로 SQLi/XSS/JWT위조 등 탐지
              3) 공격으로 판정되면
                   -> WafAlert를 OTel(OTLP)로 otel-collector에 전송 (mitre_technique_id 자동 채움)
                   -> detection 모드(기본): 로그만 남기고 4)로 진행
                   -> prevention 모드: 여기서 403 리턴, Juice Shop으로 전달하지 않음
              4) 시그니처 미탐지, 또는 detection 모드일 땐 settings.target_service_url(Juice Shop)로
                 그대로 전달하고 받은 응답을 브라우저에 그대로 돌려줌.

    주의: 이 차단은 시그니처 탐지 경로(여기)에만 적용된다. GatewayMiddleware의 Bad Bot/
    CORS위반/RateLimit/BruteForce 탐지는 이 모드와 무관하게 여전히 로그만 남기고 통과시킨다
    (그쪽 차단은 별도 작업 — blacklist_store 도입 이후).
"""
import httpx
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.config import settings
from app.detection.engine import inspect_request
from app.middleware.decoder import normalize_query_params, normalize_text
from app.middleware.gateway import get_client_ip
from app.storage.log_store import add_log as save_log

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
    "user-agent",
    "content-type",
    "x-api-key",
}

# 백엔드(Juice Shop)로 그대로 전달하면 안 되는 hop-by-hop 헤더
# (RFC 7230 기준, 프록시가 자체적으로 관리해야 하는 헤더들)
# + nginx-was-logger가 실어준 X-Served-By-* 헤더 - WafAlert에 옮겨 담는 내부용이라
# 브라우저 응답에 그대로 흘려보내 내부 pod 이름을 노출시키면 안 된다.
_EXCLUDED_RESPONSE_HEADERS = {
    "content-encoding",
    "content-length",
    "transfer-encoding",
    "connection",
    "x-served-by-pod",
    "x-served-by-namespace",
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

    # get_client_ip()는 gateway.py의 신뢰-프록시 검증(trusted_proxies)을 그대로
    # 재사용한다 - settings.trusted_proxies에 등록된 IP에서 직접 연결된 요청만
    # X-Forwarded-For를 신뢰하고, 그 외에는 request.client.host로 폴백한다(원래
    # 이 파일의 동작과 동일). 이전엔 여기서만 request.client.host를 직접 썼는데,
    # 그러면 Traefik 같은 리버스 프록시 뒤에서는 WafAlert.source_ip가 항상 프록시
    # 자신의 IP로 남아 S4(동일 IP 다발 차단)의 IP 기준 상관분석이 실제 배포
    # 환경에서 무력화되는 문제가 있었다 - gateway.py의 나머지 탐지(Rate Limit/Bad
    # Bot 등)와 동일한 신원 판별 로직으로 통일.
    client_ip = get_client_ip(request)

    attack_log = inspect_request(
        source_ip=client_ip,
        target_endpoint=f"/{path}",
        http_method=request.method,
        body_text=body_text,
        headers_text=headers_text,
        user_agent=request.headers.get("user-agent"),
    )

    # target_pod_name/target_namespace(어느 pod가 처리했는지)와 달리 target_name(이
    # WAF backend 인스턴스가 어느 타깃을 보호하는지)은 배포 시점에 이미 정해진
    # 정적 설정값이라 요청을 넘기기도 전에 바로 채울 수 있다 - prevention 모드로
    # 차단되는 경우에도 채워지도록 여기서 처리(config.py의 target_name 참고).
    if attack_log is not None:
        attack_log.target_name = settings.target_name

    # prevention 모드로 차단되는 경우는 Juice Shop까지 전달하지 않으므로, 어느 pod가
    # "처리했을지"를 알 방법이 없다(target_pod_name/target_namespace는 None으로 남음) -
    # 여기서 바로 저장하고 반환한다. detection 모드(기본)에서는 이 분기를 타지 않고
    # 그대로 진행해서, 아래에서 실제로 요청을 넘긴 뒤 응답 헤더로 처리 pod를 채우고
    # 나서 저장한다(save_log 호출 위치 참고).
    if attack_log is not None and attack_log.blocked:
        save_log(attack_log)
        return JSONResponse(
            status_code=403,
            content={"detail": "Request blocked by WAF"},
        )

    # 쿼리 파라미터도 정규화 (HTTP Parameter Pollution 방어)
    raw_query_params: dict = {}
    for key in request.query_params.keys():
        raw_query_params[key] = request.query_params.getlist(key)
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

    if attack_log is not None:
        # nginx-was-logger 사이드카가 실어준 헤더(juice-shop-nginx-configmap.yaml 참고) -
        # "이 요청을 실제로 처리한 pod"를 매 요청마다 정확히 가리킨다(정적 하드코딩 아님).
        attack_log.target_pod_name = upstream_response.headers.get("x-served-by-pod")
        attack_log.target_namespace = upstream_response.headers.get("x-served-by-namespace")
        save_log(attack_log)

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