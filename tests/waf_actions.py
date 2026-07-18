"""
WAF(`log.source=waf`) 기반 상관분석 시나리오(S4, S5의 stage1, 2026-07-18부로
S26/S27/S28/S29/S33/S51도 추가)를 트리거하는 HTTP 요청 빌더 + 정상(benign) 트래픽
생성기.

반드시 WAF_URL(`/proxy/{path}`)을 거쳐서 보낸다 - Juice Shop(WAS_URL)로 직접 보내면
`log.source=was`만 남고 `waf`는 안 남는다(app/proxy/proxy.py 참고). WAF는 detection
모드(기본값)에서는 판정과 무관하게 항상 Juice Shop까지 그대로 전달하므로, 이 요청들이
막히지 않고 응답을 받는 게 정상이다.

payload는 backend/app/detection/signatures.py의 정규식과 매칭되도록 만들어졌고,
severity.yaml(risk_level.CRITICAL -> severity 4)에서 CRITICAL로 분류되는 것만 S5
stage1(min_severity=4)에 쓴다.

출발지 IP 다양화: 모든 요청이 이 스크립트를 돌리는 한 대의 테스트 머신에서 나가기
때문에 그냥 두면 WafAlert.source_ip가 전부 똑같다(실제 GeoIP DB를 붙였을 때도 전부
한 점으로 찍히는 원인). IDS-COLLECTOR 쪽 GeoIP lookup을 손대는 대신, 로그가 "발생하는"
지점인 여기서 매 요청마다 X-Forwarded-For로 서로 다른 가짜 공인 IP를 실어 보낸다 -
source_ip가 원래부터 다양했던 것처럼 만들어서, GeoLite2-City가 붙은 지금은 그 IP가
실제로 다양한 국가/도시로 흩어져 찍힌다.

2026-07-17: "국가도 더 늘리고 공격 방식도 늘리고 싶다"는 요청으로 두 가지를 확장:
1) random_source_ip()를 고정 48개 1옥텟 풀 대신 전체 공인 IPv4 대역에서 뽑도록 바꿔서
   국가 다양성을 크게 늘림.
2) backend/app/detection/signatures.py에 이미 정의돼 있었지만 이 파일에서 한 번도
   트리거되지 않던 시그니처(주석 종료자 SQLi, 따옴표 주입 SQLi, XSS 이벤트 핸들러/
   javascript: URI/iframe, 인코딩된 Path Traversal, 명령어 파이프)를 겨냥한 빌더를
   추가하고, engine.py가 별도 처리하는 JWT alg:none 위조도 새로 추가.
"""
import base64
import ipaddress
import json as json_module
import os
import random
from typing import Optional

import requests

WAF_URL = os.getenv("WAF_URL", "http://localhost:8000")
REQUEST_TIMEOUT_SECONDS = 5


def random_source_ip() -> str:
    """다양한 국가로 흩어지는 가짜 공인 IP 생성기.

    이전엔 48개로 고정된 1옥텟 풀에서만 뽑아서(특정 대역에 몰려있어) GeoLite2로 봤을 때
    나오는 국가 수가 제한적이었다. 지금은 IPv4 전체 대역에서 매번 무작위로 뽑고,
    IDS-COLLECTOR 쪽 normalizer/app/geoip.py의 _is_routable_public()과 정확히 같은
    기준(사설/루프백/예약/멀티캐스트/미지정/링크로컬 제외)으로 걸러서 재시도한다 -
    두 코드베이스가 같은 기준을 쓰므로, 여기서 통과된 IP는 저쪽에서도 반드시
    "조회할 가치가 있는" 주소로 취급된다. 공인 유니캐스트 대역이 전체의 대다수라
    평균 1~2번 안에 뽑힌다."""
    while True:
        candidate = ipaddress.IPv4Address(random.getrandbits(32))
        if (
            candidate.is_private
            or candidate.is_loopback
            or candidate.is_reserved
            or candidate.is_multicast
            or candidate.is_unspecified
            or candidate.is_link_local
        ):
            continue
        return str(candidate)


def _send(method: str, path: str, *, json: Optional[dict] = None,
          params: Optional[dict] = None, headers: Optional[dict] = None,
          source_ip: Optional[str] = None) -> str:
    url = f"{WAF_URL}/proxy/{path}"
    req_headers = dict(headers or {})
    req_headers["X-Forwarded-For"] = source_ip or random_source_ip()
    try:
        resp = requests.request(
            method=method, url=url, json=json, params=params, headers=req_headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        return f"{method} /proxy/{path} -> {resp.status_code} (X-Forwarded-For: {req_headers['X-Forwarded-For']})"
    except requests.RequestException as e:
        return f"{method} /proxy/{path} -> 오류: {e}"


# --- CRITICAL 등급 공격 (S4 threshold 재료 / S5 stage1) ---

def send_sqli_critical(source_ip: Optional[str] = None) -> str:
    payload = random.choice(["' OR 1=1 --", "1 UNION SELECT username, password FROM users"])
    return _send("POST", "rest/products/search", json={"q": payload}, source_ip=source_ip)


def send_sqli_quote_injection_critical(source_ip: Optional[str] = None) -> str:
    """signatures.py의 sqli_quote_injection(['\"]\\s*(OR|AND)\\s*['\"]?\\d, CRITICAL) 타깃 -
    send_sqli_critical과 달리 UNION/OR 1=1이 아니라 따옴표+숫자 조합으로 우회를 시도한다."""
    payload = random.choice(["' OR '1", "\" AND \"1", "' AND 1"])
    return _send("POST", "rest/products/search", json={"q": payload}, source_ip=source_ip)


def send_xss_critical(source_ip: Optional[str] = None) -> str:
    return _send(
        "POST", "api/Feedbacks", json={"comment": "<script>alert(document.cookie)</script>", "rating": 1},
        source_ip=source_ip,
    )


def send_path_traversal_critical(source_ip: Optional[str] = None) -> str:
    return _send(
        "POST", "rest/user/change-password", json={"filename": "../../../../etc/passwd"}, source_ip=source_ip
    )


def send_path_traversal_encoded_critical(source_ip: Optional[str] = None) -> str:
    """signatures.py의 path_encoded_traversal(%2e%2e%2f, CRITICAL) 타깃 - URL 인코딩으로
    필터를 우회하려는 흔한 변형."""
    payload = "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    return _send(
        "POST", "rest/user/change-password", json={"filename": payload}, source_ip=source_ip
    )


def send_cmdi_critical(source_ip: Optional[str] = None) -> str:
    return _send("POST", "rest/admin/application-version", json={"cmd": "; cat /etc/passwd"}, source_ip=source_ip)


def _fake_jwt_alg_none() -> str:
    """engine.py의 _check_jwt_alg_none()이 잡아내는 JWT 위조 - 헤더 세그먼트를
    base64url(패딩 없이)로 인코딩해 {"alg":"none"}을 실어 보낸다. 서명 세그먼트는
    빈 문자열로 둬도 정규식(third segment는 0개 이상 허용)과 디코딩 로직 둘 다 통과한다."""
    def b64url(obj: dict) -> str:
        raw = json_module.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64url({"alg": "none", "typ": "JWT"})
    payload = b64url({"sub": "admin", "role": "admin"})
    return f"{header}.{payload}."


def send_jwt_alg_none_critical(source_ip: Optional[str] = None) -> str:
    """signatures.py를 안 거치고 engine.py가 헤더에서 직접 검사하는 JWT alg:none 위조 -
    Authorization 헤더로 실어 보낸다(body가 아니라 헤더 검사 대상이라는 게 이 룰의 핵심)."""
    headers = {"Authorization": f"Bearer {_fake_jwt_alg_none()}"}
    return _send("GET", "rest/user/whoami", headers=headers, source_ip=source_ip)


_CRITICAL_BUILDERS = [
    send_sqli_critical,
    send_sqli_quote_injection_critical,
    send_xss_critical,
    send_path_traversal_critical,
    send_path_traversal_encoded_critical,
    send_cmdi_critical,
    send_jwt_alg_none_critical,
]


def send_random_critical_attack(source_ip: Optional[str] = None) -> str:
    return random.choice(_CRITICAL_BUILDERS)(source_ip=source_ip)


def send_waf_burst(count: int = 6) -> list:
    """S4(같은 IP에서 60초 안에 WAF 이벤트 5건 이상) 재료 - CRITICAL 공격을 연속으로 쏜다.
    join_on=source_ip라 이 burst 안에서는 반드시 같은 IP를 써야 하지만(안 그러면
    threshold가 절대 안 채워짐), burst마다는(=시나리오 실행마다는) 다른 IP를 뽑아서
    실행할 때마다 다른 발원지로 보이게 한다."""
    ip = random_source_ip()
    return [send_random_critical_attack(source_ip=ip) for _ in range(count)]


# --- MEDIUM 등급 공격 - signatures.py에 정의는 있었지만 이 파일에서 한 번도 트리거되지
# 않던 규칙들(주석 종료자 SQLi, XSS 이벤트 핸들러/javascript: URI/iframe, 명령어 파이프).
# S4/S5는 severity 조건(threshold=CRITICAL 5건, min_severity=4)이 있어서 여기 섞으면
# 그 조건이 깨질 수 있으므로 일부러 _CRITICAL_BUILDERS에는 안 넣는다 - 대신
# send_random_attack()으로 CRITICAL/MEDIUM을 가리지 않고 더 폭넓은 공격 방식을 보고
# 싶을 때 따로 쓸 수 있게 노출한다.

def send_sqli_comment_terminator(source_ip: Optional[str] = None) -> str:
    payload = random.choice(["admin'--", "1; DROP TABLE users#", "test/*"])
    return _send("POST", "rest/products/search", json={"q": payload}, source_ip=source_ip)


def send_xss_event_handler(source_ip: Optional[str] = None) -> str:
    payload = random.choice(["<img src=x onerror=alert(1)>", "<div onload=alert(1)>", "<a onclick=alert(1)>click</a>"])
    return _send("POST", "api/Feedbacks", json={"comment": payload, "rating": 1}, source_ip=source_ip)


def send_xss_javascript_uri(source_ip: Optional[str] = None) -> str:
    return _send(
        "POST", "api/Feedbacks", json={"comment": '<a href="javascript:alert(1)">click</a>', "rating": 1},
        source_ip=source_ip,
    )


def send_xss_iframe(source_ip: Optional[str] = None) -> str:
    return _send(
        "POST", "api/Feedbacks", json={"comment": '<iframe src="//evil.example"></iframe>', "rating": 1},
        source_ip=source_ip,
    )


def send_cmd_pipe(source_ip: Optional[str] = None) -> str:
    return _send("POST", "rest/admin/application-version", json={"cmd": "| ls -la"}, source_ip=source_ip)


_MEDIUM_BUILDERS = [
    send_sqli_comment_terminator,
    send_xss_event_handler,
    send_xss_javascript_uri,
    send_xss_iframe,
    send_cmd_pipe,
]


def send_random_attack(source_ip: Optional[str] = None) -> str:
    """CRITICAL/MEDIUM 가리지 않고 아무 공격 방식이나 하나 골라서 보낸다 - 공격 유형
    다양성 자체가 목적일 때 사용. S4(threshold)/S5(min_severity=4)처럼 심각도 조건이
    있는 시나리오에는 쓰지 않는다(threshold가 안 채워질 수 있음) - 그쪽은 계속
    send_random_critical_attack()을 쓴다."""
    return random.choice(_CRITICAL_BUILDERS + _MEDIUM_BUILDERS)(source_ip=source_ip)


# --- S26/S27/S28/S33/S51 (2026-07-18 추가) - backend/app/middleware/gateway.py의
# GatewayMiddleware가 판정하는 4대 탐지(Bad Bot/CORS/RateLimit/BruteForce) +
# UA 로테이션을 재료로 하는 시나리오. 전부 threshold=1(gateway.py가 이미 자기
# 내부 윈도우로 카운팅을 끝내고 판정까지 마친 신호라 S26~S29와 같은 논리 -
# network.yaml S26/S27/S28/S29/S33/S51 주석 참고) - S27/S51/S26만 내부적으로
# 여러 요청을 반복해야 gateway.py 쪽 카운터가 채워진다.

def send_login_failure_via_waf(source_ip: Optional[str] = None) -> str:
    """S26(WAF 계층 브루트포스) stage 재료 - was_actions.send_login_failure와 달리
    반드시 /proxy를 거쳐서 gateway.py의 GatewayMiddleware(IP/계정/시스템전체 3종
    카운터)가 직접 판정하게 한다. was_actions 쪽(S19, WAF 미경유)과는 독립적인
    탐지 경로라는 게 이 시나리오의 취지이므로 WAF_URL이 아닌 다른 경로로 보내면
    안 된다."""
    return _send(
        "POST", "rest/user/login",
        json={"email": "dummy-nonexistent-user@example.com", "password": "wrong-password"},
        source_ip=source_ip,
    )


def send_brute_force_burst_via_waf(count: int = 6) -> list:
    """S26 재료 - gateway.py의 brute_force_max_failures(5)/brute_force_window_seconds(300)를
    채우도록 같은 IP로 /proxy 경유 로그인 실패를 연속 전송한다(send_waf_burst와 동일 패턴)."""
    ip = random_source_ip()
    return [send_login_failure_via_waf(source_ip=ip) for _ in range(count)]


def send_rate_limit_burst(count: int = 35) -> list:
    """S27(WAF Rate Limit 남용) 재료 - gateway.py의 rate_limit_max_requests(30)/
    rate_limit_window_seconds(60)를 넘기도록 같은 IP로 /proxy 요청을 연속 전송한다.
    이 시나리오는 '요청 빈도' 자체가 신호라 페이로드 내용은 무관 - 시그니처에
    안 걸리는 정상적인 조회 경로를 반복 사용한다."""
    ip = random_source_ip()
    return [_send("GET", "rest/products/search", params={"q": "juice"}, source_ip=ip) for _ in range(count)]


_BAD_BOT_USER_AGENTS_SAMPLE = ["sqlmap/1.7.2", "Mozilla/5.0 (compatible; Nikto/2.5)", "masscan/1.3"]


def send_bad_bot_request(source_ip: Optional[str] = None) -> str:
    """S28(알려진 스캐너 툴 User-Agent 탐지) 재료 - gateway.py의
    BAD_BOT_USER_AGENTS 목록(sqlmap/nikto/nmap/masscan/acunetix/curl/7.0/zap/burp) 중
    하나가 User-Agent 문자열에 포함되도록 보낸다."""
    ua = random.choice(_BAD_BOT_USER_AGENTS_SAMPLE)
    return _send(
        "GET", "rest/products/search", params={"q": "test"}, headers={"User-Agent": ua}, source_ip=source_ip
    )


def send_cors_violation_request(source_ip: Optional[str] = None) -> str:
    """S33(CORS 위반 탐지) 재료 - gateway.py의 allowed_origins 화이트리스트(기본
    http://localhost:5173, http://localhost:3000)에 없는 Origin을 실어 보낸다 - 다른
    사이트(evil.example)가 피해자 브라우저를 통해 API를 몰래 호출하려는 상황 흉내."""
    return _send(
        "GET", "rest/products/search", params={"q": "test"},
        headers={"Origin": "http://evil.example"}, source_ip=source_ip,
    )


_UA_ROTATION_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "msnbot/2.0b (+http://search.msn.com/msnbot.htm)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0",
]


def send_ua_rotation_burst(source_ip: Optional[str] = None) -> list:
    """S51(User-Agent 로테이션 탐지) 재료 - gateway.py의 record_user_agent_rotation
    (ua_rotation_distinct_threshold=4/ua_rotation_window_seconds=60)을 채우도록 같은
    IP로 서로 다른 User-Agent 4개를 순서대로 보낸다 - OWASP ZAP처럼 매 요청마다
    UA를 바꿔가며 자신을 숨기는 스캐너를 흉내(S28 문자열 매칭의 사각지대,
    network.yaml S51 주석 참고)."""
    ip = source_ip or random_source_ip()
    return [
        _send("GET", "rest/products/search", params={"q": "test"}, headers={"User-Agent": ua}, source_ip=ip)
        for ua in random.sample(_UA_ROTATION_POOL, 4)
    ]


# --- 정상(benign) 트래픽 - 시그니처에 안 걸리는 흔한 요청들 ---

_BENIGN_REQUESTS = [
    {"method": "GET", "path": "rest/products/search", "params": {"q": "apple juice"}},
    {"method": "GET", "path": "rest/products/search", "params": {"q": "banana"}},
    {"method": "GET", "path": "api/Products", "params": None},
    {"method": "GET", "path": "rest/products/1/reviews", "params": None},
    {"method": "GET", "path": "rest/products/2/reviews", "params": None},
    {"method": "GET", "path": "", "params": None},
    {"method": "GET", "path": "rest/admin/application-version", "params": None},
    {"method": "GET", "path": "api/Challenges", "params": None},
    {"method": "POST", "path": "api/Feedbacks", "json": {"comment": "great store!", "rating": 5}},
    {"method": "POST", "path": "api/Feedbacks", "json": {"comment": "fast delivery, thanks", "rating": 4}},
    {"method": "GET", "path": "rest/user/whoami", "params": None},
]


def send_normal_request() -> str:
    spec = random.choice(_BENIGN_REQUESTS)
    return _send(spec["method"], spec["path"], json=spec.get("json"), params=spec.get("params"))
