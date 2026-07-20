"""
S19(동일 IP 로그인 실패 다발)/S30(동일 IP 404 다발, 2026-07-18 추가, 둘 다
IDS-COLLECTOR/servers/correlation-engine/app/scenarios/network.yaml)를 트리거하는
요청 빌더 - waf_actions.py와 달리 WAF backend의
`/proxy/{path}`를 거치지 않고 Juice Shop(nginx-was-logger 사이드카)에 곧바로 보낸다.
S19의 근거 자체가 "WAF 프록시를 거치지 않고 Juice Shop에 바로 온 요청도 nginx는
무조건 잡는다"는 독립 탐지 경로이므로, WAF를 거치면 이 시나리오의 의미가 없어진다.

로컬에서 Juice Shop에 직접 붙으려면 README "4) Juice Shop 배포" 절 안내대로
port-forward가 필요하다:
    kubectl port-forward svc/juice-shop 3000:3000
WAS_URL 기본값(http://localhost:3000)은 이 포트포워드를 그대로 가리킨다.

로그인 실패 판정(Target 저장소 backend/app/middleware/gateway.py의
LOGIN_FAILURE_STATUS_CODES={401,403})과 이 시나리오의 match 조건(url_path_prefix=
"/rest/user/login", http_request_method=POST, http_response_status_code in
[401,403])을 맞추려면 실제로 로그인에 실패해야 한다 - Juice Shop은 잘못된
자격증명으로 POST /rest/user/login을 하면 401을 반환한다.

출발지 IP 다양화는 waf_actions.py와 같은 이유(join_on=source_ip라 burst 안에서는
반드시 같은 IP를 써야 threshold가 채워짐, 회차마다는 다른 IP)로 X-Forwarded-For를
쓴다 - normalizer/app/normalizer.py의 _was_source_ip()가 XFF 첫 홉을 remote_addr보다
우선한다(nginx access log에 $http_x_forwarded_for가 실려있어야 함, Target 저장소
juice-shop-nginx-configmap.yaml 참고).
"""
import os
import random
import uuid
from typing import Optional, Tuple

import requests

from waf_actions import random_source_ip

WAS_URL = os.getenv("WAS_URL", "http://localhost:3000")
REQUEST_TIMEOUT_SECONDS = 5
LOGIN_PATH = "rest/user/login"


def send_login_failure(source_ip: Optional[str] = None) -> str:
    """존재하지 않는 계정으로 로그인을 시도해 401을 유도한다."""
    url = f"{WAS_URL}/{LOGIN_PATH}"
    headers = {"X-Forwarded-For": source_ip or random_source_ip()}
    try:
        resp = requests.post(
            url,
            json={"email": "dummy-nonexistent-user@example.com", "password": "wrong-password"},
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        return f"POST /{LOGIN_PATH} -> {resp.status_code} (X-Forwarded-For: {headers['X-Forwarded-For']})"
    except requests.RequestException as e:
        return f"POST /{LOGIN_PATH} -> 오류: {e}"


def send_login_failure_burst(count: int = 6) -> list:
    """S19(같은 IP에서 60초 안에 로그인 실패 5건 이상) 재료 - 같은 IP로 로그인
    실패를 연속으로 쏜다(waf_actions.send_waf_burst와 동일 패턴)."""
    ip = random_source_ip()
    return [send_login_failure(source_ip=ip) for _ in range(count)]


def send_not_found_request(source_ip: Optional[str] = None) -> str:
    """S30(동일 IP WAS 404 다발, 2026-07-18 추가) 재료 - 존재하지 않는 임의 경로에
    요청을 보내 404를 유도한다. send_login_failure와 같은 이유로 WAF(/proxy)를
    거치지 않고 Juice Shop에 직접 보낸다 - 페이로드 기반 시그니처가 전혀 없는
    "정상적인 척하는" 요청이라 WAF 시그니처 엔진의 사각지대이므로, WAF를 거치지
    않는 요청도 잡는 이 독립 탐지 경로의 취지를 그대로 살린다."""
    path = f"rest/dummy-nonexistent-path-{random.randint(100000, 999999)}"
    url = f"{WAS_URL}/{path}"
    headers = {"X-Forwarded-For": source_ip or random_source_ip()}
    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
        return f"GET /{path} -> {resp.status_code} (X-Forwarded-For: {headers['X-Forwarded-For']})"
    except requests.RequestException as e:
        return f"GET /{path} -> 오류: {e}"


def send_not_found_burst(count: int = 11) -> list:
    """S30(60초 안에 404 10건 이상) 재료 - 같은 IP로 존재하지 않는 경로를
    연속으로 두드린다(send_login_failure_burst와 동일 패턴)."""
    ip = random_source_ip()
    return [send_not_found_request(source_ip=ip) for _ in range(count)]


# ---- 2026-07-20 추가 (S60/S63/S65/S82/S83/S84/S85/S92/S93) ----

def send_whoami_request(source_ip: Optional[str] = None) -> str:
    """S63/S65/S85 stage2 재료 - `/rest/user/whoami`는 로그인 여부와 무관하게 항상
    200을 반환하는 Juice Shop 엔드포인트라(비로그인 시 빈 user 객체) waf_actions.py의
    benign 요청 풀에도 이미 포함돼 있다 - "인증이 필요한 엔드포인트에 실제로 접근이
    성공했다"를 근사하는 용도로 S63/S65/S85가 재사용."""
    url = f"{WAS_URL}/rest/user/whoami"
    headers = {"X-Forwarded-For": source_ip or random_source_ip()}
    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
        return f"GET /rest/user/whoami -> {resp.status_code} (X-Forwarded-For: {headers['X-Forwarded-For']})"
    except requests.RequestException as e:
        return f"GET /rest/user/whoami -> 오류: {e}"


def send_malformed_json_request(source_ip: Optional[str] = None) -> str:
    """S60/S78/S84 stage2 재료 - "WAF가 판정한 공격이 실제로 서버 오류(5xx)로
    이어졌는지"를 재현하려면 진짜 500/502/503을 유발할 요청이 필요한데, 어떤 요청이
    Juice Shop에서 실제로 5xx를 내는지 이 세션에서 실측 검증할 방법이 없다
    (correlation-engine network.yaml S78 주석도 이 문제를 그대로 인정함 - "그런 신호를
    pod 상태 텔레메트리 없이 근사할 방법이 마땅치 않다"). 가장 신뢰도 높은 후보(Express
    body-parser가 깨진 JSON을 파싱하다 던지는 예외를 앱이 명시적으로 안 잡으면 기본
    에러 핸들러가 500으로 응답하는 흔한 패턴)로 시도하지만, ⚠️ 이 파일의 다른 요청과
    달리 이게 실제로 5xx를 반환하는지는 검증되지 않았다 - 실제 클러스터에서 응답
    코드를 직접 확인하고 필요하면 다른 요청으로 교체할 것."""
    url = f"{WAS_URL}/rest/products/search"
    headers = {"X-Forwarded-For": source_ip or random_source_ip(), "Content-Type": "application/json"}
    try:
        resp = requests.post(url, data="{not valid json", headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
        return f"POST /rest/products/search(깨진 JSON) -> {resp.status_code} (X-Forwarded-For: {headers['X-Forwarded-For']})"
    except requests.RequestException as e:
        return f"POST /rest/products/search(깨진 JSON) -> 오류: {e}"


def send_file_upload_request(source_ip: Optional[str] = None) -> str:
    """S82(파일 업로드 → 실행/크립토마이닝 → CronJob 지속성 확보) stage1 재료 -
    Juice Shop의 실제 업로드 엔드포인트(멀티파트, multer 미들웨어 기반)로 더미
    PDF를 하나 올린다. ⚠️ 실측 확인(2026-07-20, techeer-ids 클러스터): 성공하면
    200/201이 아니라 204(No Content)를 반환한다 - correlation-engine S82 yaml의
    match 조건(`http_response_status_code: [200, 201]`)이 204를 안 담고 있어서
    실제로는 이 요청이 성공해도 매칭되지 않는다(scenarios.py의 _run_s82 docstring
    참고, 별도 확인/수정 필요)."""
    url = f"{WAS_URL}/file-upload"
    headers = {"X-Forwarded-For": source_ip or random_source_ip()}
    files = {"file": ("dummy.pdf", b"%PDF-1.4 dummy content for scenario S82", "application/pdf")}
    try:
        resp = requests.post(url, files=files, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
        return f"POST /file-upload -> {resp.status_code} (X-Forwarded-For: {headers['X-Forwarded-For']})"
    except requests.RequestException as e:
        return f"POST /file-upload -> 오류: {e}"


def register_and_get_token(source_ip: Optional[str] = None, email_prefix: str = "dummy") -> Tuple[Optional[str], str]:
    """계정을 몰라도 실제 로그인 성공(200)을 얻어야 하는 시나리오들의 공통 재료
    (S83 stage2, S85 stage2) - Juice Shop의 공개 회원가입 API(POST /api/Users)로
    이 실행 전용 임시 계정을 직접 만들고 그 계정으로 로그인해서 실제 JWT를 받는다 -
    가짜로 성공 처리하는 게 아니라 "탈취됐다고 가정할 계정"을 스스로 만들고 그 계정
    인증에 실제로 성공하는 방식. 로그인 성공 시 (토큰, 로그) 튜플, 실패 시
    (None, 로그)를 반환한다."""
    ip = source_ip or random_source_ip()
    email = f"{email_prefix}-{uuid.uuid4().hex[:8]}@example.com"
    password = "Dummy-Passw0rd!23"
    headers = {"X-Forwarded-For": ip}
    lines = []
    try:
        reg = requests.post(
            f"{WAS_URL}/api/Users",
            json={
                "email": email, "password": password, "passwordRepeat": password,
                "securityQuestion": None, "securityAnswer": None,
            },
            headers=headers, timeout=REQUEST_TIMEOUT_SECONDS,
        )
        lines.append(f"POST /api/Users(임시 계정 {email} 등록) -> {reg.status_code}")
    except requests.RequestException as e:
        lines.append(f"POST /api/Users(임시 계정 등록) -> 오류: {e}")
        return None, "\n    ".join(lines)

    try:
        login = requests.post(
            f"{WAS_URL}/{LOGIN_PATH}", json={"email": email, "password": password},
            headers=headers, timeout=REQUEST_TIMEOUT_SECONDS,
        )
        lines.append(f"POST /{LOGIN_PATH}(방금 만든 계정으로 로그인) -> {login.status_code}")
        if login.status_code != 200:
            return None, "\n    ".join(lines)
        token = login.json()["authentication"]["token"]
        return token, "\n    ".join(lines)
    except (requests.RequestException, KeyError, ValueError) as e:
        lines.append(f"POST /{LOGIN_PATH} -> 오류: {e}")
        return None, "\n    ".join(lines)


def register_and_login(source_ip: Optional[str] = None) -> Tuple[bool, str]:
    """S83 stage2 재료 - register_and_get_token()을 그대로 쓰되 토큰 자체는 필요
    없고 "로그인 성공(200) 여부"만 보면 된다."""
    token, detail = register_and_get_token(source_ip=source_ip, email_prefix="dummy-s83")
    return token is not None, detail


def send_api_users_list(source_ip: Optional[str] = None, token: Optional[str] = None) -> str:
    """S85 stage1/2 재료 - `/api/Users`(사용자 목록 조회 API)는 실측 확인
    (2026-07-20, techeer-ids 클러스터) 결과 인증 없이 부르면 401
    ("No Authorization header was found")이 나오고, 유효한 로그인 토큰이면(관리자
    role일 필요도 없음) 200으로 전체 사용자 목록(이메일 등)을 그대로 돌려준다 -
    "인증 우회 전 차단(stage1) vs 우회 성공(stage2)"을 실제로 재현할 수 있는
    엔드포인트다(원래 썼던 `/rest/admin/application-configuration`은 이 배포에서
    인증 없이도 이미 200이 나와서 이 조건 자체가 성립하지 않았다 - correlation-engine
    network.yaml S85 주석 참고, 2026-07-20에 이 엔드포인트로 교체됨). token을 안
    주면 stage1(무인증, 401 기대)이고 주면 stage2(인증됨, 200 기대)다."""
    headers = {"X-Forwarded-For": source_ip or random_source_ip()}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = requests.get(f"{WAS_URL}/api/Users", headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
        return f"GET /api/Users({'인증됨' if token else '무인증'}) -> {resp.status_code}"
    except requests.RequestException as e:
        return f"GET /api/Users({'인증됨' if token else '무인증'}) -> 오류: {e}"


def send_endpoint_scan_burst(count: int = 16, source_ip: Optional[str] = None) -> list:
    """S92(동일 IP의 WAS 엔드포인트 다양성 스캔, threshold=15/60s distinct url_path)
    재료 - 응답 코드/실존 여부는 무관하고 서로 다른 url_path 문자열 자체가 신호라,
    상품 리뷰 경로의 ID를 바꿔가며 서로 다른 경로 count개를 순서대로 두드린다."""
    ip = source_ip or random_source_ip()
    results = []
    for product_id in range(1, count + 1):
        path = f"rest/products/{product_id}/reviews"
        url = f"{WAS_URL}/{path}"
        headers = {"X-Forwarded-For": ip}
        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
            results.append(f"GET /{path} -> {resp.status_code} (X-Forwarded-For: {ip})")
        except requests.RequestException as e:
            results.append(f"GET /{path} -> 오류: {e}")
    return results
