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
from typing import Optional

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
