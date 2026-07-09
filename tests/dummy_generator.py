"""
Juice Shop(WAS)으로 가짜 공격/트래픽 요청을 흘려보내는 더미 생성기.

예전에는 WAF 백엔드의 /proxy/{path}를 거쳐 탐지 엔진이 동작하는지 검증했지만, WAF가
차단 로직을 걷어내고 로그 전용 구조로 바뀌면서 그 로그 발생지 역할 자체가 Juice Shop 앞단
nginx-was-logger 사이드카의 WAS 접근 로그로 대체됐다 (WAF 배포는 현재 주석 처리됨, README
참고). 그래서 이 스크립트도 이제 WAS_URL(Juice Shop Service)로 직접 요청을 보낸다 — 여기
담긴 페이로드들은 예전 WAF 탐지 시그니처와 매칭되도록 만들어진 것들이라 공격처럼 보이는
트래픽을 실제 서비스에 흘려보내는 용도로만 남아있고, 지금은 탐지·차단되지 않는다. 확인
포인트는 "차단됐는지"가 아니라 nginx-was-logger의 access log가 otel-collector를 거쳐
(`log.source=was`) 실시간으로 찍히는지다.

Falco/K8s Audit 이벤트는 이 스크립트가 HTTP로 흉내내지 않는다 - stdout/hostPath 로그를
otel-collector가 직접 tail하므로, 실제 파이프라인을 검증하려면 README에 있는 대로 kubectl로
진짜 이벤트를 발생시켜야 한다 (예: kubectl run attacker --rm -it --image=ubuntu -- bash -c "cat /etc/shadow").
"""
import os
import random
import time

import requests
from faker import Faker

WAS_URL = os.getenv("WAS_URL", "http://localhost:3000")
EVENTS_PER_SECOND = int(os.getenv("EVENTS_PER_SECOND", "5"))
REQUEST_TIMEOUT_SECONDS = 5

fake = Faker()


# --- 예전 app/detection/signatures.py의 정규식과 매칭되도록 만들어진 페이로드들 ---

def _build_sqli_request():
    payload = random.choice(["' OR 1=1 --", "1 UNION SELECT username, password FROM users"])
    return {"method": "POST", "path": "rest/products/search", "json": {"q": payload}}


def _build_xss_request():
    payload = random.choice(["<script>alert(document.cookie)</script>", "<img src=x onerror=alert(1)>"])
    return {"method": "POST", "path": "api/Feedbacks", "json": {"comment": payload, "rating": 1}}


def _build_path_traversal_request():
    payload = random.choice(["../../../../etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"])
    return {"method": "POST", "path": "rest/user/change-password", "json": {"filename": payload}}


def _build_os_command_injection_request():
    payload = random.choice(["; cat /etc/passwd", "| whoami"])
    return {"method": "POST", "path": "rest/admin/application-version", "json": {"cmd": payload}}


def _build_jwt_forgery_request():
    import base64
    import json

    header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps({"sub": fake.user_name(), "admin": True}).encode()
    ).decode().rstrip("=")
    token = f"{header_b64}.{payload_b64}."
    return {"method": "GET", "path": "rest/user/whoami", "headers": {"Authorization": f"Bearer {token}"}}


REQUEST_BUILDERS = [
    _build_sqli_request,
    _build_xss_request,
    _build_path_traversal_request,
    _build_os_command_injection_request,
    _build_jwt_forgery_request,
]


def send_was_event():
    """Juice Shop(WAS)에 직접 요청을 보낸다 (nginx-was-logger의 access log 트리거)."""
    request_spec = random.choice(REQUEST_BUILDERS)()
    url = f"{WAS_URL}/{request_spec['path']}"
    try:
        response = requests.request(
            method=request_spec.get("method", "GET"),
            url=url,
            params=request_spec.get("params"),
            json=request_spec.get("json"),
            headers=request_spec.get("headers"),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        print(f"[WAS] {request_spec.get('method', 'GET')} /{request_spec['path']} -> {response.status_code}")
    except requests.RequestException as e:
        print(f"[WAS] Error sending request: {e}")


def main():
    print(f"Starting dummy event generator against WAS: {WAS_URL}")
    print(f"Generating {EVENTS_PER_SECOND} events per second...")

    event_counter = 0
    start_time = time.time()

    while True:
        if event_counter >= EVENTS_PER_SECOND:
            elapsed_time = time.time() - start_time
            if elapsed_time < 1.0:
                time.sleep(1.0 - elapsed_time)
            event_counter = 0
            start_time = time.time()

        send_was_event()
        event_counter += 1


if __name__ == "__main__":
    main()
