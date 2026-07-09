"""
백엔드로 가짜 WAF 공격 요청을 흘려보내는 더미 생성기.

실제 파이프라인을 그대로 타야 의미가 있으므로, app/proxy/proxy.py의 /proxy/{path}로
실제 공격 페이로드를 담아 요청을 보내서 app/detection/engine.py + signatures.py의 탐지
로직이 그대로 동작하게 한다 (탐지되면 403 + AttackLog가 OTel로 otel-collector에 전송됨).

Falco/K8s Audit 이벤트는 더 이상 이 스크립트가 HTTP로 흉내내지 않는다 - Falco는 이제
백엔드의 /api/alerts를 거치지 않고 stdout 로그를 otel-collector가 직접 tail하므로, 실제
파이프라인을 검증하려면 README에 있는 대로 kubectl로 진짜 이벤트를 발생시켜야 한다
(예: kubectl run attacker --rm -it --image=ubuntu -- bash -c "cat /etc/shadow").
"""
import os
import random
import time

import requests
from faker import Faker

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
EVENTS_PER_SECOND = int(os.getenv("EVENTS_PER_SECOND", "5"))
REQUEST_TIMEOUT_SECONDS = 5

fake = Faker()


# --- app/detection/signatures.py의 정규식과 실제로 매칭되는 페이로드 ---

def _build_sqli_request():
    # app/proxy/proxy.py의 inspect_request()는 body_text/headers_text만 검사하고
    # 쿼리 파라미터나 URL 경로는 보지 않으므로, 페이로드는 반드시 body에 실어야 탐지된다.
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

    # engine.py의 _check_jwt_alg_none()이 헤더 세그먼트만 base64 디코딩해서 alg 값을 확인한다.
    header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps({"sub": fake.user_name(), "admin": True}).encode()
    ).decode().rstrip("=")
    token = f"{header_b64}.{payload_b64}."
    return {"method": "GET", "path": "rest/user/whoami", "headers": {"Authorization": f"Bearer {token}"}}


WAF_REQUEST_BUILDERS = [
    _build_sqli_request,
    _build_xss_request,
    _build_path_traversal_request,
    _build_os_command_injection_request,
    _build_jwt_forgery_request,
]


def send_waf_event():
    """실제 공격 페이로드를 담아 /proxy/{path}로 요청을 보낸다 (WAF 탐지 트리거)."""
    request_spec = random.choice(WAF_REQUEST_BUILDERS)()
    url = f"{BACKEND_URL}/proxy/{request_spec['path']}"
    try:
        response = requests.request(
            method=request_spec.get("method", "GET"),
            url=url,
            params=request_spec.get("params"),
            json=request_spec.get("json"),
            headers=request_spec.get("headers"),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        print(f"[WAF] {request_spec.get('method', 'GET')} /{request_spec['path']} -> {response.status_code}")
    except requests.RequestException as e:
        print(f"[WAF] Error sending request: {e}")


def main():
    print(f"Starting dummy event generator against backend: {BACKEND_URL}")
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

        send_waf_event()
        event_counter += 1


if __name__ == "__main__":
    main()
