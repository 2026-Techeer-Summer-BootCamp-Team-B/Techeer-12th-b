"""
WAF(`log.source=waf`) 기반 상관분석 시나리오(S4, S5의 stage1)를 트리거하는 HTTP 요청
빌더 + 정상(benign) 트래픽 생성기.

반드시 WAF_URL(`/proxy/{path}`)을 거쳐서 보낸다 - Juice Shop(WAS_URL)로 직접 보내면
`log.source=was`만 남고 `waf`는 안 남는다(app/proxy/proxy.py 참고). WAF는 detection
모드(기본값)에서는 판정과 무관하게 항상 Juice Shop까지 그대로 전달하므로, 이 요청들이
막히지 않고 응답을 받는 게 정상이다.

payload는 backend/app/detection/signatures.py의 정규식과 매칭되도록 만들어졌고,
severity.yaml(risk_level.CRITICAL -> severity 4)에서 CRITICAL로 분류되는 것만 S5
stage1(min_severity=4)에 쓴다.

출발지 IP 다양화: 모든 요청이 이 스크립트를 돌리는 한 대의 테스트 머신에서 나가기
때문에 그냥 두면 WafAlert.source_ip가 전부 똑같다(나중에 실제 GeoIP DB를 붙였을 때도
전부 한 점으로 찍히는 원인). IDS-COLLECTOR 쪽 GeoIP lookup을 손대는 대신, 로그가
"발생하는" 지점인 여기서 매 요청마다 X-Forwarded-For로 서로 다른 가짜 공인 IP를
실어 보낸다 - source_ip가 원래부터 다양했던 것처럼 만들어서, 나중에 진짜 GeoIP DB를
붙이면 그 시점부터 바로 여러 위치로 흩어져 보이게 된다.
"""
import os
import random
from typing import Optional

import requests

WAF_URL = os.getenv("WAF_URL", "http://localhost:8000")
REQUEST_TIMEOUT_SECONDS = 5

# 사설/예약 대역(10., 127., 172.16-31., 192.168., 169.254. 등)을 피해서 고른 "공인
# IP처럼 보이는" 1옥텟 풀 - 실제 지리적 정확도는 중요하지 않다(GeoIP DB가 아직
# 없어서 지금은 국가/도시로 안 바뀜), 그냥 서로 다른 IP가 로그에 남는 게 목적.
_PUBLIC_FIRST_OCTETS = [
    1, 3, 5, 8, 9, 11, 20, 23, 31, 37, 41, 45, 58, 60, 77, 82, 85, 91, 94,
    101, 103, 109, 113, 118, 121, 125, 138, 139, 141, 144, 150, 157, 162,
    165, 171, 175, 180, 185, 190, 193, 195, 198, 200, 203, 209, 212, 216, 218, 223,
]


def random_source_ip() -> str:
    """다양한 출발지 IP를 만들기 위한 가짜 공인 IP 생성기(사설/예약 대역 회피)."""
    first = random.choice(_PUBLIC_FIRST_OCTETS)
    rest = [random.randint(0, 255) for _ in range(3)]
    return ".".join(str(o) for o in [first, *rest])


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


def send_xss_critical(source_ip: Optional[str] = None) -> str:
    return _send(
        "POST", "api/Feedbacks", json={"comment": "<script>alert(document.cookie)</script>", "rating": 1},
        source_ip=source_ip,
    )


def send_path_traversal_critical(source_ip: Optional[str] = None) -> str:
    return _send(
        "POST", "rest/user/change-password", json={"filename": "../../../../etc/passwd"}, source_ip=source_ip
    )


def send_cmdi_critical(source_ip: Optional[str] = None) -> str:
    return _send("POST", "rest/admin/application-version", json={"cmd": "; cat /etc/passwd"}, source_ip=source_ip)


_CRITICAL_BUILDERS = [send_sqli_critical, send_xss_critical, send_path_traversal_critical, send_cmdi_critical]


def send_random_critical_attack(source_ip: Optional[str] = None) -> str:
    return random.choice(_CRITICAL_BUILDERS)(source_ip=source_ip)


def send_waf_burst(count: int = 6) -> list:
    """S4(같은 IP에서 60초 안에 WAF 이벤트 5건 이상) 재료 - CRITICAL 공격을 연속으로 쏜다.
    join_on=source_ip라 이 burst 안에서는 반드시 같은 IP를 써야 하지만(안 그러면
    threshold가 절대 안 채워짐), burst마다는(=시나리오 실행마다는) 다른 IP를 뽑아서
    실행할 때마다 다른 발원지로 보이게 한다."""
    ip = random_source_ip()
    return [send_random_critical_attack(source_ip=ip) for _ in range(count)]


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
