"""
담당: 이용욱 (게이트웨이 & 트래픽 컨트롤러)

시스템의 입구를 담당하는 미들웨어.

WAF는 더 이상 아무것도 차단하지 않는다 — 실제 접근 제어(차단/락아웃)는 WAS(보호 대상
서비스) 쪽 책임이고, 이 미들웨어는 의심스러운 트래픽을 "탐지해서 로그로 남기는" 역할만
한다 (Redis 기반 블랙리스트/계정 잠금 저장소도 그래서 제거됨 — 상태를 들고 있을 이유가
없어졌다):
1) Bad Bot 탐지 (알려진 해킹 툴 User-Agent)
2) CORS 위반 탐지 (화이트리스트에 없는 Origin에서의 브라우저 요청)
3) Rate Limiting 초과 탐지 (짧은 시간에 너무 많은 요청)
4) Brute Force 탐지 — 3단계
   4-1) IP 기준: 같은 IP의 반복된 로그인 실패
   4-2) 계정 기준: IP를 바꿔가며 같은 계정만 노리는 경우 (IP 로테이션 대응)
   4-3) 시스템 전체 기준: IP/계정 다 분산시켜서 도는 대규모 공격 조짐 감지
5) 에러 마스킹 (서버 내부 에러 메시지가 그대로 노출되지 않도록)

FastAPI의 미들웨어 체인에서 가장 먼저 실행되지만, 모든 요청은 여기서 걸러지지 않고
그대로 디코더(app/middleware/decoder.py)와 탐지 엔진(app/detection/engine.py)으로
넘어간다.
"""
import json
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional
from urllib.parse import parse_qs

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.models.schemas import AttackLog, AttackType, RiskLevel
from app.storage.log_store import add_log as save_log

# 알려진 해킹 툴 / 스캐너의 User-Agent 키워드 (필요시 계속 추가)
BAD_BOT_USER_AGENTS = ["sqlmap", "nikto", "nmap", "masscan", "acunetix", "curl/7.0"]

# 로그인/인증 관련 엔드포인트로 간주할 경로 키워드
LOGIN_PATH_KEYWORDS = ["login", "signin", "sign-in", "auth"]

# 로그인 요청 body에서 계정 식별자로 인식할 필드 이름 후보
LOGIN_IDENTIFIER_FIELDS = ["email", "username", "user", "id", "account"]

# 인증 실패로 간주할 응답 상태코드
LOGIN_FAILURE_STATUS_CODES = {401, 403}

# 시스템 전체 스파이크로 판단할 임계치 (1-1의 "레벨 1: 규칙 기반 이상탐지"에 해당)
# IP/계정별로는 임계치 밑이어도, 시스템 전체적으로 로그인 실패가 이 수치를 넘으면
# "분산형 브루트포스(자격증명 스터핑 등) 조짐"으로 보고 로그만 남긴다
SYSTEM_WIDE_FAILURE_THRESHOLD = 50
SYSTEM_WIDE_WINDOW_SECONDS = 60

# CORS 검증을 적용할 경로 접두사 — 실제 데이터를 주고받는 API/프록시 경로만 검사한다.
# (/health, /docs 같은 건 브라우저가 아니어도 호출하는 경우가 많아 제외)
CORS_PROTECTED_PATH_PREFIXES = ("/api", "/proxy")

# IP별 최근 요청 시각을 저장하는 메모리 저장소 (Rate Limiting 탐지용)
_request_history: Dict[str, Deque[float]] = defaultdict(deque)

# IP별 최근 로그인 실패 시각 (4-1: IP 기준 브루트포스)
_login_failure_by_ip: Dict[str, Deque[float]] = defaultdict(deque)

# 계정 식별자별 최근 로그인 실패 시각 (4-2: 계정 기준 브루트포스, IP 로테이션 대응)
_login_failure_by_account: Dict[str, Deque[float]] = defaultdict(deque)

# 시스템 전체 로그인 실패 시각 (4-3: 분산형 공격 스파이크 감지용)
_system_wide_login_failures: Deque[float] = deque()


def get_client_ip(request: Request) -> str:
    """
    실제 클라이언트 IP를 판단한다.

    배포 아키텍처상 Traefik 같은 리버스 프록시가 앞단에 있으면
    request.client.host는 프록시 자신의 IP가 되어버린다. 이때 프록시는
    X-Forwarded-For 헤더에 원본 클라이언트 IP를 남겨주므로 그 값을 써야 한다.

    다만 X-Forwarded-For는 누구나 마음대로 조작해서 보낼 수 있는 일반 HTTP 헤더다.
    그래서 이 헤더를 무조건 믿으면, 공격자가 매 요청마다 이 값을 바꿔가며 보내는 것만으로
    IP 기준 탐지(Rate Limiting, Brute Force)를 통째로 우회할 수 있게 된다.

    따라서 반드시 "누가 이 헤더를 보냈는지"부터 확인해야 한다:
    1) 지금 이 요청을 실제로 우리 서버에 직접 연결한 IP(request.client.host)가
       우리가 운영하는 신뢰된 프록시(settings.trusted_proxies) 목록에 있는지 확인
    2) 신뢰된 프록시가 보낸 요청일 때만 X-Forwarded-For 값을 사용
    3) 그 외의 경우(직접 우리 서버를 호출하거나, 모르는 프록시를 거친 경우)는
       헤더를 무시하고 직접 연결된 IP를 그대로 신뢰한다 — 헤더 위조로 우회하지 못하게 막는 핵심 로직
    """
    direct_client_ip = request.client.host if request.client else None

    if direct_client_ip in settings.trusted_proxies:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # "client, proxy1, proxy2" 형태로 올 수 있어 맨 앞(원본 클라이언트)만 사용
            return forwarded_for.split(",")[0].strip()

    return direct_client_ip or "unknown"


def _is_rate_limited(ip: str) -> bool:
    """최근 rate_limit_window_seconds 안에 rate_limit_max_requests 넘게 요청했는지 확인."""
    now = time.time()
    history = _request_history[ip]

    while history and now - history[0] > settings.rate_limit_window_seconds:
        history.popleft()

    history.append(now)
    return len(history) > settings.rate_limit_max_requests


def _is_bad_bot(user_agent: str) -> bool:
    ua_lower = (user_agent or "").lower()
    return any(bad_ua in ua_lower for bad_ua in BAD_BOT_USER_AGENTS)


def is_login_endpoint(path: str) -> bool:
    """요청 경로가 로그인/인증 엔드포인트인지 판단."""
    path_lower = path.lower()
    return any(keyword in path_lower for keyword in LOGIN_PATH_KEYWORDS)


def is_cors_protected_path(path: str) -> bool:
    """CORS 검증이 필요한 경로인지 판단 (실제 데이터를 다루는 API/프록시만)."""
    return path.startswith(CORS_PROTECTED_PATH_PREFIXES)


def check_cors_violation(request: Request) -> bool:
    """
    Origin 헤더를 화이트리스트(settings.allowed_origins)와 비교한다.

    핵심 판단 기준: Origin 헤더는 "브라우저가 자동으로 붙이는" 헤더라서
    curl이나 서버 대 서버 호출에는 보통 없다. 그래서:
    - Origin이 아예 없으면 브라우저 fetch가 아닐 가능성이 높으므로 통과시킨다
      (여기서 다 막아버리면 정상적인 서버 간 통신, curl 테스트도 막혀버림)
    - Origin이 있는데 화이트리스트에 없으면, 다른 사이트(evil.com 등)에서
      브라우저를 통해 우리 API를 몰래 호출하려는 시도로 간주하고 로그를 남긴다.
    """
    origin = request.headers.get("origin")
    if not origin:
        return False
    return origin not in settings.allowed_origins


def _log_bad_bot(ip: str, path: str, user_agent: str) -> None:
    save_log(
        AttackLog(
            source_ip=ip,
            attack_type=AttackType.BAD_BOT,
            target_endpoint=path,
            http_method="",
            payload_snippet=f"User-Agent: {user_agent}"[:200],
            user_agent=user_agent,
            matched_rule_id="bad_bot_user_agent",
            blocked=False,
            risk_level=RiskLevel.MEDIUM,
        )
    )


def _log_cors_violation(ip: str, path: str, origin: str) -> None:
    """CORS 위반 시도를 AttackLog로 남긴다."""
    save_log(
        AttackLog(
            source_ip=ip,
            attack_type=AttackType.CORS_ABUSE,
            target_endpoint=path,
            http_method="",  # 호출부에서 필요시 채움
            payload_snippet=f"Origin: {origin}"[:200],
            matched_rule_id="cors_violation",
            blocked=False,
            risk_level=RiskLevel.MEDIUM,
        )
    )


def _log_rate_limit_exceeded(ip: str, path: str) -> None:
    save_log(
        AttackLog(
            source_ip=ip,
            attack_type=AttackType.RATE_LIMIT_ABUSE,
            target_endpoint=path,
            http_method="",
            payload_snippet="rate_limit_exceeded",
            matched_rule_id="rate_limit_exceeded",
            blocked=False,
            risk_level=RiskLevel.LOW,
        )
    )


def _log_brute_force(ip: str, path: str, matched_rule_id: str, risk_level: RiskLevel = RiskLevel.MEDIUM) -> None:
    save_log(
        AttackLog(
            source_ip=ip,
            attack_type=AttackType.BRUTE_FORCE,
            target_endpoint=path,
            http_method="",
            payload_snippet=matched_rule_id,
            matched_rule_id=matched_rule_id,
            blocked=False,
            risk_level=risk_level,
        )
    )


def extract_login_identifier(body_bytes: bytes, content_type: str) -> Optional[str]:
    """
    로그인 요청 body에서 계정 식별자(이메일/아이디)를 뽑아낸다.
    JSON과 form-urlencoded 두 형식을 지원. 파싱 실패하면 None을 반환하고
    이 경우 IP 기준 탐지(4-1)만으로 대응한다 — 계정 추출은 "있으면 더 좋은" 보강 계층.
    """
    if not body_bytes:
        return None

    try:
        if "application/json" in content_type:
            data = json.loads(body_bytes.decode("utf-8", errors="ignore"))
        elif "application/x-www-form-urlencoded" in content_type:
            parsed = parse_qs(body_bytes.decode("utf-8", errors="ignore"))
            data = {k: v[0] for k, v in parsed.items()}
        else:
            return None
    except Exception:
        return None

    for field in LOGIN_IDENTIFIER_FIELDS:
        if field in data and data[field]:
            return str(data[field]).strip().lower()
    return None


def record_login_failure_by_ip(ip: str) -> bool:
    """4-1: IP 기준. Rate Limiting과 완전히 독립된 카운터를 쓴다."""
    now = time.time()
    history = _login_failure_by_ip[ip]

    while history and now - history[0] > settings.brute_force_window_seconds:
        history.popleft()

    history.append(now)
    return len(history) >= settings.brute_force_max_failures


def record_login_failure_by_account(identifier: str) -> bool:
    """4-2: 계정 기준. IP가 계속 바뀌어도 같은 계정이 타겟이면 여기서 잡힌다."""
    now = time.time()
    history = _login_failure_by_account[identifier]

    while history and now - history[0] > settings.brute_force_window_seconds:
        history.popleft()

    history.append(now)
    return len(history) >= settings.brute_force_max_failures


def record_system_wide_login_failure() -> bool:
    """
    4-3: 시스템 전체 기준 (레벨 1 이상탐지).
    IP도 계정도 매번 다르게 분산시키는 대규모/분산형 공격은 4-1, 4-2 둘 다 못 잡는다.
    "짧은 시간 안에 시스템 전체 로그인 실패가 비정상적으로 많다"는 것 자체를 신호로 본다.
    """
    now = time.time()
    while _system_wide_login_failures and now - _system_wide_login_failures[0] > SYSTEM_WIDE_WINDOW_SECONDS:
        _system_wide_login_failures.popleft()

    _system_wide_login_failures.append(now)
    return len(_system_wide_login_failures) >= SYSTEM_WIDE_FAILURE_THRESHOLD


class GatewayMiddleware(BaseHTTPMiddleware):
    """main.py에서 app.add_middleware(GatewayMiddleware) 형태로 등록해서 사용."""

    async def dispatch(self, request: Request, call_next):
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        is_login_request = is_login_endpoint(request.url.path)

        # 1) Bad Bot 탐지 — 차단하지 않고 로그만 남긴다
        if _is_bad_bot(user_agent):
            _log_bad_bot(client_ip, request.url.path, user_agent)

        # 2) CORS 위반 탐지 — 화이트리스트에 없는 Origin에서 온 브라우저 요청을 로그로 남긴다.
        #    정적 문서(/docs)나 헬스체크는 검사 대상에서 제외 (CORS_PROTECTED_PATH_PREFIXES 참고)
        if is_cors_protected_path(request.url.path) and check_cors_violation(request):
            origin = request.headers.get("origin", "")
            _log_cors_violation(client_ip, request.url.path, origin)

        # 3) Rate Limiting 초과 탐지
        if _is_rate_limited(client_ip):
            _log_rate_limit_exceeded(client_ip, request.url.path)

        # 4-2 사전 체크용 계정 식별자 추출 (락아웃 저장소는 제거됐으므로 여기서는 로그인 실패
        # 집계에만 쓰인다)
        login_identifier: Optional[str] = None
        if is_login_request and request.method in ("POST", "PUT"):
            body_bytes = await request.body()
            content_type = request.headers.get("content-type", "")
            login_identifier = extract_login_identifier(body_bytes, content_type)

        # 5) 에러 마스킹 — 하위 로직에서 예외가 터져도 상세 스택트레이스를 노출하지 않음
        try:
            response = await call_next(request)

            # 4) Brute Force 판정 — 로그인 엔드포인트에서 실패(401/403) 응답이 나온 경우에만 집계.
            #    응답을 봐야 판단 가능하므로 call_next() 이후 시점에서 검사한다.
            if is_login_request and response.status_code in LOGIN_FAILURE_STATUS_CODES:
                # 4-1: IP 기준
                if record_login_failure_by_ip(client_ip):
                    _log_brute_force(client_ip, request.url.path, "brute_force_login_ip")

                # 4-2: 계정 기준 (IP 로테이션 대응) — 계정 식별을 못 했으면 건너뜀
                if login_identifier and record_login_failure_by_account(login_identifier):
                    _log_brute_force(client_ip, request.url.path, f"brute_force_login_account:{login_identifier}")

                # 4-3: 시스템 전체 스파이크 (분산형 공격 조짐)
                if record_system_wide_login_failure():
                    _log_brute_force(
                        client_ip,
                        request.url.path,
                        "brute_force_system_wide_spike",
                        risk_level=RiskLevel.CRITICAL,
                    )

            return response
        except Exception:
            import traceback
            print(f"[Gateway] Unhandled error while processing request from {client_ip}")
            traceback.print_exc()
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"},  # 상세 내용 숨김
            )
