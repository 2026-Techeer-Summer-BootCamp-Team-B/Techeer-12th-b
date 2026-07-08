"""
담당: 윤재영 (서버·DB 탐지) / 심다움 (클라이언트 탐지) — 탐지 로직 통합 지점

app/middleware/decoder.py 에서 정규화(디코딩)까지 끝낸 문자열을 받아서
signatures.py의 규칙과 매칭시키고, 걸리면 AttackLog를 만들어 반환한다.

이 파일은 "공통 탐지 프레임워크" 역할만 하고,
실제 패턴은 signatures.py에 팀원별로 나눠서 채워 넣는 구조.
"""
import base64
import json
import re
import urllib.parse
from typing import Optional

from app.config import settings
from app.detection.signatures import SIGNATURES
from app.models.schemas import AttackLog, AttackType, RiskLevel

_BEARER_TOKEN_PATTERN = re.compile(r"Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*)", re.IGNORECASE)

_CSRF_STATE_CHANGING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

_OPEN_REDIRECT_PARAM_PATTERN = re.compile(
    r'(?i)(redirect|return|next|url|continue|dest|destination)["\']?\s*[:=]\s*["\']?((?:https?:)?//[^\s"\'/]+)'
)

_XXE_ENTITY_DECLARATION_PATTERN = re.compile(r"(?i)<!entity\s+%?\s*\S+\s+")
_XXE_ENTITY_BOMB_THRESHOLD = 3


def _check_jwt_alg_none(headers_text: str) -> bool:
    """
    JWT의 alg:none 위조 공격은 헤더 부분이 base64url로 인코딩되어 있어서
    일반 정규식으로는 못 잡는다 (PoC 때 실제로 겪었던 문제).
    Authorization 헤더에서 토큰을 뽑아 헤더 세그먼트만 디코딩해서 확인해야 한다.
    """
    match = _BEARER_TOKEN_PATTERN.search(headers_text)
    if not match:
        return False

    token = match.group(1)
    header_segment = token.split(".")[0]

    padding_needed = (4 - len(header_segment) % 4) % 4
    header_segment += "=" * padding_needed

    try:
        decoded_bytes = base64.urlsafe_b64decode(header_segment)
        header_json = json.loads(decoded_bytes)
    except Exception:
        return False

    alg_value = str(header_json.get("alg", "")).lower()
    return alg_value == "none"


def _check_csrf_risk(headers_text: str, http_method: str) -> bool:
    """
    CSRF는 피해자 브라우저가 "자동으로 붙이는" 세션 쿠키를 이용해 상태를 바꾸는 공격이다.
    공격자 페이지의 <form>/<img> 기반 요청은 fetch/XHR이 아니라서 Origin 헤더 자체가
    아예 없는 경우가 흔한데, 이는 gateway.py의 CORS 검사("Origin 없으면 통과")를 그대로
    우회한다. 그래서 "세션 쿠키는 있는데 Origin/Referer로 출처를 전혀 확인할 수 없는
    상태변경 요청"을 여기서 별도로 잡는다 (CORS_ABUSE 탐지와 상호 보완 관계).
    """
    if http_method.upper() not in _CSRF_STATE_CHANGING_METHODS:
        return False

    headers_lower = headers_text.lower()
    has_session_cookie = bool(re.search(r"^cookie:", headers_lower, re.MULTILINE))
    if not has_session_cookie:
        return False

    has_origin = bool(re.search(r"^origin:", headers_lower, re.MULTILINE))
    has_referer = bool(re.search(r"^referer:", headers_lower, re.MULTILINE))
    return not has_origin and not has_referer


def _hostname_of(url_fragment: str) -> str:
    if "://" in url_fragment:
        candidate = url_fragment
    elif url_fragment.startswith("//"):
        candidate = f"http:{url_fragment}"
    else:
        candidate = f"http://{url_fragment}"
    return (urllib.parse.urlparse(candidate).hostname or "").lower()


def _check_open_redirect(inspection_text: str) -> bool:
    """
    redirect=https://evil.com 같은 페이로드를 "외부 도메인이면 무조건 의심"으로 잡으면
    정상적인 리다이렉트 흐름도 많이 막혀서 오탐이 커진다. 그래서 실제로 우리가 신뢰하는
    도메인 목록(settings.allowed_origins, 프록시 대상인 target_service_url)과 비교해서
    화이트리스트에 없는 도메인으로 튀는 경우만 공격으로 판단한다.
    """
    match = _OPEN_REDIRECT_PARAM_PATTERN.search(inspection_text)
    if not match:
        return False

    target_host = _hostname_of(match.group(2))
    if not target_host:
        return False

    allowed_hosts = {
        (urllib.parse.urlparse(origin).hostname or origin).lower()
        for origin in settings.allowed_origins
    }
    target_service_host = urllib.parse.urlparse(settings.target_service_url).hostname
    if target_service_host:
        allowed_hosts.add(target_service_host.lower())

    return target_host not in allowed_hosts


def _check_xxe_entity_bomb(body_text: str) -> bool:
    """
    Billion Laughs류 엔티티 확장 폭탄(DoS)은 특정 문자열 패턴이 아니라
    "<!ENTITY 선언이 비정상적으로 여러 번 반복된다"는 횟수 자체가 신호다.
    정상적인 XML 문서에 이 정도로 많은 내부 엔티티 선언이 들어있는 경우는 거의 없다.
    """
    return len(_XXE_ENTITY_DECLARATION_PATTERN.findall(body_text)) > _XXE_ENTITY_BOMB_THRESHOLD


def inspect_request(
    *,
    source_ip: str,
    target_endpoint: str,
    http_method: str,
    body_text: str,
    headers_text: str,
    user_agent: Optional[str] = None,
) -> Optional[AttackLog]:
    """
    요청 하나를 검사해서 공격으로 판단되면 AttackLog를, 아니면 None을 반환.

    PoC 때 겪은 버그(JWT 위조가 헤더에만 있어서 못 잡음)를 반영해서
    body와 헤더를 합친 문자열(inspection_text)을 통째로 검사한다.
    """
    inspection_text = f"{body_text}\n{headers_text}"

    if _check_jwt_alg_none(headers_text):
        return AttackLog(
            source_ip=source_ip,
            attack_type=AttackType.JWT_FORGERY,
            target_endpoint=target_endpoint,
            http_method=http_method,
            payload_snippet=headers_text[:200],
            user_agent=user_agent,
            matched_rule_id="jwt_alg_none",
            blocked=True,
            risk_level=RiskLevel.CRITICAL,
        )

    if _check_csrf_risk(headers_text, http_method):
        return AttackLog(
            source_ip=source_ip,
            attack_type=AttackType.CSRF,
            target_endpoint=target_endpoint,
            http_method=http_method,
            payload_snippet=headers_text[:200],
            user_agent=user_agent,
            matched_rule_id="csrf_missing_origin_referer",
            blocked=True,
            risk_level=RiskLevel.MEDIUM,
        )

    if _check_xxe_entity_bomb(body_text):
        return AttackLog(
            source_ip=source_ip,
            attack_type=AttackType.XXE,
            target_endpoint=target_endpoint,
            http_method=http_method,
            payload_snippet=body_text[:200],
            user_agent=user_agent,
            matched_rule_id="xxe_entity_expansion_bomb",
            blocked=True,
            risk_level=RiskLevel.CRITICAL,
        )

    for attack_type, rule_name, pattern, severity in SIGNATURES:
        match = pattern.search(inspection_text)
        if match:
            # 매칭된 부분 앞뒤로 살짝 잘라서 로그에 남김 (전체 페이로드 저장 금지)
            snippet_start = max(match.start() - 20, 0)
            snippet_end = min(match.end() + 20, len(inspection_text))
            snippet = inspection_text[snippet_start:snippet_end]

            return AttackLog(
                source_ip=source_ip,
                attack_type=AttackType(attack_type),
                target_endpoint=target_endpoint,
                http_method=http_method,
                payload_snippet=snippet,
                user_agent=user_agent,
                matched_rule_id=rule_name,
                blocked=True,
                risk_level=RiskLevel(severity),
            )

    # Open Redirect는 "redirect=외부URL"이라는 아주 흔한 형태라 SSRF 등 더 구체적인
    # 신호(SIGNATURES)가 먼저 걸릴 기회를 준 다음, 그래도 안 걸렸을 때만 최후 판단으로 본다.
    if _check_open_redirect(inspection_text):
        return AttackLog(
            source_ip=source_ip,
            attack_type=AttackType.OPEN_REDIRECT,
            target_endpoint=target_endpoint,
            http_method=http_method,
            payload_snippet=inspection_text[:200],
            user_agent=user_agent,
            matched_rule_id="open_redirect_untrusted_host",
            blocked=True,
            risk_level=RiskLevel.MEDIUM,
        )

    return None