"""
담당: 심다움 / 하지환 / 윤재영 (탐지 로직 통합 지점)

app/middleware/decoder.py 에서 정규화(디코딩)까지 끝낸 문자열을 받아서
signatures.py의 규칙과 매칭시키고, 걸리면 AttackLog를 만들어 반환한다.

이 파일은 "공통 탐지 프레임워크" 역할만 하고,
실제 패턴은 signatures.py에 팀원별로 나눠서 채워 넣는 구조.
"""
import base64
import json
import re
from typing import Optional

from app.detection.signatures import SIGNATURES
from app.models.schemas import AttackLog, AttackType, RiskLevel

_BEARER_TOKEN_PATTERN = re.compile(r"Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*)", re.IGNORECASE)


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

    return None