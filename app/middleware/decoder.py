"""
담당: 심다움 (데이터 정규화 & 우회 방어)

해커가 필터를 피하려고 꼬아놓은 입력값을 깨끗하게 펴서
탐지 엔진(app/detection/engine.py)에 넘겨주는 전처리 계층.
이 계층이 없으면 %27, %3Cscript%3E 같은 인코딩된 페이로드가
정규식 탐지를 그대로 통과해버림.
"""
import urllib.parse
from typing import Dict


def normalize_text(raw_text: str) -> str:
    """
    1) URL 디코딩을 반복 적용 (이중 인코딩 우회 방지: %2527 -> %27 -> ')
    2) 대소문자를 소문자로 통일 (sCrIpt -> script)
    탐지는 이 정규화된 문자열을 대상으로 수행한다.
    """
    text = raw_text
    # 최대 3번까지 디코딩 반복 (이중/삼중 인코딩 우회 대비)
    for _ in range(3):
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            break
        text = decoded
    return text.lower()


def normalize_query_params(raw_query_params: Dict[str, list]) -> Dict[str, str]:
    """
    HTTP Parameter Pollution(HPP) 방어.
    동일한 이름의 파라미터가 여러 개 들어오면(예: ?id=1&id=2' OR 1=1)
    첫 번째 값만 채택하고 나머지는 버려서 꼼수를 무력화한다.

    raw_query_params 예시: {"id": ["1", "2' OR 1=1"]}
    반환값 예시: {"id": "1"}
    """
    normalized = {}
    for key, values in raw_query_params.items():
        # 여러 개 들어왔다는 것 자체가 의심스러운 패턴이므로,
        # 실제 운영 시에는 이 경우를 별도로 로깅하는 것도 고려할 것.
        normalized[key] = values[0] if values else ""
    return normalized