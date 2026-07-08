"""
담당: 하지환 (데이터 정규화 & 우회 방어)

해커가 필터를 피하려고 꼬아놓은 입력값을 깨끗하게 펴서
탐지 엔진(app/detection/engine.py)에 넘겨주는 전처리 계층.
이 계층이 없으면 %27, %3Cscript%3E 같은 인코딩된 페이로드가
정규식 탐지를 그대로 통과해버림.
"""
import html
import re
import unicodedata
import urllib.parse
from typing import Dict

_MULTIPART_BOUNDARY_PATTERN = re.compile(r'boundary=(?:"([^"]+)"|([^;\s]+))', re.IGNORECASE)


def normalize_text(raw_text: str) -> str:
    """
    1) URL 디코딩 + HTML 엔티티 디코딩을 번갈아 반복 적용
       (이중 인코딩 우회 방지: %2527 -> %27 -> ' / &amp;lt; -> &lt; -> <)
       두 인코딩이 섞여서 오는 경우(예: %26lt%3B = URL인코딩된 "&lt;")도 있어서
       한쪽만 디코딩하고 끝내면 안 되고 두 방식을 같이 반복해야 한다.
    2) 유니코드 정규화(NFKC) — 전각문자(＜ｓｃｒｉｐｔ＞) 같은 유니코드 트릭으로
       정규식 필터를 우회하려는 시도를 일반 ASCII 형태로 되돌림.
    3) 대소문자를 소문자로 통일 (sCrIpt -> script)
    탐지는 이 정규화된 문자열을 대상으로 수행한다.
    """
    text = raw_text
    # 최대 3번까지 디코딩 반복 (이중/삼중 인코딩 우회 대비)
    for _ in range(3):
        decoded = html.unescape(urllib.parse.unquote(text))
        if decoded == text:
            break
        text = decoded

    text = unicodedata.normalize("NFKC", text)
    return text.lower()


def strip_multipart_boundary_lines(body_text: str, content_type: str) -> str:
    """
    multipart/form-data 요청은 파트 구분을 위해 "--<boundary>" 줄이 바디 전체에
    반복해서 등장한다. 이 대시(--)가 SQLi 주석 종료 패턴(sqli_comment_terminator: --|#|/*)과
    우연히 일치해서, 파일 업로드 요청이 통째로 SQLi로 먼저 걸려버려 그 뒤에 있는
    file_upload 시그니처(filename=...php)까지 도달하지도 못하는 문제가 있었다
    (실제로 정상적인 이미지 업로드조차 SQLi 오탐이 났다).

    Content-Disposition/필드 값 등 실제 내용은 그대로 두고, Content-Type 헤더에 선언된
    정확한 boundary 토큰과 일치하는 줄만 제거한다 — 임의의 "--"로 시작하는 줄을 다 지우면
    공격자가 필드 값 자체를 "-- DROP TABLE ..." 처럼 줄 맨 앞에 넣는 진짜 SQLi까지
    같이 지워버릴 수 있어서, boundary 토큰 매칭을 반드시 정확하게 해야 한다.
    """
    match = _MULTIPART_BOUNDARY_PATTERN.search(content_type)
    if not match:
        return body_text

    boundary = (match.group(1) or match.group(2) or "").strip().lower()
    if not boundary:
        return body_text

    # body_text는 이미 normalize_text()에서 소문자화됐으므로 boundary도 맞춰서 소문자로 비교
    boundary_line_pattern = re.compile(rf"(?m)^--{re.escape(boundary)}(--)?[^\n]*$")
    return boundary_line_pattern.sub("", body_text)


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