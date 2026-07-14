"""
담당: 윤재영 (서버·DB 방어 룰), 심다움 (클라이언트 방어 룰)

여기 있는 패턴은 "초기 뼈대"용 최소 세트다.
실제 룰 추가/고도화는 여기에 딕셔너리 항목을 추가하면 되고,
나중에는 app/models/schemas.py의 DetectionRule을 통해
DB/파일에서 동적으로 불러오는 방식으로 바꿔도 이 구조를 그대로 재사용 가능.

주의: PoC 때 겪었던 문제 — 페이로드가 body가 아니라
Authorization 헤더 등에 들어있는 경우도 있으므로,
탐지 엔진(engine.py)에서 검사 대상 문자열에 헤더까지 반드시 포함시킬 것.
"""
import re

# (attack_type, rule_id, rule_name, 정규식, severity)
#
# rule_id는 매칭 결과 식별/로그 조회용 슬러그, rule_name은 사람이 읽는 표시용 이름 -
# 예전엔 rule_id 하나만 있어서 정규화 단계(NormalizedEvent.rule.name)가 rule.id를
# 그대로 재사용해야 했다(README "아직 안 된 것" 참고, 2026-07-14 분리).
SIGNATURES = [
    # --- SQL Injection (담당: 윤재영) ---
    ("sqli", "sqli_or_1_equals_1", "SQL Injection: OR 1=1 우회", re.compile(r"(?i)\bOR\b\s*['\"]?\s*1\s*=\s*1"), "CRITICAL"),
    ("sqli", "sqli_union_select", "SQL Injection: UNION SELECT", re.compile(r"(?i)\bUNION\b\s+\bSELECT\b"), "CRITICAL"),
    ("sqli", "sqli_comment_terminator", "SQL Injection: 주석 종료자", re.compile(r"(--|#|/\*)"), "MEDIUM"),
    ("sqli", "sqli_quote_injection", "SQL Injection: 따옴표 주입", re.compile(r"['\"]\s*(OR|AND)\s*['\"]?\d"), "CRITICAL"),

    # --- XSS (담당: 심다움) ---
    ("xss", "xss_script_tag", "XSS: <script> 태그", re.compile(r"(?i)<script[^>]*>"), "CRITICAL"),
    ("xss", "xss_event_handler", "XSS: 이벤트 핸들러 속성", re.compile(r"(?i)on(load|error|click|mouseover)\s*="), "MEDIUM"),
    ("xss", "xss_javascript_uri", "XSS: javascript: URI", re.compile(r"(?i)javascript:"), "MEDIUM"),
    ("xss", "xss_iframe_tag", "XSS: <iframe> 태그", re.compile(r"(?i)<iframe[^>]*>"), "MEDIUM"),

    # --- OS Command Injection (담당: 윤재영) ---
    ("os_command_injection", "cmd_chaining", "OS Command Injection: 명령어 체이닝", re.compile(r"(;|\|\||&&)\s*(cat|ls|whoami|ping|curl|wget)\b"), "CRITICAL"),
    ("os_command_injection", "cmd_pipe", "OS Command Injection: 파이프", re.compile(r"\|\s*\w+"), "MEDIUM"),

    # --- Path Traversal (담당: 윤재영) ---
    ("path_traversal", "path_dot_dot_slash", "Path Traversal: ../ 패턴", re.compile(r"\.\./"), "CRITICAL"),
    ("path_traversal", "path_encoded_traversal", "Path Traversal: URL 인코딩 우회", re.compile(r"(?i)%2e%2e%2f"), "CRITICAL"),

    # JWT alg:none 위조는 base64 디코딩이 필요해서 app/detection/engine.py의
    # _check_jwt_alg_none()에서 별도 처리함 (담당: 이용욱 - PoC 검증 완료)
]

# 악성 파일 업로드 차단 확장자 (담당: 심다움)
BLOCKED_FILE_EXTENSIONS = {".php", ".jsp", ".exe", ".sh", ".bat", ".asp", ".aspx"}