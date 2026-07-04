"""
담당: 심다움 (서버·DB 방어 룰), 하지환 (서버·DB 방어 룰), 윤재영 (클라이언트 방어 룰)

여기 있는 패턴은 "초기 뼈대"용 최소 세트다.
실제 룰 추가/고도화는 여기에 딕셔너리 항목을 추가하면 되고,
나중에는 app/models/schemas.py의 DetectionRule을 통해
DB/파일에서 동적으로 불러오는 방식으로 바꿔도 이 구조를 그대로 재사용 가능.

주의: PoC 때 겪었던 문제 — 페이로드가 body가 아니라
Authorization 헤더 등에 들어있는 경우도 있으므로,
탐지 엔진(engine.py)에서 검사 대상 문자열에 헤더까지 반드시 포함시킬 것.
"""
import re

# (attack_type, rule_name, 정규식, severity)
SIGNATURES = [
    # --- SQL Injection (담당: 하지환) ---
    ("sqli", "sqli_or_1_equals_1", re.compile(r"(?i)\bOR\b\s*['\"]?\s*1\s*=\s*1"), "CRITICAL"),
    ("sqli", "sqli_union_select", re.compile(r"(?i)\bUNION\b\s+\bSELECT\b"), "CRITICAL"),
    ("sqli", "sqli_comment_terminator", re.compile(r"(--|#|/\*)"), "MEDIUM"),
    ("sqli", "sqli_quote_injection", re.compile(r"['\"]\s*(OR|AND)\s*['\"]?\d"), "CRITICAL"),

    # --- XSS (담당: 윤재영) ---
    ("xss", "xss_script_tag", re.compile(r"(?i)<script[^>]*>"), "CRITICAL"),
    ("xss", "xss_event_handler", re.compile(r"(?i)on(load|error|click|mouseover)\s*="), "MEDIUM"),
    ("xss", "xss_javascript_uri", re.compile(r"(?i)javascript:"), "MEDIUM"),
    ("xss", "xss_iframe_tag", re.compile(r"(?i)<iframe[^>]*>"), "MEDIUM"),

    # --- OS Command Injection (담당: 하지환) ---
    ("os_command_injection", "cmd_chaining", re.compile(r"(;|\|\||&&)\s*(cat|ls|whoami|ping|curl|wget)\b"), "CRITICAL"),
    ("os_command_injection", "cmd_pipe", re.compile(r"\|\s*\w+"), "MEDIUM"),

    # --- Path Traversal (담당: 하지환) ---
    ("path_traversal", "path_dot_dot_slash", re.compile(r"\.\./"), "CRITICAL"),
    ("path_traversal", "path_encoded_traversal", re.compile(r"(?i)%2e%2e%2f"), "CRITICAL"),

    # JWT alg:none 위조는 base64 디코딩이 필요해서 app/detection/engine.py의
    # _check_jwt_alg_none()에서 별도 처리함 (담당: 이용욱 - PoC 검증 완료)
]

# 악성 파일 업로드 차단 확장자 (담당: 윤재영)
BLOCKED_FILE_EXTENSIONS = {".php", ".jsp", ".exe", ".sh", ".bat", ".asp", ".aspx"}