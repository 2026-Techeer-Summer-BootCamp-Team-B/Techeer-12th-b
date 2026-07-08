"""
담당: 윤재영 (서버·DB 방어 룰), 심다움 (클라이언트 방어 룰)

여기 있는 패턴은 "초기 뼈대"용 최소 세트다.
실제 룰 추가/고도화는 여기에 딕셔너리 항목을 추가하면 되고,
나중에는 app/models/schemas.py의 DetectionRule을 통해
DB/파일에서 동적으로 불러오는 방식으로 바꿔도 이 구조를 그대로 재사용 가능.

주의: PoC 때 겪었던 문제 — 페이로드가 body가 아니라
Authorization 헤더 등에 들어있는 경우도 있으므로,
탐지 엔진(engine.py)에서 검사 대상 문자열에 헤더까지 반드시 포함시킬 것.

주의 2: engine.py는 body_text/headers_text가 decoder.py의 normalize_text()를 거쳐
"URL/HTML 엔티티 디코딩 + 유니코드 정규화 + 소문자화"까지 끝난 상태로 넘어온다는 걸
전제로 정규식을 짠다. 그래서 %2e%2e%2f 같은 인코딩된 패턴 룰은 decoder를 우회해서
들어오는 경우를 대비한 방어선(defense-in-depth)이지, 주 탐지 경로가 아니다.

Open Redirect / XXE(엔티티 폭탄)는 순수 정규식만으로는 오탐이 크거나(화이트리스트 비교가
필요) 아예 표현이 안 되는(반복 횟수 세기) 유형이라 여기 SIGNATURES가 아니라
app/detection/engine.py의 _check_open_redirect() / _check_xxe_entity_bomb()에서
구조적으로 처리한다.
"""
import re

# 악성 파일 업로드 차단 확장자 (담당: 심다움)
BLOCKED_FILE_EXTENSIONS = {".php", ".jsp", ".exe", ".sh", ".bat", ".asp", ".aspx"}
_BLOCKED_EXTENSIONS_PATTERN = "|".join(ext.lstrip(".") for ext in BLOCKED_FILE_EXTENSIONS)

# (attack_type, rule_name, 정규식, severity)
SIGNATURES = [
    # --- NoSQL Injection ---
    # SQLi의 sleep(/#/-- 같은 범용 패턴보다 먼저 검사해야 한다 — 안 그러면
    # {"$where": "sleep(5000)"} 같은 NoSQLi 페이로드가 sqli_time_based_blind에
    # 먼저 걸려서 SQLi로 오분류된다 (아래 SQLi 블록보다 이 블록이 위에 있어야 하는 이유).
    # MongoDB류 쿼리 연산자를 JSON body에 직접 주입하는 패턴 (예: {"password": {"$ne": null}})
    ("nosqli", "nosqli_operator_injection", re.compile(r'(?i)"\$(where|ne|gt|gte|lt|lte|regex|in|nin|exists|or|and|expr|function|accumulator)"\s*:'), "CRITICAL"),
    # Express/PHP 스타일 대괄호 표기법으로 폼 필드에 연산자를 주입하는 패턴 (예: email[$ne]=admin)
    ("nosqli", "nosqli_bracket_operator_injection", re.compile(r"(?i)\[\$(ne|gt|gte|lt|lte|regex|where|exists)\]\s*="), "CRITICAL"),
    # $where에 JS를 넣어 시간 지연을 유발하는 NoSQL 버전 blind injection
    ("nosqli", "nosqli_where_js_sleep", re.compile(r"(?i)\$where.{0,80}sleep\s*\("), "CRITICAL"),

    # --- SQL Injection (담당: 윤재영) ---
    ("sqli", "sqli_or_1_equals_1", re.compile(r"(?i)\bOR\b\s*['\"]?\s*1\s*=\s*1"), "CRITICAL"),
    ("sqli", "sqli_union_select", re.compile(r"(?i)\bUNION\b\s+\bSELECT\b"), "CRITICAL"),
    ("sqli", "sqli_comment_terminator", re.compile(r"(--|#|/\*)"), "MEDIUM"),
    ("sqli", "sqli_quote_injection", re.compile(r"['\"]\s*(OR|AND)\s*['\"]?\d"), "CRITICAL"),
    # 시간 지연 함수로 응답 시간을 재는 blind SQLi (조건식이 없어 위 규칙들을 다 피해감)
    ("sqli", "sqli_time_based_blind", re.compile(r"(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\("), "CRITICAL"),
    # 세미콜론으로 원래 쿼리를 끝내고 별도의 DDL/DML 쿼리를 이어붙이는 stacked query
    ("sqli", "sqli_stacked_query", re.compile(r"(?i);\s*(drop|insert|update|delete|alter|exec)\s+"), "CRITICAL"),
    # 스키마 정보를 탐색해서 테이블/컬럼명을 알아내려는 정찰 단계
    ("sqli", "sqli_information_schema_probe", re.compile(r"(?i)information_schema"), "MEDIUM"),
    # 따옴표 필터를 우회하려고 문자열 리터럴을 16진수로 인코딩하는 트릭 (예: 0x2774727565)
    ("sqli", "sqli_hex_encoded_literal", re.compile(r"(?i)=\s*0x[0-9a-f]{8,}"), "MEDIUM"),

    # --- XSS (담당: 심다움) ---
    ("xss", "xss_script_tag", re.compile(r"(?i)<script[^>]*>"), "CRITICAL"),
    ("xss", "xss_event_handler", re.compile(r"(?i)on(load|error|click|mouseover)\s*="), "MEDIUM"),
    ("xss", "xss_javascript_uri", re.compile(r"(?i)javascript:"), "MEDIUM"),
    ("xss", "xss_iframe_tag", re.compile(r"(?i)<iframe[^>]*>"), "MEDIUM"),
    # <script>/<iframe> 말고도 이벤트 핸들러를 실행시킬 수 있는 태그 전반
    # (<svg onload=...>, <body onload=...>, <img onerror=...> 등 필터 우회에 자주 쓰임)
    ("xss", "xss_dangerous_tag_with_handler", re.compile(r"(?i)<(svg|body|img|input|details|video|audio|marquee|object|embed)\b[^>]*\bon\w+\s*="), "CRITICAL"),
    # base64로 인코딩한 HTML/스크립트를 data URI로 실행시키는 패턴
    ("xss", "xss_data_uri_html", re.compile(r"(?i)data:text/html"), "MEDIUM"),
    # 옛 IE 계열 CSS expression() XSS (여전히 레거시 브라우저/렌더러 대상 테스트에 등장)
    ("xss", "xss_css_expression", re.compile(r"(?i)expression\s*\("), "MEDIUM"),

    # --- OS Command Injection (담당: 윤재영) ---
    ("os_command_injection", "cmd_chaining", re.compile(r"(?i)(;|\|\||&&)\s*(cat|ls|whoami|ping|curl|wget|nc|bash|sh|python[3]?|perl|id|uname|powershell)\b"), "CRITICAL"),
    ("os_command_injection", "cmd_pipe", re.compile(r"\|\s*\w+"), "MEDIUM"),
    # 백틱 / $() 명령어 치환 문법 — 파이프/세미콜론 필터링만 해서는 못 막는 우회 경로
    ("os_command_injection", "cmd_substitution", re.compile(r"`[^`]+`|\$\([^)]+\)"), "CRITICAL"),
    # ${IFS}로 공백을 대체해서 공백 기반 필터를 우회하는 전형적인 트릭
    ("os_command_injection", "cmd_ifs_obfuscation", re.compile(r"(?i)\$\{ifs\}"), "MEDIUM"),

    # --- Path Traversal (담당: 윤재영) ---
    ("path_traversal", "path_dot_dot_slash", re.compile(r"\.\./"), "CRITICAL"),
    ("path_traversal", "path_encoded_traversal", re.compile(r"(?i)%2e%2e%2f"), "CRITICAL"),
    # 윈도우 스타일 경로 구분자를 쓰는 변형
    ("path_traversal", "path_backslash_traversal", re.compile(r"\.\.\\"), "CRITICAL"),
    # 확장자 필터 뒤의 경로를 잘라내는 (구식 서버에서 여전히 유효한) NULL 바이트 트릭
    ("path_traversal", "path_null_byte_truncation", re.compile(r"(?i)%00"), "MEDIUM"),
    # UTF-8 overlong 인코딩으로 '.'/'/' 를 표현해 단순 디코더를 우회하는 시도
    ("path_traversal", "path_overlong_utf8_encoding", re.compile(r"(?i)%c0%ae|%e0%80%ae|%c0%af"), "MEDIUM"),

    # --- RFI (Remote File Inclusion) ---
    # page/file/include 같은 파라미터에 외부 URL을 실어 원격 악성 스크립트를 끌어오는 패턴.
    # 쿼리스트링(page=http://...)과 JSON body("page": "http://...") 형태를 모두 커버.
    ("rfi", "rfi_remote_url_parameter", re.compile(r'(?i)(page|file|include|template|doc|path)["\']?\s*[:=]\s*["\']?(https?|ftp)://'), "CRITICAL"),
    # PHP 등에서 로컬 필터 우회/원격 코드 실행에 쓰이는 스트림 래퍼
    ("rfi", "rfi_stream_wrapper", re.compile(r"(?i)(php|data|expect|phar|zip)://"), "CRITICAL"),

    # --- File Upload (Web Shell) ---
    # multipart body의 filename이 실행 가능한 확장자로 끝나는 경우 (BLOCKED_FILE_EXTENSIONS 재사용)
    ("file_upload", "file_upload_blocked_extension", re.compile(rf'(?i)filename\s*=\s*["\']?[^"\';\n]+\.({_BLOCKED_EXTENSIONS_PATTERN})\b'), "CRITICAL"),
    # 확장자 필터 우회에 쓰이는 이중 확장자 트릭 (예: shell.php.jpg)
    ("file_upload", "file_upload_double_extension", re.compile(r"(?i)filename\s*=\s*[\"']?[^\"';\n]+\.(php|jsp|asp|aspx)\.\w+"), "MEDIUM"),

    # --- SSTI (Server-Side Template Injection) ---
    # 파이썬 sandbox escape에 쓰이는 dunder 체인 (Jinja2 RCE payload 핵심 부분)
    ("ssti", "ssti_python_sandbox_escape", re.compile(r"__(class|globals|builtins|import|subclasses|mro|base)__"), "CRITICAL"),
    # Jinja2/Twig 표현식 안에서 서버 내부 객체(config, self, request 등)에 접근하려는 시도
    ("ssti", "ssti_jinja_object_access", re.compile(r"(?i)\{\{.*(config|self|request|lipsum|cycler|joiner|namespace)[^}]*\}\}"), "CRITICAL"),
    # Jinja2/Twig 표현식·구문 전반 ({{ ... }}, {% ... %}) — 일반 텍스트에서는 잘 안 나오는 조합
    ("ssti", "ssti_jinja_generic", re.compile(r"\{\{.*\}\}|\{%.*%\}"), "MEDIUM"),
    # Freemarker(<#assign>, #if(), ${...}) / Velocity(#set(), #foreach()) 계열
    ("ssti", "ssti_freemarker_velocity", re.compile(r"(?i)(<#(assign|if|list)\b|#(set|if|foreach)\s*\()"), "MEDIUM"),
    # Smarty 템플릿에서 PHP 코드를 직접 실행시키는 블록
    ("ssti", "ssti_smarty_php_block", re.compile(r"(?i)\{php\}"), "CRITICAL"),
    # Thymeleaf 인라인 표현식 전처리 문법 — 자바 클래스를 호출해 RCE로 이어지는 대표 payload
    ("ssti", "ssti_thymeleaf_expression", re.compile(r"(?i)__\$\{.*\}__|\bT\([\w.]+\)\s*\."), "CRITICAL"),

    # --- XXE (XML External Entity) ---
    ("xxe", "xxe_entity_system_or_public", re.compile(r"(?i)<!entity\s+\S+\s+(system|public)\b"), "CRITICAL"),
    # DOCTYPE에 내부 서브셋([...])을 선언하는 것 자체가 일반 REST API의 정상 XML에서는 드묾
    ("xxe", "xxe_doctype_internal_subset", re.compile(r"(?i)<!doctype\s+[^>]*\[", re.DOTALL), "CRITICAL"),
    # OOB(Out-of-band) XXE에 쓰이는 외부 DTD 참조
    ("xxe", "xxe_external_dtd_reference", re.compile(r'(?i)(system|public)\s+["\'](https?|file|ftp|jar|php):'), "CRITICAL"),
    # 파라미터 엔티티(%로 시작) — 응답에 안 보이는 blind XXE/OOB 유출에 주로 쓰는 고급 변형
    ("xxe", "xxe_parameter_entity", re.compile(r"(?i)<!entity\s+%\s+\S+\s+(system|public)\b"), "CRITICAL"),

    # --- SSRF (Server-Side Request Forgery) ---
    # url/target/callback 등의 파라미터가 내부망·클라우드 메타데이터 주소를 가리키는 패턴
    # "redirect"는 Open Redirect 쪽 용어라서 여기 키워드 목록에서 일부러 뺐다 —
    # 같이 넣으면 정상적인 리다이렉트 대상(예: 우리 프론트엔드 자체 주소)까지 SSRF로 오탐남.
    ("ssrf", "ssrf_internal_target", re.compile(r'(?i)(url|uri|target|dest|endpoint|callback|webhook)["\']?\s*[:=]\s*["\']?(https?://)?(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|\[::1\]|metadata\.google\.internal|100\.100\.100\.200)'), "CRITICAL"),
    # IP를 16진수 등으로 인코딩해서 필터를 우회하려는 시도 (예: http://0x7f000001/)
    ("ssrf", "ssrf_encoded_ip_bypass", re.compile(r"(?i)(url|uri|target|dest)[\"']?\s*[:=]\s*[\"']?https?://0x[0-9a-f]+"), "MEDIUM"),
    # IPv6 루프백 표기의 다양한 변형 (콜론이 URL 인코딩되어 오는 경우도 decoder가 풀어서 넘김)
    ("ssrf", "ssrf_ipv6_loopback_variant", re.compile(r"(?i)(\[::1\]|::ffff:127\.0\.0\.1|0:0:0:0:0:0:0:1)"), "CRITICAL"),
    # 임의 도메인을 내부 IP로 응답하게 만들어 화이트리스트 필터를 우회하는 DNS 리바인딩 서비스
    ("ssrf", "ssrf_dns_rebinding_service", re.compile(r"(?i)\.(nip|xip|sslip)\.io\b"), "MEDIUM"),

    # --- Insecure Deserialization ---
    # 자바 직렬화 객체 매직 바이트 (base64 "rO0..." / 헥사 "ACED0005")
    ("insecure_deserialization", "deser_java_magic_bytes", re.compile(r"(?i)(ro0ab|aced0005)"), "CRITICAL"),
    # PHP 객체 직렬화 포맷 (예: O:4:"User":2:{...})
    ("insecure_deserialization", "deser_php_object_injection", re.compile(r'(?i)o:\d+:"[a-z0-9_\\]+":\d+:\{'), "CRITICAL"),
    # .NET BinaryFormatter 직렬화 매직 헤더 (base64 "AAEAAAD...")
    ("insecure_deserialization", "deser_dotnet_binary_formatter", re.compile(r"(?i)aaeaaad"), "MEDIUM"),
    # 파이썬 pickle GLOBAL opcode 포맷 — "c<모듈>\n<이름>\n" 이 줄 단위로 나타나는 것 자체가
    # 정상 JSON/텍스트 바디에서는 나올 일이 거의 없는 강한 신호
    ("insecure_deserialization", "deser_python_pickle_global_opcode", re.compile(r"(?m)^c[\w.]+\n[\w.]+\n"), "CRITICAL"),
    # PyYAML의 안전하지 않은 로더(yaml.load)에서만 실행되는 파이썬 객체 태그
    ("insecure_deserialization", "deser_yaml_unsafe_tag", re.compile(r"(?i)!!python/(object|module|name)"), "CRITICAL"),

    # --- CRLF Injection ---
    # 디코딩된 CR/LF 뒤에 응답 헤더를 이어붙이려는 시도 (HTTP Response/Header Splitting).
    # content-type/content-length는 일부러 뺐다 — engine.py가 body_text와 headers_text를
    # 합쳐서 검사하는데, headers_text 자체가 "user-agent: ...\ncontent-type: ..."처럼
    # 실제 요청 헤더를 줄바꿈으로 이어붙인 문자열이라, Content-Type이 있는 평범한 POST
    # 요청마다 이 룰이 자기 자신(정상 헤더)에 걸려 전부 CRLF 공격으로 오탐났었다.
    # set-cookie/location 등은 클라이언트가 보내는 요청 헤더로는 등장하지 않는
    # "응답 전용" 헤더라서 이런 자기충돌이 없다.
    ("crlf_injection", "crlf_header_injection", re.compile(r"(?i)[\r\n]\s*(set-cookie|location|x-xss-protection|refresh|www-authenticate)\s*:"), "CRITICAL"),
    # 디코더를 우회해서 인코딩된 형태 그대로 들어온 경우에 대한 방어선
    ("crlf_injection", "crlf_encoded_sequence", re.compile(r"(?i)%0d%0a|%0d%0d|%0a%0a"), "MEDIUM"),

    # --- LDAP Injection ---
    # LDAP 필터 문법을 깨는 메타문자 조합 (예: *)(uid=*))(|(uid=*)
    ("ldap_injection", "ldap_filter_metacharacter_injection", re.compile(r"(\*\)\(|\)\(\||\(\|\(|\)\(&|\)\(!)"), "CRITICAL"),
    ("ldap_injection", "ldap_wildcard_field_injection", re.compile(r"(?i)(uid|cn|sn|mail|ou|dc)=\*"), "MEDIUM"),
    # 필터 전체를 항상 참으로 만들어 전체 디렉터리를 덤프시키는 대표적인 정찰 페이로드
    ("ldap_injection", "ldap_objectclass_probe", re.compile(r"(?i)\(objectclass=\*\)"), "MEDIUM"),

    # --- XPath Injection ---
    # 참고: '따옴표 or 1=1' 형태 페이로드는 SQLi 룰과 문법이 겹쳐서 앞쪽의 sqli 룰에 먼저 걸릴 수 있음
    # (실제 WAF들도 겪는 흔한 애매함 — 여기서는 XPath 전용 문법(축 이동, 서술절 탈출)으로 보강)
    ("xpath_injection", "xpath_predicate_breakout", re.compile(r"(?i)['\"]\s*\]\s*\|\s*//|//\*\[|\bnode\(\)"), "MEDIUM"),
    ("xpath_injection", "xpath_function_probe", re.compile(r"(?i)\b(substring|concat|string-length|count)\([^)]*\)\s*="), "MEDIUM"),
    # document()/doc() 함수로 서버의 다른 XML/파일을 읽어들이는 XXE 유사 트릭
    ("xpath_injection", "xpath_external_document_probe", re.compile(r"(?i)\bdoc(ument)?\s*\("), "MEDIUM"),

    # JWT alg:none 위조는 base64 디코딩이 필요해서 app/detection/engine.py의
    # _check_jwt_alg_none()에서 별도 처리함 (담당: 이용욱 - PoC 검증 완료)
    #
    # CSRF는 정규식이 아니라 "상태변경 요청 + 세션 쿠키 있음 + Origin/Referer 전부 없음"이라는
    # 구조적 조건이라 engine.py의 _check_csrf_risk()에서 별도 처리함.
    #
    # Open Redirect는 "외부 도메인이면 무조건 의심"이 아니라 settings.allowed_origins /
    # target_service_url 화이트리스트와 실제로 비교해야 오탐이 안 나서
    # engine.py의 _check_open_redirect()에서 별도 처리함.
    #
    # XXE 엔티티 폭탄(billion laughs)은 패턴 매칭이 아니라 "<!ENTITY 선언이 비정상적으로
    # 많다"는 횟수 기반 판단이 필요해서 engine.py의 _check_xxe_entity_bomb()에서 처리함.
    #
    # CORS 악용은 Origin 헤더를 화이트리스트와 비교해야 해서 app/middleware/gateway.py의
    # check_cors_violation()에서 처리하고, 브루트포스는 시간창 기반 카운팅이 필요해서
    # 같은 파일의 record_login_failure_by_*() / record_system_wide_login_failure()에서 처리함.
    # HPP는 쿼리 파라미터의 "같은 이름이 여러 번 오는" 구조를 봐야 해서 app/proxy/proxy.py에서
    # 처리함 (정규식으로 표현하기 어려운 axis).
]
