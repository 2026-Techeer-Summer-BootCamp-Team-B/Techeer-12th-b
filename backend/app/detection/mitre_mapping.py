"""
담당: 이용욱 (게이트웨이) — MITRE ATT&CK 매핑

탐지된 AttackType 각각을 MITRE ATT&CK(Enterprise Matrix)의 전술(Tactic)/기법(Technique)에
연결해서, 대시보드에서 "우리가 탐지한 공격이 업계 표준 프레임워크의 어디에 해당하는지"
보여주기 위한 매핑 테이블.

주의 — 매핑의 한계:
ATT&CK은 웹 애플리케이션 취약점 전용 프레임워크가 아니라, 공격자의 전체 침투
생명주기(정찰~데이터유출)를 다루는 범용 프레임워크다. 그래서 SQLi, XSS 같은
"OWASP식 취약점 분류"와 1:1로 안 맞아떨어지는 경우가 많다.
HPP, CRLF Injection처럼 전용 기법 번호가 없는 경우는 가장 근접한 상위 기법으로
근사(approximate) 매핑했다 — is_exact_match=False로 표시해뒀으니 발표 자료에는
"근사 매핑"이라고 명시할 것.

참고: https://attack.mitre.org/matrices/enterprise/
"""
from typing import Optional, TypedDict

from app.models.schemas import AttackType


class MitreMapping(TypedDict):
    tactic: str            # ATT&CK 전술 이름
    technique_id: str      # 예: "T1190"
    technique_name: str
    is_exact_match: bool   # False면 "가장 가까운 근사치" 매핑이라는 뜻


ATTACK_TYPE_TO_MITRE: dict[AttackType, MitreMapping] = {
    AttackType.SQLI: {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "is_exact_match": True,
    },
    AttackType.XSS: {
        "tactic": "Initial Access",
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "is_exact_match": False,  # XSS 자체 전용 기법은 없고, "방문자 브라우저에서 코드 실행"이라는 결과가 유사
    },
    AttackType.OS_COMMAND_INJECTION: {
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "is_exact_match": True,
    },
    AttackType.PATH_TRAVERSAL: {
        "tactic": "Collection",
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "is_exact_match": False,  # 취약점 유형 자체보다 "결과적으로 로컬 파일을 읽어간다"는 점에서 근사
    },
    AttackType.RFI: {
        "tactic": "Command and Control",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "is_exact_match": False,  # 외부 악성 코드를 서버로 끌어온다는 점에서 근사
    },
    AttackType.FILE_UPLOAD: {
        "tactic": "Persistence",
        "technique_id": "T1505.003",
        "technique_name": "Server Software Component: Web Shell",
        "is_exact_match": True,
    },
    AttackType.SSTI: {
        "tactic": "Execution",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "is_exact_match": False,  # 템플릿 엔진 악용 자체 전용 번호는 없어 상위 기법 사용
    },
    AttackType.XXE: {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "is_exact_match": False,
    },
    AttackType.SSRF: {
        "tactic": "Command and Control",
        "technique_id": "T1090",
        "technique_name": "Proxy",
        "is_exact_match": False,  # "서버를 대리인으로 악용"한다는 개념적 유사성
    },
    AttackType.HPP: {
        "tactic": "Defense Evasion",
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "is_exact_match": False,  # 전용 기법 없음 — "탐지 로직을 헷갈리게 한다"는 점에서 근사
    },
    AttackType.CSRF: {
        "tactic": "Initial Access",
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "is_exact_match": False,  # 피해자가 모르게 요청을 실행시킨다는 점에서 근사
    },
    AttackType.NOSQLI: {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "is_exact_match": True,  # SQLi와 동일 계열(인젝션)이라 같은 기법으로 분류됨
    },
    AttackType.INSECURE_DESERIALIZATION: {
        "tactic": "Initial Access",
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "is_exact_match": False,
    },
    AttackType.OPEN_REDIRECT: {
        "tactic": "Initial Access",
        "technique_id": "T1566.002",
        "technique_name": "Phishing: Spearphishing Link",
        "is_exact_match": False,  # 주로 피싱의 보조 수단으로 악용된다는 점에서 근사
    },
    AttackType.CRLF_INJECTION: {
        "tactic": "Defense Evasion",
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "is_exact_match": False,  # 전용 기법 없음
    },
    AttackType.LDAP_INJECTION: {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "is_exact_match": True,
    },
    AttackType.XPATH_INJECTION: {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "is_exact_match": True,
    },
    AttackType.CORS_ABUSE: {
        "tactic": "Collection",
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "is_exact_match": False,  # 정확 일치 기법 없음 — "허가 안 된 출처의 데이터 수집" 개념으로 근사
    },
    AttackType.JWT_FORGERY: {
        "tactic": "Defense Evasion / Credential Access",
        "technique_id": "T1550.001",
        "technique_name": "Use Alternate Authentication Material: Application Access Token",
        "is_exact_match": True,
    },
    AttackType.BRUTE_FORCE: {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "is_exact_match": True,
    },
}


def get_mitre_mapping(attack_type: AttackType) -> Optional[MitreMapping]:
    """대시보드/API에서 특정 AttackType의 ATT&CK 정보를 조회할 때 사용."""
    return ATTACK_TYPE_TO_MITRE.get(attack_type)