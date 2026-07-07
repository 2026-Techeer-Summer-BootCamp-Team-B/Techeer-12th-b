from fastapi import APIRouter, Request
from datetime import datetime
import uuid

from app.models.schemas import AttackLog, AttackType, RiskLevel
from app.storage.log_store import add_log

from app.api.ws import manager

router = APIRouter(tags=["Falco Alerts"])

# Falco 룰 이름에 등장하는 키워드로 AttackType과 MITRE ATT&CK 테크닉 ID를 함께 추정한다.
# 위에서부터 순서대로 검사해서 먼저 매칭되는 항목을 사용하므로,
# 더 구체적인 키워드를 일반적인 키워드보다 앞에 배치해야 한다.
# (Falco 기본 룰셋: https://github.com/falcosecurity/rules 의 falco_rules.yaml 기준 룰 이름들을 참고해 매핑)
_FALCO_RULE_MAPPINGS: list[tuple[list[str], AttackType, str]] = [
    # 자격증명 탈취 -> Unsecured Credentials
    (["private key", "password", "credential", "secret"], AttackType.JWT_FORGERY, "T1552"),
    # 민감 파일/디렉토리 열람 -> File and Directory Discovery
    (["sensitive file", "read sensitive", "directory traversal", "path traversal"], AttackType.PATH_TRAVERSAL, "T1083"),
    # 시스템 파일 변조 -> File and Directory Permissions Modification
    (["write below etc", "write below binary", "write below root", "unexpected write"], AttackType.PATH_TRAVERSAL, "T1222"),
    # 비인가 외부/제어plane 통신 -> Application Layer Protocol (C2 통신)
    (["contact k8s api server", "outbound connection", "unexpected network", "connection to c2"], AttackType.SSRF, "T1071"),
    # 원격 페이로드 다운로드/실행 -> Ingress Tool Transfer
    (["drop and execute", "download and execute", "new binary in container"], AttackType.RFI, "T1105"),
    # 정찰용 네트워크 도구 실행 -> Network Service Discovery
    (["network tool", "nmap", "packet socket"], AttackType.OS_COMMAND_INJECTION, "T1046"),
    # 권한 상승/컨테이너 탈출 -> Escape to Host
    (["privilege escalation", "setuid", "container escape", "sudo"], AttackType.OS_COMMAND_INJECTION, "T1611"),
    # 쉘 실행 -> Command and Scripting Interpreter
    (["terminal shell", "shell in container", "shell spawned", "non shell process"], AttackType.OS_COMMAND_INJECTION, "T1059"),
]

# 매칭되는 키워드가 없을 때의 기본값 (Command and Scripting Interpreter) — 기본 AttackType인
# OS_COMMAND_INJECTION과 실제로 짝이 맞는 테크닉으로 맞춰둔다.
_DEFAULT_ATTACK_TYPE = AttackType.OS_COMMAND_INJECTION
_DEFAULT_MITRE_TECHNIQUE_ID = "T1059"


def _infer_falco_mapping(rule_name: str) -> tuple[AttackType, str]:
    """Falco 룰 이름 키워드로 가장 그럴듯한 (AttackType, MITRE 테크닉 ID) 조합을 추정."""
    rule_lower = rule_name.lower()
    for keywords, attack_type, mitre_technique_id in _FALCO_RULE_MAPPINGS:
        if any(keyword in rule_lower for keyword in keywords):
            return attack_type, mitre_technique_id
    return _DEFAULT_ATTACK_TYPE, _DEFAULT_MITRE_TECHNIQUE_ID


@router.post("")
@router.post("/")
async def receive_falco_alert(request: Request):
    """
    Falco 런타임 위협 탐지 로그를 수신하여,
    로그 마스터의 표준 'AttackLog' 포맷으로 파싱 및 변환 후 저장합니다.
    """
    try:
        falco_raw = await request.json()
        
        # 1. Falco 내부 컨텍스트 데이터 추출
        output_fields = falco_raw.get("output_fields", {})
        rule_name = falco_raw.get("rule", "Unknown Falco Rule")
        priority = falco_raw.get("priority", "Notice")
        
        # 2. Falco 심각도를 프로젝트의 RiskLevel(LOW, MEDIUM, CRITICAL)로 매핑
        risk_level = RiskLevel.LOW
        if priority in ["Emergency", "Alert", "Critical"]:
            risk_level = RiskLevel.CRITICAL
        elif priority in ["Error", "Warning"]:
            risk_level = RiskLevel.MEDIUM

        # 3. Falco 룰 특징에 맞춰 가장 적절한 AttackType과 MITRE 테크닉 ID를 함께 동적 매핑
        attack_type, mitre_technique_id = _infer_falco_mapping(rule_name)

        # 4. 규격화된 AttackLog 인스턴스 빌드
        attack_log = AttackLog(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            # 수신한 Pod 이름이 있다면 할당, 없으면 컨테이너 ID나 K8s-Host 처리
            source_ip=output_fields.get("k8s.pod.name", output_fields.get("container.id", "K8s-Host")),
            attack_type=attack_type,
            target_endpoint=output_fields.get("fd.name", "System Call / Host-Space"),
            http_method="EXEC",  # 커널 레벨 시스템 콜 추적임을 명시
            payload_snippet=falco_raw.get("output", "No output text")[:200],  # 200자 제한 방어
            user_agent=f"Falco Agent (proc: {output_fields.get('proc.name', 'Unknown')})",
            matched_rule_id=rule_name,
            blocked=False,  # Falco는 기본적으로 차단(Inline Block)이 아닌 탐지 모드이므로 False
            target_name=output_fields.get("container.image.repository", "Host Machine"),
            mitre_technique_id=mitre_technique_id,
            risk_level=risk_level
        )
        
        # 5. log_store.get_logs가 조회하는 것과 동일한 인덱스(ATTACK_LOG_INDEX)에 저장.
        # (예전엔 es_client.index(index="attack-logs", ...)를 직접 호출해서 실제 조회
        # 인덱스인 "attack_logs"와 이름이 어긋나 새로고침 시 로그가 사라졌었다.)
        add_log(attack_log)

        # [파이프라인 2] 실시간 웹소켓 브로드캐스트 (화면에 실시간으로 팝업/로그 뜸)
        # 프론트(SecurityDashboard.jsx)는 app/proxy/proxy.py가 보내는 {"event", "data"} 형태를
        # 기대한다. 여기서 log_dict를 그대로(래핑 없이) 보내면 payload.data가 없어서
        # 프론트가 조용히 무시해버리므로 반드시 동일한 포맷으로 맞춰야 한다.
        # data는 model_dump(mode="json")으로 datetime을 문자열로 직렬화해야
        # WebSocket.send_json()이 던지는 TypeError(및 manager.broadcast의 조용한 연결 드랍)를 피할 수 있다.
        if hasattr(manager, "broadcast"):
            event_type = "critical_alert" if attack_log.risk_level == RiskLevel.CRITICAL else "attack_detected"
            await manager.broadcast({"event": event_type, "data": attack_log.model_dump(mode="json")})
        
        print(f"🚨 [프론트 송신 완료] 대시보드로 실시간 알림을 전송했습니다.")
        return {"status": "success", "message": "Falco alert standardized, stored, and broadcasted"}
        
    except Exception as e:
        print(f"❌ [Falco 매핑/송신 에러] {str(e)}")
        return {"status": "error", "message": str(e)}