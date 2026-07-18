"""
IDS-COLLECTOR/servers/correlation-engine/app/scenarios/*.yaml의 S1~S51 상관분석
시나리오를 실제로 발화시키는 레시피 모음. 각 레시피는 로그 문자열을 하나씩 yield하는
제너레이터라 프론트엔드(dummy_ui)가 "지금 뭘 하고 있는지"를 실시간으로 보여줄 수 있다.

각 시나리오의 stage1/stage2, join_on, window_seconds 등 판정 조건의 근거는 해당 yaml
파일 자체의 주석을 참고할 것 - 여기서는 그 조건을 만족시키는 "실제 행동"만 수행한다
(가짜 로그 주입이 아니라 진짜 K8s API 호출/HTTP 요청/exec).

같은 K8s 신원(현재 kubeconfig 컨텍스트)으로 모든 K8s API 호출을 하기 때문에
join_on=user_or_sa(같은 user/SA가 했는지로 묶는 시나리오)는 별道 처리 없이 자동으로
만족된다. join_on=pod 시나리오(S1)는 이 스크립트가 직접 만든 pod 하나에 stage1/2를
모두 몰아서 확실하게 매칭시킨다.

S19(로그인 브루트포스, WAS 원본 access log)는 waf_actions.py의 `/proxy` 경유가 아니라
was_actions.py로 Juice Shop에 직접 요청을 보낸다 - 그래야 WAF 계층과 독립적인 이
시나리오의 취지가 산다(해당 파일 docstring 참고). S22/S23(falco, join_on=pod)은
k8s_actions.py에 저수준 헬퍼가 없다 - S1처럼 sleep pod 하나를 만들어 그 안에서
exec으로 falco 룰 조건을 직접 재현한다(각 함수 docstring 참고).

2026-07-18: correlation-engine이 falcosecurity/rules 공식 falco_rules.yaml을
WebFetch로 재확인해서 추가한 S26~S51(26개)을 이 파일에도 추가했다. join_on=pod인
falco 전용 시나리오(S32/S34~S51 중 falco 것들)는 S22/S23과 같은 패턴(_run_pod_falco_
scenario 공용 헬퍼로 통합 - 개수가 많아 매번 손으로 반복하면 실수하기 쉬움)을 쓰고,
각 명령어가 실제로 그 falco 룰을 발화시키는지는 이 파일을 작성하면서 실제 k3d
클러스터(falco 파드 로그 tail)로 하나씩 직접 검증했다 - 아래 목록은 전부 실측 확인됨
(2026-07-18):
  S32(Redirect STDOUT/STDIN), S34(Drop and execute), S35(Netcat RCE),
  S36(memfd_create), S37(Remove Bulk Data), S38(Find AWS Credentials),
  S39(Search Private Keys), S40(PTRACE attached), S41(/dev/shm 실행),
  S44(PTRACE anti-debug), S45(민감파일 열람), S46(하드링크), S47(심링크),
  S49(경로 탐색 열람).
S36/S40/S44는 memfd_create/ptrace가 POSIX 셸 빌트인이 아니라 libc 직접 호출이
필요해서 busybox가 아니라 k8s_actions.PYTHON_IMAGE(python:3-alpine, ctypes로 libc
호출) pod를 쓴다.

S42(비표준 포트 SSH 연결)/S43(시스템 계정 인터랙티브 셸)/S48(신뢰된 프로세스의 뒤늦은
민감파일 열람)은 검토 결과 이 테스트 환경에서 재현이 사실상 불가능해 best-effort로
스킵하고 이유를 그대로 보고한다(S5/S9와 같은 정직성 원칙 - 안 되는 걸 되는 척 꾸미지
않는다):
  - S42는 falco_rules.yaml 조건이 `proc.exe endswith ssh`인 실제 ssh 클라이언트
    바이너리의 outbound connect를 요구하는데, busybox에는 ssh 클라이언트가 없고
    임의 이름의 symlink/스크립트로는 proc.exe가 "ssh"로 안 끝나서 우회 불가.
  - S43은 `interactive` 매크로가 sshd/systemd-logind/login 조상 프로세스를 요구하는데
    (실제 SSH 세션이 있어야 함) 이 pod들엔 sshd 자체가 없다.
  - S48은 `server_procs`(http_server_binaries/db_server_binaries/docker_binaries/
    sshd)이면서 proc_is_new가 아닌(5초 이상 산 프로세스) 조건인데, busybox 이미지에는
    그 목록에 해당하는 실제 서버 바이너리가 없다.
"""
import base64
import time
from typing import Callable, Dict, Iterator, List, Optional

import k8s_actions as k8s
import waf_actions as waf
import was_actions as was

_JUICE_SHOP_HARDCODED_POD = "juice-shop-68ccbc74b4-xh7r8"  # normalizer/app/enrichment.py의 _TARGET_POD_NAME


def _step(label: str, fn: Callable[[], None]) -> Iterator[str]:
    """한 액션(라벨+실행+결과)을 한 줄로 yield한다 - 프론트엔드가 이 한 줄을
    "실제 로그가 있는 카드" 하나로 그대로 보여준다(진행중/결과 두 줄로 쪼개면
    카드 하나에 대응이 안 됨)."""
    try:
        fn()
        yield f"  - {label} -> OK"
    except Exception as e:
        yield f"  - {label} -> 실패: {e}"


def _exec_many(
    namespace: str, pod_name: str, commands: List[str], label: str, container: Optional[str] = None
) -> Iterator[str]:
    """pod 하나에 여러 명령을 순서대로 exec - falco 룰(예: "Terminal shell in
    container"는 tty가 있어야 잡히는 등 조건이 까다로워 명령 하나만으로는 stage2가
    안 걸릴 수 있다)이나 탐지 시그니처를 하나만 시도하면 못 뚫을 수 있어서, 여러
    변형을 한 번에 다 시도해 그중 하나라도 매칭될 확률을 올린다.

    container는 컨테이너가 2개 이상인 pod(S5의 실제 Juice Shop pod = juice-shop +
    nginx-was-logger)에서 반드시 지정해야 한다 - 안 그러면 kube-apiserver가 400
    "a container name must be specified"로 거부하고, 그 에러를 감싸는 과정에서
    kubernetes-client 자체 버그로 'NoneType' object has no attribute 'decode'라는
    엉뚱한 메시지만 보이게 된다(k8s_actions.exec_in_pod docstring 참고, 실측 확인
    2026-07-15). 이 스크립트가 직접 만드는 단일 컨테이너 sleep pod(S1/S3/S22/S23)는
    생략해도 kube-apiserver가 그 하나뿐인 컨테이너로 자동 선택한다."""
    for idx, cmd in enumerate(commands, 1):
        try:
            out = k8s.exec_in_pod(namespace, pod_name, ["sh", "-c", cmd], container=container)
            yield f"  - {label} {idx}/{len(commands)}: {cmd} -> OK ({out.strip()[:80]})"
        except Exception as e:
            yield f"  - {label} {idx}/{len(commands)}: {cmd} -> 실패: {e}"
        time.sleep(1)


def _pipe_python(script: str) -> str:
    """파이썬 스크립트를 base64로 인코딩해서 `echo ... | base64 -d | python3`로
    표준입력에 흘려보내는 셸 명령 문자열을 만든다(S36/S40/S44 재료) - 여러 줄 스크립트를
    `sh -c` 인자 하나에 그대로 끼워 넣으면 따옴표/개행 이스케이프가 꼬이기 쉬운데,
    base64 인코딩으로 그 문제 자체를 없앤다. k8s_actions.PYTHON_IMAGE(python:3-alpine)
    pod에서만 쓴다 - alpine의 base64(busybox 계열)/python3 둘 다 이미지에 포함돼 있다."""
    encoded = base64.b64encode(script.encode()).decode()
    return f"echo {encoded} | base64 -d | python3"


def _run_pod_falco_scenario(
    prefix: str, commands: List[str], image: str = k8s.BUSYBOX_IMAGE, sleep_seconds: int = 60
) -> Iterator[str]:
    """join_on=pod, threshold=1인 falco 전용 시나리오(S22/S23이 먼저 쓰던 패턴을
    S32/S34~S51에서 재사용할 수 있게 공용화, 2026-07-18) - 자체 pod를 하나 만들어
    그 안에서 명령을 실행한다. pod 이름 자체가 correlation_key_value
    (orchestrator.resource.name)가 되므로 join이 항상 이 pod 하나로 확실히 매칭된다.
    각 명령이 실제로 의도한 falco 룰을 발화시키는지는 이 파일 작성 중 실제 k3d
    클러스터(falco 파드 로그)로 실측 검증했다(모듈 docstring 참고)."""
    k8s.ensure_namespace()
    name = f"dummy-{prefix}-{k8s.short_id()}"
    yield from _step(
        f"pod {name} 생성(sleep {sleep_seconds}s, image={image})",
        lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, name, sleep_seconds, image=image),
    )
    try:
        k8s.wait_pod_running(k8s.DUMMY_NAMESPACE, name)
        yield "  - pod Running 대기 -> OK"
        yield from _exec_many(k8s.DUMMY_NAMESPACE, name, commands, "시도")
    except Exception as e:
        yield f"  - pod Running 대기 -> 실패: {e} (exec 스킵)"
    yield from _step(f"pod {name} 정리", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, name))


_S1_EXEC_COMMANDS = [
    "id && whoami",
    "wget -qO- --no-check-certificate https://kubernetes.default.svc/version || true",
    "cat /etc/shadow 2>/dev/null || echo no-shadow",
    "ps aux || ps",
]


def _run_s1() -> Iterator[str]:
    """S1: k8s_audit(pods/exec) -> falco(컨테이너 내 쉘 실행/K8s API 접근) 시퀀스, join=pod.
    자체 pod를 하나 만들어서 그 안에서 exec으로 stage1(exec 감사로그)과 stage2(falco
    탐지)를 동시에 만족시킨다 - 두 신호가 반드시 같은 pod에서 나오게 되므로
    join_on=pod가 확실히 매칭된다. stage2가 매칭하는 falco 액션은 "Terminal shell in
    container"/"Contact K8s API Server From Container" 둘 중 하나인데, 명령 하나만
    실행하면 falco 룰 조건(tty 여부 등)에 따라 안 걸릴 수 있어서 여러 명령을
    순서대로 다 실행해 그중 하나라도 매칭될 확률을 올린다(_S1_EXEC_COMMANDS)."""
    k8s.ensure_namespace()
    name = f"dummy-s1-{k8s.short_id()}"
    yield from _step(f"pod {name} 생성(sleep 120s)", lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, name, 120))
    try:
        k8s.wait_pod_running(k8s.DUMMY_NAMESPACE, name)
        yield "  - pod Running 대기 -> OK"
    except Exception as e:
        yield f"  - pod Running 대기 -> 실패: {e} (exec 스킵)"
        yield from _step(f"pod {name} 정리", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, name))
        return
    yield "  - pod exec으로 여러 명령 실행(create pods/exec 감사 + falco 쉘/API접근 탐지 노려봄)"
    yield from _exec_many(k8s.DUMMY_NAMESPACE, name, _S1_EXEC_COMMANDS, "시도")
    yield from _step(f"pod {name} 정리", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, name))


def _run_s2() -> Iterator[str]:
    """S2: k8s_audit(get/list secrets) -> k8s_audit(delete pods/deployments), join=user_or_sa."""
    k8s.ensure_namespace()
    secret_name = f"dummy-secret-{k8s.short_id()}"
    pod_name = f"dummy-s2-{k8s.short_id()}"
    yield from _step(
        f"시크릿 {secret_name} 생성", lambda: k8s.create_secret(k8s.DUMMY_NAMESPACE, secret_name, {"password": "hunter2"})
    )
    yield from _step(f"pod {pod_name} 생성(정리 대상)", lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, pod_name, 30))
    yield from _step("stage1: 시크릿 조회(get secrets)", lambda: k8s.get_secret(k8s.DUMMY_NAMESPACE, secret_name))
    time.sleep(2)
    yield from _step("stage2: pod 삭제(delete pods, 흔적 인멸 흉내)", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, pod_name))
    yield from _step(f"시크릿 {secret_name} 정리", lambda: k8s.delete_secret(k8s.DUMMY_NAMESPACE, secret_name))


_S3_EXEC_COMMANDS = ["id", "whoami && hostname"]


def _run_s3() -> Iterator[str]:
    """S3: k8s_audit(RBAC 객체 변경) -> k8s_audit(pod exec), join=user_or_sa.
    stage2는 verb(create/get pods/exec|attach) 매칭이라 명령 내용과 무관하게 exec
    한 번으로도 걸리지만, 여러 명령을 실행해 로그 자체는 더 다양하게 남긴다."""
    k8s.ensure_namespace()
    role_name = f"dummy-test-role-{k8s.short_id()}"
    pod_name = f"dummy-s3-{k8s.short_id()}"
    yield from _step(
        "stage1: ClusterRole 생성(RBAC 변경)",
        lambda: k8s.create_clusterrole(role_name, [{"api_groups": [""], "resources": ["pods"], "verbs": ["get"]}]),
    )
    time.sleep(2)
    yield from _step(f"pod {pod_name} 생성", lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, pod_name, 30))
    try:
        k8s.wait_pod_running(k8s.DUMMY_NAMESPACE, pod_name)
        yield "  - stage2: pod exec 여러 번(권한상승 이후 실제 사용 흉내)"
        yield from _exec_many(k8s.DUMMY_NAMESPACE, pod_name, _S3_EXEC_COMMANDS, "시도")
    except Exception as e:
        yield f"    pod 대기 실패, stage2 스킵: {e}"
    yield from _step(f"pod {pod_name} 정리", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, pod_name))
    yield from _step(f"ClusterRole {role_name} 정리", lambda: k8s.delete_clusterrole(role_name))


def _run_s4() -> Iterator[str]:
    """S4: 같은 IP에서 60초 안에 WAF 이벤트 5건 이상 (threshold)."""
    yield "  - WAF CRITICAL 공격 6건 연속 전송 (같은 소스 IP)"
    for line in waf.send_waf_burst(6):
        yield f"    {line}"


_S5_EXEC_COMMANDS = [
    "wget -qO- --no-check-certificate https://kubernetes.default.svc/version || true",
    "wget -qO- --no-check-certificate https://kubernetes.default.svc/api || true",
    "id && whoami",
]


def _run_s5() -> Iterator[str]:
    """S5: WAF CRITICAL(min_severity=4) -> falco(쉘/K8s API 접근), join=pod.
    주의 1: enrichment.py가 WAF 이벤트의 pod 이름을 하드코딩(_TARGET_POD_NAME)해서 채우므로,
    실제 Juice Shop pod 이름과 다르면 join이 안 맞아 인시던트가 안 뜰 수 있다 - 실행 전에
    실제 pod 이름을 조회해서 다르면 경고한다(IDS-COLLECTOR 쪽 코드 수정 필요).

    주의 2(실측 확인, 2026-07-15): 배포된 공식 Juice Shop 이미지(bkimminich/juice-shop)의
    juice-shop 컨테이너는 distroless라 쉘 자체가 없다(/bin/sh, /bin/bash 전부 없음,
    /nodejs/bin/node는 있지만 PATH에는 없음) - 그래서 stage2의 `sh -c "..."` exec는
    OK로 찍혀도 항상 빈 출력만 나오고(exec 자체가 시작을 못 해서), Falco의 "Terminal
    shell in container"/"Contact K8S API Server From Container"는 실제로는 안 걸린다.
    exec_in_pod() 자체는 정상 동작한다(k8s_actions.py의 container 파라미터 참고,
    S1처럼 이 스크립트가 직접 만드는 busybox 기반 sleep pod에는 쉘이 있어서 문제없음) -
    이건 순수히 이 특정 타깃 이미지의 특성이다. stage2를 실제로 재현하려면 Target
    저장소 쪽에서 셸이 있는 이미지로 바꾸거나, `kubectl debug`(ephemeral container,
    busybox 등 셸 있는 이미지를 같은 pod에 붙임)로 우회해야 한다 - 이 스크립트가
    당장 시도하지는 않음."""
    real_pod = None
    try:
        real_pod = k8s.find_juice_shop_pod()
    except Exception as e:
        yield f"  - Juice Shop pod 조회 실패: {e}"

    if real_pod is None:
        yield "  - Juice Shop pod을 못 찾음 (default 네임스페이스에 app=juice-shop 라벨 pod 필요) - stage2 스킵"
    elif real_pod != _JUICE_SHOP_HARDCODED_POD:
        yield (
            f"  - 경고: 실제 Juice Shop pod 이름({real_pod})이 IDS-COLLECTOR의 "
            f"normalizer/app/enrichment.py에 하드코딩된 값({_JUICE_SHOP_HARDCODED_POD})과 다름 - "
            f"WAF 이벤트와 falco 이벤트의 orchestrator.resource.name이 어긋나서 이 시나리오는 "
            f"상관분석 엔진에서 매칭되지 않을 수 있습니다(_TARGET_POD_NAME을 실제 값으로 갱신 필요)."
        )

    yield "  - stage1: WAF CRITICAL 공격 여러 건 연속 전송(공격 유형을 섞어서 시그니처 매칭 확률을 올림)"
    for _ in range(3):
        yield f"    {waf.send_random_critical_attack()}"
    time.sleep(2)

    if real_pod:
        yield "  - stage2: 해당 pod에서 K8s API 서버 접근/쉘 실행을 여러 방식으로 시도(falco 'Terminal shell in container'/'Contact K8s API Server From Container' 노려봄)"
        yield from _exec_many("default", real_pod, _S5_EXEC_COMMANDS, "시도", container="juice-shop")


def _run_s6() -> Iterator[str]:
    """S6: kube-public에 서비스어카운트 생성 (threshold=1). kube-system 대신 kube-public 사용
    (시스템 네임스페이스 조건은 둘 다 만족하지만 kube-public이 더 안전)."""
    name = f"dummy-test-sa-{k8s.short_id()}"
    yield from _step(f"kube-public에 ServiceAccount {name} 생성", lambda: k8s.create_service_account("kube-public", name))
    yield from _step(f"{name} 정리", lambda: k8s.delete_service_account("kube-public", name))


def _run_s7() -> Iterator[str]:
    """S7: SA 생성 -> 즉시 RBAC 바인딩 부여, join=user_or_sa."""
    k8s.ensure_namespace()
    sa_name = f"dummy-test-sa2-{k8s.short_id()}"
    binding_name = f"dummy-test-binding-{k8s.short_id()}"
    yield from _step(f"stage1: ServiceAccount {sa_name} 생성", lambda: k8s.create_service_account(k8s.DUMMY_NAMESPACE, sa_name))
    time.sleep(2)
    yield from _step(
        "stage2: ClusterRoleBinding으로 view 권한 즉시 부여",
        lambda: k8s.create_clusterrolebinding(binding_name, k8s.DUMMY_NAMESPACE, sa_name, "view"),
    )
    yield from _step(f"{binding_name} 정리", lambda: k8s.delete_clusterrolebinding(binding_name))
    yield from _step(f"{sa_name} 정리", lambda: k8s.delete_service_account(k8s.DUMMY_NAMESPACE, sa_name))


def _run_s8() -> Iterator[str]:
    """S8: 네임스페이스 삭제 (threshold=1). 기존 네임스페이스가 아니라 방금 만든
    일회용 네임스페이스만 지운다."""
    ns_name = f"dummy-test-ns-{k8s.short_id()}"
    yield from _step(f"일회용 네임스페이스 {ns_name} 생성", lambda: k8s.create_namespace(ns_name))
    time.sleep(1)
    yield from _step(f"{ns_name} 삭제(그 네임스페이스 자체가 감사 대상)", lambda: k8s.delete_namespace(ns_name))


_S9_ANONYMOUS_TARGETS = [
    ("pods", "/api/v1/namespaces/default/pods"),
    ("secrets", "/api/v1/namespaces/default/secrets"),
    ("configmaps", "/api/v1/namespaces/default/configmaps"),
    ("nodes(cluster 범위)", "/api/v1/nodes"),
]


def _run_s9() -> Iterator[str]:
    """S9: system:anonymous 요청이 실제로 성공하면 발화 (threshold=1). 클러스터 RBAC이
    익명 접근을 막고 있으면 정상적으로 실패한다 - 강제로 뚫으려 하지 않고 결과만 보고.
    리소스 종류별로 RBAC이 부분적으로만 열려있는 경우(예: pods는 막았는데 nodes는
    깜빡 열어둔 미스컨피그)가 흔해서, 여러 리소스를 돌아가며 시도해 하나라도 뚫릴
    확률을 올린다(_S9_ANONYMOUS_TARGETS)."""
    yield "  - 익명(무인증) 요청으로 여러 리소스 조회 시도 (하나라도 성공하면 발화)"
    any_success = False
    for label, path in _S9_ANONYMOUS_TARGETS:
        ok, detail = k8s.try_anonymous_request(path)
        if ok:
            any_success = True
            yield f"    {label}: 성공({detail}) - 클러스터가 익명 접근을 허용하고 있음(RBAC 점검 필요)"
        else:
            yield f"    {label}: 차단됨({detail})"
    if not any_success:
        yield "  - 전부 차단됨 - 정상 (클러스터 RBAC이 익명 접근을 막고 있어 이 시나리오는 발화하지 않음)"


def _run_s10() -> Iterator[str]:
    """S10: 60초 안에 get/list/watch 30회 이상 (threshold)."""
    k8s.ensure_namespace()
    try:
        k8s.burst_list_pods("default", 32)
        yield "  - default 네임스페이스에 pod 목록 조회 32회 연속 호출 -> OK"
    except Exception as e:
        yield f"  - default 네임스페이스에 pod 목록 조회 32회 연속 호출 -> 실패: {e}"


def _run_s11() -> Iterator[str]:
    """S11: system: 접두어를 가진 ClusterRole 변조 (threshold=1). 실제 내장 system:
    롤은 절대 건드리지 않고, 이름 자체가 system:으로 시작하는 자체 테스트 롤을
    만들어서 그걸 삭제(변조)한다."""
    name = f"system:dummy-test-{k8s.short_id()}"
    yield from _step(
        f"자체 테스트용 ClusterRole {name} 생성(실제 system 롤 아님)",
        lambda: k8s.create_clusterrole(name, [{"api_groups": [""], "resources": ["pods"], "verbs": ["get"]}]),
    )
    time.sleep(1)
    yield from _step(f"{name} 삭제(system: 접두어 롤 변조로 판정됨)", lambda: k8s.delete_clusterrole(name))


_S12_RULE_VARIANTS = [
    ("wildcard_resource", [{"api_groups": [""], "resources": ["*"], "verbs": ["get"]}]),
    ("wildcard_verb", [{"api_groups": [""], "resources": ["pods"], "verbs": ["*"]}]),
    ("write_verb", [{"api_groups": ["apps"], "resources": ["deployments"], "verbs": ["create", "delete"]}]),
    ("pods_exec", [{"api_groups": [""], "resources": ["pods/exec"], "verbs": ["create"]}]),
]


def _run_s12() -> Iterator[str]:
    """S12: wildcard/write 권한을 가진 Role/ClusterRole 생성 (threshold=1, match 조건은
    audit_role_rule_flags_any = wildcard_resource/wildcard_verb/write_verb/pods_exec 중
    하나만 있어도 발화). 하나로 다 몰아 만들면(예: resources=*, verbs=*) 이미 여러 플래그가
    동시에 켜지지만, 각 플래그를 단독으로도 확인할 수 있게 ClusterRole을 플래그별로
    따로 만들어 더 다양한 로그를 남긴다(_S12_RULE_VARIANTS)."""
    created = []
    for flag, rules in _S12_RULE_VARIANTS:
        name = f"dummy-test-{flag.replace('_', '-')}-{k8s.short_id()}"
        yield from _step(f"[{flag}] ClusterRole {name} 생성", lambda n=name, r=rules: k8s.create_clusterrole(n, r))
        created.append(name)
        time.sleep(1)
    for name in created:
        yield from _step(f"{name} 정리", lambda n=name: k8s.delete_clusterrole(n))


def _run_s13() -> Iterator[str]:
    """S13: cluster-admin 롤 바인딩 부여 (threshold=1)."""
    k8s.ensure_namespace()
    sa_name = f"dummy-test-sa3-{k8s.short_id()}"
    binding_name = f"dummy-test-admin-binding-{k8s.short_id()}"
    yield from _step(f"ServiceAccount {sa_name} 생성", lambda: k8s.create_service_account(k8s.DUMMY_NAMESPACE, sa_name))
    yield from _step(
        f"cluster-admin ClusterRoleBinding {binding_name} 생성",
        lambda: k8s.create_clusterrolebinding(binding_name, k8s.DUMMY_NAMESPACE, sa_name, "cluster-admin"),
    )
    yield from _step(f"{binding_name} 정리", lambda: k8s.delete_clusterrolebinding(binding_name))
    yield from _step(f"{sa_name} 정리", lambda: k8s.delete_service_account(k8s.DUMMY_NAMESPACE, sa_name))


def _run_s14() -> Iterator[str]:
    """S14: 실행 중 pod에 ephemeral container 추가 (threshold=1)."""
    k8s.ensure_namespace()
    pod_name = f"dummy-s14-{k8s.short_id()}"
    yield from _step(f"pod {pod_name} 생성", lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, pod_name, 60))
    try:
        k8s.wait_pod_running(k8s.DUMMY_NAMESPACE, pod_name)
        yield from _step("ephemeral container 추가(patch pods/ephemeralcontainers)",
                          lambda: k8s.add_ephemeral_container(k8s.DUMMY_NAMESPACE, pod_name))
    except Exception as e:
        yield f"    pod 대기 실패: {e}"
    yield from _step(f"pod {pod_name} 정리", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, pod_name))


def _run_s15() -> Iterator[str]:
    """S15: kube-public에 pod 생성 (threshold=1)."""
    name = f"dummy-test-pod-{k8s.short_id()}"
    yield from _step(f"kube-public에 pod {name} 생성", lambda: k8s.create_sleep_pod("kube-public", name, 10))
    time.sleep(1)
    yield from _step(f"{name} 정리", lambda: k8s.delete_pod("kube-public", name))


_S16_POD_VARIANTS = [
    ("privileged+hostNetwork", {"privileged": True, "host_network": True}),
    ("hostPID+hostIPC", {"host_pid": True, "host_ipc": True}),
    ("hostPath 볼륨 마운트", {"host_path_volume": True}),
]


def _run_s16() -> Iterator[str]:
    """S16: privileged/hostNetwork/hostPID/hostIPC/hostPath 등 컨테이너 이스케이프
    벡터를 가진 pod 생성 (threshold=1, match 조건은 audit_pod_security_flags_any라
    이 중 하나만 있어도 발화). 벡터 조합을 하나로 몰지 않고 pod를 여러 개 만들어
    각 벡터를 따로도 재현한다(_S16_POD_VARIANTS)."""
    k8s.ensure_namespace()
    for label, kwargs in _S16_POD_VARIANTS:
        name = f"dummy-s16-{k8s.short_id()}"
        yield from _step(
            f"[{label}] pod {name} 생성",
            lambda n=name, kw=kwargs: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, n, 10, **kw),
        )
        time.sleep(1)
        yield from _step(f"{name} 정리", lambda n=name: k8s.delete_pod(k8s.DUMMY_NAMESPACE, n))


def _run_s17() -> Iterator[str]:
    """S17: NodePort Service 노출 (threshold=1)."""
    k8s.ensure_namespace()
    name = f"dummy-svc-{k8s.short_id()}"
    yield from _step(f"NodePort Service {name} 생성", lambda: k8s.create_nodeport_service(k8s.DUMMY_NAMESPACE, name))
    yield from _step(f"{name} 정리", lambda: k8s.delete_service(k8s.DUMMY_NAMESPACE, name))


_S18_CREDENTIAL_VARIANTS = [
    ("aws_access_key_id", {"aws_access_key_id": "AKIAFAKEEXAMPLE0000"}),
    ("password", {"password": "SuperSecretPassw0rd!"}),
    ("passphrase", {"passphrase": "correct horse battery staple"}),
    ("aws-s3-access-key-id", {"aws-s3-access-key-id": "AKIAFAKEBUCKET0001"}),
]


def _run_s18() -> Iterator[str]:
    """S18: ConfigMap에 평문 자격증명 노출 (threshold=1, audit_configmap_has_credentials가
    aws_access_key_id/aws-access-key-id/aws_s3_access_key_id/aws-s3-access-key-id/
    password/passphrase 중 뭐가 들어있어도 발화). 매번 같은 키 하나만 쓰지 않고 여러
    키 패턴으로 ConfigMap을 나눠 만들어 판정 로직이 어떤 키에도 반응하는지 폭넓게
    재현한다(_S18_CREDENTIAL_VARIANTS)."""
    k8s.ensure_namespace()
    for label, data in _S18_CREDENTIAL_VARIANTS:
        name = f"dummy-cm-{k8s.short_id()}"
        yield from _step(
            f"[{label}] 자격증명이 담긴 ConfigMap {name} 생성",
            lambda n=name, d=data: k8s.create_configmap_with_credentials(k8s.DUMMY_NAMESPACE, n, d),
        )
        yield from _step(f"{name} 정리", lambda n=name: k8s.delete_configmap(k8s.DUMMY_NAMESPACE, n))


def _run_s19() -> Iterator[str]:
    """S19: 동일 IP에서 60초 안에 로그인 실패 5건 이상 (threshold)."""
    yield "  - 존재하지 않는 계정으로 로그인 실패 6건 연속 전송 (같은 소스 IP, WAF 미경유)"
    for line in was.send_login_failure_burst(6):
        yield f"    {line}"


def _run_s20() -> Iterator[str]:
    """S20: DaemonSet 생성 (threshold=1)."""
    name = f"dummy-ds-{k8s.short_id()}"
    yield from _step(f"DaemonSet {name} 생성", lambda: k8s.create_daemonset(k8s.DUMMY_NAMESPACE, name))
    yield from _step(f"{name} 정리", lambda: k8s.delete_daemonset(k8s.DUMMY_NAMESPACE, name))


def _run_s21() -> Iterator[str]:
    """S21: CronJob 생성 (threshold=1)."""
    name = f"dummy-cj-{k8s.short_id()}"
    yield from _step(f"CronJob {name} 생성", lambda: k8s.create_cronjob(k8s.DUMMY_NAMESPACE, name))
    yield from _step(f"{name} 정리", lambda: k8s.delete_cronjob(k8s.DUMMY_NAMESPACE, name))


# stratum+tcp/stratum2+tcp/stratum+ssl/stratum2+ssl 중 하나만 cmdline에 있으면
# falco-values.yaml customRules의 "Detect crypto miners using the Stratum
# protocol" 룰이 매칭된다(spawned_process and proc.cmdline contains ...) - 실제로
# 어디에도 연결하지 않는 `true`(항상 성공, 인자 무시)에 가짜 스트라텀 URI를 인자로만
# 얹어서 cmdline에 그 문자열이 찍히게 한다. 실제 마이너 바이너리를 심거나 진짜
# 마이닝 풀에 접속하지 않고도 룰 조건(문자열 매칭)만 안전하게 재현하는 방식.
_S22_MINER_COMMAND = "true stratum+tcp://fake-pool.dummy.local:3333"


def _run_s22() -> Iterator[str]:
    """S22: 컨테이너 내 크립토마이닝 정황 (threshold=1, falco). S1과 같은 방식으로
    자체 pod를 하나 만들어 그 안에서 exec한다 - join_on=pod라 이 pod 자체가
    correlation_key_value(orchestrator.resource.name)가 된다."""
    k8s.ensure_namespace()
    name = f"dummy-s22-{k8s.short_id()}"
    yield from _step(f"pod {name} 생성(sleep 60s)", lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, name, 60))
    try:
        k8s.wait_pod_running(k8s.DUMMY_NAMESPACE, name)
        yield "  - pod Running 대기 -> OK"
        yield from _step(
            "크립토마이닝 정황 재현(Stratum 프로토콜 URI가 담긴 프로세스 실행)",
            lambda: k8s.exec_in_pod(k8s.DUMMY_NAMESPACE, name, ["sh", "-c", _S22_MINER_COMMAND]),
        )
    except Exception as e:
        yield f"  - pod Running 대기 -> 실패: {e} (exec 스킵)"
    yield from _step(f"pod {name} 정리", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, name))


# access_log_files 목록(auth.log 등)에 있는 파일 이름을 O_TRUNC로 열면 falco 코어
# "Clear Log Activities" 룰이 매칭된다 - 셸 리다이렉트(`>`)는 항상 O_WRONLY|O_CREAT|
# O_TRUNC로 여니 파일이 원래 없어도(busybox 이미지엔 /var/log/auth.log가 없음)
# 그대로 매칭된다.
_S23_CLEAR_LOG_COMMAND = "mkdir -p /var/log && : > /var/log/auth.log"


def _run_s23() -> Iterator[str]:
    """S23: 시스템 로그 삭제 시도(흔적 인멸) (threshold=1, falco). S22와 같은
    방식으로 자체 pod를 만들어 그 안에서 exec한다."""
    k8s.ensure_namespace()
    name = f"dummy-s23-{k8s.short_id()}"
    yield from _step(f"pod {name} 생성(sleep 60s)", lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, name, 60))
    try:
        k8s.wait_pod_running(k8s.DUMMY_NAMESPACE, name)
        yield "  - pod Running 대기 -> OK"
        yield from _step(
            "시스템 로그 파일을 O_TRUNC로 열기(흔적 인멸 흉내)",
            lambda: k8s.exec_in_pod(k8s.DUMMY_NAMESPACE, name, ["sh", "-c", _S23_CLEAR_LOG_COMMAND]),
        )
    except Exception as e:
        yield f"  - pod Running 대기 -> 실패: {e} (exec 스킵)"
    yield from _step(f"pod {name} 정리", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, name))


def _run_s24() -> Iterator[str]:
    """S24: TLS 없는 Ingress 노출 (threshold=1)."""
    k8s.ensure_namespace()
    name = f"dummy-ing-{k8s.short_id()}"
    yield from _step(
        f"TLS 없는 Ingress {name} 생성", lambda: k8s.create_ingress_without_tls(k8s.DUMMY_NAMESPACE, name)
    )
    yield from _step(f"{name} 정리", lambda: k8s.delete_ingress(k8s.DUMMY_NAMESPACE, name))


def _run_s25() -> Iterator[str]:
    """S25: ServiceAccount 토큰 명시적 발급 정황 (threshold=1, TokenRequest API)."""
    k8s.ensure_namespace()
    sa_name = f"dummy-sa-token-{k8s.short_id()}"
    yield from _step(f"ServiceAccount {sa_name} 생성", lambda: k8s.create_service_account(k8s.DUMMY_NAMESPACE, sa_name))
    yield from _step(
        f"TokenRequest API로 {sa_name} 토큰 명시적 발급",
        lambda: k8s.create_service_account_token(k8s.DUMMY_NAMESPACE, sa_name),
    )
    yield from _step(f"{sa_name} 정리", lambda: k8s.delete_service_account(k8s.DUMMY_NAMESPACE, sa_name))


# ============================================================================
# S26~S51 (2026-07-18 추가) - falcosecurity/rules 공식 falco_rules.yaml을
# WebFetch로 재확인해 correlation-engine이 새로 추가한 시나리오들의 재현 레시피.
# 모듈 docstring 참고.
# ============================================================================

def _run_s26() -> Iterator[str]:
    """S26: WAF 계층 로그인 브루트포스 (threshold=1). S19(was_actions, WAF 미경유)와
    달리 /proxy를 거쳐 gateway.py의 GatewayMiddleware가 직접 판정하게 한다."""
    yield "  - /proxy 경유 로그인 실패 6건 연속 전송 (같은 소스 IP)"
    for line in waf.send_brute_force_burst_via_waf(6):
        yield f"    {line}"


def _run_s27() -> Iterator[str]:
    """S27: WAF Rate Limit 남용 (threshold=1)."""
    yield "  - /proxy 요청 35건 연속 전송 (같은 소스 IP, rate_limit_max_requests=30 초과 노림)"
    for line in waf.send_rate_limit_burst(35):
        yield f"    {line}"


def _run_s28() -> Iterator[str]:
    """S28: 알려진 스캐너 툴 User-Agent 탐지 (threshold=1)."""
    yield "  - 알려진 스캐너 User-Agent(sqlmap 등)로 요청 전송"
    yield f"    {waf.send_bad_bot_request()}"


def _run_s29() -> Iterator[str]:
    """S29: JWT 위조 시도 alg:none (threshold=1). waf_actions.send_jwt_alg_none_critical은
    이미 있음(S4/S5의 CRITICAL 재료 풀에도 포함돼 있음) - 여기서는 이 공격 하나만
    확실히 골라서 보낸다."""
    yield "  - JWT alg:none 위조 헤더로 요청 전송"
    yield f"    {waf.send_jwt_alg_none_critical()}"


def _run_s30() -> Iterator[str]:
    """S30: 동일 IP WAS 404 다발 (threshold=10, 엔드포인트 무차별 탐색 정황)."""
    yield "  - 존재하지 않는 경로로 404 11건 연속 요청 (같은 소스 IP, WAF 미경유)"
    for line in was.send_not_found_burst(11):
        yield f"    {line}"


def _run_s31() -> Iterator[str]:
    """S31: RBAC 권한/역할 열거 정황 (threshold=5, S10보다 좁은 범위)."""
    k8s.ensure_namespace()
    try:
        k8s.burst_list_rbac_objects(k8s.DUMMY_NAMESPACE, 6)
        yield "  - roles/clusterroles/rolebindings/clusterrolebindings get/list 6회 연속 호출 -> OK"
    except Exception as e:
        yield f"  - RBAC 오브젝트 목록 조회 6회 연속 호출 -> 실패: {e}"


def _run_s33() -> Iterator[str]:
    """S33: CORS 위반 탐지 (threshold=1, 신뢰되지 않은 Origin)."""
    yield "  - 화이트리스트에 없는 Origin(http://evil.example)으로 요청 전송"
    yield f"    {waf.send_cors_violation_request()}"


# S32(dup)는 실제로 자기 자신에게 접속하는 리버스쉘 패턴이 있어야 한다(단순 문자열
# 매칭이 아니라 진짜 dup2 syscall이 필요) - 같은 pod 안에서 nc 리스너를 하나 띄우고
# loopback으로 접속해 -e /bin/sh로 쉘을 붙인다. 접속에 성공한 nc가 그 소켓을
# stdin/stdout/stderr에 dup하는 순간 이 rule이 매칭된다(실측 확인, 2026-07-18).
# nc -e로 연결된 쉘은 스스로 안 끝나므로(양쪽 다 입력을 기다리며 무한 대기) 반드시
# timeout으로 전체를 감싸서 강제 종료해야 한다 - 안 그러면 이 exec 세션 자체가
# 영원히 안 끝난다(kubectl exec가 행업, 실측 확인).
_S32_DUP_NETWORK_COMMAND = (
    "timeout 6 sh -c "
    "'nc -lp 4599 -w4 -e /bin/sh & sleep 1; nc -w2 127.0.0.1 4599 -e /bin/sh >/dev/null 2>&1'"
)


def _run_s32() -> Iterator[str]:
    """S32: 컨테이너 내 리버스 쉘/원격 코드 실행 의심 (threshold=1, falco
    "Redirect STDOUT/STDIN to Network Connection in Container"). join_on=pod."""
    yield from _run_pod_falco_scenario("s32", [_S32_DUP_NETWORK_COMMAND])


# is_exe_from_upper_layer=true(컨테이너 이미지에 없던, 컨테이너가 뜬 뒤 새로 쓰인
# 실행파일)를 재현 - busybox를 새 이름으로 복사해서 실행한다. 주의: busybox 멀티콜
# 바이너리는 argv[0]가 "busybox"일 때만 다음 인자를 애플릿 이름으로 해석한다 -
# 아무 이름으로나 복사해서 바로 실행하면 "applet not found"로 죽는다(실측 확인,
# 2026-07-18) - 그래서 복사본 이름을 반드시 "busybox" 그대로 유지한다.
_S34_DROP_EXECUTE_COMMAND = "cp /bin/busybox /tmp/busybox && /tmp/busybox true"


def _run_s34() -> Iterator[str]:
    """S34: 컨테이너 내 미확인 바이너리 드롭 후 실행 (threshold=1, falco "Drop and
    execute new binary in container"). join_on=pod."""
    yield from _run_pod_falco_scenario("s34", [_S34_DROP_EXECUTE_COMMAND])


# nc -e는 실제 연결 성공 여부와 무관하게 spawned_process 이벤트(cmdline에 " -e"
# 포함)만으로 이 rule이 매칭된다(S32와 달리 dup 성공이 필요 없음, 실측 확인) - 존재할
# 필요 없는 포트로 짧은 타임아웃만 주고 던진다.
_S35_NETCAT_RCE_COMMAND = "nc -w1 -e /bin/sh 127.0.0.1 1 2>/dev/null; true"


def _run_s35() -> Iterator[str]:
    """S35: 컨테이너 내 Netcat 기반 원격 코드 실행 정황 (threshold=1, falco "Netcat
    Remote Code Execution in Container"). join_on=pod."""
    yield from _run_pod_falco_scenario("s35", [_S35_NETCAT_RCE_COMMAND])


# memfd_create/execve는 POSIX 셸 빌트인이 아니라 libc 직접 호출이 필요해서 busybox로는
# 재현 불가 - k8s_actions.PYTHON_IMAGE(python:3-alpine)에서 os.memfd_create()로
# /bin/sh 바이트를 메모리 파일에 써넣고 그 fd를 그대로 실행한다. argv[0]를 "dummy"로
# 두면 busybox(alpine의 /bin/sh 실체)가 "applet not found"로 죽는다(실측 확인) -
# "sh"로 둬서 정상적으로 쉘이 뜨게 한다(어차피 즉시 종료돼도 falco 이벤트는 exec
# 시점에 이미 발생).
_S36_MEMFD_SCRIPT = """
import os
fd = os.memfd_create("dummy")
os.write(fd, open("/bin/sh", "rb").read())
os.execv("/proc/self/fd/%d" % fd, ["sh"])
"""


def _run_s36() -> Iterator[str]:
    """S36: memfd_create를 통한 파일리스 실행 정황 (threshold=1, falco "Fileless
    execution via memfd_create"). join_on=pod, python:3-alpine 이미지 필요."""
    yield from _run_pod_falco_scenario(
        "s36", [_pipe_python(_S36_MEMFD_SCRIPT)], image=k8s.PYTHON_IMAGE
    )


# falco_rules.yaml의 clear_data_procs는 proc.name이 정확히 shred/mkfs/mke2fs여야
# 하는데 busybox엔 이 애플릿 자체가 없다 - busybox를 그 이름으로 심볼릭링크해서
# 실행한다(comm은 execve에 넘긴 경로의 basename을 그대로 따라간다, S22의 "true
# stratum+tcp://..." 트릭과 같은 원리). "shred"가 실제 애플릿이 아니라 곧바로
# "applet not found"로 죽지만 falco는 exec 이벤트 자체에서 이미 매칭한다(실측 확인,
# 2026-07-18).
_S37_REMOVE_BULK_DATA_COMMAND = (
    "echo dummy > /tmp/dummy-bulk-data && ln -sf /bin/busybox /tmp/shred && "
    "/tmp/shred /tmp/dummy-bulk-data 2>/dev/null; true"
)


def _run_s37() -> Iterator[str]:
    """S37: 디스크 대량 데이터 삭제 정황 (threshold=1, falco "Remove Bulk Data from
    Disk"). join_on=pod."""
    yield from _run_pod_falco_scenario("s37", [_S37_REMOVE_BULK_DATA_COMMAND])


# find의 마지막 인자가 정확히 ".aws/credentials"로 끝나야 한다(falco_rules.yaml
# private_aws_credentials와 별개 조건, proc.args endswith) - 실제 파일이 없어도
# find 프로세스가 그 인자로 spawn되는 순간 매칭된다.
_S38_FIND_AWS_CREDS_COMMAND = "find /root/.aws/credentials 2>/dev/null; true"


def _run_s38() -> Iterator[str]:
    """S38: 컨테이너 내 AWS 자격증명 탐색 정황 (threshold=1, falco "Find AWS
    Credentials"). join_on=pod."""
    yield from _run_pod_falco_scenario("s38", [_S38_FIND_AWS_CREDS_COMMAND])


_S39_SEARCH_PRIVATE_KEYS_COMMAND = "find / -maxdepth 3 -name id_rsa 2>/dev/null; true"


def _run_s39() -> Iterator[str]:
    """S39: 컨테이너 내 개인키/비밀번호 탐색 정황 (threshold=1, falco "Search
    Private Keys or Passwords" - find 인자에 id_rsa/id_dsa/id_ed25519/id_ecdsa
    포함). join_on=pod."""
    yield from _run_pod_falco_scenario("s39", [_S39_SEARCH_PRIVATE_KEYS_COMMAND])


# PTRACE_ATTACH(=16)를 자식 프로세스에 걸어서 재현 - ptrace()도 memfd_create처럼 셸
# 빌트인이 아니라 libc 직접 호출이 필요해서 python:3-alpine + ctypes를 쓴다.
_S40_PTRACE_ATTACH_SCRIPT = """
import ctypes, os, time
pid = os.fork()
if pid == 0:
    time.sleep(2)
    os._exit(0)
else:
    time.sleep(0.3)
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.ptrace(16, pid, 0, 0)
    os.waitpid(pid, 0)
"""


def _run_s40() -> Iterator[str]:
    """S40: 프로세스 PTRACE 부착 정황 (threshold=1, falco "PTRACE attached to
    process"). join_on=pod, python:3-alpine 이미지 필요."""
    yield from _run_pod_falco_scenario(
        "s40", [_pipe_python(_S40_PTRACE_ATTACH_SCRIPT)], image=k8s.PYTHON_IMAGE
    )


# /dev/shm(tmpfs)에 busybox를 복사해서 그 자리에서 실행 - S34(드롭&실행)와 원리는
# 같지만 falco_rules.yaml의 "Execution from /dev/shm" rule이 별도로 tmpfs 경로 자체를
# proc.exe 조건으로 본다. S34와 같은 이유로 복사본 이름은 반드시 "busybox"로 유지.
_S41_DEV_SHM_EXEC_COMMAND = "cp /bin/busybox /dev/shm/busybox && /dev/shm/busybox true"


def _run_s41() -> Iterator[str]:
    """S41: /dev/shm에서의 실행 정황 (threshold=1, falco "Execution from
    /dev/shm"). join_on=pod."""
    yield from _run_pod_falco_scenario("s41", [_S41_DEV_SHM_EXEC_COMMAND])


def _run_s42() -> Iterator[str]:
    """S42: 비표준 포트 SSH 연결 시도 (falco "Disallowed SSH Connection Non
    Standard Port"). 재현 불가로 best-effort 스킵 - 모듈 docstring 참고
    (falco_rules.yaml 조건이 proc.exe endswith "ssh"인 실제 ssh 클라이언트의 outbound
    connect를 요구하는데, busybox엔 ssh 클라이언트가 없고 임의 이름의 symlink/스크립트로는
    proc.exe가 "ssh"로 안 끝나서 우회할 방법이 없다)."""
    yield (
        "  - 스킵: 이 rule은 실제 ssh 클라이언트 바이너리(proc.exe가 'ssh'로 끝나야 함)의 "
        "outbound connect가 필요한데, busybox 기반 테스트 환경에는 ssh 클라이언트가 없어 "
        "재현할 방법이 없습니다(정직하게 보고 - 가짜로 성공 처리하지 않음)."
    )


def _run_s43() -> Iterator[str]:
    """S43: 시스템 계정의 인터랙티브 셸 획득 정황 (falco "System user interactive").
    재현 불가로 best-effort 스킵 - 모듈 docstring 참고(interactive 매크로가 sshd/
    systemd-logind/login 조상 프로세스, 즉 실제 SSH 세션을 요구하는데 이 테스트 pod들엔
    sshd 자체가 없다)."""
    yield (
        "  - 스킵: 이 rule은 sshd/systemd-logind/login을 조상 프로세스로 둔 실제 SSH "
        "세션이 필요한데, 이 테스트 환경의 pod에는 sshd가 없어 재현할 방법이 없습니다"
        "(정직하게 보고 - 가짜로 성공 처리하지 않음)."
    )


# PTRACE_TRACEME(=0)를 자기 자신에게 걸어서 안티디버깅 정황을 재현 - S40과 같은 이유로
# python:3-alpine + ctypes.
_S44_PTRACE_TRACEME_SCRIPT = """
import ctypes
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.ptrace(0, 0, 0, 0)
"""


def _run_s44() -> Iterator[str]:
    """S44: 안티디버깅 시도 정황 (threshold=1, falco "PTRACE anti-debug attempt").
    join_on=pod, python:3-alpine 이미지 필요."""
    yield from _run_pod_falco_scenario(
        "s44", [_pipe_python(_S44_PTRACE_TRACEME_SCRIPT)], image=k8s.PYTHON_IMAGE
    )


_S45_READ_SENSITIVE_FILE_COMMAND = "cat /etc/shadow 2>/dev/null; true"


def _run_s45() -> Iterator[str]:
    """S45: 신뢰되지 않은 프로세스의 민감 파일 열람 (threshold=1, falco "Read
    sensitive file untrusted" - busybox cat은 falco의 신뢰 프로그램 예외 목록에
    없음). join_on=pod."""
    yield from _run_pod_falco_scenario("s45", [_S45_READ_SENSITIVE_FILE_COMMAND])


_S46_HARDLINK_SENSITIVE_COMMAND = "ln /etc/shadow /tmp/dummy-shadow-hardlink 2>/dev/null; true"


def _run_s46() -> Iterator[str]:
    """S46: 민감 파일에 하드링크 생성 시도 (threshold=1, falco "Create Hardlink
    Over Sensitive Files"). join_on=pod. link() syscall 자체가 이벤트를 만들어서
    실제로 성공(같은 파일시스템)하지 않아도 매칭된다."""
    yield from _run_pod_falco_scenario("s46", [_S46_HARDLINK_SENSITIVE_COMMAND])


_S47_SYMLINK_SENSITIVE_COMMAND = "ln -s /etc/shadow /tmp/dummy-shadow-symlink 2>/dev/null; true"


def _run_s47() -> Iterator[str]:
    """S47: 민감 파일에 심볼릭링크 생성 시도 (threshold=1, falco "Create Symlink
    Over Sensitive Files"). join_on=pod."""
    yield from _run_pod_falco_scenario("s47", [_S47_SYMLINK_SENSITIVE_COMMAND])


def _run_s48() -> Iterator[str]:
    """S48: 신뢰된 프로세스의 뒤늦은 민감 파일 열람 (falco "Read sensitive file
    trusted after startup"). 재현 불가로 best-effort 스킵 - 모듈 docstring 참고
    (server_procs 목록 - http/db 서버, docker 런타임, sshd - 에 속하는 실제 서버
    바이너리가 5초 이상 살아있다가 민감 파일을 열어야 하는데, busybox 이미지에는 그
    목록에 해당하는 프로세스가 없다)."""
    yield (
        "  - 스킵: 이 rule은 http/db 서버·docker 런타임·sshd 등 실제 서버 프로세스가 "
        "떠 있다가 뒤늦게 민감 파일을 열어야 하는데, busybox 기반 테스트 환경에는 그런 "
        "서버 바이너리가 없어 재현할 방법이 없습니다(정직하게 보고 - 가짜로 성공 처리하지 않음)."
    )


# 조기 리턴 트릭: "cd ... && exec cat ..."에서 exec은 지금 이 sh 프로세스를 cat으로
# 갈아치운다(같은 PID) - 그래서 cat의 부모(proc.pname)가 이 sh 자신이 아니라 이
# sh를 스폰한 컨테이너 런타임(containerd-shim 등)이 된다. falco_rules.yaml의
# directory_traversal 조건이 "not proc.pname in shell_binaries"를 요구해서, 이
# exec 없이 그냥 "sh -c 'cat ...'"로 실행하면 cat의 부모가 sh 자신이라 절대 안
# 걸린다(실측 확인, 2026-07-18) - 반드시 exec으로 셸 계층 자체를 없애야 한다.
_S49_DIRECTORY_TRAVERSAL_COMMAND = (
    "mkdir -p /tmp/dummy-dt/a/b && cd /tmp/dummy-dt/a/b && exec cat ../../../../etc/passwd"
)


def _run_s49() -> Iterator[str]:
    """S49: 경로 탐색을 통한 민감 파일 접근 시도 (threshold=1, falco "Directory
    traversal monitored file read"). join_on=pod."""
    yield from _run_pod_falco_scenario("s49", [_S49_DIRECTORY_TRAVERSAL_COMMAND])


def _run_s50() -> Iterator[str]:
    """S50: 컨테이너 내 Raw 패킷 소켓 생성 (threshold=1, falco "Packet socket
    created in container" - AF_PACKET 소켓 생성, 스니핑/ARP 스푸핑 정황). join_on=pod.
    busybox에 raw AF_PACKET 소켓을 여는 애플릿이 없어 python:3-alpine + socket 모듈로
    직접 연다."""
    script = (
        "import socket\n"
        "socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))\n"
    )
    yield from _run_pod_falco_scenario("s50", [_pipe_python(script)], image=k8s.PYTHON_IMAGE)


def _run_s51() -> Iterator[str]:
    """S51: User-Agent 로테이션 탐지 (threshold=1, 핑거프린팅 회피 정황)."""
    yield "  - 같은 IP로 서로 다른 User-Agent 4개를 순서대로 전송 (60초 안에 4개 이상 -> 발화)"
    for line in waf.send_ua_rotation_burst():
        yield f"    {line}"


SCENARIOS: Dict[str, Dict] = {
    "S1": {
        "name": "Pod Exec 권한 사용 이후 컨테이너 내 이상행동",
        "modules": ["k8s_audit", "falco"],
        "story": "공격자가 이미 확보한 pod 접근 권한으로 컨테이너에 exec 명령을 실행해 쉘을 띄운다 → "
                  "K8s 감사로그(pods/exec)와 Falco의 실시간 쉘 실행 탐지가 같은 pod에서 거의 동시에 잡힌다 (join=pod).",
        "run": _run_s1,
    },
    "S2": {
        "name": "자격증명 조회 이후 흔적 삭제 시도",
        "modules": ["k8s_audit"],
        "story": "공격자가 시크릿(자격증명)을 조회한 뒤 → 흔적을 지우려 관련 pod를 삭제한다. "
                  "'정찰 → 증거 인멸' 패턴 (join=user_or_sa).",
        "run": _run_s2,
    },
    "S3": {
        "name": "RBAC 권한상승 이후 pod exec",
        "modules": ["k8s_audit"],
        "story": "공격자가 ClusterRole을 만들어 권한을 확보한 뒤 → 곧바로 pod에 접속해 그 권한을 실제로 사용한다. "
                  "'권한상승 → 즉시 악용' 패턴 (join=user_or_sa).",
        "run": _run_s3,
    },
    "S4": {
        "name": "동일 IP WAF 다발 차단",
        "modules": ["waf"],
        "story": "동일 출발지 IP에서 WAF가 CRITICAL로 판정한 요청이 60초 안에 5건 이상 몰린다 — "
                  "자동화된 스캐너/툴을 이용한 다발성 공격 정황 (threshold).",
        "run": _run_s4,
    },
    "S5": {
        "name": "WAF CRITICAL 차단 이후 실제 컨테이너 침투 확인",
        "modules": ["waf", "falco"],
        "story": "WAF가 CRITICAL 공격(SQLi/XSS/Path Traversal 등)을 차단한 직후 → 같은 대상 pod 안에서 "
                  "K8s API 서버로의 접근이 Falco에 잡힌다 — 애플리케이션 취약점을 뚫고 실제 컨테이너까지 "
                  "침투했을 가능성 (join=pod).",
        "run": _run_s5,
    },
    "S6": {
        "name": "시스템 네임스페이스 서비스어카운트 생성",
        "modules": ["k8s_audit"],
        "story": "공격자가 kube-system/kube-public 같은 시스템 네임스페이스에 서비스어카운트를 몰래 만든다 — "
                  "지속적인 접근권 확보(persistence) 시도 (threshold=1).",
        "run": _run_s6,
    },
    "S7": {
        "name": "서비스어카운트 생성 이후 RBAC 권한 즉시 부여",
        "modules": ["k8s_audit"],
        "story": "새 서비스어카운트를 만들자마자 → 곧바로 RBAC 권한을 부여한다 — 백도어성 계정을 만들고 "
                  "즉시 무기화하는 패턴 (join=user_or_sa).",
        "run": _run_s7,
    },
    "S8": {
        "name": "네임스페이스 삭제",
        "modules": ["k8s_audit"],
        "story": "네임스페이스 자체를 통째로 삭제한다 — 파괴적 행위 또는 흔적 인멸 정황 (threshold=1).",
        "run": _run_s8,
    },
    "S9": {
        "name": "익명 요청 성공(RBAC 노출)",
        "modules": ["k8s_audit"],
        "story": "인증 없는(익명) 요청이 실제로 성공한다 — RBAC 설정 미비로 인한 무방비 노출 (threshold=1).",
        "run": _run_s9,
    },
    "S10": {
        "name": "get/list/watch 대량 호출(정찰 정황)",
        "modules": ["k8s_audit"],
        "story": "60초 안에 get/list/watch 같은 조회성 API를 30회 이상 호출한다 — 클러스터 구조를 "
                  "파악하려는 정찰(reconnaissance) 정황 (threshold).",
        "run": _run_s10,
    },
    "S11": {
        "name": "내장(system:) RBAC 롤 변조",
        "modules": ["k8s_audit"],
        "story": "이름이 system:으로 시작하는 내장급 RBAC 롤을 변조한다 — 핵심 권한 체계를 직접 "
                  "건드리는 고위험 행위 (threshold=1).",
        "run": _run_s11,
    },
    "S12": {
        "name": "위험한 권한을 가진 RBAC 룰 생성",
        "modules": ["k8s_audit"],
        "story": "와일드카드(*)로 모든 리소스에 모든 동작을 허용하는 RBAC 룰을 새로 만든다 — "
                  "과도한 권한 부여 (threshold=1).",
        "run": _run_s12,
    },
    "S13": {
        "name": "cluster-admin 롤 바인딩 부여",
        "modules": ["k8s_audit"],
        "story": "서비스어카운트에 cluster-admin 롤을 바인딩한다 — 클러스터 전체 권한 탈취 (threshold=1).",
        "run": _run_s13,
    },
    "S14": {
        "name": "실행 중 pod에 ephemeral container 추가",
        "modules": ["k8s_audit"],
        "story": "이미 떠 있는 pod에 ephemeral container를 몰래 추가한다 — 탐지를 피해 실행 중인 "
                  "워크로드에 스며드는 시도 (threshold=1).",
        "run": _run_s14,
    },
    "S15": {
        "name": "시스템 네임스페이스에 pod 생성",
        "modules": ["k8s_audit"],
        "story": "시스템 네임스페이스(kube-public)에 pod를 생성한다 — 시스템 영역에 발판(foothold)을 "
                  "마련하려는 시도 (threshold=1).",
        "run": _run_s15,
    },
    "S16": {
        "name": "컨테이너 이스케이프 벡터를 가진 pod 생성",
        "modules": ["k8s_audit"],
        "story": "privileged + hostNetwork 옵션을 가진 pod를 생성한다 — 컨테이너 탈출(escape)에 "
                  "쓰일 수 있는 위험한 설정 (threshold=1).",
        "run": _run_s16,
    },
    "S17": {
        "name": "NodePort Service 노출",
        "modules": ["k8s_audit"],
        "story": "NodePort로 서비스를 외부에 노출한다 — 의도치 않은 네트워크 노출/공격 표면 확대 (threshold=1).",
        "run": _run_s17,
    },
    "S18": {
        "name": "ConfigMap 평문 자격증명 노출",
        "modules": ["k8s_audit"],
        "story": "ConfigMap에 평문 AWS 키 같은 자격증명을 그대로 저장한다 — 자격증명 노출/유출 위험 (threshold=1).",
        "run": _run_s18,
    },
    "S19": {
        "name": "동일 IP 로그인 실패 다발 (Brute Force)",
        "modules": ["was"],
        "story": "동일 출발지 IP에서 로그인 실패(401/403)가 60초 안에 5건 이상 몰린다 — WAF를 거치지 않고 "
                  "Juice Shop에 바로 온 요청도 잡는, WAF 계층과 독립적인 브루트포스 탐지 경로 (threshold).",
        "run": _run_s19,
    },
    "S20": {
        "name": "DaemonSet 생성 (전체 노드 지속성 확보)",
        "modules": ["k8s_audit"],
        "story": "DaemonSet을 생성한다 — 클러스터의 모든 노드(신규 편입 노드 포함)에 컨테이너를 자동으로 "
                  "심어 지속적인 접근권을 확보하려는 시도 (threshold=1).",
        "run": _run_s20,
    },
    "S21": {
        "name": "CronJob 생성 (예약 실행 지속성 확보)",
        "modules": ["k8s_audit"],
        "story": "CronJob을 생성한다 — 재접속 없이 예약된 시각마다 코드를 반복 실행시키는 '예약된 백도어' "
                  "정황 (threshold=1).",
        "run": _run_s21,
    },
    "S22": {
        "name": "컨테이너 내 크립토마이닝 정황",
        "modules": ["falco"],
        "story": "컨테이너 안에서 마이너 풀 접속/Stratum 프로토콜/알려진 마이너 바이너리 실행 정황 중 "
                  "하나가 감지된다 — 컴퓨팅 자원을 무단으로 암호화폐 채굴에 쓰는 리소스 남용 (threshold=1).",
        "run": _run_s22,
    },
    "S23": {
        "name": "시스템 로그 삭제 시도 (흔적 인멸)",
        "modules": ["falco"],
        "story": "auth.log/syslog 같은 시스템 로그 파일을 O_TRUNC로 잘라낸다 — 침투 흔적을 지우려는 "
                  "흔적 인멸(Defense Evasion) 시도 (threshold=1).",
        "run": _run_s23,
    },
    "S24": {
        "name": "TLS 없는 Ingress 노출",
        "modules": ["k8s_audit"],
        "story": "TLS 인증서 없이 Ingress를 생성한다 — 평문(HTTP)으로 클러스터 밖에 노출되는 새 경로가 "
                  "생기는 정황 (threshold=1).",
        "run": _run_s24,
    },
    "S25": {
        "name": "ServiceAccount 토큰 명시적 발급 정황",
        "modules": ["k8s_audit"],
        "story": "TokenRequest API로 서비스어카운트 토큰을 명시적으로 발급한다 — 탈취한 토큰을 외부 API "
                  "호출이나 lateral movement에 재사용하려는 정황 (threshold=1).",
        "run": _run_s25,
    },
    "S26": {
        "name": "WAF 계층 로그인 브루트포스 탐지",
        "modules": ["waf"],
        "story": "동일 IP로 /proxy(WAF)를 거쳐 로그인 실패를 반복한다 — gateway.py가 자체적으로 IP/계정/"
                  "시스템 전체 3단계로 판정을 마친 브루트포스 신호 (S19와 독립적인 탐지 경로, threshold=1).",
        "run": _run_s26,
    },
    "S27": {
        "name": "WAF Rate Limit 남용 (DoS 정황)",
        "modules": ["waf"],
        "story": "동일 IP로 60초 안에 과도하게 많은 요청을 보낸다 — WAF Rate Limiting이 이미 판정을 마친 "
                  "DoS 정황 신호 (threshold=1).",
        "run": _run_s27,
    },
    "S28": {
        "name": "알려진 스캐너 툴 User-Agent 탐지",
        "modules": ["waf"],
        "story": "sqlmap/nikto 등 알려진 해킹 툴의 User-Agent로 요청을 보낸다 — 자동화 스캐너를 이용한 "
                  "정찰 시도 (threshold=1).",
        "run": _run_s28,
    },
    "S29": {
        "name": "JWT 위조 시도 (alg: none)",
        "modules": ["waf"],
        "story": "JWT의 alg 헤더를 'none'으로 위조해 서명 검증 자체를 우회하려 시도한다 — 인증 우회 "
                  "고위험 취약점 (threshold=1).",
        "run": _run_s29,
    },
    "S30": {
        "name": "동일 IP WAS 404 다발 (엔드포인트 무차별 탐색)",
        "modules": ["was"],
        "story": "동일 IP로 존재하지 않는 경로를 대량으로 두드린다 — 페이로드 시그니처가 없는 "
                  "디렉터리/엔드포인트 무차별 탐색(dirbuster류) 정황, WAF 시그니처 엔진의 사각지대 "
                  "(threshold=10).",
        "run": _run_s30,
    },
    "S31": {
        "name": "RBAC 권한/역할 열거 정황",
        "modules": ["k8s_audit"],
        "story": "roles/clusterroles/rolebindings/clusterrolebindings를 짧은 시간에 반복 조회한다 — "
                  "S10(전체 조회 대량 호출)보다 좁고 목적이 뚜렷한 'RBAC 자체를 훑어보는' 권한 정찰 "
                  "(threshold=5).",
        "run": _run_s31,
    },
    "S32": {
        "name": "컨테이너 내 리버스 쉘/원격 코드 실행 의심",
        "modules": ["falco"],
        "story": "컨테이너 안에서 stdin/stdout이 네트워크 소켓으로 리다이렉트된다(dup 변형) — 전형적인 "
                  "리버스 쉘/원격 코드 실행 패턴 (threshold=1).",
        "run": _run_s32,
    },
    "S33": {
        "name": "CORS 위반 탐지 (신뢰되지 않은 Origin)",
        "modules": ["waf"],
        "story": "화이트리스트에 없는 Origin에서 브라우저 요청이 온다 — 다른 사이트가 피해자 브라우저를 "
                  "통해 API를 몰래 호출하려는 시도 (threshold=1).",
        "run": _run_s33,
    },
    "S34": {
        "name": "컨테이너 내 미확인 바이너리 드롭 후 실행",
        "modules": ["falco"],
        "story": "컨테이너 베이스 이미지에 없던 실행파일이 새로 실행된다 — 초기 침투 후 페이로드를 심고 "
                  "실행하는 전형적인 패턴 (threshold=1).",
        "run": _run_s34,
    },
    "S35": {
        "name": "컨테이너 내 Netcat 기반 원격 코드 실행 정황",
        "modules": ["falco"],
        "story": "nc/ncat이 리버스쉘/RCE에 쓰이는 플래그(-e 등)로 실행된다 (threshold=1).",
        "run": _run_s35,
    },
    "S36": {
        "name": "memfd_create를 통한 파일리스 실행 정황",
        "modules": ["falco"],
        "story": "디스크에 흔적을 남기지 않고 메모리에서 바로 바이너리를 실행한다(memfd_create) — 멀웨어의 "
                  "대표적인 탐지 회피 기법 (threshold=1).",
        "run": _run_s36,
    },
    "S37": {
        "name": "디스크 대량 데이터 삭제 정황 (데이터 파괴)",
        "modules": ["falco"],
        "story": "대량 데이터 삭제 유틸리티(shred/mkfs류)가 실행된다 — 파괴/랜섬웨어 정황 (threshold=1).",
        "run": _run_s37,
    },
    "S38": {
        "name": "컨테이너 내 AWS 자격증명 탐색 정황",
        "modules": ["falco"],
        "story": "컨테이너 내에서 AWS 자격증명 표준 저장 위치를 grep/find로 뒤진다 (threshold=1).",
        "run": _run_s38,
    },
    "S39": {
        "name": "컨테이너 내 개인키/비밀번호 탐색 정황",
        "modules": ["falco"],
        "story": "grep/find로 SSH 개인키/비밀번호 패턴을 뒤진다 (threshold=1).",
        "run": _run_s39,
    },
    "S40": {
        "name": "프로세스 PTRACE 부착 정황 (인젝션/크리덴셜 덤핑)",
        "modules": ["falco"],
        "story": "ptrace로 다른 프로세스에 attach한다 — 프로세스 인젝션/크리덴셜 덤핑 정황 (threshold=1).",
        "run": _run_s40,
    },
    "S41": {
        "name": "/dev/shm에서의 실행 정황 (파일시스템 흔적 최소화)",
        "modules": ["falco"],
        "story": "디스크가 아니라 tmpfs(/dev/shm)에 심어진 바이너리가 실행된다 — 파일시스템 흔적을 최소화하려는 "
                  "회피 패턴 (threshold=1).",
        "run": _run_s41,
    },
    "S42": {
        "name": "비표준 포트 SSH 연결 시도",
        "modules": ["falco"],
        "story": "SSH가 비표준 포트로 연결을 시도한다 — 방화벽/모니터링 우회 목적의 은닉 통신 정황 "
                  "(threshold=1). 이 테스트 환경(ssh 클라이언트 없음)에서는 재현 불가 - best-effort 스킵.",
        "run": _run_s42,
    },
    "S43": {
        "name": "시스템 계정의 인터랙티브 셸 획득 정황",
        "modules": ["falco"],
        "story": "www-data/nobody처럼 로그인이 없어야 할 시스템 계정이 인터랙티브 셸을 얻는다 (threshold=1)."
                  " 이 테스트 환경(sshd 없음)에서는 재현 불가 - best-effort 스킵.",
        "run": _run_s43,
    },
    "S44": {
        "name": "안티디버깅 시도 정황",
        "modules": ["falco"],
        "story": "프로세스가 자기 자신에게 PTRACE_TRACEME를 걸어 디버거 부착을 회피한다 — 분석 도구의 "
                  "관찰을 피하려는 멀웨어의 전형적 특징 (threshold=1).",
        "run": _run_s44,
    },
    "S45": {
        "name": "신뢰되지 않은 프로세스의 민감 파일 열람",
        "modules": ["falco"],
        "story": "신뢰 목록에 없는 프로세스가 /etc/shadow 등 민감 파일을 연다 (threshold=1).",
        "run": _run_s45,
    },
    "S46": {
        "name": "민감 파일에 하드링크 생성 시도",
        "modules": ["falco"],
        "story": "민감 파일에 하드링크를 만든다 — 접근 제어를 우회해 다른 경로로 같은 파일을 읽으려는 시도 "
                  "(threshold=1).",
        "run": _run_s46,
    },
    "S47": {
        "name": "민감 파일에 심볼릭링크 생성 시도",
        "modules": ["falco"],
        "story": "민감 파일에 심볼릭링크를 만든다 — S46과 같은 접근 제어 우회 시도 (threshold=1).",
        "run": _run_s47,
    },
    "S48": {
        "name": "신뢰된 프로세스의 뒤늦은 민감 파일 열람",
        "modules": ["falco"],
        "story": "원래 시작 시점에만 민감 파일을 읽어야 할 신뢰된 프로그램이 한참 뒤에 다시 읽는다 "
                  "(threshold=1). 이 테스트 환경(해당 서버 바이너리 없음)에서는 재현 불가 - best-effort 스킵.",
        "run": _run_s48,
    },
    "S49": {
        "name": "경로 탐색을 통한 민감 파일 접근 시도",
        "modules": ["falco"],
        "story": "'../' 경로 탐색으로 /etc 등 민감 경로에 접근한다 — 페이로드 기반이 아니라 경로 조작 "
                  "기반의 파일 읽기 시도 (threshold=1).",
        "run": _run_s49,
    },
    "S50": {
        "name": "컨테이너 내 Raw 패킷 소켓 생성 (스니핑/ARP 스푸핑 정황)",
        "modules": ["falco"],
        "story": "raw AF_PACKET 소켓을 만든다 — 같은 네트워크 네임스페이스의 트래픽을 스니핑/ARP 스푸핑하려는 "
                  "정황 (threshold=1).",
        "run": _run_s50,
    },
    "S51": {
        "name": "User-Agent 로테이션 탐지 (핑거프린팅 회피 정황)",
        "modules": ["waf"],
        "story": "짧은 시간에 같은 IP가 User-Agent를 여러 개로 바꿔가며 요청한다 — OWASP ZAP처럼 매 요청마다 "
                  "정체를 숨기는 스캐너 탐지, S28(문자열 매칭)의 사각지대를 메움 (threshold=1).",
        "run": _run_s51,
    },
}

SCENARIO_IDS: List[str] = list(SCENARIOS.keys())

# k8s_audit/falco를 건드리는 시나리오가 나머지보다 훨씬 많아서(2026-07-18 S26~S51
# 추가 이후로도 여전히 그렇다 - falco만 20개 가까이 됨), 균등 랜덤
# (random.choice(SCENARIO_IDS))으로는 특정 채널 로그가 다른 채널에 묻힌다.
# dummy_generator.py의 "random" 선택이 모듈 채널(was/waf/falco/k8s_audit) 4개를 먼저
# 25:25:25:25로 고르고 그 안에서 균등하게 뽑도록 이 딕셔너리로 나눠둔다 - 시나리오
# 하나가 모듈 여러 개를 건드리면(예: S1은 k8s_audit+falco, S5는 waf+falco) 해당하는
# 채널 버킷 전부에 들어간다. 리스트 컴프리헨션이라 SCENARIOS에 새 시나리오가 추가되면
# 이 매핑도 자동으로 갱신된다.
MODULE_SCENARIO_IDS: Dict[str, List[str]] = {
    module: [sid for sid in SCENARIO_IDS if module in SCENARIOS[sid]["modules"]]
    for module in ("was", "waf", "falco", "k8s_audit")
}
