"""
IDS-COLLECTOR/servers/correlation-engine/app/scenarios/*.yaml의 S1~S109 상관분석
시나리오를 실제로 발화시키는 레시피 모음. 각 레시피는 로그 문자열을 하나씩 yield하는
제너레이터라 프론트엔드(dummy_ui)가 "지금 뭘 하고 있는지"를 실시간으로 보여줄 수 있다.

2026-07-20 2차 추가: S101~S109(9개) - "단일 소스 정밀화" 배치. 전부 threshold/
cardinality고 새 falco 룰 확인이 필요 없는(기존 S1/S4/S10/S21/S30/S32/S34/S35/
S36/S41 재료 재사용) 조합이라, S60~S100 때와 달리 이번 배치는 재현 코드
작성만으로 끝났다 - k3d 클러스터 실측 검증은 아직 안 거쳤다(각 _run_s10x
docstring 참고).

2026-07-20: S60~S100(41개) 추가 - correlation-engine이 S59 이후 늘어난 나머지
시나리오 전체를 커버한다(app/scenarios/*.yaml의 실제 카탈로그와 1:1 대응, S1~S100
빠짐없이 존재). 처음엔 실제 클러스터 없이 작성했다가, 이후 실제 k3d 클러스터
(techeer-ids)에 붙어서 하나씩 실측 확인했다 - falco 로그(rule 매칭 여부)/kube-apiserver
감사로그(sourceIPs 등 실제 필드값)/WAF·WAS 실제 응답 코드를 직접 떠서 대조했다.
그 과정에서 원래 가정이 틀렸던 것들을 바로잡았다:
  - k8s_audit의 source_ip는 X-Forwarded-For로 못 바꾼다고 가정했는데, 실측 결과
    이 클러스터의 kube-apiserver는 sourceIPs에 X-Forwarded-For 값을 그대로 실어서
    WAF/WAS와 똑같이 통제 가능했다 - S95를 그 방식으로 다시 썼다
    (k8s_actions._client_with_source_ip 참고).
  - `release_agent` 트릭(S75/S76)·MutatingWebhookConfiguration(S86)·port-forward
    호출(S77)·pods/log(S89)·actor_identity 브릿지(토큰 탈취 + call_as_stolen_token,
    S61/S66 등)는 전부 실측으로 의도대로 동작함을 확인했다.
  - WAS가 실제로 5xx를 내는지(S60/S78/S84)는 malformed JSON 요청이 실제로 500을
    반환함을 확인했다.
  - `/rest/admin/application-configuration`(S85 원안)이 이 배포에서는 인증 없이도
    이미 200을 반환하고, `/file-upload`(S82)의 성공 응답이 200/201이 아니라
    204임을 실측으로 확인했다 - 이 스크립트가 아니라 correlation-engine
    yaml(S82/S85)의 match 조건 쪽이 실제 앱 동작과 어긋나 있었다. S82는 204를
    상태코드 목록에 추가했고, S85는 실제로 무인증 401/로그인 토큰으로 200이 되는
    엔드포인트(`/api/Users`)로 교체했다(둘 다 2026-07-20, 각 함수 docstring과
    correlation-engine 쪽 network.yaml/resource_abuse.yaml 주석 참고).
  - S66/S69/S74(SSH·시스템계정 falco 룰), S81/S84 stage 3~4(privileged 권한·
    프로세스 계보), S91(7일 창), S90(WAF가 단일 타깃에 고정돼 pod 분산 불가)은
    실측으로도 여전히 재현 불가/완주 불가임을 재확인했다 - 각 함수 docstring 참고.

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
    prefix: str,
    commands: List[str],
    image: str = k8s.BUSYBOX_IMAGE,
    sleep_seconds: int = 60,
    privileged: bool = False,
) -> Iterator[str]:
    """join_on=pod, threshold=1인 falco 전용 시나리오(S22/S23이 먼저 쓰던 패턴을
    S32/S34~S51에서 재사용할 수 있게 공용화, 2026-07-18) - 자체 pod를 하나 만들어
    그 안에서 명령을 실행한다. pod 이름 자체가 correlation_key_value
    (orchestrator.resource.name)가 되므로 join이 항상 이 pod 하나로 확실히 매칭된다.
    각 명령이 실제로 의도한 falco 룰을 발화시키는지는 이 파일 작성 중 실제 k3d
    클러스터(falco 파드 로그)로 실측 검증했다(모듈 docstring 참고).

    privileged(S52 재료, 2026-07-18 추가): "Debugfs Launched in Privileged
    Container"처럼 조건 자체가 container.privileged=true를 요구하는 룰은 일반
    pod로는 절대 안 걸린다 - k8s_actions.create_sleep_pod의 privileged 옵션을
    그대로 통과시킨다."""
    k8s.ensure_namespace()
    name = f"dummy-{prefix}-{k8s.short_id()}"
    yield from _step(
        f"pod {name} 생성(sleep {sleep_seconds}s, image={image}, privileged={privileged})",
        lambda: k8s.create_sleep_pod(
            k8s.DUMMY_NAMESPACE, name, sleep_seconds, image=image, privileged=privileged
        ),
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


# ============================================================================
# S52~S53 (2026-07-18 추가) - falcosecurity/event-generator + Atomic Red Team +
# OWASP ZAP으로 correlation-engine 전체 시나리오를 재검증하다가 발견한 두 사각지대의
# 재현 레시피. correlation-engine/app/scenarios/workload.yaml(S52)·rbac.yaml(S53)
# 주석 참고.
# ============================================================================

# debugfs는 alpine 기본 이미지에 없다(e2fsprogs 패키지가 debugfs 애플릿을 안 포함 -
# 실측 확인, e2fsprogs-extra에 따로 있음) - apk로 설치한 뒤 실행한다. 이 룰
# (falco-values.yaml customRules) 조건이 container.privileged=true를 요구해서
# _run_pod_falco_scenario(privileged=True)로 띄운다.
_S52_DEBUGFS_COMMAND = "apk add --no-cache e2fsprogs-extra >/dev/null 2>&1 && debugfs </dev/null 2>&1; true"


def _run_s52() -> Iterator[str]:
    """S52: 특권 컨테이너 내 Debugfs 실행 (threshold=1, falco "Debugfs Launched in
    Privileged Container"). join_on=pod, privileged pod 필요."""
    yield from _run_pod_falco_scenario(
        "s52", [_S52_DEBUGFS_COMMAND], image=k8s.PYTHON_IMAGE, privileged=True
    )


# busybox 자체 adduser 애플릿으로 재현 - falco-values.yaml의 커스텀 룰
# (account_creation_binaries = useradd/adduser/newusers)이 매칭한다.
_S53_ACCOUNT_CREATION_COMMAND = "adduser -D -H evilbackdoor 2>&1; true"


def _run_s53() -> Iterator[str]:
    """S53: 컨테이너 내부 OS 계정 생성 (threshold=1, 커스텀 falco 룰 "Account
    Creation Inside Container" - 코어 falco_rules.yaml엔 이 계열 바이너리 실행
    자체를 알리는 룰이 없어 이 프로젝트 전용으로 추가함, falco-values.yaml 참고).
    join_on=pod."""
    yield from _run_pod_falco_scenario("s53", [_S53_ACCOUNT_CREATION_COMMAND])


def _run_s54() -> Iterator[str]:
    """S54: User-Agent 누락 요청 탐지 (threshold=1, S28/S51 사각지대 보강 -
    OWASP ZAP baseline 스캔이 실제로 User-Agent 헤더를 아예 안 보내는 걸 실측
    확인해서 추가함, network.yaml S54 주석 참고)."""
    yield "  - /proxy 경유 요청에 User-Agent 헤더를 아예 안 실어 보냄 (OWASP ZAP baseline 흉내)"
    yield f"    {waf.send_missing_user_agent_request()}"


def _run_s56() -> Iterator[str]:
    """S56: ServiceAccount 토큰 파일 탈취 정황 (threshold=1, falco "ServiceAccount
    Token File Read" - Techeer-12th-b/backend/falco-values.yaml의 커스텀 룰,
    2026-07-18 추가). S1처럼 자체 sleep pod를 하나 만들어 그 안에서 마운트된
    자기 자신의 SA 토큰 파일을 exec으로 읽는다 - DataDog stratus-red-team의
    k8s.credential-access.steal-serviceaccount-token과 동일 원리. join_on=pod."""
    k8s.ensure_namespace()
    name = f"dummy-s56-{k8s.short_id()}"
    yield from _step(f"pod {name} 생성(sleep 60s)", lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, name, 60))
    try:
        k8s.wait_pod_running(k8s.DUMMY_NAMESPACE, name)
        yield "  - pod Running 대기 -> OK"
        yield from _step(
            "마운트된 ServiceAccount 토큰 파일 열람(탈취 흉내)",
            lambda: k8s.exec_in_pod(
                k8s.DUMMY_NAMESPACE, name,
                ["sh", "-c", "cat /var/run/secrets/kubernetes.io/serviceaccount/token"],
            ),
        )
    except Exception as e:
        yield f"  - pod Running 대기 -> 실패: {e} (exec 스킵)"
    yield from _step(f"pod {name} 정리", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, name))


def _run_s57() -> Iterator[str]:
    """S57: CSR 기반 클라이언트 인증서 발급 정황 (threshold=1). CSR을 만들고 스스로
    승인해서 system:kube-controller-manager 신원의 클라이언트 인증서를 발급받는다 -
    DataDog stratus-red-team의 k8s.persistence.create-client-certificate와 동일
    원리. join_on=user_or_sa."""
    name = f"dummy-csr-{k8s.short_id()}"
    yield from _step(
        f"CSR {name} 생성+승인(system:kube-controller-manager 신원의 클라이언트 인증서 발급)",
        lambda: k8s.create_and_approve_csr(name, "system:kube-controller-manager"),
    )
    yield from _step(f"CSR {name} 정리", lambda: k8s.delete_csr(name))


def _run_s58() -> Iterator[str]:
    """S58: nodes/proxy 권한상승 악용 정황 (threshold=1). nodes/proxy에 대한 get
    권한만 가진 ClusterRole을 SA에 부여한 뒤, 그 SA 토큰으로 Kubelet API를 직접
    프록시한다(어드미션 컨트롤/API 서버 로깅 우회) - DataDog stratus-red-team의
    k8s.privilege-escalation.nodes-proxy와 동일 원리. join_on=user_or_sa(프록시를
    실제로 호출한 SA 신원 기준)."""
    k8s.ensure_namespace()
    sa_name = f"dummy-np-sa-{k8s.short_id()}"
    role_name = f"dummy-np-role-{k8s.short_id()}"
    binding_name = f"dummy-np-binding-{k8s.short_id()}"
    yield from _step(f"ServiceAccount {sa_name} 생성", lambda: k8s.create_service_account(k8s.DUMMY_NAMESPACE, sa_name))
    yield from _step(
        f"nodes/proxy get 권한만 가진 ClusterRole {role_name} 생성",
        lambda: k8s.create_nodeproxy_clusterrole(role_name),
    )
    yield from _step(
        f"ClusterRoleBinding {binding_name} 생성",
        lambda: k8s.create_clusterrolebinding(binding_name, k8s.DUMMY_NAMESPACE, sa_name, role_name),
    )
    try:
        node_name = k8s.get_any_node_name()
        yield from _step(
            f"{sa_name} 토큰으로 노드 {node_name}를 거쳐 Kubelet API 프록시 호출",
            lambda: k8s.call_node_proxy(k8s.DUMMY_NAMESPACE, sa_name, node_name),
        )
    except Exception as e:
        yield f"  - 노드 조회/프록시 호출 실패: {e}"
    yield from _step(f"{binding_name} 정리", lambda: k8s.delete_clusterrolebinding(binding_name))
    yield from _step(f"{role_name} 정리", lambda: k8s.delete_clusterrole(role_name))
    yield from _step(f"{sa_name} 정리", lambda: k8s.delete_service_account(k8s.DUMMY_NAMESPACE, sa_name))


# S59(2026-07-19)용 - S5와 같은 exec 명령이지만 container="juice-shop"(distroless,
# 셸 없음)이 아니라 container="nginx-was-logger"(실제 셸 있음, 실측 확인)를 쓴다 -
# S5는 이 한계 때문에 stage2가 사실상 재현 안 되는 걸 알면서도 그대로 둔 시나리오였고
# (해당 함수 docstring 참고), S59는 처음부터 셸이 있는 사이드카를 골라 실제로
# 재현되게 한다.
_S59_STAGE2_EXEC_COMMANDS = [
    "wget -qO- --no-check-certificate https://kubernetes.default.svc/version || true",
    "wget -qO- --no-check-certificate https://kubernetes.default.svc/api || true",
]


def _run_s59() -> Iterator[str]:
    """S59: 공개 웹앱 공격(WAF) -> 컨테이너 발판 확보(Falco, 시뮬레이션) -> SA 토큰
    탈취(Falco, S56 재료) -> 그 신원으로 실제 K8s API 호출(k8s_audit, S25 재료) ->
    같은 신원으로 (cluster)rolebinding 권한상승 시도(k8s_audit, S13류)까지 5단계 -
    network.yaml S59 주석 참고. join_on=user_or_sa - stage1~3(waf/falco)은
    enrichment.py가 대상 pod(juice-shop)에 정적으로 매핑해둔 actor_identity로,
    stage4~5(k8s_audit)는 실제 인증된 user_name으로 join되는데 둘 다
    system:serviceaccount:default:default라 자연히 이어진다.

    ⚠️ stage1->stage2는 S5와 같은 시뮬레이션 한계(Juice Shop엔 실제 RCE가 없어
    WAF 공격이 진짜로 컨테이너 침투를 유발하지 않음, 그래서 이 스크립트가 두 신호를
    같은 타이밍에 각각 만들어준다). stage3부터는 진짜 인과관계다 - stage3에서 exec으로
    읽은 토큰 문자열을 실제로 캡처해서(display용으로 잘라 보여주기만 하던 이전 버전의
    한계를 고침, 2026-07-19) stage4/5에 그대로 재사용한다 - "훔친 토큰으로 그
    신원 행세를 한다"는 이 시나리오의 핵심 주장이 문자 그대로 참이 되도록."""
    real_pod = None
    try:
        real_pod = k8s.find_juice_shop_pod()
    except Exception as e:
        yield f"  - Juice Shop pod 조회 실패: {e}"
    if not real_pod:
        yield "  - Juice Shop pod을 못 찾음(default 네임스페이스에 app=juice-shop 라벨 pod 필요) - 스킵"
        return

    yield "  - stage1: WAF CRITICAL 공격 전송(공개 웹앱 익스플로잇 흉내)"
    yield f"    {waf.send_random_injection_critical_attack()}"
    time.sleep(2)

    yield "  - stage2: 해당 pod에서 K8s API 접근 시도(컨테이너 발판 확보 흉내 - S5와 같은 시뮬레이션 한계, docstring 참고)"
    yield from _exec_many("default", real_pod, _S59_STAGE2_EXEC_COMMANDS, "시도", container="nginx-was-logger")
    time.sleep(2)

    yield "  - stage3: 마운트된 ServiceAccount 토큰 파일 실제로 열람 및 탈취(여기부터 진짜 인과관계 - 이 값을 stage4/5에 그대로 재사용)"
    try:
        stolen_token = k8s.exec_in_pod(
            "default", real_pod,
            ["sh", "-c", "cat /var/run/secrets/kubernetes.io/serviceaccount/token"],
            container="nginx-was-logger",
        ).strip()
        yield f"    토큰 열람 -> OK ({stolen_token[:40]}...)"
    except Exception as e:
        yield f"    토큰 열람 실패: {e} (stage4/5 스킵)"
        return
    time.sleep(2)

    yield "  - stage4: 방금 훔친 바로 그 토큰으로 자기 자신에게 토큰 재발급 시도(실제 K8s API 호출)"
    yield (
        "    "
        + k8s.call_as_stolen_token(
            "POST",
            "/api/v1/namespaces/default/serviceaccounts/default/token",
            stolen_token,
            {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": {"expirationSeconds": 600}},
        )
    )
    time.sleep(2)

    yield "  - stage5: 같은(훔친) 토큰으로 cluster-admin 권한 바인딩 시도(권한상승 시도)"
    binding_name = f"dummy-s59-privesc-{k8s.short_id()}"
    body = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": binding_name},
        "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "default"}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
    }
    yield "    " + k8s.call_as_stolen_token(
        "POST", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", stolen_token, body
    )


def _run_s55() -> Iterator[str]:
    """S55: WAF 시그니처 단발 CRITICAL 공격 탐지 (threshold=1, network.yaml S55
    주석 참고 - WAF가 signatures.py로 이미 CRITICAL 판정을 끝낸 sqli/xss/
    os_command_injection/path_traversal 공격이 S4(다발)/S5(falco 침투 후속) 조건을
    안 채워도 correlation-engine이 예전엔 완전히 놓치던 사각지대).

    일부러 S4처럼 burst로 여러 건 보내지 않고, S5처럼 뒤이어 pod exec도 하지
    않는다 - 이 시나리오의 취지 자체가 "단 한 건, 그리고 그걸로 끝"이 상관분석
    엔진에서 잡히는지 확인하는 것이라, 공격 하나만 딱 전송한다."""
    yield "  - WAF 시그니처 기반 CRITICAL 공격 1건만 단독 전송 (burst도, 이어지는 pod 침투도 없음)"
    yield f"    {waf.send_random_injection_critical_attack()}"


# ============================================================================
# S60~S100 (2026-07-20 추가) - correlation-engine/app/scenarios/*.yaml이 S59 이후에
# 늘어난 41개 시나리오의 재현 레시피. 실제 k3d 클러스터(techeer-ids)에 붙어서
# falco 로그/kube-apiserver 감사로그/WAF·WAS 실제 응답 코드로 하나씩 실측
# 확인했다(모듈 최상단 docstring의 "2026-07-20" 문단 참고) - 그 결과 재현 불가로
# 확인된 것(S66/S69/S74/S81·S84 stage 3~4/S91/S90)과, 원래 가정이 틀려서 고친 것
# (S95의 source_ip, S82/S85의 실제 응답 코드 불일치)은 각 함수 docstring에 남겨뒀다.
#
# actor_identity 브릿지가 필요한 체인(S61/S70/S82/S83/S85/S87/S88 - 전부
# join_on=user_or_sa로 WAF/WAS/Falco와 K8s Audit을 잇는다): 이 스크립트의 K8s API
# 호출은 기본적으로 스크립트를 실행하는 kubeconfig 신원을 쓰지만(모듈 최상단 docstring
# 참고), WAF/WAS/Falco 이벤트의 user_or_sa 조인 키는 enrichment.py가 juice-shop 계열
# pod에만 정적으로 매핑해둔 actor_identity(system:serviceaccount:default:default)이거나
# (매핑 안 되면) falco가 채우는 OS 유저(root)라 스크립트의 kubeconfig 신원과 문자열이
# 다르다 - 그대로 두면 join이 안 걸린다(workload.yaml S1이 예전에 겪었던 것과 같은
# 종류의 문제, S1 docstring 참고). 그래서 이 체인들은 S59가 이미 증명한 방식대로 실제
# Juice Shop pod(신원 = system:serviceaccount:default:default)에서 falco/was 신호를
# 내고, 그 pod에 마운트된 SA 토큰을 그대로 훔쳐 k8s_audit 쪽 행위도 같은 신원으로
# 호출한다(k8s.call_as_stolen_token) - default SA는 대개 RBAC 권한이 없어 401/403이
# 나겠지만, S9/S58/S59와 같은 원칙으로 "그 신원이 그 행위를 시도했다"는 감사 이벤트
# 자체가 목적이라 실패해도 상관없다.
# ============================================================================


def _steal_juice_shop_sa_token(pod: str) -> str:
    """actor_identity 브릿지 재료 - S59 stage3과 동일하게 실제 Juice Shop pod에
    마운트된 SA 토큰을 그대로 훔쳐서 반환한다."""
    return k8s.exec_in_pod(
        "default", pod,
        ["sh", "-c", "cat /var/run/secrets/kubernetes.io/serviceaccount/token"],
        container="nginx-was-logger",
    ).strip()


def _run_s60() -> Iterator[str]:
    """S60: WAF 공격 패턴 매칭(SQLi/XSS/CMDi/Path Traversal) -> WAS 실제 5xx 응답
    확인, join=source_ip."""
    ip = waf.random_source_ip()
    yield "  - stage1: WAF가 페이로드 시그니처로 잡는 공격 전송"
    yield f"    {waf.send_random_injection_critical_attack(source_ip=ip)}"
    time.sleep(2)
    yield "  - stage2: 같은 IP로 WAS 5xx 유발 시도(실측 확인 - 깨진 JSON이 실제로 500을 반환함, 2026-07-20)"
    yield f"    {was.send_malformed_json_request(source_ip=ip)}"


def _run_s61() -> Iterator[str]:
    """S61: Falco(리버스쉘/RCE/이스케이프 계열) -> K8s Audit(권한 확장 시도),
    join=user_or_sa. S1/S3와 반대 방향 체인 - actor_identity 브릿지(모듈 docstring)로
    실제 Juice Shop pod에서 falco 신호를 내고 그 pod의 SA 토큰으로 stage2를 호출한다."""
    real_pod = None
    try:
        real_pod = k8s.find_juice_shop_pod()
    except Exception as e:
        yield f"  - Juice Shop pod 조회 실패: {e}"
    if not real_pod:
        yield "  - Juice Shop pod을 못 찾음 - 스킵"
        return

    yield "  - stage1: 해당 pod에서 리버스쉘/RCE 계열 명령 실행(S32/S34 재료)"
    yield from _exec_many(
        "default", real_pod, [_S34_DROP_EXECUTE_COMMAND, _S32_DUP_NETWORK_COMMAND], "시도",
        container="nginx-was-logger",
    )
    time.sleep(2)

    yield "  - stage2: 같은 pod의 SA 토큰을 훔쳐서 같은 신원으로 K8s API 권한 확장 시도(secrets 조회)"
    try:
        token = _steal_juice_shop_sa_token(real_pod)
        yield "    " + k8s.call_as_stolen_token(
            "GET", "/api/v1/namespaces/default/secrets/dummy-nonexistent", token
        )
    except Exception as e:
        yield f"    토큰 탈취/API 호출 실패: {e}"


def _run_s62() -> Iterator[str]:
    """S62: RBAC 열거 정찰(S31 재료) 이후 저빈도 민감 리소스 접근, join=user_or_sa,
    requires_recent_fire: S31 - S31이 먼저 실제로 발화(threshold=5)해야 하므로 이
    함수가 그 조건을 스스로 채운 뒤 매치 액션을 수행한다. 둘 다 k8s_audit만 쓰는
    시나리오라 스크립트 자신의 kubeconfig 신원 하나로 자동 조인된다(모듈 docstring)."""
    yield "  - 선행 조건: S31(RBAC 권한/역할 열거 정황)을 먼저 발화시킨다"
    yield from _run_s31()
    time.sleep(2)

    k8s.ensure_namespace()
    secret_name = f"dummy-s62-{k8s.short_id()}"
    yield "  - 그 뒤 민감 리소스(시크릿) 조회 1건"
    yield from _step(
        f"시크릿 {secret_name} 생성(조회용)",
        lambda: k8s.create_secret(k8s.DUMMY_NAMESPACE, secret_name, {"password": "hunter2"}),
    )
    yield from _step("get secrets", lambda: k8s.get_secret(k8s.DUMMY_NAMESPACE, secret_name))
    yield from _step(f"{secret_name} 정리", lambda: k8s.delete_secret(k8s.DUMMY_NAMESPACE, secret_name))


def _run_s63() -> Iterator[str]:
    """S63: WAF CORS 위반 탐지 -> WAS 인증 필요 엔드포인트 정상 응답 확인, join=source_ip."""
    ip = waf.random_source_ip()
    yield "  - stage1: 화이트리스트에 없는 Origin으로 CORS 위반 요청 전송"
    yield f"    {waf.send_cors_violation_request(source_ip=ip)}"
    time.sleep(2)
    yield "  - stage2: 같은 IP로 /rest/user/whoami 요청(항상 200을 반환하는 엔드포인트)"
    yield f"    {was.send_whoami_request(source_ip=ip)}"


def _run_s64() -> Iterator[str]:
    """S64: Falco(로그 삭제) -> K8s Audit(pod 삭제) -> K8s Audit(같은 이름으로 pod
    재생성), join=pod, window=180. 삭제된 pod와 정확히 같은 이름으로 재생성해야
    join이 이어진다(workload.yaml S64 주석 참고)."""
    k8s.ensure_namespace()
    name = f"dummy-s64-{k8s.short_id()}"
    yield from _step(f"pod {name} 생성(sleep 60s)", lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, name, 60))
    try:
        k8s.wait_pod_running(k8s.DUMMY_NAMESPACE, name)
        yield "  - stage1: 시스템 로그 파일 O_TRUNC(흔적 인멸 흉내)"
        yield from _step(
            "Clear Log Activities 재현",
            lambda: k8s.exec_in_pod(k8s.DUMMY_NAMESPACE, name, ["sh", "-c", _S23_CLEAR_LOG_COMMAND]),
        )
    except Exception as e:
        yield f"  - pod 대기 실패: {e} (stage1 스킵)"
    time.sleep(1)

    yield f"  - stage2: pod {name} 삭제"
    yield from _step(f"pod {name} 삭제", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, name))
    time.sleep(1)

    yield f"  - stage3: 정확히 같은 이름({name})으로 pod 재생성"
    yield from _step(f"pod {name} 재생성", lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, name, 10))
    time.sleep(1)
    yield from _step(f"pod {name} 정리", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, name))


def _run_s65() -> Iterator[str]:
    """S65: WAF JWT 위조(alg:none) 탐지 -> WAS 인증 필요 엔드포인트 정상 응답 확인,
    join=source_ip."""
    ip = waf.random_source_ip()
    yield "  - stage1: JWT alg:none 위조 헤더로 요청 전송"
    yield f"    {waf.send_jwt_alg_none_critical(source_ip=ip)}"
    time.sleep(2)
    yield "  - stage2: 같은 IP로 /rest/user/whoami 요청"
    yield f"    {was.send_whoami_request(source_ip=ip)}"


def _run_s66() -> Iterator[str]:
    """S66: Falco(계정 생성) -> Falco(비표준 포트 SSH 연결), join=pod. stage2가
    S42와 같은 재현 불가 룰(실제 ssh 클라이언트 바이너리 필요) - stage1은 실제로
    수행하지만 stage2가 원천적으로 안 걸려 이 시퀀스는 완주하지 못한다(정직하게
    보고, _run_s42 참고)."""
    yield "  - stage1: 컨테이너 내부 OS 계정 생성(S53 재료)"
    yield from _run_pod_falco_scenario("s66", [_S53_ACCOUNT_CREATION_COMMAND])
    yield (
        "  - stage2 스킵: S42와 동일한 이유로 재현 불가(실제 ssh 클라이언트 바이너리 "
        "필요) - 이 시퀀스는 완주되지 않습니다(정직하게 보고)."
    )


def _run_s67() -> Iterator[str]:
    """S67: K8s Audit(ephemeral container 추가) -> Falco(미확인 바이너리 실행),
    join=pod - 같은 pod에서 두 단계를 이어붙인다."""
    k8s.ensure_namespace()
    name = f"dummy-s67-{k8s.short_id()}"
    yield from _step(f"pod {name} 생성", lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, name, 60))
    try:
        k8s.wait_pod_running(k8s.DUMMY_NAMESPACE, name)
        yield from _step(
            "stage1: ephemeral container 추가", lambda: k8s.add_ephemeral_container(k8s.DUMMY_NAMESPACE, name)
        )
        time.sleep(2)
        yield "  - stage2: 같은 pod에서 미확인 바이너리 드롭 후 실행"
        yield from _step(
            "Drop and execute 재현",
            lambda: k8s.exec_in_pod(k8s.DUMMY_NAMESPACE, name, ["sh", "-c", _S34_DROP_EXECUTE_COMMAND]),
        )
    except Exception as e:
        yield f"  - pod 대기 실패: {e}"
    yield from _step(f"pod {name} 정리", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, name))


def _run_s68() -> Iterator[str]:
    """S68: K8s Audit(시스템 네임스페이스 pod 생성) -> Falco(크립토마이닝 또는 계정
    생성), join=pod - 같은 pod에서 이어붙인다."""
    name = f"dummy-s68-{k8s.short_id()}"
    yield from _step(f"stage1: kube-public에 pod {name} 생성", lambda: k8s.create_sleep_pod("kube-public", name, 60))
    try:
        k8s.wait_pod_running("kube-public", name)
        time.sleep(2)
        yield "  - stage2: 같은 pod에서 크립토마이닝 정황 재현"
        yield from _step(
            "Stratum 프로토콜 재현", lambda: k8s.exec_in_pod("kube-public", name, ["sh", "-c", _S22_MINER_COMMAND])
        )
    except Exception as e:
        yield f"  - pod 대기 실패: {e}"
    yield from _step(f"pod {name} 정리", lambda: k8s.delete_pod("kube-public", name))


def _run_s69() -> Iterator[str]:
    """S69: Falco(시스템 계정 인터랙티브 셸) -> Falco(Debugfs 이스케이프), join=pod.
    stage1이 S43과 같은 재현 불가 룰(실제 SSH 세션 필요) - 이 시퀀스는 완주하지
    못한다(정직하게 보고, _run_s43 참고)."""
    yield (
        "  - 스킵: stage1(System user interactive)이 S43과 동일한 이유로 재현 불가"
        "(sshd/systemd-logind/login 조상 프로세스, 즉 실제 SSH 세션 필요) - 이 "
        "시퀀스는 완주되지 않습니다(정직하게 보고)."
    )


_S70_RECON_COMMAND = "whoami; id; who; uname -a"


def _run_s70() -> Iterator[str]:
    """S70: Falco(인터랙티브 정찰) -> K8s Audit(권한 확장 시도), join=user_or_sa.
    S61과 같은 actor_identity 브릿지(모듈 docstring)."""
    real_pod = None
    try:
        real_pod = k8s.find_juice_shop_pod()
    except Exception as e:
        yield f"  - Juice Shop pod 조회 실패: {e}"
    if not real_pod:
        yield "  - Juice Shop pod을 못 찾음 - 스킵"
        return

    yield "  - stage1: 해당 pod에서 whoami/id/who/uname 인터랙티브 정찰 명령 실행"
    yield from _step(
        "정찰 명령 실행",
        lambda: k8s.exec_in_pod("default", real_pod, ["sh", "-c", _S70_RECON_COMMAND], container="nginx-was-logger"),
    )
    time.sleep(2)

    yield "  - stage2: 같은 pod의 SA 토큰을 훔쳐서 권한 확장 시도(secrets 조회)"
    try:
        token = _steal_juice_shop_sa_token(real_pod)
        yield "    " + k8s.call_as_stolen_token(
            "GET", "/api/v1/namespaces/default/secrets/dummy-nonexistent", token
        )
    except Exception as e:
        yield f"    토큰 탈취/API 호출 실패: {e}"


def _run_s71() -> Iterator[str]:
    """S71: NetworkPolicy 삭제를 통한 방어 설정 무력화 (threshold=1)."""
    k8s.ensure_namespace()
    name = f"dummy-netpol-{k8s.short_id()}"
    yield from _step(f"NetworkPolicy {name} 생성", lambda: k8s.create_networkpolicy(k8s.DUMMY_NAMESPACE, name))
    time.sleep(1)
    yield from _step(f"{name} 삭제(방어 설정 무력화로 판정됨)", lambda: k8s.delete_networkpolicy(k8s.DUMMY_NAMESPACE, name))


def _run_s72() -> Iterator[str]:
    """S72: 워크로드 삭제를 통한 서비스 중단 (threshold=1, match 조건은
    orchestrator_resource_type in [deployments, statefulsets, services] - Deployment로 재현)."""
    k8s.ensure_namespace()
    name = f"dummy-deploy-{k8s.short_id()}"
    yield from _step(f"Deployment {name} 생성", lambda: k8s.create_deployment(k8s.DUMMY_NAMESPACE, name))
    time.sleep(1)
    yield from _step(f"{name} 삭제(서비스 중단으로 판정됨)", lambda: k8s.delete_deployment(k8s.DUMMY_NAMESPACE, name))


def _run_s73() -> Iterator[str]:
    """S73: DaemonSet 지속성 확보와 위험한 런타임 설정의 결합 탐지, join=user_or_sa -
    두 단계 다 스크립트 자신의 kubeconfig 신원으로 하므로 별도 브릿지 없이 자동으로
    조인된다(모듈 docstring)."""
    k8s.ensure_namespace()
    ds_name = f"dummy-s73-ds-{k8s.short_id()}"
    pod_name = f"dummy-s73-pod-{k8s.short_id()}"
    yield from _step(f"stage1: DaemonSet {ds_name} 생성", lambda: k8s.create_daemonset(k8s.DUMMY_NAMESPACE, ds_name))
    time.sleep(2)
    yield from _step(
        f"stage2: 위험한 설정(privileged)의 pod {pod_name} 생성",
        lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, pod_name, 10, privileged=True),
    )
    time.sleep(1)
    yield from _step(f"pod {pod_name} 정리", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, pod_name))
    yield from _step(f"DaemonSet {ds_name} 정리", lambda: k8s.delete_daemonset(k8s.DUMMY_NAMESPACE, ds_name))


def _run_s74() -> Iterator[str]:
    """S74: Falco(비표준 포트 SSH 연결) -> Falco(미확인 바이너리/Netcat RCE),
    join=pod, window=60. stage1이 S42와 같은 재현 불가 룰이라 이 시퀀스는 완주하지
    못한다(정직하게 보고, _run_s42 참고)."""
    yield (
        "  - 스킵: stage1(Disallowed SSH Connection Non Standard Port)이 S42와 동일한 "
        "이유로 재현 불가(실제 ssh 클라이언트 바이너리 필요) - 이 시퀀스는 완주되지 "
        "않습니다(정직하게 보고)."
    )


# falco_rules.yaml의 "Detect release_agent File Container Escapes" 조건은 실제
# cgroup 탈출을 완주할 필요 없이 "open_write and fd.name endswith release_agent"
# (+ root/CAP_DAC_OVERRIDE 및 CAP_SYS_ADMIN)만 보면 매칭된다(S22의 가짜 stratum URI,
# S37의 busybox-symlink-as-shred와 같은 "조건 문자열만 만족시키는" 트릭) - 실제 cgroup
# v1 release_agent 파일을 여는 대신, 이름이 "release_agent"로 끝나는 파일을 privileged
# 컨테이너(CAP_SYS_ADMIN 보유) 안에서 쓰기 모드로 열기만 한다.
_S75_RELEASE_AGENT_COMMAND = "echo x > /tmp/dummy-release_agent"


def _run_s75() -> Iterator[str]:
    """S75: K8s Audit(위험한 pod 생성) -> Falco(release_agent 이스케이프 확인),
    join=pod - pod 생성 자체가 stage1이라 그 pod 안에서 곧바로 stage2를 재현한다."""
    k8s.ensure_namespace()
    name = f"dummy-s75-{k8s.short_id()}"
    yield from _step(
        f"stage1: privileged pod {name} 생성(컨테이너 이스케이프 벡터)",
        lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, name, 60, privileged=True),
    )
    try:
        k8s.wait_pod_running(k8s.DUMMY_NAMESPACE, name)
        yield "  - stage2: 같은 pod에서 release_agent 이스케이프 정황 재현"
        yield from _step(
            "release_agent 파일 쓰기",
            lambda: k8s.exec_in_pod(k8s.DUMMY_NAMESPACE, name, ["sh", "-c", _S75_RELEASE_AGENT_COMMAND]),
        )
    except Exception as e:
        yield f"  - pod 대기 실패: {e}"
    yield from _step(f"pod {name} 정리", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, name))


def _run_s76() -> Iterator[str]:
    """S76: Falco(이스케이프 시도: release_agent) -> Falco(디스크 대량 삭제),
    join=pod - 같은 privileged pod 안에서 이어붙인다."""
    yield from _run_pod_falco_scenario(
        "s76", [_S75_RELEASE_AGENT_COMMAND, _S37_REMOVE_BULK_DATA_COMMAND], privileged=True
    )


def _run_s77() -> Iterator[str]:
    """S77: kubectl port-forward를 이용한 프록시 터널 구축 탐지 (threshold=1)."""
    k8s.ensure_namespace()
    name = f"dummy-s77-{k8s.short_id()}"
    yield from _step(f"pod {name} 생성", lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, name, 30))
    try:
        k8s.wait_pod_running(k8s.DUMMY_NAMESPACE, name)
        yield from _step(
            "포트포워드 연결 시도(create/get pods/portforward)",
            lambda: k8s.call_port_forward(k8s.DUMMY_NAMESPACE, name),
        )
    except Exception as e:
        yield f"  - pod 대기 실패: {e}"
    yield from _step(f"pod {name} 정리", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, name))


def _run_s78() -> Iterator[str]:
    """S78: 익스플로잇/퍼징 트래픽 이후 서비스 불안정 확인, join=source_ip -
    S60과 재료 공유(stage2 상태코드 범위만 504까지 더 넓음)."""
    ip = waf.random_source_ip()
    yield "  - stage1: WAF가 페이로드 시그니처로 잡는 공격 전송"
    yield f"    {waf.send_random_injection_critical_attack(source_ip=ip)}"
    time.sleep(2)
    yield "  - stage2: 같은 IP로 WAS 5xx 유발 시도(실측 확인 - 깨진 JSON이 실제로 500을 반환함, 2026-07-20)"
    yield f"    {was.send_malformed_json_request(source_ip=ip)}"


def _run_s79() -> Iterator[str]:
    """S79: 서비스어카운트 대량 열거 탐지 (threshold=10/60s)."""
    k8s.ensure_namespace()
    try:
        k8s.burst_list_serviceaccounts(k8s.DUMMY_NAMESPACE, 11)
        yield "  - default 네임스페이스에 serviceaccount 목록 조회 11회 연속 호출 -> OK"
    except Exception as e:
        yield f"  - serviceaccount 목록 조회 11회 연속 호출 -> 실패: {e}"


def _run_s80() -> Iterator[str]:
    """S80: Falco(PTRACE 부착) -> Falco(미확인 바이너리 실행), join=pod - 같은 pod
    안에서 이어붙인다(alpine 기반 python:3-alpine에도 busybox가 포함돼 있어 stage2
    명령도 그대로 동작)."""
    yield from _run_pod_falco_scenario(
        "s80", [_pipe_python(_S40_PTRACE_ATTACH_SCRIPT), _S34_DROP_EXECUTE_COMMAND], image=k8s.PYTHON_IMAGE
    )


def _run_s81() -> Iterator[str]:
    """S81: 웹 침투(WAF) -> 컨테이너 침해 확인(Falco) -> 컨테이너 이스케이프(Falco)
    -> 커널 모듈 삽입(Falco), join=pod, 4단계. ⚠️ 전체 체인이 하나의 pod(join=pod)에서
    이어져야 하는데, stage1(WAF)은 실제 서빙 pod에 매핑되고(enrichment.py) 그 pod은
    이 스크립트가 만든 pod이 아니라 실제 배포된 Juice Shop pod이다 - 그 pod의
    사이드카(nginx-was-logger)는 privileged가 아니라서 stage3(Debugfs, container.
    privileged=true 필수)/stage4(커널 모듈 삽입, CAP_SYS_MODULE 필수)가 요구하는 권한
    자체가 없다. S5/S59와 같은 시뮬레이션 한계 - stage1/2까지만 실제로 재현하고
    stage3/4는 시도하지 않는다(가짜로 성공 처리하지 않음, 정직하게 보고)."""
    real_pod = None
    try:
        real_pod = k8s.find_juice_shop_pod()
    except Exception as e:
        yield f"  - Juice Shop pod 조회 실패: {e}"
    if not real_pod:
        yield "  - Juice Shop pod을 못 찾음 - 스킵"
        return

    yield "  - stage1: WAF CRITICAL 공격 전송"
    yield f"    {waf.send_random_critical_attack()}"
    time.sleep(2)

    yield "  - stage2: 해당 pod에서 쉘 실행/K8s API 접근 시도"
    yield from _exec_many("default", real_pod, _S5_EXEC_COMMANDS, "시도", container="nginx-was-logger")

    yield (
        "  - stage3/4 스킵: 실제 Juice Shop 사이드카(nginx-was-logger)는 privileged "
        "컨테이너가 아니라 Debugfs 실행/커널 모듈 삽입 둘 다 필요한 권한 자체가 없습니다 - "
        "이 4단계 체인은 stage1/2까지만 재현되고 완주되지 않습니다(정직하게 보고)."
    )


def _run_s82() -> Iterator[str]:
    """S82: 파일 업로드(WAS) -> 크립토마이닝(Falco) -> CronJob 지속성 확보(K8s Audit),
    join=user_or_sa, 3단계. actor_identity 브릿지(모듈 docstring) - stage3은 실제
    Juice Shop pod의 SA 토큰으로 호출해야 stage1/2와 같은 신원으로 조인된다.

    ⚠️ 실측 확인(2026-07-20): 이 클러스터의 `/file-upload`는 성공하면 200/201이
    아니라 204(No Content)를 반환한다 - correlation-engine의 S82 yaml
    match 조건(`http_response_status_code: [200, 201]`)이 204를 포함하지 않아서,
    이 stage1 요청 자체는 실제로 성공해도 상관분석에서 매칭되지 않는다. 이 스크립트가
    아니라 correlation-engine 쪽 yaml 조건이 실제 앱 동작과 어긋난 것으로 보인다 -
    별도로 확인/수정이 필요하다(그대로 요청은 보낸다 - 가짜로 200을 보고하지 않음)."""
    real_pod = None
    try:
        real_pod = k8s.find_juice_shop_pod()
    except Exception as e:
        yield f"  - Juice Shop pod 조회 실패: {e}"
    if not real_pod:
        yield "  - Juice Shop pod을 못 찾음 - 스킵"
        return

    yield "  - stage1: 파일 업로드(⚠️ 실측 확인 - 성공해도 200/201이 아니라 204를 반환해 S82 yaml 조건과 안 맞음, docstring 참고)"
    yield f"    {was.send_file_upload_request()}"
    time.sleep(2)

    yield "  - stage2: 해당 pod에서 크립토마이닝 정황 재현"
    yield from _step(
        "Stratum 프로토콜 재현",
        lambda: k8s.exec_in_pod("default", real_pod, ["sh", "-c", _S22_MINER_COMMAND], container="nginx-was-logger"),
    )
    time.sleep(2)

    yield "  - stage3: 같은 pod의 SA 토큰을 훔쳐서 그 신원으로 CronJob 생성 시도"
    try:
        token = _steal_juice_shop_sa_token(real_pod)
        cronjob_name = f"dummy-s82-{k8s.short_id()}"
        body = {
            "apiVersion": "batch/v1", "kind": "CronJob",
            "metadata": {"name": cronjob_name, "namespace": "default"},
            "spec": {"schedule": "*/5 * * * *", "jobTemplate": {"spec": {"template": {"spec": {
                "containers": [{"name": "main", "image": k8s.BUSYBOX_IMAGE, "command": ["echo", "hi"]}],
                "restartPolicy": "OnFailure",
            }}}}},
        }
        yield "    " + k8s.call_as_stolen_token(
            "POST", "/apis/batch/v1/namespaces/default/cronjobs", token, body
        )
    except Exception as e:
        yield f"    토큰 탈취/API 호출 실패: {e}"


def _run_s83() -> Iterator[str]:
    """S83: 브루트포스(WAF) -> 계정 탈취 성공(WAS) -> 관리 API 오남용(K8s Audit),
    join=user_or_sa, 3단계. stage2는 이 실행 전용 임시 계정을 스스로 등록해 실제
    로그인 성공(200)을 얻는다(was_actions.register_and_login 참고). stage3은
    actor_identity 브릿지(모듈 docstring) - 실제 Juice Shop pod의 SA 토큰으로
    호출해야 stage1/2(system:serviceaccount:default:default)와 조인된다."""
    real_pod = None
    try:
        real_pod = k8s.find_juice_shop_pod()
    except Exception as e:
        yield f"  - Juice Shop pod 조회 실패: {e}"
    if not real_pod:
        yield "  - Juice Shop pod을 못 찾음 - 스킵"
        return

    ip = waf.random_source_ip()
    yield "  - stage1: WAF 경유 로그인 실패 반복(브루트포스 판정)"
    for line in waf.send_brute_force_burst_via_waf(6):
        yield f"    {line}"
    time.sleep(2)

    yield "  - stage2: 임시 계정을 스스로 등록하고 로그인 성공"
    ok, detail = was.register_and_login(source_ip=ip)
    yield f"    {detail}"
    if not ok:
        yield "    로그인 성공(200)을 못 받음 - stage3은 계속 시도하되 이 체인은 완주 안 될 수 있음"
    time.sleep(2)

    yield "  - stage3: 같은 pod의 SA 토큰을 훔쳐서 관리 API(ConfigMap 생성) 오남용 시도"
    try:
        token = _steal_juice_shop_sa_token(real_pod)
        cm_name = f"dummy-s83-{k8s.short_id()}"
        body = {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": cm_name, "namespace": "default"}, "data": {"note": "dummy"},
        }
        yield "    " + k8s.call_as_stolen_token("POST", "/api/v1/namespaces/default/configmaps", token, body)
    except Exception as e:
        yield f"    토큰 탈취/API 호출 실패: {e}"


def _run_s84() -> Iterator[str]:
    """S84: WAF 익스플로잇 -> WAS 에러율 증가 -> Falco(웹서버 프로세스의 이상 자식
    프로세스), join=pod, 3단계. ⚠️ stage3은 "웹서버 프로세스 자신이 낳은 자식
    프로세스"를 요구하는데 kubectl exec은 컨테이너 런타임(containerd-shim)의 자식으로
    새 프로세스를 붙이는 것이라 애초에 웹서버 프로세스의 자식이 될 수 없다 - kubectl
    exec으로는 구조적으로 재현 불가능하다(가짜로 성공 처리하지 않음, 정직하게 보고)."""
    ip = waf.random_source_ip()
    yield "  - stage1: WAF가 페이로드 시그니처로 잡는 공격 전송"
    yield f"    {waf.send_random_injection_critical_attack(source_ip=ip)}"
    time.sleep(2)

    yield "  - stage2: 같은 IP로 WAS 5xx 유발 시도(실측 확인 - 깨진 JSON이 실제로 500을 반환함, 2026-07-20)"
    yield f"    {was.send_malformed_json_request(source_ip=ip)}"

    yield (
        "  - stage3 스킵: \"웹서버 프로세스 자신이 낳은 자식 프로세스\"가 필요한데 kubectl exec은 "
        "컨테이너 런타임의 자식으로 새 프로세스를 붙이는 것이라(웹서버 프로세스의 자식이 될 수 "
        "없음) 이 도구로는 구조적으로 재현 불가능합니다(정직하게 보고) - 이 시퀀스는 stage1/2까지만 "
        "재현되고 완주되지 않습니다."
    )


def _run_s85(_pod_name_out: Optional[List[str]] = None) -> Iterator[str]:
    """S85: 인증 우회(WAS) -> 관리 콘솔 접근(WAS) -> RBAC 권한 상승(K8s Audit) ->
    위험한 pod 생성(K8s Audit), join=user_or_sa, 4단계, stamps_fired_marker(S94가
    이어받음). stage3/4는 actor_identity 브릿지(모듈 docstring)로 실제 Juice Shop
    pod의 SA 토큰을 쓴다.

    stage1/2 엔드포인트는 2026-07-20에 `/rest/admin/application-configuration`에서
    `/api/Users`로 교체됐다 - 실측 확인 결과 전자는 이 배포에서 인증 없이도 이미
    200을 반환해서 "인증 우회 확인"이라는 이 시나리오의 전제 자체가 성립하지
    않았다. `/api/Users`(사용자 목록 조회)는 실제로 무인증 401, 유효한 로그인
    토큰이면 200으로 확인됐다(was_actions.send_api_users_list docstring 참고,
    correlation-engine network.yaml S85 주석도 같이 갱신함) - stage2는 이 실행
    전용 임시 계정을 스스로 등록/로그인해 진짜 200을 얻는다(S83과 같은 기법,
    was_actions.register_and_get_token).

    _pod_name_out: S94가 stage4에서 만든 pod 이름을 이어받을 수 있게 하는 선택적
    출력 파라미터(제너레이터는 return 값을 못 써서 리스트에 append하는 방식으로
    전달) - S94가 아니라 단독 실행할 때는 그냥 두면 된다."""
    real_pod = None
    try:
        real_pod = k8s.find_juice_shop_pod()
    except Exception as e:
        yield f"  - Juice Shop pod 조회 실패: {e}"
    if not real_pod:
        yield "  - Juice Shop pod을 못 찾음 - 스킵"
        return

    ip = waf.random_source_ip()
    yield "  - stage1: 인증 없이 사용자 목록 조회 시도(401 예상)"
    yield f"    {was.send_api_users_list(source_ip=ip)}"
    time.sleep(2)

    yield "  - stage2: 임시 계정을 스스로 등록/로그인해서 그 토큰으로 같은 API 재시도(200 예상)"
    token, detail = was.register_and_get_token(source_ip=ip, email_prefix="dummy-s85")
    yield f"    {detail}"
    if token:
        yield f"    {was.send_api_users_list(source_ip=ip, token=token)}"
    else:
        yield "    로그인 실패로 stage2 요청을 못 보냄 - 이 체인은 완주되지 않을 수 있음"
    time.sleep(2)

    try:
        token = _steal_juice_shop_sa_token(real_pod)
    except Exception as e:
        yield f"  - stage3/4 스킵: 토큰 탈취 실패: {e}"
        return

    yield "  - stage3: 같은 신원으로 RBAC 바인딩 생성 시도"
    rb_name = f"dummy-s85-{k8s.short_id()}"
    rb_body = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": rb_name, "namespace": "default"},
        "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "default"}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"},
    }
    yield "    " + k8s.call_as_stolen_token(
        "POST", "/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings", token, rb_body
    )
    time.sleep(2)

    yield (
        "  - stage4: 같은 신원으로 위험한(privileged) pod 생성 시도(⚠️ default SA는 "
        "대개 RBAC 권한이 없어 403 예상 - 그러면 pod 자체가 안 생겨서 S94가 이어받을 "
        "실제 pod이 없다)"
    )
    pod_name = f"dummy-s85-pod-{k8s.short_id()}"
    if _pod_name_out is not None:
        _pod_name_out.append(pod_name)
    pod_body = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": "default"},
        "spec": {
            "containers": [{
                "name": "main", "image": k8s.BUSYBOX_IMAGE, "command": ["sleep", "60"],
                "securityContext": {"privileged": True},
            }],
            "restartPolicy": "Never",
        },
    }
    yield "    " + k8s.call_as_stolen_token("POST", "/api/v1/namespaces/default/pods", token, pod_body)


def _run_s86() -> Iterator[str]:
    """S86: MutatingWebhookConfiguration 생성/수정을 통한 백도어 등록 탐지 (threshold=1)."""
    name = f"dummy-webhook-{k8s.short_id()}"
    yield from _step(f"MutatingWebhookConfiguration {name} 생성", lambda: k8s.create_mutating_webhook(name))
    yield from _step(f"{name} 정리", lambda: k8s.delete_mutating_webhook(name))


def _run_s87() -> Iterator[str]:
    """S87: CronJob 등록(K8s Audit) -> 의심스러운 실행 확인(Falco), join=user_or_sa.
    actor_identity 브릿지(모듈 docstring) - stage1을 실제 Juice Shop pod의 SA
    토큰으로 호출해야 stage2(그 pod에서 재현)와 같은 신원으로 조인된다."""
    real_pod = None
    try:
        real_pod = k8s.find_juice_shop_pod()
    except Exception as e:
        yield f"  - Juice Shop pod 조회 실패: {e}"
    if not real_pod:
        yield "  - Juice Shop pod을 못 찾음 - 스킵"
        return

    yield "  - stage1: 같은 pod의 SA 토큰을 훔쳐서 그 신원으로 CronJob 생성 시도"
    try:
        token = _steal_juice_shop_sa_token(real_pod)
        cronjob_name = f"dummy-s87-{k8s.short_id()}"
        body = {
            "apiVersion": "batch/v1", "kind": "CronJob",
            "metadata": {"name": cronjob_name, "namespace": "default"},
            "spec": {"schedule": "*/5 * * * *", "jobTemplate": {"spec": {"template": {"spec": {
                "containers": [{"name": "main", "image": k8s.BUSYBOX_IMAGE, "command": ["echo", "hi"]}],
                "restartPolicy": "OnFailure",
            }}}}},
        }
        yield "    " + k8s.call_as_stolen_token("POST", "/apis/batch/v1/namespaces/default/cronjobs", token, body)
    except Exception as e:
        yield f"    토큰 탈취/API 호출 실패: {e}"
        return
    time.sleep(2)

    yield "  - stage2: 같은 pod에서 의심스러운 바이너리 실행(미확인 바이너리 드롭)"
    yield from _step(
        "Drop and execute 재현",
        lambda: k8s.exec_in_pod("default", real_pod, ["sh", "-c", _S34_DROP_EXECUTE_COMMAND], container="nginx-was-logger"),
    )


def _run_s88() -> Iterator[str]:
    """S88: 대량 데이터 삭제(Falco) -> 백업/PVC 삭제(K8s Audit), join=user_or_sa.
    actor_identity 브릿지(모듈 docstring) - stage1을 실제 Juice Shop pod에서 재현하고
    stage2를 그 pod의 SA 토큰으로 호출해야 같은 신원으로 조인된다. match 조건은
    orchestrator_resource_type in [volumesnapshots, persistentvolumeclaims]라
    VolumeSnapshot(external-snapshotter CRD 필요, k3d 기본 설치엔 없음) 대신 PVC로
    재현한다."""
    real_pod = None
    try:
        real_pod = k8s.find_juice_shop_pod()
    except Exception as e:
        yield f"  - Juice Shop pod 조회 실패: {e}"
    if not real_pod:
        yield "  - Juice Shop pod을 못 찾음 - 스킵"
        return

    yield "  - stage1: 해당 pod에서 디스크 대량 데이터 삭제 정황 재현"
    yield from _step(
        "Remove Bulk Data 재현",
        lambda: k8s.exec_in_pod("default", real_pod, ["sh", "-c", _S37_REMOVE_BULK_DATA_COMMAND], container="nginx-was-logger"),
    )
    time.sleep(2)

    yield "  - stage2: 같은 pod의 SA 토큰을 훔쳐서 PVC 생성 후 삭제(백업 삭제 흉내)"
    try:
        token = _steal_juice_shop_sa_token(real_pod)
        pvc_name = f"dummy-s88-{k8s.short_id()}"
        create_body = {
            "apiVersion": "v1", "kind": "PersistentVolumeClaim",
            "metadata": {"name": pvc_name, "namespace": "default"},
            "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Mi"}}},
        }
        yield "    " + k8s.call_as_stolen_token(
            "POST", "/api/v1/namespaces/default/persistentvolumeclaims", token, create_body
        )
        time.sleep(1)
        yield "    " + k8s.call_as_stolen_token(
            "DELETE", f"/api/v1/namespaces/default/persistentvolumeclaims/{pvc_name}", token
        )
    except Exception as e:
        yield f"    토큰 탈취/API 호출 실패: {e}"


def _run_s89() -> Iterator[str]:
    """S89: 컨테이너 로그 조회를 통한 자격증명 유출 탐지 (threshold=1, get pods/log)."""
    k8s.ensure_namespace()
    name = f"dummy-s89-{k8s.short_id()}"
    yield from _step(f"pod {name} 생성", lambda: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, name, 30))
    try:
        k8s.wait_pod_running(k8s.DUMMY_NAMESPACE, name)
        yield from _step("pod 로그 조회(get pods/log)", lambda: k8s.read_pod_log(k8s.DUMMY_NAMESPACE, name))
    except Exception as e:
        yield f"  - pod 대기 실패: {e}"
    yield from _step(f"pod {name} 정리", lambda: k8s.delete_pod(k8s.DUMMY_NAMESPACE, name))


def _run_s90() -> Iterator[str]:
    """S90: 여러 pod에 걸친 동일 공격 시그니처의 짧은 확산 (cardinality, join=rule_id,
    threshold=3/60s, distinct_field=orchestrator_resource_name). ⚠️ 이 테스트
    하네스(waf_actions.py)는 WAF_URL 하나로 단일 타깃만 때리므로, enrichment.py가
    응답 헤더로 채우는 실제 서빙 pod가 레플리카 분산 없이 항상 같은 pod로 찍힐 수
    있다 - 그러면 "서로 다른 3개 pod" 조건 자체가 이 하네스로는 보장되지 않는다
    (정직하게 보고). 같은 공격 유형(같은 rule_id)을 여러 번 반복 전송해서, 레플리카가
    여럿이라 실제로 요청이 분산되는 환경이라면 우연히도 조건이 채워질 수 있게 한다."""
    yield "  - 같은 공격 시그니처(SQLi)를 6건 연속 전송(⚠️ 서로 다른 pod로 분산되는지는 이 하네스가 보장 못 함, docstring 참고)"
    for _ in range(6):
        yield f"    {waf.send_sqli_critical()}"
        time.sleep(1)


def _run_s91() -> Iterator[str]:
    """S91: 반복적 정찰-침해 사이클 탐지 (cardinality, window_seconds=604800(7일),
    distinct_field=event_date, threshold=3 - "일주일 중 최소 3일에 정찰 패턴").
    재현 불가로 스킵 - 한 번의 스크립트 실행 안에서는 벽시계 시간을 며칠씩 앞당길
    방법이 없다(시스템 클록 조작은 이 스크립트의 권한 밖이고, 감사로그 타임스탬프는
    kube-apiserver가 실제 요청 처리 시각으로 찍으므로 조작 불가) - 이 시나리오를
    실제로 확인하려면 S10 재료(get/list/watch burst)를 최소 3일에 걸쳐 각각 실행해야
    한다(정직하게 보고, S42/S43/S48과 같은 원칙)."""
    yield (
        "  - 스킵: 이 시나리오는 서로 다른 3일에 걸친 정찰 패턴을 요구하는데"
        "(window_seconds=604800), 한 번의 스크립트 실행으로는 벽시계 시간을 앞당길 "
        "방법이 없어 재현할 수 없습니다(정직하게 보고) - 실제로 확인하려면 S10 재료를 "
        "최소 3일에 걸쳐 각각 실행할 것."
    )


def _run_s92() -> Iterator[str]:
    """S92: 동일 IP의 WAS 엔드포인트 다양성 스캔 (cardinality, join=source_ip,
    threshold=15/60s, distinct_field=url_path)."""
    ip = waf.random_source_ip()
    yield "  - 같은 IP로 서로 다른 16개 경로 연속 요청(threshold=15 초과 노림)"
    for line in was.send_endpoint_scan_burst(16, source_ip=ip):
        yield f"    {line}"


def _run_s93() -> Iterator[str]:
    """S93: WAS 정찰 이후 동일 Pod의 Falco 민감 파일 접근 (threshold=1, join=pod,
    requires_recent_fire: S92). S92는 join_on=source_ip라 join_key가 공격자 IP지만,
    fired_marker_join_on=pod로 실제 서빙 pod을 마킹한다 - 이 테스트 하네스는 클라이언트
    쪽에서 어느 pod이 그 요청을 처리했는지 알 방법이 없어(WAS는 응답 헤더로 pod을
    노출하지 않음, WAF만 X-Served-By-Pod를 노출) S5/S59와 같은 가정(실제 Juice Shop
    pod이 단일 서빙 pod)으로 그 pod을 그대로 쓴다."""
    real_pod = None
    try:
        real_pod = k8s.find_juice_shop_pod()
    except Exception as e:
        yield f"  - Juice Shop pod 조회 실패: {e}"
    if not real_pod:
        yield "  - Juice Shop pod을 못 찾음 - 스킵"
        return

    yield "  - 선행 조건: S92(WAS 엔드포인트 다양성 스캔)를 먼저 발화시킨다"
    yield from _run_s92()
    time.sleep(2)

    yield "  - 그 뒤 같은 pod에서 민감 파일 접근 재현(Read sensitive file untrusted)"
    yield from _step(
        "민감 파일 열람 재현",
        lambda: k8s.exec_in_pod("default", real_pod, ["sh", "-c", _S45_READ_SENSITIVE_FILE_COMMAND], container="nginx-was-logger"),
    )


def _run_s94() -> Iterator[str]:
    """S94: 웹 계층 침투 체인 완주 이후 신규 Pod의 실제 이상행동 확인 (threshold=1,
    join=pod, requires_recent_fire: S85). S85가 stage4에서 실제로 생성에 성공한 그
    pod에서만 join이 이어진다 - S85 stage4는 탈취한 default SA 토큰으로 호출해서
    (권한이 없으면 403) 실제로 pod가 안 생겼을 수 있다(_run_s85 docstring 참고) -
    그 경우 아래 wait_pod_running/exec가 실패로 끝나며 이 체인이 완주되지 않았음을
    그대로 보여준다(가짜로 성공 처리하지 않음)."""
    captured_pod: List[str] = []
    yield "  - 선행 조건: S85(웹 계층 침투 체인)를 먼저 발화시킨다(stage4 pod 생성 성공 여부는 RBAC에 달림)"
    yield from _run_s85(_pod_name_out=captured_pod)
    if not captured_pod:
        yield "  - S85가 pod 이름을 만들기 전에 중단돼 이어서 진행할 수 없음 - 스킵"
        return

    pod_name = captured_pod[0]
    time.sleep(2)
    yield f"  - 그 pod({pod_name})에서 실제 이상행동 재현 시도(⚠️ S85 stage4가 RBAC에 막혀 pod 자체가 안 생겼을 수 있음)"
    try:
        k8s.wait_pod_running("default", pod_name, timeout_s=15)
        yield "  - pod Running 확인 -> OK (S85 stage4가 실제로 성공했음)"
        yield from _exec_many("default", pod_name, _S1_EXEC_COMMANDS, "시도")
    except Exception as e:
        yield f"  - pod가 존재하지 않거나 Running이 아님: {e} (S85 stage4가 RBAC에 막혔을 가능성 - 이 체인은 완주되지 않았습니다)"
        return
    yield from _step(f"pod {pod_name} 정리(스크립트 자신의 신원으로)", lambda: k8s.delete_pod("default", pod_name))


def _run_s95() -> Iterator[str]:
    """S95: 동일 신원의 광범위한 소스 IP 재사용 정황 (cardinality, join=user_or_sa,
    threshold=5/300s, distinct_field=source_ip). 처음엔 "k8s_audit의 source_ip는
    kube-apiserver가 실제로 관측한 TCP 출발지라 WAF/WAS처럼 X-Forwarded-For로 못
    바꾼다"고 가정했는데, 실제 k3d 클러스터(techeer-ids)의 kube-apiserver 감사로그를
    직접 떠서 확인한 결과 틀렸다(2026-07-20) - 이 클러스터의 kube-apiserver는
    X-Forwarded-For 값을 sourceIPs 맨 앞에 그대로 싣고, normalizer.py는 그 첫 번째
    값을 source.ip로 쓴다 - WAF/WAS와 똑같이 통제 가능하다(k8s_actions.py의
    _client_with_source_ip 참고)."""
    k8s.ensure_namespace()
    yield "  - 서로 다른 6개 IP로 쓰기 작업(ConfigMap 생성/삭제) 반복"
    for _ in range(6):
        ip = waf.random_source_ip()
        name = f"dummy-s95-{k8s.short_id()}"
        yield from _step(
            f"[{ip}] ConfigMap {name} 생성",
            lambda n=name, i=ip: k8s.create_configmap_with_credentials_from_ip(k8s.DUMMY_NAMESPACE, n, {"note": "dummy"}, i),
        )
        yield from _step(
            f"[{ip}] {name} 정리", lambda n=name, i=ip: k8s.delete_configmap_from_ip(k8s.DUMMY_NAMESPACE, n, i)
        )
        time.sleep(1)


def _run_s96() -> Iterator[str]:
    """S96: 반복적 소규모 권한 부여를 통한 RBAC 감사 우회 정황 (cardinality,
    join=user_or_sa, threshold=5/1800s, distinct_field=audit_binding_subject)."""
    k8s.ensure_namespace()
    created = []
    for i in range(6):
        binding_name = f"dummy-s96-{k8s.short_id()}"
        sa_name = f"dummy-s96-subject-{k8s.short_id()}"
        yield from _step(
            f"[{i + 1}/6] 서로 다른 주체({sa_name})에게 view 권한 바인딩 {binding_name} 생성",
            lambda b=binding_name, s=sa_name: k8s.create_clusterrolebinding(b, k8s.DUMMY_NAMESPACE, s, "view"),
        )
        created.append(binding_name)
        time.sleep(1)
    for binding_name in created:
        yield from _step(f"{binding_name} 정리", lambda b=binding_name: k8s.delete_clusterrolebinding(b))


def _run_s97() -> Iterator[str]:
    """S97: 이름을 바꿔가며 반복되는 NodePort Service 노출 정황 (cardinality,
    threshold=3/1800s, distinct_field=orchestrator_resource_name)."""
    k8s.ensure_namespace()
    created = []
    for i in range(4):
        name = f"dummy-svc-s97-{k8s.short_id()}"
        yield from _step(f"[{i + 1}/4] NodePort Service {name} 생성", lambda n=name: k8s.create_nodeport_service(k8s.DUMMY_NAMESPACE, n))
        created.append(name)
        time.sleep(1)
    for name in created:
        yield from _step(f"{name} 정리", lambda n=name: k8s.delete_service(k8s.DUMMY_NAMESPACE, n))


def _run_s98() -> Iterator[str]:
    """S98: 이름을 바꿔가며 반복되는 TLS 없는 Ingress 노출 정황 (cardinality,
    threshold=3/1800s, distinct_field=orchestrator_resource_name)."""
    k8s.ensure_namespace()
    created = []
    for i in range(4):
        name = f"dummy-ing-s98-{k8s.short_id()}"
        yield from _step(f"[{i + 1}/4] TLS 없는 Ingress {name} 생성", lambda n=name: k8s.create_ingress_without_tls(k8s.DUMMY_NAMESPACE, n))
        created.append(name)
        time.sleep(1)
    for name in created:
        yield from _step(f"{name} 정리", lambda n=name: k8s.delete_ingress(k8s.DUMMY_NAMESPACE, n))


def _run_s99() -> Iterator[str]:
    """S99: 다종 민감 파일 접근 룰의 동시다발 발화 (cardinality, join=pod,
    threshold=3/300s, distinct_field=event_action - S45~S49 중 3종 이상 필요).
    S48은 재현 불가(모듈 docstring 참고)라 나머지 4종(S45/S46/S47/S49)을 한 pod에서
    전부 실행해 4/5로 threshold(3)를 넉넉히 채운다."""
    yield from _run_pod_falco_scenario(
        "s99",
        [
            _S45_READ_SENSITIVE_FILE_COMMAND,
            _S46_HARDLINK_SENSITIVE_COMMAND,
            _S47_SYMLINK_SENSITIVE_COMMAND,
            _S49_DIRECTORY_TRAVERSAL_COMMAND,
        ],
    )


def _run_s100() -> Iterator[str]:
    """S100: PTRACE 부착과 안티디버깅 시도 동시 발생 (cardinality, join=pod,
    threshold=2/120s, distinct_field=event_action - S40+S44 둘 다 필요)."""
    yield from _run_pod_falco_scenario(
        "s100",
        [_pipe_python(_S40_PTRACE_ATTACH_SCRIPT), _pipe_python(_S44_PTRACE_TRACEME_SCRIPT)],
        image=k8s.PYTHON_IMAGE,
    )


# ---- 2026-07-20 2차 추가 (S101~S109) - "단일 소스 정밀화" 배치. Notion "여러 계층
# 시나리오" 문서의 M34/M45/M46/M49/M50/M62/M67/M72/M75를 코드 변경 없이(기존 매처/
# 필드/join_on 축만으로) YAML화한 correlation-engine 쪽 추가에 맞춰, 이 파일에도 그
# 재현 레시피를 같이 추가한다. 전부 이미 검증된 재료(S1/S4/S10/S21/S30/S32/S34/S35/
# S36/S41)의 조합이라 falco 룰 존재 여부 재확인이 새로 필요하지 않았다.


def _run_s101() -> Iterator[str]:
    """S101: 무차별 경로 탐색 이후 실제 리소스 적중 확인 (sequence, join=source_ip,
    window=60s). stage1(404)/stage2(200)를 같은 IP로 연달아 보낸다 - S30의 "다발"
    조건은 sequence stage(정적 단일 이벤트)로 못 옮겨 단발 404로 근사했다
    (network.yaml S101 주석 참고, S78/S83과 같은 제약)."""
    ip = waf.random_source_ip()
    yield "  - 존재하지 않는 경로 요청(404) 이후 실제 응답이 있는 경로(200) 요청, 같은 IP"
    yield f"    {was.send_not_found_request(source_ip=ip)}"
    time.sleep(1)
    yield f"    {was.send_whoami_request(source_ip=ip)}"


def _run_s102() -> Iterator[str]:
    """S102: 리버스쉘/RCE 계열 Falco 시그널 동시다발 발화 (cardinality, join=pod,
    threshold=2/120s, distinct_field=event_action - S32/S34/S35 중 2종 이상 필요)."""
    yield from _run_pod_falco_scenario(
        "s102", [_S32_DUP_NETWORK_COMMAND, _S34_DROP_EXECUTE_COMMAND, _S35_NETCAT_RCE_COMMAND]
    )


def _run_s103() -> Iterator[str]:
    """S103: 파일리스 실행 기법의 복합 사용 탐지 (cardinality, join=pod,
    threshold=2/120s, distinct_field=event_action - S36+S41 둘 다 필요). S80이 이미
    증명한 "python 스크립트(S36) + busybox cp 명령(S41)을 PYTHON_IMAGE 한 pod에서
    같이 실행" 조합을 그대로 재사용한다."""
    yield from _run_pod_falco_scenario(
        "s103", [_pipe_python(_S36_MEMFD_SCRIPT), _S41_DEV_SHM_EXEC_COMMAND], image=k8s.PYTHON_IMAGE
    )


def _run_s104() -> Iterator[str]:
    """S104: 동일 IP의 서로 다른 WAF 공격 유형 복합 발생 (cardinality, join=source_ip,
    threshold=3/60s, distinct_field=event_action). S90/S95와 같은 이유로 같은 IP를
    고정해서 sqli/xss/os_command_injection 3종을 순서대로 보낸다."""
    ip = waf.random_source_ip()
    yield "  - 같은 IP로 서로 다른 WAF 공격 유형 3종 연속 전송(sqli/xss/cmdi)"
    yield f"    {waf.send_sqli_critical(source_ip=ip)}"
    yield f"    {waf.send_xss_critical(source_ip=ip)}"
    yield f"    {waf.send_cmdi_critical(source_ip=ip)}"


def _run_s105() -> Iterator[str]:
    """S105: 정찰 리소스 타입의 다양성 탐지 (cardinality, join=user_or_sa,
    threshold=5/60s, distinct_field=orchestrator_resource_type). S10과 같은 신원
    (이 스크립트 자신)이 pods/secrets/services/configmaps/roles 5종을 돌아가며
    조회한다(k8s_actions.burst_list_diverse_resources, S10의 burst_list_pods/S31의
    burst_list_rbac_objects와 같은 패턴)."""
    k8s.ensure_namespace()
    try:
        k8s.burst_list_diverse_resources("default", 6)
        yield "  - pods/secrets/services/configmaps/roles 5종을 돌아가며 6회 조회 -> OK"
    except Exception as e:
        yield f"  - 리소스 타입 다양성 조회 -> 실패: {e}"


def _run_s106() -> Iterator[str]:
    """S106: 대량 RBAC 바인딩 삭제를 통한 접근 차단 정황 (cardinality, join=user_or_sa,
    threshold=3/300s, distinct_field=orchestrator_resource_name). S96과 같은 패턴
    (create_clusterrolebinding/delete_clusterrolebinding)으로 서로 다른 이름의
    바인딩 여러 개를 만들었다 지운다 - match 조건은 delete뿐이라 create는 순수
    "지울 대상을 만드는" 사전 준비다."""
    k8s.ensure_namespace()
    created = []
    for i in range(4):
        binding_name = f"dummy-s106-{k8s.short_id()}"
        sa_name = f"dummy-s106-subject-{k8s.short_id()}"
        yield from _step(
            f"[{i + 1}/4] 삭제 대상 바인딩 {binding_name} 생성",
            lambda b=binding_name, s=sa_name: k8s.create_clusterrolebinding(b, k8s.DUMMY_NAMESPACE, s, "view"),
        )
        created.append(binding_name)
        time.sleep(1)
    yield "  - 방금 만든 서로 다른 이름의 바인딩을 전부 삭제(대량 삭제 정황 재현)"
    for binding_name in created:
        yield from _step(f"{binding_name} 삭제", lambda b=binding_name: k8s.delete_clusterrolebinding(b))


def _run_s107() -> Iterator[str]:
    """S107: 동일 신원의 비정상적으로 넓은 pod exec 범위 탐지 (cardinality,
    join=user_or_sa, threshold=4/300s, distinct_field=orchestrator_resource_name -
    S1 stage1 재료). 서로 다른 pod 4개를 만들어 각각 한 번씩 exec한다 - S1과 달리
    falco 후속 조치는 필요 없어(k8s_audit만 보는 시나리오) exec 한 번씩만으로 충분."""
    k8s.ensure_namespace()
    names = [f"dummy-s107-{k8s.short_id()}" for _ in range(4)]
    for i, name in enumerate(names, 1):
        yield from _step(f"[{i}/4] pod {name} 생성(sleep 60s)", lambda n=name: k8s.create_sleep_pod(k8s.DUMMY_NAMESPACE, n, 60))
    for i, name in enumerate(names, 1):
        try:
            k8s.wait_pod_running(k8s.DUMMY_NAMESPACE, name)
            yield from _step(f"[{i}/4] pod {name} exec(id)", lambda n=name: k8s.exec_in_pod(k8s.DUMMY_NAMESPACE, n, ["sh", "-c", "id"]))
        except Exception as e:
            yield f"  - [{i}/4] pod {name} Running 대기 -> 실패: {e} (exec 스킵)"
    for name in names:
        yield from _step(f"pod {name} 정리", lambda n=name: k8s.delete_pod(k8s.DUMMY_NAMESPACE, n))


def _run_s108() -> Iterator[str]:
    """S108: 동일 신원의 비정상적으로 넓은 네임스페이스 범위 탐지 (cardinality,
    join=user_or_sa, threshold=3/300s, distinct_field=orchestrator_namespace - S1
    stage1 재료). S107이 "몇 개의 pod"를 봤다면 이건 "몇 개의 네임스페이스"를
    본다 - 서로 다른 네임스페이스 3개에 각각 pod 하나씩 만들어 exec한다."""
    namespaces = [f"dummy-s108-{k8s.short_id()}" for _ in range(3)]
    pod_name = "probe"
    for i, ns in enumerate(namespaces, 1):
        yield from _step(f"[{i}/3] 네임스페이스 {ns} 생성", lambda n=ns: k8s.create_namespace(n))
        yield from _step(f"[{i}/3] {ns}에 pod {pod_name} 생성(sleep 60s)", lambda n=ns: k8s.create_sleep_pod(n, pod_name, 60))
    for i, ns in enumerate(namespaces, 1):
        try:
            k8s.wait_pod_running(ns, pod_name)
            yield from _step(f"[{i}/3] {ns}/{pod_name} exec(id)", lambda n=ns: k8s.exec_in_pod(n, pod_name, ["sh", "-c", "id"]))
        except Exception as e:
            yield f"  - [{i}/3] {ns}/{pod_name} Running 대기 -> 실패: {e} (exec 스킵)"
    for ns in namespaces:
        yield from _step(f"네임스페이스 {ns} 정리", lambda n=ns: k8s.delete_namespace(n))


def _run_s109() -> Iterator[str]:
    """S109: 동일 신원의 여러 네임스페이스에 걸친 CronJob 분산 생성 탐지 (cardinality,
    join=user_or_sa, threshold=3/300s, distinct_field=orchestrator_namespace - S21
    재료). S108과 같은 "여러 네임스페이스" 골격이지만 exec 대신 CronJob 생성을
    각 네임스페이스에서 한 번씩 반복한다."""
    namespaces = [f"dummy-s109-{k8s.short_id()}" for _ in range(3)]
    cj_name = "dummy-cj"
    for i, ns in enumerate(namespaces, 1):
        yield from _step(f"[{i}/3] 네임스페이스 {ns} 생성", lambda n=ns: k8s.create_namespace(n))
        yield from _step(f"[{i}/3] {ns}에 CronJob {cj_name} 생성", lambda n=ns: k8s.create_cronjob(n, cj_name))
    for ns in namespaces:
        yield from _step(f"네임스페이스 {ns} 정리", lambda n=ns: k8s.delete_namespace(n))


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
    "S52": {
        "name": "특권 컨테이너 내 Debugfs 실행 (컨테이너 이스케이프 시도)",
        "modules": ["falco"],
        "story": "privileged 컨테이너 안에서 debugfs(파일시스템 디버거)를 실행한다 — 호스트 파일시스템에 "
                  "직접 접근해 컨테이너 탈출로 이어질 수 있는 정황 (threshold=1).",
        "run": _run_s52,
    },
    "S53": {
        "name": "컨테이너 내부 OS 계정 생성 (백도어 계정 정황)",
        "modules": ["falco"],
        "story": "stateless 앱 컨테이너 안에서 useradd/adduser로 새 Linux 계정을 만든다 — K8s 감사로그에도 "
                  "안 남고 코어 Falco 룰셋에도 대응 규칙이 없던 사각지대, 이 프로젝트 전용 커스텀 룰로 "
                  "탐지 (threshold=1).",
        "run": _run_s53,
    },
    "S54": {
        "name": "User-Agent 누락 요청 탐지 (스캐너 정찰 정황)",
        "modules": ["waf"],
        "story": "/api,/proxy 요청에 User-Agent 헤더 자체가 없다 — OWASP ZAP baseline 스캔처럼 UA를 아예 "
                  "안 보내는 스캐너 정찰 정황, S28(문자열 매칭)/S51(빈 UA 제외) 둘 다의 사각지대를 메움 "
                  "(threshold=1).",
        "run": _run_s54,
    },
    "S55": {
        "name": "WAF 시그니처 단발 CRITICAL 공격 탐지 (다발/침투 없이도 즉시 발화)",
        "modules": ["waf"],
        "story": "WAF가 signatures.py로 이미 CRITICAL 판정을 마친 SQLi/XSS/OS Command Injection/"
                  "Path Traversal 공격을 단 1건만 보낸다 - S4(같은 IP 5건 이상 다발)도, S5(같은 pod에서 "
                  "falco 침투 후속)도 안 채워지는 조건이라, 지금까지는 WAF가 CRITICAL로 기록해도 "
                  "correlation-engine이 인시던트를 하나도 안 만들던 사각지대였다 (threshold=1).",
        "run": _run_s55,
    },
    "S56": {
        "name": "ServiceAccount 토큰 파일 탈취 정황",
        "modules": ["falco"],
        "story": "pod 안에서 마운트된 자기 자신의 ServiceAccount 토큰 파일을 그대로 읽어간다 - 그 신원을 "
                  "파드 밖에서 재사용하려는 자격증명 탈취 시도(threshold=1). k8s_audit만으로는 exec 안에서 "
                  "무슨 명령을 실행했는지 알 수 없어(S1과 이벤트가 동일) 전용 falco 커스텀 룰로 잡는다.",
        "run": _run_s56,
    },
    "S57": {
        "name": "CSR 기반 클라이언트 인증서 발급 정황",
        "modules": ["k8s_audit"],
        "story": "CSR을 만들고 스스로 승인해서 system:kube-controller-manager처럼 이미 강력한 권한을 가진 "
                  "내장 신원의 클라이언트 인증서를 발급받는다 - SA 토큰이 아닌 별도 인증 경로로 확보하는 "
                  "지속성(persistence) 시도 (threshold=1).",
        "run": _run_s57,
    },
    "S58": {
        "name": "nodes/proxy 권한상승 악용 정황",
        "modules": ["k8s_audit"],
        "story": "nodes/proxy 권한만으로 Kubelet API를 직접 프록시해 어드미션 컨트롤과 API 서버 로깅을 "
                  "우회한다 - RBAC상 정상 부여된 권한인데도 사실상 cluster-admin급으로 승격되는 권한상승 "
                  "벡터 (threshold=1).",
        "run": _run_s58,
    },
    "S59": {
        "name": "공개 웹앱 공격이 SA 토큰 탈취를 거쳐 클러스터 관리자 권한 탈취로 이어지는 정황",
        "modules": ["waf", "falco", "k8s_audit"],
        "story": "WAF CRITICAL 공격(1) → 그 pod에서 K8s API 접근 시도(2, 컨테이너 발판 확보 흉내) → "
                  "마운트된 SA 토큰 실제로 탈취(3) → 그 신원으로 실제 K8s API 호출(4) → 같은 신원으로 "
                  "cluster-admin 권한 바인딩 시도(5)까지 5단계 - WAS/WAF/Falco/k8s_audit을 하나의 "
                  "체인으로 잇는 첫 시나리오. actor_identity 브릿지로 join_on=user_or_sa 하나가 "
                  "5단계 내내 끊기지 않는다.",
        "run": _run_s59,
    },
    "S60": {
        "name": "WAF 공격 패턴 매칭 이후 WAS 실제 오류 응답 확인 (탐지 vs 실제 침투)",
        "modules": ["waf", "was"],
        "story": "WAF가 SQLi/XSS/CMDi/Path Traversal 페이로드를 매칭한 뒤 → 같은 IP의 요청에 WAS가 "
                  "실제로 5xx 오류를 낸다면 페이로드가 실제로 먹혔다는 뜻이다.",
        "run": _run_s60,
    },
    "S61": {
        "name": "컨테이너 침해 확인 이후 클러스터 권한 확장 시도 (Falco → K8s Audit)",
        "modules": ["falco", "k8s_audit"],
        "story": "S1/S3와 반대 방향 체인 - Falco가 먼저 컨테이너 침해(리버스쉘/RCE)를 확인한 뒤, "
                  "그 신원이 K8s API로 권한 확장을 시도한다.",
        "run": _run_s61,
    },
    "S62": {
        "name": "RBAC 열거 정찰 이후 저빈도 민감 리소스 접근 (threshold 우회 대응)",
        "modules": ["k8s_audit"],
        "story": "S31(RBAC 열거)이 먼저 실제로 발화한 신원만, 그 뒤 아주 낮은 빈도로 민감 리소스에 "
                  "접근해도 잡는다 - threshold를 우회하려는 저속(low-and-slow) 정찰 대응.",
        "run": _run_s62,
    },
    "S63": {
        "name": "CORS 남용 이후 인증된 세션의 이상 API 호출 확인 (WAF → WAS)",
        "modules": ["waf", "was"],
        "story": "신뢰되지 않은 Origin의 CORS 요청 이후 같은 IP가 인증이 필요한 엔드포인트에서 정상 "
                  "응답을 받으면 세션 도용이 실제로 먹혔다는 확정적 증거.",
        "run": _run_s63,
    },
    "S64": {
        "name": "로그 삭제 이후 pod 재시작을 통한 흔적 완전 인멸 (Falco → K8s Audit)",
        "modules": ["falco", "k8s_audit"],
        "story": "시스템 로그를 지운 뒤 컨테이너 자체를 delete+recreate로 통째로 갈아치우면 런타임 "
                  "흔적까지 사라진다 - 흔적 인멸의 더 근본적인 버전.",
        "run": _run_s64,
    },
    "S65": {
        "name": "위조 JWT의 실제 인증 우회 성공 확인 (WAF → WAS)",
        "modules": ["waf", "was"],
        "story": "JWT alg:none 위조 시도 이후 같은 IP가 인증이 필요한 엔드포인트에서 정상 응답을 "
                  "받으면 인증 우회가 실제로 먹혔다는 확정적 증거.",
        "run": _run_s65,
    },
    "S66": {
        "name": "백도어 OS 계정 생성 이후 비표준 경로로의 재접속 (Falco)",
        "modules": ["falco"],
        "story": "컨테이너 안에 계정을 만든 뒤 그 계정으로 재접속을 시도하면 계정이 실제로 쓰이기 "
                  "시작했다는 증거다 (⚠️ stage2가 S42와 같은 재현 불가 룰이라 이 체인은 완주되지 않음).",
        "run": _run_s66,
    },
    "S67": {
        "name": "임시 컨테이너 추가 이후 미확인 바이너리 실행 (K8s Audit → Falco)",
        "modules": ["k8s_audit", "falco"],
        "story": "kubectl debug류로 실행 중 pod에 디버그 컨테이너를 추가한 직후 미확인 바이너리가 "
                  "실행되면 디버깅이 아니라 악의적 목적이었다는 확정적 증거.",
        "run": _run_s67,
    },
    "S68": {
        "name": "시스템 네임스페이스 침투 파드에서의 실제 악성 행위 확인 (K8s Audit → Falco)",
        "modules": ["k8s_audit", "falco"],
        "story": "kube-system/kube-public에 심어진 pod가 실제로 악성 행위(크립토마이닝 등)까지 하면 "
                  "단순 배치 실수가 아니라 의도적 침투로 확정된다.",
        "run": _run_s68,
    },
    "S69": {
        "name": "시스템 계정의 인터랙티브 셸 획득 직후 컨테이너 이스케이프 시도 (Falco)",
        "modules": ["falco"],
        "story": "희소한 전조(시스템 계정 인터랙티브 셸) 직후 실제 이스케이프 시도까지 이어지면 침해가 "
                  "권한 상승 단계로 진행 중이라는 확정적 증거 (⚠️ stage1이 S43과 같은 재현 불가 룰이라 "
                  "이 체인은 완주되지 않음).",
        "run": _run_s69,
    },
    "S70": {
        "name": "인터랙티브 정찰 이후 실제 권한 상승 시도 (Falco → K8s Audit)",
        "modules": ["falco", "k8s_audit"],
        "story": "컨테이너 안에서 whoami/id 등으로 정찰한 직후 실제 권한 상승 시도로 이어지면 단순 "
                  "호기심이 아니라 의도적 침해가 진행 중이라는 증거.",
        "run": _run_s70,
    },
    "S71": {
        "name": "NetworkPolicy 삭제를 통한 방어 설정 무력화",
        "modules": ["k8s_audit"],
        "story": "파드 간 네트워크 세그멘테이션을 강제하는 NetworkPolicy를 지우면 이미 뚫린 pod에서 "
                  "옆으로 이동(lateral movement)하기 훨씬 쉬워진다 (threshold=1).",
        "run": _run_s71,
    },
    "S72": {
        "name": "워크로드 삭제를 통한 서비스 중단",
        "modules": ["k8s_audit"],
        "story": "Deployment/StatefulSet/Service 등 개별 워크로드를 지워 서비스 가용성만 정확히 끊는 "
                  "정밀한 방해 공작 (threshold=1).",
        "run": _run_s72,
    },
    "S73": {
        "name": "DaemonSet 지속성 확보와 위험한 런타임 설정의 결합 탐지",
        "modules": ["k8s_audit"],
        "story": "같은 신원이 DaemonSet(전체 노드 지속성)도 만들고, 짧은 시간 안에 위험한 설정(privileged "
                  "등)의 pod도 직접 만들면 지속성 확보와 에스컬레이션을 병행하는 정황.",
        "run": _run_s73,
    },
    "S74": {
        "name": "SSH 비표준 포트 연결 직후 의심스러운 바이너리 실행 (Falco)",
        "modules": ["falco"],
        "story": "SSH 연결 시도 자체가 아니라 그 직후 의심스러운 실행까지 이어져야 발화 (⚠️ stage1이 "
                  "S42와 같은 재현 불가 룰이라 이 체인은 완주되지 않음).",
        "run": _run_s74,
    },
    "S75": {
        "name": "release_agent 파일 조작을 통한 컨테이너 이스케이프 확인 (K8s Audit → Falco)",
        "modules": ["k8s_audit", "falco"],
        "story": "위험한 설정(privileged 등)의 pod가 생성된 뒤 그 안에서 release_agent cgroup 탈출 "
                  "수법이 실제로 쓰였는지까지 확인하는 체인.",
        "run": _run_s75,
    },
    "S76": {
        "name": "이스케이프 시도 직후 호스트 경로 파괴 탐지 (Falco)",
        "modules": ["falco"],
        "story": "컨테이너 이스케이프 시도 직후 대량 데이터 삭제가 확인되면 단순 컨테이너 내부 정리가 "
                  "아니라 호스트 자체를 노린 파괴 행위라는 확정적 증거.",
        "run": _run_s76,
    },
    "S77": {
        "name": "kubectl port-forward를 이용한 프록시 터널 구축 탐지",
        "modules": ["k8s_audit"],
        "story": "port-forward 서브리소스 호출 자체가 어드미션/로깅을 우회하는 프록시 인프라 구축의 "
                  "신호다 (threshold=1).",
        "run": _run_s77,
    },
    "S78": {
        "name": "익스플로잇/퍼징 트래픽 이후 서비스 불안정 확인 (WAF → WAS)",
        "modules": ["waf", "was"],
        "story": "반복적 익스플로잇/퍼징 시도가 서비스 자체를 불안정하게 만들었는지(5xx/타임아웃) 확인.",
        "run": _run_s78,
    },
    "S79": {
        "name": "서비스어카운트 대량 열거 탐지",
        "modules": ["k8s_audit"],
        "story": "짧은 시간 안에 서비스어카운트만 좁혀서 반복 조회하면 계정 탐색(Account Discovery) "
                  "정찰 정황.",
        "run": _run_s79,
    },
    "S80": {
        "name": "PTRACE 부착 이후 비정상 실행까지 이어지는지 확인 (Falco)",
        "modules": ["falco"],
        "story": "PTRACE 부착(디버깅 도구와 오탐 가능)이 그 직후 실제 바이너리 실행으로 이어지면 오탐 "
                  "의심이 실제 악용으로 확정된다.",
        "run": _run_s80,
    },
    "S81": {
        "name": "웹 침투 → 컨테이너 이스케이프 → 커널 모듈 삽입(루트킷) 확인",
        "modules": ["waf", "falco"],
        "story": "웹 공격이 쉘 확보를 거쳐 이스케이프 시도, 최종적으로 커널 모듈 삽입(루트킷 설치)까지 "
                  "이어지는 4단계 킬체인 (⚠️ 실제 Juice Shop 사이드카는 privileged가 아니라 stage3/4는 "
                  "완주되지 않음).",
        "run": _run_s81,
    },
    "S82": {
        "name": "파일 업로드 → 실행/크립토마이닝 → CronJob 지속성 확보 (WAF/WAS → Falco → K8s Audit)",
        "modules": ["was", "falco", "k8s_audit"],
        "story": "파일 업로드 이후 크립토마이닝 감염이 확인되고, 그 감염이 CronJob으로 지속성 확보까지 "
                  "이어지는 킬체인 (⚠️ 실측 확인 - 이 배포의 업로드 성공 응답은 200/201이 아니라 204라 "
                  "correlation-engine의 S82 yaml 조건과 안 맞음, _run_s82 docstring 참고).",
        "run": _run_s82,
    },
    "S83": {
        "name": "브루트포스 → 계정 탈취 → 관리 API 오남용 (WAF → WAS → K8s Audit)",
        "modules": ["waf", "was", "k8s_audit"],
        "story": "브루트포스가 실제 로그인 성공으로 이어지고, 그 뒤 관리 API(ConfigMap/Secret/RBAC 등) "
                  "오남용까지 확인되는 킬체인 - stage2는 임시 계정을 스스로 등록해 진짜 200을 얻는다.",
        "run": _run_s83,
    },
    "S84": {
        "name": "웹 익스플로잇 → 에러율 증가 → 웹서버 프로세스 이상 자식 프로세스 확인 (WAF/WAS → WAS → Falco)",
        "modules": ["waf", "was", "falco"],
        "story": "S60(탐지→에러율)에 이어 웹서버 프로세스가 예상 밖 자식 프로세스를 낳았는지까지 확인 "
                  "(⚠️ kubectl exec은 웹서버 프로세스의 자식이 될 수 없어 stage3은 구조적으로 재현 불가).",
        "run": _run_s84,
    },
    "S85": {
        "name": "인증 우회 → 관리 콘솔 접근 → RBAC 권한 상승 (WAF/WAS → K8s Audit)",
        "modules": ["was", "k8s_audit"],
        "story": "웹 계층에서의 인증 우회(무인증 401 → 로그인 토큰으로 200, /api/Users 실측 확인)가 "
                  "관리 콘솔 접근, RBAC 권한 상승, 위험한 pod 생성까지 이어지는 4단계.",
        "run": _run_s85,
    },
    "S86": {
        "name": "MutatingWebhookConfiguration 생성/수정을 통한 백도어 등록 탐지",
        "modules": ["k8s_audit"],
        "story": "MutatingWebhookConfiguration을 만들면 이후 생성되는 리소스를 가로채 변조할 수 있는 "
                  "강력한 지속성 벡터가 생긴다 (threshold=1).",
        "run": _run_s86,
    },
    "S87": {
        "name": "CronJob 등록 이후 의심스러운 실행 확인",
        "modules": ["k8s_audit", "falco"],
        "story": "등록된 CronJob이 실제로 예상치 못한 바이너리/스크립트를 실행하는지까지 확인 - "
                  "S21(CronJob 생성) 단독보다 확정적인 증거.",
        "run": _run_s87,
    },
    "S88": {
        "name": "백업/스냅샷 삭제를 통한 복구 방해 (Falco → K8s Audit)",
        "modules": ["falco", "k8s_audit"],
        "story": "데이터를 파괴하는 동시에 백업(스냅샷/PVC)까지 지우면 복구 자체가 불가능해진다 - "
                  "랜섬웨어의 전형적인 마무리 단계.",
        "run": _run_s88,
    },
    "S89": {
        "name": "컨테이너 로그 조회를 통한 자격증명 유출 탐지",
        "modules": ["k8s_audit"],
        "story": "kubectl logs류 API 호출도 exec 못지않게 위험한 수집 경로가 될 수 있다 - 앱이 실수로 "
                  "환경변수/토큰을 stdout에 출력하는 경우가 흔하다 (threshold=1).",
        "run": _run_s89,
    },
    "S90": {
        "name": "여러 pod에 걸친 동일 공격 시그니처의 짧은 확산 (웜형 자동 전파 탐지)",
        "modules": ["waf"],
        "story": "같은 공격 시그니처가 짧은 시간에 여러 pod에서 동시다발적으로 나타나면 자동화된 전파 "
                  "(웜)나 협조 공격 정황 (⚠️ 이 하네스는 단일 타깃만 때려서 서로 다른 pod 분산이 "
                  "보장되지 않음).",
        "run": _run_s90,
    },
    "S91": {
        "name": "반복적 정찰-침해 사이클 탐지 (여러 날에 걸친 정찰 재발생)",
        "modules": ["k8s_audit"],
        "story": "같은 신원이 여러 날에 걸쳐 반복적으로 정찰 패턴을 보이면 지속적으로 침투 기회를 노리는 "
                  "내부자/장기 잠복 위협 (재현 불가로 스킵 - 벽시계 시간을 며칠 앞당길 방법이 없음, "
                  "docstring 참고).",
        "run": _run_s91,
    },
    "S92": {
        "name": "동일 IP의 WAS 엔드포인트 다양성 스캔 (경로 정찰 정황)",
        "modules": ["was"],
        "story": "같은 IP가 짧은 시간에 서로 다른 WAS 엔드포인트를 여러 개 두드리면 반복 재시도가 아니라 "
                  "경로 다양성 자체가 신호인 엔드포인트 스캔 정황.",
        "run": _run_s92,
    },
    "S93": {
        "name": "WAS 정찰 이후 동일 Pod의 Falco 민감 파일 접근 (정찰→침해 확정 체인)",
        "modules": ["falco"],
        "story": "S92(엔드포인트 스캔)가 대상 pod에서 최근 발화한 상태에서 그 pod에 민감 파일 접근까지 "
                  "확인되면 정찰이 실제 침해로 이어졌다는 확정적 체인.",
        "run": _run_s93,
    },
    "S94": {
        "name": "웹 계층 침투 체인 완주 이후 신규 Pod의 실제 이상행동 확인 (S85 후속)",
        "modules": ["falco"],
        "story": "S85(인증 우회→RBAC 상승→위험한 pod 생성) 체인이 완주된 뒤 그 신규 pod에서 실제 "
                  "이상행동까지 확인되는지 본다 (⚠️ S85 stage4가 RBAC에 막히면 이 체인도 완주되지 않음).",
        "run": _run_s94,
    },
    "S95": {
        "name": "동일 신원의 광범위한 소스 IP 재사용 정황 (토큰 유출/재사용 의심)",
        "modules": ["k8s_audit"],
        "story": "정상 SA는 보통 안정된 소수 IP에서만 API를 호출한다 - 짧은 시간에 서로 다른 소스 IP "
                  "여러 개에서 같은 신원이 쓰이면 토큰 유출/재사용 의심.",
        "run": _run_s95,
    },
    "S96": {
        "name": "반복적 소규모 권한 부여를 통한 RBAC 감사 우회 정황",
        "modules": ["k8s_audit"],
        "story": "한 관리자가 짧은 시간에 서로 다른 여러 주체에게 소규모 권한을 반복 부여하면 "
                  "threshold=1급 단발 탐지(S12/S13)를 우회하려는 분산 패턴일 수 있다.",
        "run": _run_s96,
    },
    "S97": {
        "name": "이름을 바꿔가며 반복되는 NodePort Service 노출 정황",
        "modules": ["k8s_audit"],
        "story": "매번 다른 이름으로 NodePort Service를 만들었다 지우기를 반복하면 S17의 쿨다운을 "
                  "우회하면서 계속 새 노출 경로를 만들어낼 수 있다.",
        "run": _run_s97,
    },
    "S98": {
        "name": "이름을 바꿔가며 반복되는 TLS 없는 Ingress 노출 정황",
        "modules": ["k8s_audit"],
        "story": "S97과 같은 회피 패턴을 TLS 없는 Ingress에 적용한 버전 - S24의 쿨다운을 우회한다.",
        "run": _run_s98,
    },
    "S99": {
        "name": "다종 민감 파일 접근 룰의 동시다발 발화 (조직적 자격증명 수집 정황)",
        "modules": ["falco"],
        "story": "S45~S49 중 서로 다른 룰이 짧은 시간에 한 pod에서 여러 개 뜨면 단발성 우연이 아니라 "
                  "조직적인 자격증명 수집 활동이라는 훨씬 강한 신호.",
        "run": _run_s99,
    },
    "S100": {
        "name": "PTRACE 부착과 안티디버깅 시도 동시 발생 (정교한 멀웨어 활동 정황)",
        "modules": ["falco"],
        "story": "PTRACE 부착(오탐 가능성 있는 S40)과 안티디버깅(S44)이 같은 pod에서 함께 나타나면 "
                  "우연한 정상 디버깅과 구분되는 정교한 멀웨어 활동의 신호가 된다.",
        "run": _run_s100,
    },
    "S101": {
        "name": "무차별 경로 탐색 이후 실제 리소스 적중 확인 (WAS)",
        "modules": ["was"],
        "story": "동일 IP가 WAS에서 404 다발 이후 실제로 200 응답을 받으면 무차별 경로 탐색이 실제 "
                  "정보 노출로 이어진 정황.",
        "run": _run_s101,
    },
    "S102": {
        "name": "리버스쉘/RCE 계열 Falco 시그널 동시다발 발화",
        "modules": ["falco"],
        "story": "STDOUT/STDIN 리다이렉트·미확인 바이너리 실행·Netcat RCE 중 서로 다른 신호가 짧은 "
                  "시간에 겹치면 확정적 RCE 체인 정황.",
        "run": _run_s102,
    },
    "S103": {
        "name": "파일리스 실행 기법의 복합 사용 탐지",
        "modules": ["falco"],
        "story": "memfd_create 파일리스 실행과 /dev/shm 실행이 짧은 시간에 함께 나타나면 방어 회피 "
                  "기법을 번갈아 시도하는 정교한 활동 정황.",
        "run": _run_s103,
    },
    "S104": {
        "name": "동일 IP의 서로 다른 WAF 공격 유형 복합 발생",
        "modules": ["waf"],
        "story": "같은 IP에서 서로 다른 여러 WAF 공격 유형이 시도되면 다양한 벡터를 체계적으로 "
                  "시험하는 자동화 스캔 도구(sqlmap, Burp Suite 등) 정황.",
        "run": _run_s104,
    },
    "S105": {
        "name": "정찰 리소스 타입의 다양성 탐지",
        "modules": ["k8s_audit"],
        "story": "같은 신원이 짧은 시간에 서로 다른 리소스 타입을 폭넓게 조회하면 컨트롤러가 아니라 "
                  "사람이 둘러보는 정찰 정황.",
        "run": _run_s105,
    },
    "S106": {
        "name": "대량 RBAC 바인딩 삭제를 통한 접근 차단 정황",
        "modules": ["k8s_audit"],
        "story": "같은 신원이 짧은 시간에 서로 다른 이름의 rolebinding/clusterrolebinding을 여러 개 "
                  "삭제하면 다른 사용자들의 접근 권한을 한꺼번에 빼앗는 계정 잠금 시도 정황.",
        "run": _run_s106,
    },
    "S107": {
        "name": "동일 신원의 비정상적으로 넓은 pod exec 범위 탐지",
        "modules": ["k8s_audit"],
        "story": "같은 신원이 짧은 시간에 서로 다른 여러 pod에 exec하면 탈취된 관리 자격증명이 "
                  "광범위하게 남용되고 있다는 정황.",
        "run": _run_s107,
    },
    "S108": {
        "name": "동일 신원의 비정상적으로 넓은 네임스페이스 범위 탐지",
        "modules": ["k8s_audit"],
        "story": "같은 신원이 짧은 시간에 여러 네임스페이스를 넘나들며 exec하면 탈취된 신원이나 "
                  "침해된 CI 봇이 폭넓게 손대고 있다는 정황.",
        "run": _run_s108,
    },
    "S109": {
        "name": "동일 신원의 여러 네임스페이스에 걸친 CronJob 분산 생성 탐지",
        "modules": ["k8s_audit"],
        "story": "같은 신원이 짧은 시간에 여러 네임스페이스에 CronJob을 분산 생성하면 발각을 피해 "
                  "지속성을 여러 곳에 나눠 심는 시도 정황.",
        "run": _run_s109,
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
