"""
IDS-COLLECTOR/servers/correlation-engine/app/scenarios/*.yaml의 S1~S18 상관분석
시나리오를 실제로 발화시키는 레시피 모음. 각 레시피는 로그 문자열을 하나씩 yield하는
제너레이터라 프론트엔드(dummy_ui)가 "지금 뭘 하고 있는지"를 실시간으로 보여줄 수 있다.

각 시나리오의 stage1/stage2, join_on, window_seconds 등 판정 조건의 근거는 해당 yaml
파일 자체의 주석을 참고할 것 - 여기서는 그 조건을 만족시키는 "실제 행동"만 수행한다
(가짜 로그 주입이 아니라 진짜 K8s API 호출/HTTP 요청/exec).

같은 K8s 신원(현재 kubeconfig 컨텍스트)으로 모든 K8s API 호출을 하기 때문에
join_on=user_or_sa(같은 user/SA가 했는지로 묶는 시나리오)는 별道 처리 없이 자동으로
만족된다. join_on=pod 시나리오(S1)는 이 스크립트가 직접 만든 pod 하나에 stage1/2를
모두 몰아서 확실하게 매칭시킨다.
"""
import time
from typing import Callable, Dict, Iterator, List

import k8s_actions as k8s
import waf_actions as waf

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


def _exec_many(namespace: str, pod_name: str, commands: List[str], label: str, container: str = None) -> Iterator[str]:
    """pod 하나에 여러 명령을 순서대로 exec - falco 룰(예: "Terminal shell in
    container"는 tty가 있어야 잡히는 등 조건이 까다로워 명령 하나만으로는 stage2가
    안 걸릴 수 있다)이나 탐지 시그니처를 하나만 시도하면 못 뚫을 수 있어서, 여러
    변형을 한 번에 다 시도해 그중 하나라도 매칭될 확률을 올린다. container는 pod에
    컨테이너가 2개 이상일 때(예: S5의 Juice Shop pod) 반드시 지정해야 한다 -
    안 그러면 exec 자체가 애매한 대상 때문에 알 수 없는 에러로 실패한다."""
    for idx, cmd in enumerate(commands, 1):
        try:
            out = k8s.exec_in_pod(namespace, pod_name, ["sh", "-c", cmd], container=container)
            yield f"  - {label} {idx}/{len(commands)}: {cmd} -> OK ({out.strip()[:80]})"
        except Exception as e:
            yield f"  - {label} {idx}/{len(commands)}: {cmd} -> 실패: {e}"
        time.sleep(1)


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
    주의: enrichment.py가 WAF 이벤트의 pod 이름을 하드코딩(_TARGET_POD_NAME)해서 채우므로,
    실제 Juice Shop pod 이름과 다르면 join이 안 맞아 인시던트가 안 뜰 수 있다 - 실행 전에
    실제 pod 이름을 조회해서 다르면 경고한다(IDS-COLLECTOR 쪽 코드 수정 필요)."""
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
}

SCENARIO_IDS: List[str] = list(SCENARIOS.keys())

# falco를 건드리는 시나리오(S1, S5)가 18개 중 2개뿐이라 균등 랜덤(random.choice(SCENARIO_IDS))
# 으로는 falco 이벤트가 나머지 16개(k8s_audit/waf만 건드리는 순수 컨트롤 플레인 API 조작 -
# 컨테이너 내부에서 아무것도 실행 안 해서 falco가 볼 게 없는 시나리오들)에 묻혀 1/9 확률로만
# 뽑힌다. dummy_generator.py의 "random" 선택이 이 목록을 갖고 falco 그룹 vs 나머지 그룹을
# 50:50으로 먼저 고른 뒤 그 안에서 균등하게 뽑도록 두 그룹으로 나눠둔다.
FALCO_SCENARIO_IDS: List[str] = [sid for sid in SCENARIO_IDS if "falco" in SCENARIOS[sid]["modules"]]
NON_FALCO_SCENARIO_IDS: List[str] = [sid for sid in SCENARIO_IDS if sid not in FALCO_SCENARIO_IDS]
