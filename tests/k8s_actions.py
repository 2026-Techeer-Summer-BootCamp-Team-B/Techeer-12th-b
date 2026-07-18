"""
K8s Audit(+Falco) 기반 상관분석 시나리오(S1~S3, S6~S18, S20/S21/S24/S25, S31,
2026-07-18부로 S32/S34~S51의 falco 전용 시나리오도 이 파일의 create_sleep_pod/
exec_in_pod을 재사용)를 실제로 트리거하는 저수준 액션 모음. "가짜 로그를 흉내"내는
게 아니라 실제 K8s API 호출(생성/조회/삭제)을 해서 kube-apiserver가 진짜 감사
로그를 남기게 하는 방식 - IDS-COLLECTOR/servers/correlation-engine/app/scenarios/
*.yaml의 판정 조건과 그대로 매칭된다. S22/S23(falco 전용)은 이 pod exec
헬퍼(exec_in_pod)만 재사용하고 여기엔 없다 - scenarios.py에 직접 있음.

안전 원칙:
- 실제 시스템 리소스(system: ClusterRole, 기존 네임스페이스 등)는 절대 건드리지 않는다.
  스크립트가 직접 만든 test-prefixed 리소스만 생성/삭제한다(dummy-attacks 네임스페이스,
  system:dummy-test-* 이름의 자체 ClusterRole 등).
- kube-system/kube-public에 리소스를 만들어야 하는 시나리오(S6, S15)도 스크립트가
  만든 걸 즉시 정리(delete)한다 - 남겨두지 않는다.
- 네임스페이스 삭제(S8)는 기존 네임스페이스가 아니라 이 스크립트가 방금 만든
  일회용 네임스페이스만 지운다.

kubeconfig은 기본 위치(~/.kube/config, 현재 컨텍스트)를 그대로 쓴다 - k3d cluster
create 시 자동으로 등록된다(Techeer-12th-b/README.md "k3d 클러스터 생성" 참고).
"""
import base64
import random
import time
import uuid
from typing import Callable, List, Optional, Tuple

try:
    from kubernetes import client
    from kubernetes import config as kube_config
    from kubernetes.client import Configuration
    from kubernetes.client.rest import ApiException
    from kubernetes.stream import stream
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "kubernetes 패키지가 필요합니다: pip install -r requirements.txt"
    ) from e

DUMMY_NAMESPACE = "dummy-attacks"
BUSYBOX_IMAGE = "busybox:1.36"
# S36(memfd_create)/S40/S44(ptrace) 전용 - create_sleep_pod() docstring 참고.
PYTHON_IMAGE = "python:3-alpine"

_core: Optional["client.CoreV1Api"] = None
_rbac: Optional["client.RbacAuthorizationV1Api"] = None
_apps: Optional["client.AppsV1Api"] = None
_batch: Optional["client.BatchV1Api"] = None
_networking: Optional["client.NetworkingV1Api"] = None


class K8sUnavailable(Exception):
    """kubeconfig을 못 불러오거나 API 서버에 접근할 수 없을 때."""


def short_id() -> str:
    return uuid.uuid4().hex[:8]


def _clients() -> Tuple["client.CoreV1Api", "client.RbacAuthorizationV1Api"]:
    global _core, _rbac
    if _core is None:
        try:
            kube_config.load_kube_config()
        except Exception:
            try:
                kube_config.load_incluster_config()
            except Exception as e:
                raise K8sUnavailable(
                    f"kubeconfig을 불러올 수 없습니다 - k3d 클러스터가 떠 있고 "
                    f"현재 컨텍스트가 맞는지 확인하세요 ({e})"
                )
        _core = client.CoreV1Api()
        _rbac = client.RbacAuthorizationV1Api()
    return _core, _rbac


# S20(DaemonSet)/S21(CronJob)/S24(Ingress)는 CoreV1Api/RbacAuthorizationV1Api가
# 아니라 각자 다른 API 그룹을 쓴다 - _clients()로 kubeconfig 로드를 보장한 뒤
# 필요할 때만 지연 생성한다(다른 클라이언트와 같은 캐싱 패턴).
def _apps_client() -> "client.AppsV1Api":
    global _apps
    _clients()
    if _apps is None:
        _apps = client.AppsV1Api()
    return _apps


def _batch_client() -> "client.BatchV1Api":
    global _batch
    _clients()
    if _batch is None:
        _batch = client.BatchV1Api()
    return _batch


def _networking_client() -> "client.NetworkingV1Api":
    global _networking
    _clients()
    if _networking is None:
        _networking = client.NetworkingV1Api()
    return _networking


def ensure_namespace(name: str = DUMMY_NAMESPACE) -> None:
    core, _ = _clients()
    try:
        core.read_namespace(name)
    except ApiException as e:
        if e.status == 404:
            core.create_namespace(client.V1Namespace(metadata=client.V1ObjectMeta(name=name)))
        else:
            raise


def _ignore_404(fn, *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except ApiException as e:
        if e.status != 404:
            raise


# ---- Pod ----

def create_sleep_pod(namespace: str, name: str, seconds: int = 120, privileged: bool = False,
                      host_network: bool = False, host_pid: bool = False, host_ipc: bool = False,
                      host_path_volume: bool = False, image: str = BUSYBOX_IMAGE) -> None:
    """host_pid/host_ipc/host_path_volume은 S16(audit_pod_security_flags_any)의
    privileged/host_network 외 나머지 이스케이프 벡터(hostPID, hostIPC, hostPath 마운트)를
    각각 따로도 재현할 수 있게 추가한 옵션 - 매 시나리오 실행마다 벡터를 섞어서 여러
    조합의 로그가 나오게 하는 용도.

    image(2026-07-18, S36/S40/S44 재료): busybox는 순수 셸 명령만으로 memfd_create/
    ptrace 같은 raw syscall을 낼 방법이 없다(둘 다 POSIX 셸 빌트인이 아니라 C
    라이브러리 호출이 필요) - 이 세 시나리오만 PYTHON_IMAGE(ctypes로 libc를 직접
    호출)를 쓰고, 나머지는 기존처럼 BUSYBOX_IMAGE 그대로 쓴다."""
    core, _ = _clients()
    volumes = None
    volume_mounts = None
    if host_path_volume:
        volumes = [client.V1Volume(name="hostfs", host_path=client.V1HostPathVolumeSource(path="/tmp"))]
        volume_mounts = [client.V1VolumeMount(name="hostfs", mount_path="/host-tmp")]
    container = client.V1Container(
        name="main",
        image=image,
        command=["sleep", str(seconds)],
        security_context=client.V1SecurityContext(privileged=True) if privileged else None,
        volume_mounts=volume_mounts,
    )
    pod = client.V1Pod(
        metadata=client.V1ObjectMeta(name=name, namespace=namespace),
        spec=client.V1PodSpec(
            containers=[container], restart_policy="Never", host_network=host_network,
            host_pid=host_pid, host_ipc=host_ipc, volumes=volumes,
        ),
    )
    core.create_namespaced_pod(namespace, pod)


def wait_pod_running(namespace: str, name: str, timeout_s: int = 40) -> None:
    core, _ = _clients()
    deadline = time.time() + timeout_s
    last_phase = "Unknown"
    while time.time() < deadline:
        pod = core.read_namespaced_pod(name, namespace)
        last_phase = pod.status.phase
        if last_phase == "Running":
            return
        time.sleep(1)
    raise TimeoutError(f"pod {namespace}/{name}이 {timeout_s}초 안에 Running이 안 됨 (마지막 상태: {last_phase})")


def exec_in_pod(namespace: str, name: str, command: List[str], container: Optional[str] = None) -> str:
    """container를 안 주면(create_sleep_pod로 만든 단일 컨테이너 pod 등) kube-apiserver가
    알아서 그 하나뿐인 컨테이너를 고른다 - 하지만 컨테이너가 2개 이상인 pod(예: 실제
    Juice Shop pod의 juice-shop+nginx-was-logger 사이드카)에 container 없이 exec하면
    kube-apiserver가 400 "a container name must be specified"로 거부한다. 게다가
    kubernetes-client(설치 버전 36.0.2)가 이 에러를 ApiException으로 감싸는 경로에서
    자체 버그로 또 죽어서(api_client.py가 body가 None일 수 있다는 걸 안 가리고
    e.body.decode()를 호출) 실제 원인이 'NoneType' object has no attribute 'decode'로
    가려진다(실측 확인, 2026-07-15) - 그래서 다중 컨테이너 pod을 execute하는 호출부
    (S5의 실제 Juice Shop pod 등)는 반드시 container를 명시해야 한다."""
    core, _ = _clients()
    return stream(
        core.connect_get_namespaced_pod_exec,
        name,
        namespace,
        command=command,
        container=container,
        stderr=True,
        stdin=False,
        stdout=True,
        tty=True,
    )


def delete_pod(namespace: str, name: str) -> None:
    core, _ = _clients()
    _ignore_404(core.delete_namespaced_pod, name, namespace, grace_period_seconds=0)


def add_ephemeral_container(namespace: str, pod_name: str) -> None:
    core, _ = _clients()
    ec = client.V1EphemeralContainer(name=f"debug-{short_id()}", image=BUSYBOX_IMAGE, command=["sleep", "5"])
    body = client.V1Pod(spec=client.V1PodSpec(containers=[], ephemeral_containers=[ec]))
    core.patch_namespaced_pod_ephemeralcontainers(pod_name, namespace, body)


def find_pod_by_label(namespace: str, label_selector: str) -> Optional[str]:
    core, _ = _clients()
    pods = core.list_namespaced_pod(namespace, label_selector=label_selector)
    return pods.items[0].metadata.name if pods.items else None


def burst_list_pods(namespace: str, count: int) -> None:
    core, _ = _clients()
    for _ in range(count):
        core.list_namespaced_pod(namespace)


def burst_list_rbac_objects(namespace: str, count: int) -> None:
    """S31(60초 안에 roles/clusterroles/rolebindings/clusterrolebindings에 대한
    get/list가 5회 이상, threshold=5) 재료 - burst_list_pods와 같은 패턴이지만 RBAC
    오브젝트 4종을 돌아가며 호출해서, S10(전체 get/list/watch 대량 호출, threshold=30)과
    구분되는 "RBAC 자체를 훑어보는" 좁은 패턴을 재현한다."""
    _, rbac = _clients()
    calls = [
        rbac.list_cluster_role,
        rbac.list_cluster_role_binding,
        lambda: rbac.list_namespaced_role(namespace),
        lambda: rbac.list_namespaced_role_binding(namespace),
    ]
    for i in range(count):
        calls[i % len(calls)]()


# ---- Secret ----

def create_secret(namespace: str, name: str, data: dict) -> None:
    core, _ = _clients()
    encoded = {k: base64.b64encode(v.encode()).decode() for k, v in data.items()}
    core.create_namespaced_secret(
        namespace, client.V1Secret(metadata=client.V1ObjectMeta(name=name, namespace=namespace), data=encoded)
    )


def get_secret(namespace: str, name: str) -> None:
    core, _ = _clients()
    core.read_namespaced_secret(name, namespace)


def delete_secret(namespace: str, name: str) -> None:
    core, _ = _clients()
    _ignore_404(core.delete_namespaced_secret, name, namespace)


# ---- ConfigMap ----

def create_configmap_with_credentials(namespace: str, name: str, data: Optional[dict] = None) -> None:
    """data를 안 주면 기존 기본값(aws_access_key_id) 그대로. S18이 여러 자격증명 키
    패턴(aws_access_key_id/password/passphrase/aws-s3-access-key-id)을 돌아가며
    넣어보게 하려고 data를 파라미터로 뺐다 - normalizer의
    audit_configmap_has_credentials 판정이 어떤 키에도 반응하는지 폭넓게 재현."""
    core, _ = _clients()
    cm = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(name=name, namespace=namespace),
        data=data or {"aws_access_key_id": "AKIAFAKEEXAMPLE0000"},
    )
    core.create_namespaced_config_map(namespace, cm)


def delete_configmap(namespace: str, name: str) -> None:
    core, _ = _clients()
    _ignore_404(core.delete_namespaced_config_map, name, namespace)


# ---- Service ----

def create_nodeport_service(namespace: str, name: str) -> None:
    core, _ = _clients()
    svc = client.V1Service(
        metadata=client.V1ObjectMeta(name=name, namespace=namespace),
        spec=client.V1ServiceSpec(
            selector={"app": "dummy-nonexistent"},
            ports=[client.V1ServicePort(port=8080, target_port=8080)],
            type="NodePort",
        ),
    )
    core.create_namespaced_service(namespace, svc)


def delete_service(namespace: str, name: str) -> None:
    core, _ = _clients()
    _ignore_404(core.delete_namespaced_service, name, namespace)


# ---- ServiceAccount ----

def create_service_account(namespace: str, name: str) -> None:
    core, _ = _clients()
    core.create_namespaced_service_account(
        namespace, client.V1ServiceAccount(metadata=client.V1ObjectMeta(name=name, namespace=namespace))
    )


def delete_service_account(namespace: str, name: str) -> None:
    core, _ = _clients()
    _ignore_404(core.delete_namespaced_service_account, name, namespace)


# ---- RBAC (ClusterRole/ClusterRoleBinding) ----

def create_clusterrole(name: str, rules: List[dict]) -> None:
    _, rbac = _clients()
    policy_rules = [client.V1PolicyRule(**r) for r in rules]
    rbac.create_cluster_role(client.V1ClusterRole(metadata=client.V1ObjectMeta(name=name), rules=policy_rules))


def delete_clusterrole(name: str) -> None:
    _, rbac = _clients()
    _ignore_404(rbac.delete_cluster_role, name)


def create_clusterrolebinding(name: str, sa_namespace: str, sa_name: str, role_name: str) -> None:
    _, rbac = _clients()
    # kubernetes-client>=27에서 V1Subject가 RbacV1Subject로 이름이 바뀜(실측: 설치된
    # 36.0.3엔 V1Subject 자체가 없음) - 파라미터(kind/name/namespace)는 동일.
    subj = client.RbacV1Subject(kind="ServiceAccount", name=sa_name, namespace=sa_namespace)
    role_ref = client.V1RoleRef(api_group="rbac.authorization.k8s.io", kind="ClusterRole", name=role_name)
    rbac.create_cluster_role_binding(
        client.V1ClusterRoleBinding(metadata=client.V1ObjectMeta(name=name), subjects=[subj], role_ref=role_ref)
    )


def delete_clusterrolebinding(name: str) -> None:
    _, rbac = _clients()
    _ignore_404(rbac.delete_cluster_role_binding, name)


# ---- Namespace ----

def create_namespace(name: str) -> None:
    core, _ = _clients()
    core.create_namespace(client.V1Namespace(metadata=client.V1ObjectMeta(name=name)))


def delete_namespace(name: str) -> None:
    core, _ = _clients()
    _ignore_404(core.delete_namespace, name)


# ---- DaemonSet (S20) ----

def create_daemonset(namespace: str, name: str) -> None:
    apps = _apps_client()
    container = client.V1Container(name="main", image=BUSYBOX_IMAGE, command=["sleep", "3600"])
    template = client.V1PodTemplateSpec(
        metadata=client.V1ObjectMeta(labels={"app": name}),
        spec=client.V1PodSpec(containers=[container]),
    )
    spec = client.V1DaemonSetSpec(selector=client.V1LabelSelector(match_labels={"app": name}), template=template)
    ds = client.V1DaemonSet(metadata=client.V1ObjectMeta(name=name, namespace=namespace), spec=spec)
    apps.create_namespaced_daemon_set(namespace, ds)


def delete_daemonset(namespace: str, name: str) -> None:
    apps = _apps_client()
    _ignore_404(apps.delete_namespaced_daemon_set, name, namespace)


# ---- CronJob (S21) ----

def create_cronjob(namespace: str, name: str) -> None:
    batch = _batch_client()
    container = client.V1Container(name="main", image=BUSYBOX_IMAGE, command=["echo", "hi"])
    pod_spec = client.V1PodSpec(containers=[container], restart_policy="OnFailure")
    job_template = client.V1JobTemplateSpec(spec=client.V1JobSpec(template=client.V1PodTemplateSpec(spec=pod_spec)))
    cronjob = client.V1CronJob(
        metadata=client.V1ObjectMeta(name=name, namespace=namespace),
        spec=client.V1CronJobSpec(schedule="*/5 * * * *", job_template=job_template),
    )
    batch.create_namespaced_cron_job(namespace, cronjob)


def delete_cronjob(namespace: str, name: str) -> None:
    batch = _batch_client()
    _ignore_404(batch.delete_namespaced_cron_job, name, namespace)


# ---- Ingress (S24) ----

def create_ingress_without_tls(namespace: str, name: str) -> None:
    """S24(TLS 없는 Ingress 노출)용 - spec.tls를 아예 안 채워서 감사로그의
    audit_ingress_has_tls가 false로 판정되게 한다. backend 서비스는 실제로
    존재할 필요 없음(판정은 Ingress 생성 요청 자체를 보는 것이지 트래픽이 실제로
    도달하는지는 안 봄)."""
    networking = _networking_client()
    backend = client.V1IngressBackend(
        service=client.V1IngressServiceBackend(name="dummy-nonexistent", port=client.V1ServiceBackendPort(number=80))
    )
    rule = client.V1IngressRule(
        host=f"{name}.dummy.local",
        http=client.V1HTTPIngressRuleValue(
            paths=[client.V1HTTPIngressPath(path="/", path_type="Prefix", backend=backend)]
        ),
    )
    ingress = client.V1Ingress(
        metadata=client.V1ObjectMeta(name=name, namespace=namespace),
        spec=client.V1IngressSpec(rules=[rule]),
    )
    networking.create_namespaced_ingress(namespace, ingress)


def delete_ingress(namespace: str, name: str) -> None:
    networking = _networking_client()
    _ignore_404(networking.delete_namespaced_ingress, name, namespace)


# ---- ServiceAccount 토큰 발급 (S25) ----

def create_service_account_token(namespace: str, sa_name: str) -> None:
    """TokenRequest API(create serviceaccounts/token)로 SA 토큰을 명시적으로
    발급 - S25(T1550) 재료. 발급된 토큰 문자열 자체는 아무 데도 안 쓰고 버린다
    (감사 대상은 "발급 행위" 자체이지 토큰의 실사용이 아님)."""
    core, _ = _clients()
    body = client.AuthenticationV1TokenRequest(spec=client.V1TokenRequestSpec(expiration_seconds=600))
    core.create_namespaced_service_account_token(sa_name, namespace, body)


# ---- 정상(benign) K8s 활동 ----

def _normal_k8s_actions() -> List[Tuple[str, Callable[[], None]]]:
    """평범한 운영 중 흔히 일어나는 get/list류 단발 조회만 모았다 - delete/create/
    patch 등 상태를 바꾸는 동작은 다른 시나리오의 match 조건과 우연히 겹칠 수 있어
    일부러 뺐다. S10(60초 안에 get/list/watch 30회 이상, threshold)과 같은 조회
    기반이지만, dummy_generator.py의 run_normal_only()는 이 중 하나만 골라 1회
    호출하므로 정상적인 사용(수 초~수십 초 간격)에서는 그 임계치에 전혀 못 미친다 -
    --scenario normal을 아주 촘촘한 간격으로 대량 반복하면(예: count=50을 반복
    호출) 이론상 S10에 걸릴 수 있다는 점만 유의."""
    core, _ = _clients()
    return [
        ("default 네임스페이스 pod 목록 조회", lambda: core.list_namespaced_pod("default")),
        ("default 네임스페이스 service 목록 조회", lambda: core.list_namespaced_service("default")),
        ("전체 네임스페이스 목록 조회", lambda: core.list_namespace()),
        # 모든 네임스페이스에 kube-controller-manager가 자동으로 만들어두는
        # ConfigMap이라 별도 생성/정리 없이 안전하게 조회만 할 수 있다.
        ("kube-root-ca.crt configmap 조회", lambda: core.read_namespaced_config_map("kube-root-ca.crt", "default")),
    ]


def random_normal_action() -> Tuple[str, Callable[[], None]]:
    """(라벨, 실행함수) 튜플 하나를 무작위로 골라 반환 - 호출부(dummy_generator.py)가
    scenarios.py의 _step()과 같은 방식으로 실행하고 성공/실패를 포맷한다."""
    return random.choice(_normal_k8s_actions())


# ---- 진단용 ----

def find_juice_shop_pod(namespace: str = "default") -> Optional[str]:
    return find_pod_by_label(namespace, "app=juice-shop")


def try_anonymous_request(path: str) -> Tuple[bool, str]:
    """S9(익명 요청 성공)는 클러스터 RBAC이 익명 접근을 실제로 허용해야만 성공한다 -
    기본 RBAC는 대부분 이걸 막으므로 best-effort로 시도만 하고 결과를 정직하게
    보고한다(강제로 클러스터 보안을 낮추는 설정 변경은 하지 않는다). path는
    "/api/v1/namespaces/default/pods" 같은 절대 경로 - RBAC이 리소스 종류별로
    다르게 걸려있을 수 있어서 여러 경로를 돌아가며 시도하면 그중 하나라도 뚫릴
    확률이 올라간다(어떤 클러스터는 pods는 막고 nodes는 열어두는 식의 부분적
    미스컨피그가 흔함)."""
    import requests

    _clients()  # kubeconfig 로드 트리거(host 값 확보 목적)
    cfg = Configuration.get_default_copy()
    url = f"{cfg.host}{path}"
    try:
        resp = requests.get(url, verify=False, timeout=5)
        return resp.status_code < 400, f"HTTP {resp.status_code}"
    except Exception as e:
        return False, str(e)
