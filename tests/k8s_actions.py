"""
K8s Audit(+Falco) 기반 상관분석 시나리오(S1~S3, S6~S18)를 실제로 트리거하는 저수준
액션 모음. "가짜 로그를 흉내"내는 게 아니라 실제 K8s API 호출(생성/조회/삭제)을 해서
kube-apiserver가 진짜 감사 로그를 남기게 하는 방식 - IDS-COLLECTOR/servers/
correlation-engine/app/scenarios/*.yaml의 판정 조건과 그대로 매칭된다.

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
import time
import uuid
from typing import List, Optional, Tuple

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

_core: Optional["client.CoreV1Api"] = None
_rbac: Optional["client.RbacAuthorizationV1Api"] = None


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
                      host_path_volume: bool = False) -> None:
    """host_pid/host_ipc/host_path_volume은 S16(audit_pod_security_flags_any)의
    privileged/host_network 외 나머지 이스케이프 벡터(hostPID, hostIPC, hostPath 마운트)를
    각각 따로도 재현할 수 있게 추가한 옵션 - 매 시나리오 실행마다 벡터를 섞어서 여러
    조합의 로그가 나오게 하는 용도."""
    core, _ = _clients()
    volumes = None
    volume_mounts = None
    if host_path_volume:
        volumes = [client.V1Volume(name="hostfs", host_path=client.V1HostPathVolumeSource(path="/tmp"))]
        volume_mounts = [client.V1VolumeMount(name="hostfs", mount_path="/host-tmp")]
    container = client.V1Container(
        name="main",
        image=BUSYBOX_IMAGE,
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


def exec_in_pod(namespace: str, name: str, command: List[str]) -> str:
    core, _ = _clients()
    return stream(
        core.connect_get_namespaced_pod_exec,
        name,
        namespace,
        command=command,
        stderr=True,
        stdin=False,
        stdout=True,
        tty=False,
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
    subj = client.V1Subject(kind="ServiceAccount", name=sa_name, namespace=sa_namespace)
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
