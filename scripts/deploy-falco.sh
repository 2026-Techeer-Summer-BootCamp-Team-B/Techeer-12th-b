#!/usr/bin/env bash
# k3d 클러스터(techeer-ids)에 Falco가 떠 있는지 확인하고, 없으면(또는 클러스터 자체가
# 없으면) README.md 1)/3)번 절차를 그대로 자동화해서 배포한다.
#
# 사용법: bash scripts/deploy-falco.sh
set -euo pipefail

CLUSTER_NAME="techeer-ids"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_CONFIG="$REPO_ROOT/k3d-cluster-config.yaml"
FALCO_VALUES="$REPO_ROOT/backend/falco-values.yaml"

step() { printf '\033[36m==> %s\033[0m\n' "$1"; }
ok()   { printf '\033[32m%s\033[0m\n' "$1"; }
warn() { printf '\033[33m%s\033[0m\n' "$1"; }
err()  { printf '\033[31m%s\033[0m\n' "$1" >&2; }

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "'$1' 명령을 찾을 수 없습니다. README.md의 'k3d / kubectl / Helm 설치' 절차를 먼저 진행하세요."
        exit 1
    fi
}

require_cmd docker
require_cmd k3d
require_cmd kubectl
require_cmd helm

# 1) Docker 데몬 확인 — k3d/kubectl/helm 전부 Docker가 떠 있어야 동작한다.
step "Docker 데몬 상태 확인"
if ! docker info >/dev/null 2>&1; then
    err "Docker Desktop이 실행 중이 아닙니다. Docker Desktop을 먼저 켜고 다시 실행하세요."
    exit 1
fi
ok "Docker 데몬 정상 동작 중"

# 2) k3d 클러스터 존재 확인 (없으면 생성, 있으면 시작만 — 이미 떠 있으면 안전하게 무시됨)
step "k3d 클러스터 '$CLUSTER_NAME' 확인"
if k3d cluster list --no-headers 2>/dev/null | grep -q "^${CLUSTER_NAME}[[:space:]]"; then
    ok "클러스터가 이미 존재합니다. 혹시 정지 상태면 시작합니다 (이미 실행 중이면 무해함)"
    k3d cluster start "$CLUSTER_NAME"
else
    warn "클러스터가 없어서 새로 생성합니다: $CLUSTER_CONFIG"
    if [ ! -f "$CLUSTER_CONFIG" ]; then
        err "클러스터 설정 파일을 찾을 수 없습니다: $CLUSTER_CONFIG"
        exit 1
    fi
    k3d cluster create --config "$CLUSTER_CONFIG"
fi

kubectl config use-context "k3d-${CLUSTER_NAME}" >/dev/null

step "노드 준비 상태 대기 (서버 1개 + 에이전트 2개, 총 3노드)"
kubectl wait --for=condition=Ready nodes --all --timeout=120s
kubectl get nodes

# 3) Falco Helm repo 등록/업데이트 (이미 등록돼 있어도 안전)
step "falcosecurity Helm repo 등록/업데이트"
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
helm repo update falcosecurity >/dev/null

# 4) Falco 배포 여부 확인 후 필요하면 설치 — 'helm upgrade --install'은 멱등이라
#    이미 설치돼 있으면 그대로 upgrade(내용 동일하면 변화 없음), 없으면 새로 설치한다.
step "Falco 설치 여부 확인 (namespace: falco)"
if [ ! -f "$FALCO_VALUES" ]; then
    err "falco-values.yaml을 찾을 수 없습니다: $FALCO_VALUES"
    exit 1
fi

if helm status falco -n falco >/dev/null 2>&1; then
    warn "Falco가 이미 배포되어 있습니다. 최신 falco-values.yaml 기준으로 upgrade를 실행합니다."
else
    warn "Falco가 아직 배포되어 있지 않습니다. 새로 설치합니다."
fi
helm upgrade --install falco falcosecurity/falco -n falco --create-namespace -f "$FALCO_VALUES"

# 5) DaemonSet이 노드 수만큼(3개) 뜰 때까지 대기 후 최종 상태 출력
step "Falco DaemonSet이 모든 노드에 뜰 때까지 대기 (최대 180초)"
kubectl rollout status daemonset/falco -n falco --timeout=180s

step "최종 상태"
kubectl get nodes
echo
kubectl get daemonset -n falco
echo
kubectl get pods -n falco -o wide

echo
ok "완료. DESIRED/READY가 노드 수(3)와 같으면 Falco가 모든 노드에 정상 배포된 것입니다."
ok "backend가 --host 0.0.0.0 --port 8000으로 로컬에서 떠 있어야 Falco -> /api/alerts 알림이 도달합니다 (README 3번 항목 참고)."
