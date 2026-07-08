<#
.SYNOPSIS
    k3d 클러스터(techeer-ids)에 Falco가 떠 있는지 확인하고, 없으면(또는 클러스터 자체가
    없으면) README.md 1)/3)번 절차를 그대로 자동화해서 배포한다.

.DESCRIPTION
    1) Docker 데몬이 떠 있는지 확인 (안 떠 있으면 안내 후 종료)
    2) k3d 클러스터 'techeer-ids'가 없으면 k3d-cluster-config.yaml로 생성,
       있는데 정지 상태면 시작만 함 (컨테이너가 이미 떠 있으면 아무 영향 없음)
    3) falcosecurity Helm repo 등록/업데이트
    4) `helm upgrade --install`로 Falco 배포 — 이미 설치돼 있으면 backend/falco-values.yaml
       기준으로 upgrade(사실상 no-op), 없으면 새로 설치. 이 명령 자체가 멱등이라
       "확인 후 없으면 설치"를 별도 분기 없이 안전하게 수행한다.
    5) DaemonSet이 모든 노드에 뜰 때까지 대기하고 최종 상태 출력

.USAGE
    pwsh scripts/deploy-falco.ps1
    (또는 VS Code PowerShell 터미널에서 .\scripts\deploy-falco.ps1)
#>

$ErrorActionPreference = "Stop"

$ClusterName = "techeer-ids"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$ClusterConfigPath = Join-Path $RepoRoot "k3d-cluster-config.yaml"
$FalcoValuesPath = Join-Path $RepoRoot "backend\falco-values.yaml"

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Assert-CommandExists {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Write-Host "'$Name' 명령을 찾을 수 없습니다. README.md의 'k3d / kubectl / Helm 설치' 절차를 먼저 진행하세요." -ForegroundColor Red
        exit 1
    }
}

Assert-CommandExists "docker"
Assert-CommandExists "k3d"
Assert-CommandExists "kubectl"
Assert-CommandExists "helm"

# 1) Docker 데몬 확인 — k3d/kubectl/helm 전부 Docker가 떠 있어야 동작한다.
# $ErrorActionPreference = "Stop" 상태에서 네이티브 명령의 stderr 출력은 그대로
# 터미네이팅 에러로 승격되므로, try/catch로 감싸서 지저분한 예외 대신
# 아래 $LASTEXITCODE 분기로 깔끔하게 안내 메시지를 내보내게 한다.
Write-Step "Docker 데몬 상태 확인"
try { docker info *> $null } catch { }
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker Desktop이 실행 중이 아닙니다. Docker Desktop을 먼저 켜고 다시 실행하세요." -ForegroundColor Red
    exit 1
}
Write-Host "Docker 데몬 정상 동작 중" -ForegroundColor Green

# 2) k3d 클러스터 존재 확인 (없으면 생성, 있으면 시작만 — 이미 떠 있으면 안전하게 무시됨)
Write-Step "k3d 클러스터 '$ClusterName' 확인"
$clusterExists = $false
try {
    $clusterListRaw = k3d cluster list --no-headers
    if ($LASTEXITCODE -eq 0) {
        $clusterExists = [bool]($clusterListRaw | Select-String -Pattern "^$ClusterName\s")
    }
} catch { }

if (-not $clusterExists) {
    Write-Host "클러스터가 없어서 새로 생성합니다: $ClusterConfigPath" -ForegroundColor Yellow
    if (-not (Test-Path $ClusterConfigPath)) {
        Write-Host "클러스터 설정 파일을 찾을 수 없습니다: $ClusterConfigPath" -ForegroundColor Red
        exit 1
    }
    k3d cluster create --config $ClusterConfigPath
} else {
    Write-Host "클러스터가 이미 존재합니다. 혹시 정지 상태면 시작합니다 (이미 실행 중이면 무해함)" -ForegroundColor Green
    k3d cluster start $ClusterName
}

kubectl config use-context "k3d-$ClusterName" | Out-Null

Write-Step "노드 준비 상태 대기 (서버 1개 + 에이전트 2개, 총 3노드)"
kubectl wait --for=condition=Ready nodes --all --timeout=120s
kubectl get nodes

# 3) Falco Helm repo 등록/업데이트 (이미 등록돼 있어도 안전)
Write-Step "falcosecurity Helm repo 등록/업데이트"
try { helm repo add falcosecurity https://falcosecurity.github.io/charts | Out-Null } catch { }
try { helm repo update falcosecurity | Out-Null } catch { }

# 4) Falco 배포 여부 확인 후 필요하면 설치 — 'helm upgrade --install'은 멱등이라
#    이미 설치돼 있으면 그대로 upgrade(내용 동일하면 변화 없음), 없으면 새로 설치한다.
Write-Step "Falco 설치 여부 확인 (namespace: falco)"
if (-not (Test-Path $FalcoValuesPath)) {
    Write-Host "falco-values.yaml을 찾을 수 없습니다: $FalcoValuesPath" -ForegroundColor Red
    exit 1
}

$helmStatusExitCode = 1
try {
    helm status falco -n falco *> $null
    $helmStatusExitCode = $LASTEXITCODE
} catch { }
if ($helmStatusExitCode -eq 0) {
    Write-Host "Falco가 이미 배포되어 있습니다. 최신 falco-values.yaml 기준으로 upgrade를 실행합니다." -ForegroundColor Yellow
} else {
    Write-Host "Falco가 아직 배포되어 있지 않습니다. 새로 설치합니다." -ForegroundColor Yellow
}
helm upgrade --install falco falcosecurity/falco -n falco --create-namespace -f $FalcoValuesPath

# 5) DaemonSet이 노드 수만큼(3개) 뜰 때까지 대기 후 최종 상태 출력
Write-Step "Falco DaemonSet이 모든 노드에 뜰 때까지 대기 (최대 180초)"
kubectl rollout status daemonset/falco -n falco --timeout=180s

Write-Step "최종 상태"
kubectl get nodes
Write-Host ""
kubectl get daemonset -n falco
Write-Host ""
kubectl get pods -n falco -o wide

Write-Host ""
Write-Host "완료. DESIRED/READY가 노드 수(3)와 같으면 Falco가 모든 노드에 정상 배포된 것입니다." -ForegroundColor Green
Write-Host "backend가 --host 0.0.0.0 --port 8000으로 로컬에서 떠 있어야 Falco -> /api/alerts 알림이 도달합니다 (README 3번 항목 참고)." -ForegroundColor Green
