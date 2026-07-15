# 🛡️ Target 서버 — WAS + 3계층 보안 로그 OTel 중앙 수집

> ① 관문(WAS) / ② 내부 런타임(Falco) / ③ 제어판(K8s Audit Log) 3계층에서 나는 보안 로그를
> OTel(OTLP)로 중앙 수집해 Central SIEM에 전달하는 "분석 대상 서버(Target)". ①은 독립된 두
> 로그 소스로 구성된다 — Juice Shop 앞단 nginx 사이드카(판단 없는 raw WAS 접근 로그)와
> 자체 개발한 FastAPI WAF(`backend/`, 시그니처 기반 탐지 + Bad Bot/Rate Limiting/Brute
> Force/CORS 위반 탐지). WAF는 기본 detection 모드에서는 로그만 남기고 통과시키지만,
> prevention 모드(`WAF_MODE=prevention`)에서는 시그니처 탐지 시 실제로 403을 반환해 막는다.

<br>

## 📌 목차
- [프로젝트 소개](#-프로젝트-소개)
- [문제 정의 & 해결 가치](#-문제-정의--해결-가치)
- [주요 기능](#-주요-기능)
- [시스템 아키텍처](#-시스템-아키텍처)
- [기술 스택](#-기술-스택)
- [팀원 소개 & 역할분담](#-팀원-소개--역할분담)
- [4주 로드맵](#-4주-로드맵)
- [시작하기](#-시작하기)

<br>

## 📖 프로젝트 소개

이 리포지토리는 "분석 대상 서버(Target)"와 "중앙 SIEM 플랫폼(Central SIEM)"으로 물리적으로
분리된 아키텍처 중 **Target** 쪽이다. 대시보드/저장/조회는 더 이상 여기서 하지 않는다 —
Elasticsearch, Postgres, 프론트엔드 대시보드를 모두 제거했고, 대신 클러스터 안에서 발생하는
3계층 보안 로그를 실시간으로 한곳에 모아(OTel Collector) OTLP로 Central SIEM에 흘려보내는
역할만 한다.

<br>

## 🎯 문제 정의 & 해결 가치

**문제**
보안 이벤트는 계층마다 형태가 다 다르다 — WAS는 HTTP 요청/응답, Falco는 커널 syscall 이벤트,
K8s Audit은 API 서버 호출 로그다. 이걸 계층마다 따로 저장하고 따로 봐야 한다면 "지금 클러스터
전체에 무슨 일이 일어나고 있는지"를 한 번에 파악할 수 없다.

**해결 가치**
3계층 모두 OTel(OpenTelemetry) 표준 포맷으로 정규화해서 한 Collector로 모으고, `log.source`
속성(was/falco/k8s-audit)만으로 어느 계층에서 온 이벤트인지 구분할 수 있게 한다. Target
서버는 로그를 "만들고 중앙으로 보내는" 역할만 하고, 상관분석/시각화/장기보관은 Central SIEM이
전담하는 관심사 분리 구조.

<br>

## ✨ 주요 기능

| 기능 | 설명 |
|------|------|
| WAS 요청 로그 | Juice Shop 앞단 nginx 사이드카(`nginx-was-logger`)가 모든 요청의 access log(JSON)를 stdout에 남기고, otel-collector가 tail |
| 내부 런타임 탐지 (Falco) | 컨테이너 안에서 일어나는 민감 파일 접근, 셸 실행, 권한 상승 시도 등을 커널 레벨에서 탐지 |
| 컨트롤 플레인 방어 (K8s Audit) | 비정상 API 호출, RBAC 과다 권한 요청, ServiceAccount 탈취 시도 감사 로그 |
| OTel 중앙 수집 | 위 3계층 로그를 OTel Collector가 한 곳에서 모아 OTLP로 Central SIEM에 전송 |
| WAF 탐지 엔진 | SQLi/XSS/JWT 위조 등 시그니처 기반 탐지 + Bad Bot/Rate Limiting/Brute Force/CORS 위반 탐지. detection 모드(기본)는 로그만 남기고 통과, prevention 모드는 시그니처 탐지 시 403으로 실제 차단 |

<br>

## 🏗 시스템 아키텍처

```
[브라우저] --> nginx-was-logger(Juice Shop Pod 사이드카) --access log(stdout, JSON)--+
   (직접 접속        |                                                              |
    시 WAF 우회)      +--> Juice Shop 컨테이너(127.0.0.1:3000)                       |
                                                                       (filelog)-----+
[브라우저] --> WAF backend(/proxy, svc/backend:8000) --탐지 로그(OTLP push)---------->|
                     |                                                              |
                     +--> juice-shop Service --> nginx-was-logger --> Juice Shop     |
                          (판정과 무관하게 항상 전달, prevention 모드만 403)          |
[Falco DaemonSet] --stdout(json_output)--> 노드 로그 파일 -----(filelog)-------------+--> OTel Collector
                                                                                     |    (DaemonSet, k3d 안)
[kube-apiserver] --audit.log(JSON)--> hostPath ------------------(filelog)----------+
                                                                                     |
                                                        exporters: debug(stdout) + otlp(gRPC)
                                                                                     |
                                                                                     v
                                                          Central SIEM (별도 리포지토리, 미구현)
```

- **① 관문(WAS)**: `juice-shop-with-nginx-sidecar.yaml`이 Juice Shop Pod에 `nginx-was-logger`
  사이드카를 함께 띄운다. `svc/juice-shop`으로 직접 들어온 요청은 이 nginx(8080)를 거쳐 Juice
  Shop 컨테이너(3000)에 도달하고, nginx는 요청을 그대로 통과시키면서 access log(JSON,
  `juice-shop-nginx-configmap.yaml`)만 stdout에 남긴다 — otel-collector가 파드 로그 파일을
  tail해서 `log.source=was`로 태깅. **이 경로는 WAF를 거치지 않는다** (판단 없는 raw 로그).
- **① 관문(WAF)**: 자체 개발한 FastAPI WAF(`backend/`)가 `svc/backend`로 별도로 뜬다.
  `/proxy/{path}`로 들어온 요청을 디코딩+시그니처 탐지한 뒤 `juice-shop` Service로 그대로
  전달하므로, WAF를 거친 요청은 WAF 로그(`log.source=waf`, OTLP SDK push)와 WAS 로그
  (`log.source=was`, nginx가 여전히 남김) **양쪽 다** 남는다. detection 모드(기본)는 판정과
  무관하게 항상 통과시키고, prevention 모드(`WAF_MODE=prevention`)는 시그니처 탐지 시 403을
  반환하고 Juice Shop으로 전달하지 않는다.
- **② 내부 런타임(Falco)**: DaemonSet으로 배포, `json_output`만 켜서 stdout에 JSON을 남기고
  otel-collector가 파드 로그 파일을 tail.
- **③ 제어판(K8s Audit)**: kube-apiserver가 `k3d-audit-policy.yaml` 정책대로 JSON 감사 로그를
  파일로 남기고, otel-collector가 hostPath로 tail.

<br>

## 🛠 기술 스택

**Backend**
```
Python, FastAPI
```

**Detection**
```
정규표현식(Regex) 기반 시그니처 매칭
```

**로그 수집 / 전송**
```
OpenTelemetry Collector(WAS/Falco/K8s Audit 파일 tail + WAF otlp 수신) — OTLP(gRPC)로 Central SIEM(Otel Gateway) 전송
WAF 백엔드는 OpenTelemetry SDK로 OTLP(HTTP) push (log.source=waf)
```

**협업 도구**
```
Git / GitHub / Notion / Discord
```

<br>

## 👥 팀원 소개 & 역할분담

**테커 12기 Team-B**

| 이름 | 역할 | 담당 업무 | 담당 파일 |
|------|------|-----------|-----------|
| 이용욱 | 총괄 / 게이트웨이 & 트래픽 컨트롤러 | 전체 아키텍처 총괄, 팀 조율, 웹 서버 뼈대 구축, Bad Bot 탐지, Rate Limiting/Brute Force 탐지, 에러 마스킹 | `main.py`, `app/config.py`, `app/middleware/gateway.py`, `app/proxy/proxy.py` |
| 서동영 | 인프라 & 클러스터 관제 | k3d/Falco/OTel Collector 배포, 컨트롤 플레인(K8s Audit) 방어 | `k3d-cluster-config.yaml`, `k3d-audit-policy.yaml`, `otel-collector-*.yaml` |
| 하지환 | 데이터 정규화 & 우회 방어 | 인코딩 디코딩, 대소문자 통일, 파라미터 오염(HPP) 방어 | `app/middleware/decoder.py` |
| 윤재영 | 서버 & DB 보안 분석관 | SQL Injection, OS 커맨드 인젝션, 경로 탐색(Path Traversal) 방어 | `app/detection/signatures.py`(SQLi/OS Command Injection/Path Traversal), `app/detection/engine.py`(서버·DB 탐지 부분) |
| 심다움 | 클라이언트 보안 분석관 & 로그 마스터 | XSS 방어, 악성 파일 업로드 차단, 탐지 로그의 OTel 중앙 수집 전송 | `app/detection/signatures.py`(XSS/파일 업로드), `app/detection/engine.py`(클라이언트 탐지 부분), `app/storage/log_store.py`, `app/otel/logger.py` |

<br>

## 🗓 4주 로드맵

| 주차 | 목표 | 주요 작업 |
|------|------|-----------|
| 1주차 | 기획 확정 + 설계 완료 + 개발 착수 | 주제 확정, 문제정의/해결가치 정리, 기능명세서, 역할분담, 아키텍처·ERD·API 명세 초안, Git 전략, 개발환경 세팅 |
| 2주차 | 서비스 뼈대 완성 | 백엔드 API 개발(게이트웨이·디코더·탐지 로직), Falco/K8s Audit 연동 |
| 3주차 | Target/Central SIEM 분리 전환 | ES/Postgres/프론트엔드 제거, OTel Collector 도입, 3계층 로그 OTel 중앙 수집 전환 |
| 4주차 | 프로젝트 최종 완성 및 발표 준비 | Central SIEM 연동, 데모 영상 제작, 발표 콘티/PPT 작성, README/문서 정리 |

<br>

## 🚀 시작하기

Juice Shop(+ nginx-was-logger 사이드카), Falco, K8s Audit, WAF 백엔드 모두 **k3d 클러스터 안에
Pod로 배포**한다. 전부 클러스터 내부망에서 otel-collector에 닿을 수 있다.

### 요구사항
```
Docker Desktop (Windows/Mac) 또는 Docker Engine
k3d, kubectl, Helm
Python 3.11+
```

**k3d / kubectl / Helm 설치**
```powershell
# Windows (winget)
winget install --id k3d.k3d -e
winget install --id Kubernetes.kubectl -e
winget install --id Helm.Helm -e
```
```bash
# macOS (Homebrew)
brew install k3d kubectl helm
```
> 설치 직후 새 터미널을 열어야 PATH가 반영됩니다.

### 1) k3d 클러스터 생성
저장소 루트의 `k3d-cluster-config.yaml`로 서버 1개 + 에이전트 2개(총 3노드) 클러스터를 만듭니다.
Falco/OTel Collector는 DaemonSet(노드마다 하나씩 뜨는 파드)이라, 노드가 여러 개여야 "노드마다
하나씩 배포"되는 동작을 실제로 확인할 수 있습니다.

이 설정에는 **컨트롤 플레인 방어용 K8s Audit 로그**도 함께 켜져 있습니다. 서버 노드의
kube-apiserver가 `k3d-audit-policy.yaml` 정책(비정상 API 호출 / RBAC 과다 권한 요청 / 서비스
어카운트 탈취 시도 위주로 기록)에 따라 감사 로그를 남기고, 저장소 루트의 `k8s-audit-logs/`
디렉터리로 JSON 로그가 그대로 떨어집니다 (otel-collector가 이 파일을 tail).

정책 파일과 로그 디렉터리는 **절대경로로 bind mount** 해야 해서 (상대경로를 주면 k3d/Docker가
빈 이름의 도커 볼륨으로 오인해 kube-apiserver가 기동 실패합니다 - 실제로 겪은 이슈) `--volume`
플래그로 따로 넘깁니다. **반드시 저장소 루트에서 실행**하세요:
```powershell
# Windows (PowerShell)
k3d cluster create --config k3d-cluster-config.yaml `
  --volume "$PWD\k3d-audit-policy.yaml:/etc/kubernetes/audit-policy.yaml@server:0" `
  --volume "$PWD\k8s-audit-logs:/var/log/kubernetes/audit@server:0"
```
```bash
# macOS/Linux (bash/zsh)
k3d cluster create --config k3d-cluster-config.yaml \
  --volume "$(pwd)/k3d-audit-policy.yaml:/etc/kubernetes/audit-policy.yaml@server:0" \
  --volume "$(pwd)/k8s-audit-logs:/var/log/kubernetes/audit@server:0"
```
```bash
kubectl get nodes
# techeer-ids-server-0, techeer-ids-agent-0, techeer-ids-agent-1 3개가 Ready여야 함
```

### 2) Falco를 DaemonSet으로 배포 (기본 룰셋 그대로 사용)
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm upgrade --install falco falcosecurity/falco -n falco --create-namespace -f backend/falco-values.yaml

kubectl get daemonset -n falco
# DESIRED/READY가 노드 수(3)와 같아야 노드마다 하나씩 뜬 것
```
> `http_output`(백엔드로 직접 POST)은 더 이상 쓰지 않습니다. `json_output`만 켜서 stdout에
> JSON을 남기고, otel-collector가 파드 로그 파일을 tail합니다.

### 3) OTel Collector 배포 (3계층 로그의 중앙 수집 지점)
```bash
kubectl apply -f otel-collector-config.yaml
kubectl apply -f otel-collector-deployment.yaml

kubectl get daemonset otel-collector
# DESIRED/READY가 노드 수(3)와 같아야 함
```
Central SIEM은 아직 없으므로 `otel-collector-deployment.yaml`의 `CENTRAL_SIEM_OTLP_ENDPOINT`는
placeholder 값입니다 — 연결 실패 로그가 찍히는 건 정상이고(재시도만 함, Collector가 죽지는
않음), Central SIEM 주소가 정해지면 이 값만 바꾸면 됩니다. 지금 단계에서 "실제로 수집되는지"는
`debug` 익스포터로 확인합니다:
```bash
kubectl logs daemonset/otel-collector -c otel-collector -f
```

### 4) Juice Shop(보호 대상 + WAS 로그 소스) 배포
`juice-shop-with-nginx-sidecar.yaml`이 Juice Shop 컨테이너와 함께 `nginx-was-logger` 사이드카를
같은 Pod에 띄운다. 이 nginx가 모든 요청/응답을 그대로 통과시키면서 access log(JSON)만
stdout에 남기고, otel-collector가 이 로그 파일을 tail한다 (`log.source=was`).
```bash
kubectl apply -f juice-shop-nginx-configmap.yaml
kubectl apply -f juice-shop-with-nginx-sidecar.yaml

kubectl get pods -l app=juice-shop -w
```
확인 (로컬에서 붙으려면 port-forward — Service의 targetPort는 nginx-was-logger의 8080):
```bash
kubectl port-forward svc/juice-shop 3000:3000
curl http://localhost:3000/rest/products/search?q=test
```

### 5) WAF 백엔드 배포
자체 개발한 FastAPI WAF(탐지 엔진 + Rate Limit/Bad Bot/Brute Force/CORS 위반 탐지)를 `svc/backend`로
띄운다. 기본은 detection 모드(로그만 남기고 통과) — 차단 시연을 하려면 `backend/backend-deployment.yaml`의
`WAF_MODE` 환경변수를 `prevention`으로 바꿔서 재배포한다.
```bash
docker build -t techeer-waf-backend:latest backend/
k3d image import techeer-waf-backend:latest -c techeer-ids

kubectl apply -f backend/backend-deployment.yaml

kubectl get pods -l app=backend -w
```
확인 (로컬에서 붙으려면 port-forward):
```bash
kubectl port-forward svc/backend 8000:8000
curl http://localhost:8000/health   # {"status":"ok"}
curl "http://localhost:8000/proxy/rest/products/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users"
# detection 모드: 200(Juice Shop 응답 그대로) + otel-collector에 log.source=waf 로그 발생
# prevention 모드: {"detail":"Request blocked by WAF"} 403
```

### 6) 더미 공격 생성기 실행 (로컬, VS Code PowerShell)
`tests/dummy_generator.py`는 IDS-COLLECTOR의 상관분석 시나리오(S1~S25,
`servers/correlation-engine/app/scenarios/*.yaml`)를 실제로 발화시키는 실제 K8s API
호출(`tests/k8s_actions.py`, `tests/scenarios.py`) + 실제 WAF 공격 요청(`tests/waf_actions.py`,
`svc/backend`의 `/proxy/...` 경유) + S19 전용 WAS 직결 요청(`tests/was_actions.py`,
WAF를 거치지 않고 `svc/juice-shop`에 바로 감)을 수행한다 — 가짜 로그를 주입하는 게
아니라 진짜 kube-apiserver 감사 로그/Falco 탐지/WAF 탐지 로그/WAS 접근 로그가 그대로
나가게 만드는 방식이라 K8s API 접근(kubeconfig), WAF backend port-forward(5단계),
Juice Shop port-forward(4단계, S19 전용)가 모두 필요하다.

```bash
cd tests
pip install -r requirements.txt

# CLI로 바로 실행 (예: S4 시나리오 2회, 정상 트래픽 없이)
$env:WAF_URL="http://localhost:8000"; python dummy_generator.py --scenario S4 --count 2 --no-normal
# S19(로그인 브루트포스)는 WAF_URL이 아니라 WAS_URL(Juice Shop 직결, 4단계 port-forward)을 본다
$env:WAS_URL="http://localhost:3000"; python dummy_generator.py --scenario S19 --count 1
# 랜덤 시나리오 3회 (정상 트래픽 섞어서, 기본값)
python dummy_generator.py --scenario random --count 3
# 공격 없이 WAF+K8s 정상 트래픽만 5쌍 (베이스라인/오탐 확인용)
python dummy_generator.py --scenario normal --count 5
```

**버튼으로 실행하고 싶으면** 같은 디렉터리의 미니 웹 UI를 띄운다:
```bash
uvicorn dummy_ui.server:app --port 8900 --reload
```
브라우저로 `http://localhost:8900` 접속 → 시나리오 선택(또는 랜덤) + 횟수 지정 후
"공격 시작" 버튼을 누르면 실시간 로그 패널에 지금 어떤 공격이 진행 중인지 바로 뜬다.

⚠️ S5는 `IDS-COLLECTOR/servers/normalizer/app/enrichment.py`의 `_TARGET_POD_NAME`이
실제 Juice Shop pod 이름과 일치해야 상관분석까지 매칭된다 — 다르면 생성기가 경고를
출력한다(공격/탐지 자체는 정상 발생, 인시던트 매칭만 안 될 수 있음).

### ✅ 테스트 흐름
1. `dummy_generator.py` 실행 → 요청이 Juice Shop까지 정상적으로 도달하는지(응답 코드) 확인.
2. otel-collector의 `debug` 출력에서 `log.source: Str(was)` 레코드가 실시간으로 찍히는지 확인:
   ```powershell
   kubectl logs -f -l app=otel-collector -c otel-collector --prefix --max-log-requests=3
   Select-String -SimpleMatch "log.source: Str(was)" -Context 0,5
   ```
3. Falco가 실제로 탐지 중인지 확인 (`dummy_generator.py --scenario S1`이 pod exec로
   실제 쉘 실행을 만들어낸다 - 수동으로 흉내내려면 `kubectl run attacker --rm -it --image=ubuntu -- bash`):
   ```powershell
   kubectl logs -f -l app=otel-collector -c otel-collector --prefix --max-log-requests=3
   Select-String -SimpleMatch "log.source: Str(falco)" -Context 0,5
   ```
   otel-collector 로그에서 `log.source: Str(falco)` 레코드 확인.
4. K8s Audit 로그가 컨트롤 플레인 이상 행위를 잡는지 확인 (`dummy_generator.py --scenario S3`이
   RBAC 변경 + pod exec를 실제로 수행한다):
   ```powershell
   kubectl logs -f -l app=otel-collector -c otel-collector --prefix --max-log-requests=3
   Select-String -SimpleMatch "log.source: Str(k8s-audit)" -Context 0,5
   ```
   otel-collector 로그에서 `log.source: Str(k8s-audit)` 레코드 확인 (`k8s-audit-logs/audit.log`에도
   그대로 남아있음).
5. WAF가 실제로 탐지/차단하는지 확인 (5)의 curl 예시 사용):
   - `log.source: Str(waf)` 레코드가 찍히는지 (`Select-String -SimpleMatch "log.source: Str(waf)"`)
   - detection 모드에서는 200 + 로그만, prevention 모드에서는 403 응답으로 바뀌는지

### 종료 / 정리
```bash
# 더미 생성기/port-forward 터미널: Ctrl+C

# 클러스터 자체를 완전히 지우고 싶을 때 (모든 데이터 삭제됨)
k3d cluster delete techeer-ids
```

<br>

## 📄 라이센스
```
추가 예정
```
