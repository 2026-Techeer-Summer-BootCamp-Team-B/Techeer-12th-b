# 🛡️ 실시간 침입 탐지 플랫폼

> 동적 웹 요청 중 비정상 트래픽(SQL Injection, XSS, JWT 위조, OS 커맨드 인젝션 등)을 실시간으로 탐지·차단하고, SIEM 스타일 대시보드로 공격 현황을 시각화하는 경량 웹 방어 플랫폼

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

중소규모 웹 서비스는 상용 WAF(Web Application Firewall)를 도입하기엔 비용·운영 부담이 크고, 실제로 어떤 공격이 언제 들어오고 있는지에 대한 가시성(visibility)이 거의 없습니다.

**실시간 침입 탐지 플랫폼**은 웹 서버 앞단에서 트래픽을 가로채 알려진 공격 시그니처를 실시간으로 탐지하고, 탐지 결과를 SIEM 스타일 대시보드로 한눈에 보여주는 경량 방어 시스템입니다.

<br>

## 🎯 문제 정의 & 해결 가치

**문제**
웹 서비스는 배포와 동시에 스캐너·봇의 자동 공격 대상이 됩니다. 실시간 탐지 체계 없이는 침해 사실을 사후(로그 분석, 사고 발생 후)에나 알게 되는 경우가 많습니다.

**해결 가치**
트래픽을 실시간으로 가로채 SQL Injection, XSS, JWT 위조 등 알려진 공격 패턴을 즉시 탐지하고, 이를 대시보드로 시각화해 **"지금 누가, 어떤 방식으로, 얼마나 자주 공격을 시도하는지"**를 한눈에 파악할 수 있게 합니다. 상용 WAF/SIEM 대비 가볍고, 구조를 이해하기 쉬워 학습·데모 목적에도 적합합니다.

<br>

## ✨ 주요 기능

| 기능 | 설명 |
|------|------|
| 실시간 트래픽 게이트웨이 | 모든 요청을 프록시로 가로채 1차 필터링 (Bad Bot 차단, Rate Limiting/Brute Force 차단) |
| 데이터 정규화 & 우회 방어 | URL 인코딩 디코딩, 대소문자 통일, 파라미터 오염(HPP) 방어로 탐지 우회 차단 |
| 서버·DB 공격 탐지 | SQL Injection, OS 커맨드 인젝션, Path Traversal 시그니처 기반 탐지 |
| 클라이언트 공격 탐지 | XSS, 악성 파일 업로드(웹셸) 탐지 |
| 중앙 로깅 | 탐지된 모든 공격 내역을 JSON 형태로 저장, 대시보드용 API 제공 |
| SIEM 대시보드 | 실시간 공격 타임라인, Top 공격 IP, 공격 유형 분포, 최근 차단 로그 시각화 |

<br>

## 🏗 시스템 아키텍처

```
클라이언트 요청
    ↓
[게이트웨이] Bad Bot 차단 / Rate Limiting / 에러 마스킹
    ↓
[디코더] URL 디코딩 / 대소문자 통일 / HPP 방어
    ↓
[탐지 엔진] SQLi·커맨드인젝션·경로탐색 / XSS·파일업로드 탐지
    ↓
[중앙 로깅] 공격 로그 저장 (JSON)
    ↓
[SIEM 대시보드] 실시간 시각화
```

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

**Frontend**
```
추가 예정
```

**Database / Logging**
```
JSON 기반 로그 저장 (attack_log.jsonl)
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
| 이용욱 | 총괄 / 게이트웨이 & 트래픽 컨트롤러 | 전체 아키텍처 총괄, 팀 조율, 웹 서버 뼈대 구축, Bad Bot 차단, Rate Limiting/Brute Force 차단, 에러 마스킹 | `main.py`, `app/config.py`, `app/middleware/gateway.py`, `app/api/blacklist.py`, `app/proxy/proxy.py`(예정) |
| 서동영 | 프론트엔드 관제 대시보드 | 보안 모니터링 대시보드 UI/UX, 실시간 경고창(Alert), 공격 통계 표/그래프 | `frontend/`(예정), `app/api/ws.py`(프론트 연동) |
| 하지환 | 데이터 정규화 & 우회 방어 | 인코딩 디코딩, 대소문자 통일, 파라미터 오염(HPP) 방어 | `app/middleware/decoder.py` |
| 윤재영 | 서버 & DB 보안 분석관 | SQL Injection, OS 커맨드 인젝션, 경로 탐색(Path Traversal) 방어 | `app/detection/signatures.py`(SQLi/OS Command Injection/Path Traversal), `app/detection/engine.py`(서버·DB 탐지 부분), `app/api/rules.py`, `app/storage/rules_store.py`(서버·DB 룰 공동) |
| 심다움 | 클라이언트 보안 분석관 & 로그 마스터 | XSS 방어, 악성 파일 업로드 차단, 중앙 로깅 저장소 운영 및 API 제공 | `app/detection/signatures.py`(XSS/파일 업로드), `app/detection/engine.py`(클라이언트 탐지 부분), `app/api/logs.py`, `app/api/stats.py`, `app/api/ws.py`(알림 트리거), `app/storage/log_store.py`, `app/api/rules.py`, `app/storage/rules_store.py`(클라이언트 룰 공동) |

<br>

## 🗓 4주 로드맵

| 주차 | 목표 | 주요 작업 |
|------|------|-----------|
| 1주차 | 기획 확정 + 설계 완료 + 개발 착수 | 주제 확정, 문제정의/해결가치 정리, 기능명세서, 역할분담, 아키텍처·ERD·API 명세 초안, Git 전략, 개발환경 세팅 |
| 2주차 | 서비스 뼈대 완성 | ERD/API 명세 확정, 백엔드 API 개발(게이트웨이·디코더·탐지 로직), 프론트엔드 퍼블리싱, 프론트-백 연동 |
| 3주차 | 실제 데모 가능한 수준 만들기 | 핵심 기능 구현 완료, 배포, 버그 수정, 예외처리/성능개선, CI/CD, 모니터링 구축, UI 개선, 테스트코드 작성 |
| 4주차 | 프로젝트 최종 완성 및 발표 준비 | 데모 영상 제작, 발표 콘티/PPT 작성, 발표 리허설, README/문서 정리, 포트폴리오 정리 |

<br>

## 🚀 시작하기

로컬 개발 방식: **백엔드/프론트엔드/더미 공격 로그 생성기는 로컬(VS Code PowerShell 등)에서 직접 실행**하고,
**Elasticsearch·Postgres·Redis·Falco(DaemonSet)는 k3d 클러스터 안에 배포**해서
`kubectl port-forward`로 로컬 백엔드/DB를 연결합니다.

### 요구사항
```
Docker Desktop (Windows/Mac) 또는 Docker Engine
k3d, kubectl, Helm
Python 3.11+  (psycopg2-binary의 prebuilt wheel이 있는 버전을 권장)
Node.js 18+
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
Falco는 DaemonSet(노드마다 하나씩 뜨는 파드)이라, 노드가 여러 개여야 "노드마다 하나씩 배포"되는
동작을 실제로 확인할 수 있습니다.
```bash
k3d cluster create --config k3d-cluster-config.yaml

kubectl get nodes
# techeer-ids-server-0, techeer-ids-agent-0, techeer-ids-agent-1 3개가 Ready여야 함
```

### 2) 인프라(ES/Postgres/Redis) 배포
```bash
kubectl apply -f backend/elasticsearch-deployment.yaml
kubectl apply -f backend/postgres-deployment.yaml
kubectl apply -f backend/redis-deployment.yaml

# 전부 Running이 될 때까지 대기 (Ctrl+C로 감시 종료)
kubectl get pods -w
```

### 3) Falco를 DaemonSet으로 배포 (기본 룰셋 그대로 사용)
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm upgrade --install falco falcosecurity/falco -n falco --create-namespace -f backend/falco-values.yaml

kubectl get daemonset -n falco
# DESIRED/READY가 노드 수(3)와 같아야 노드마다 하나씩 뜬 것
```
> `falco-values.yaml`은 커스텀 룰 없이 Falco 기본 룰셋을 그대로 사용하고,
> `http_output.url`은 `http://host.docker.internal:8000/api/alerts`로 고정되어 있어
> **로컬에서 백엔드가 8000번 포트로 떠 있어야** Falco 알림이 도달합니다. k3d 노드도 결국
> Docker 컨테이너라 Docker Desktop이 주입하는 `host.docker.internal`을 그대로 씁니다.

### 4) 인프라를 로컬 포트로 연결
터미널 3개를 열어 각각 계속 실행해 둡니다 (`backend/.env`가 이미 아래 포트 기준으로 설정되어 있어 추가 설정 불필요):
```bash
kubectl port-forward svc/elasticsearch 9200:9200
kubectl port-forward svc/postgres 5432:5432
kubectl port-forward svc/redis 6379:6379
```

### 5) 백엔드 실행 (로컬, VS Code PowerShell)
```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate   /   macOS·Linux: source .venv/bin/activate
pip install -r requirements.txt

# 최초 1회만: 테이블 생성 + 관리자 계정 시딩 (admin / changeme123)
python -m app.init_db

uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
> Windows에서 `psycopg2-binary` 설치가 `pg_config executable not found`로 실패하면,
> 최신 prebuilt wheel을 먼저 받도록 `pip install --only-binary=:all: psycopg2-binary`를
> 실행한 뒤 `pip install -r requirements.txt`를 다시 시도하세요.
>
> `--host 0.0.0.0`이 중요합니다 — `127.0.0.1`로만 열면 k3d 안의 Falco 파드가
> `host.docker.internal`로 접근할 때 연결이 거부됩니다.
>
> **Windows에서 `[WinError 10013] 액세스 권한에 의해 숨겨진 소켓에 액세스를 시도했습니다`
> 에러가 나면**, `--reload`로 띄운 이전 uvicorn 프로세스가 Ctrl+C 이후에도 완전히
> 종료되지 않고 8000번 포트를 계속 붙잡고 있는 경우입니다. Docker/k3d와는 무관합니다.
> 아래로 점유 중인 PID를 찾아서 종료한 뒤 다시 실행하세요.
> ```powershell
> netstat -ano | findstr :8000
> taskkill /PID <위에서 나온 PID> /F
> ```

확인: http://localhost:8000/health → `{"status":"ok"}`

### 6) 프론트엔드 실행 (로컬, VS Code PowerShell)
```bash
cd frontend
npm install
npm run dev
```
확인: http://localhost:5173 (`frontend/.env`의 `VITE_API_URL`이 백엔드 포트(8000)와 일치해야 함)

### 7) 더미 공격 로그 생성기 실행 (로컬, VS Code PowerShell)
WAF 공격(SQLi/XSS/Path Traversal/OS Command Injection/JWT 위조)은 `/proxy/{path}`로,
Falco 스타일 탐지는 `/api/alerts`로 실제 요청을 보내 파이프라인 전체를 검증합니다.
```bash
cd tests
pip install -r requirements.txt   # backend 가상환경을 그대로 써도 무방

# Windows(PowerShell)
$env:BACKEND_URL="http://localhost:8000"; $env:EVENTS_PER_SECOND="5"; python dummy_generator.py
# macOS/Linux
BACKEND_URL=http://localhost:8000 EVENTS_PER_SECOND=5 python dummy_generator.py
```

### ✅ 테스트 흐름
1. http://localhost:5173 접속 → `admin` / `changeme123` 로그인
2. 우상단 `LIVE` 표시(녹색)로 WebSocket 연결 확인
3. `dummy_generator.py` 실행 → 공격이 403으로 차단되며 통계 카드 / 실시간 타임라인 /
   공격 유형 도넛 차트 / 최근 차단 로그 테이블 / 하단 티커에 즉시 반영되는지 확인
4. Falco가 실제로 탐지 중인지 확인 (예: 클러스터 안에서 민감 파일 접근을 흉내내는 파드 실행):
   ```bash
   kubectl run attacker --rm -it --image=ubuntu -- bash -c "cat /etc/shadow"
   ```
   Falco 파드 로그와 `http_output` 전송 성공 여부 확인:
   ```bash
   kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --tail=50
   ```
   (`"http" output timeout` / `libcurl failed to perform call` 같은 에러가 보이면
   5)번의 `--host 0.0.0.0` 여부와 백엔드가 실제로 떠 있는지부터 확인하세요.)
5. Elasticsearch 적재를 직접 확인:
   ```bash
   curl "http://localhost:9200/attack-logs/_search?sort=timestamp:desc&size=5&pretty"
   ```

### 종료 / 정리
```bash
# 더미 생성기/포트포워드/백엔드/프론트엔드 터미널: Ctrl+C

# 클러스터 자체를 완전히 지우고 싶을 때 (모든 데이터 삭제됨)
k3d cluster delete techeer-ids
```

<br>

## 📄 라이센스
```
추가 예정
```
