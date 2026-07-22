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
쓰는 기법**이라 환경 적합성 자체는 100%:
- `k8s.privilege-escalation.hostpath-volume` → T1611, **이미 커버됨(S16/S52/S69/S75)** → 회귀검증용
- 나머지 7개(`dump-secrets`, `steal-serviceaccount-token`, `create-admin-clusterrole`,
  `create-client-certificate`, `create-token`, `nodes-proxy`, `privileged-pod`) → 우리 시나리오 중
  정확히 이 행위(자격증명 자체를 훔치는 순간, RBAC 권한을 새로 만드는 순간)를 원본으로 잡는 건
  없음(S10/S91/S105는 "탈취 이후의 정찰"만 봄) → **전부 갭 후보, 우선 테스트 추천**

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

### 총계: 109개 중 77개(71%)를 인정된 외부 도구로 검증 가능

| 도구 | 커버 시나리오 수 | 근거 |
|---|---|---|
| Atomic Red Team | 61개 | MITRE 기법 ID가 폴더명이라 정밀 대조(아래 표) |
| stratus-red-team | 4개 | T1611(hostPath 컨테이너 이스케이프) |
| OWASP ZAP | 11개 | T1190(웹 공격面 공격) 계열 - WAF 시그니처 탐지 검증 |
| kube-hunter | (ART와 6개 중복) | T1046/T1595/T1087 recon 계열 - 독립된 두 번째 도구로 같은 탐지를 교차검증하는 용도 |
| **합계(중복 제거)** | **77개** | |
| 아직 외부 도구 커버 없음 | 32개 | `dummy_generator.py`로만 테스트 가능 (아래 목록) |

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
| T1136 Create Account | S6, S53, S66 | T1136.001/.002 (S53 = falco 커스텀 룰 회귀검증) |
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

### 8-2. stratus-red-team → 4개 시나리오

```bash
stratus detonate k8s.privilege-escalation.hostpath-volume
# 확인 후
stratus cleanup k8s.privilege-escalation.hostpath-volume
```
| MITRE 기법 | 대응 시나리오 |
|---|---|
| T1611 Escape to Host (hostPath) | S16, S52, S69, S75 |

(나머지 7개 stratus 기법은 아직 시나리오가 없는 "갭 후보"라 이 회귀검증 목록엔 포함 안 함 - 섹션 6 참고)

### 8-3. OWASP ZAP → 11개 시나리오

WAF의 SQLi/XSS/JWT-none 시그니처 탐지(WAF CRITICAL 차단)가 stage1 재료인 시나리오들.
⚠️ 이 중 다수가 **다단계(sequence/cardinality) 시나리오**라 ZAP 스캔 한 번으로 바로 안 터질
수 있음 - `required_modules`/`window_seconds`/`threshold`를 각 YAML에서 먼저 확인할 것.

```bash
docker run --rm --network host -v /tmp/zap-reports:/zap/wrk/:rw zaproxy/zap-stable \
  zap-baseline.py -t http://localhost:8000/proxy/ -r waf-baseline-report.html
```
| MITRE 기법 | 대응 시나리오 |
|---|---|
| T1190 Exploit Public-Facing Application | S4, S5, S33, S55, S59, S60, S63, S84, S85, S90, S104 |

### 8-4. kube-hunter → ART와 중복 (교차검증용)

`--pod` 모드 스캔이 T1046(Network Service Discovery)/T1595(Active Scanning)/T1087(Account
Discovery) 계열 행동을 실제로 만들어냄 - S28/S30/S54/S101/S92/S79와 겹치지만, **서로 다른
두 개의 인정된 도구(ART + kube-hunter)로 같은 탐지를 교차검증했다**는 근거를 추가로 만들 수
있어서 "신뢰도" 주장에는 오히려 도움이 됨.

### 8-5. 외부 도구 커버 없음 (32개, dummy_generator.py 전용)

S1, S3, S9, S10, S14, S15, S17, S24, S25, S27, S29, S34, S36, S44, S50, S57, S58, S61, S65,
S67, S68, S71, S78, S88, S91, S94, S97, S98, S103, S105, S107, S108

(K8s Audit 특화 시나리오(RBAC 변조 T1098/T1609 계열)나 falco 전용(T1610/T1611 조합) 등,
지금 세팅한 5개 도구의 기법 목록에 정확히 대응하는 게 없는 것들 - 필요하면 stratus의 갭
후보 7개나 falco-event-generator 액션으로 부분적 재현 가능성 추가 검토 가능)
