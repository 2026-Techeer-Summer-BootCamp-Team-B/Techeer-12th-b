"""
더미 생성기 트리거용 미니 웹 UI 백엔드.

WebSocket이 아니라 짧은 주기 폴링(GET /status?after=)으로 실시간 로그를 보여준다 -
IDS-COLLECTOR의 인시던트 실시간 팝업과 같은 이유(단순함, 인증/헤더 문제 없음)로
이 방식을 택했다. 생성기 자체(scenarios.py)가 requests/kubernetes 클라이언트를 쓰는
블로킹 코드라 백그라운드 스레드에서 돌리고, 메인 스레드는 그 스레드가 쌓는 로그를
그냥 읽기만 한다(전용 락으로 보호).

두 가지 실행 모드:
- 수동(manual, POST /trigger): 지금 바로 N회 실행하고 끝.
- 자동(auto, POST /auto/start): "몇 초마다 몇 개씩"을 정지할 때까지 반복
  (dummy_generator.run_auto) - POST /auto/stop으로 정지.
두 모드는 동시에 못 돈다(_mode가 "idle"일 때만 새로 시작 가능).

실행 기록(각 시나리오 회차)마다 실제로 생성된 원본 로그(k8s_audit/waf/falco/was)를
클릭해서 확인할 수 있다(GET /runs/{run_id}/raw, raw_logs.py) - otel-collector가
gRPC로 Central SIEM에 넘기기 전 단계의 원본이다. IDS-COLLECTOR의 API는 전혀
안 건드린다(k3d 노드 컨테이너/otel-collector pod stdout을 직접 읽음).

실행:
    cd Techeer-12th-b/tests
    pip install -r requirements.txt
    uvicorn dummy_ui.server:app --port 8900 --reload
    (브라우저로 http://localhost:8900 접속)
"""
import re
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # tests/ 를 import 경로에 추가

import dummy_generator  # noqa: E402
import raw_logs  # noqa: E402
import scenarios  # noqa: E402

app = FastAPI(title="IDS-COLLECTOR 더미 생성기")

_lock = threading.Lock()
_log: List[dict] = []
_next_id = 1
_mode = "idle"  # "idle" | "manual" | "auto"
_thread: Optional[threading.Thread] = None
_stop_event: Optional[threading.Event] = None

# 시나리오 회차(run) 추적 - generate()가 찍는 텍스트 라인 중 헤더/완료 패턴만
# 파싱해서 만든다(dummy_generator.py 자체는 손대지 않음 - 이 UI 레이어의 관심사).
_runs: Dict[int, dict] = {}
_next_run_id = 1
_current_run_id: Optional[int] = None

# 개별 액션(카드) 추적 - "진짜 공격/정상 트래픽/K8s 액션 한 건"에 해당하는 줄만
# 골라서 클릭 시 그 액션만의 원본 로그를 찾을 수 있게 한다(GET /events/{id}/raw).
_events: Dict[int, dict] = {}
_next_event_id = 1

# _log/_events/_runs는 프로세스가 떠 있는 동안 계속 쌓이기만 한다 - auto 모드로
# 며칠씩 돌리면(POST /auto/start, --interval 짧게) 메모리가 무한정 늘어난다.
# 매 _append() 끝에서 오래된 것부터 잘라내서 상한선을 둔다. id는 계속 단조
# 증가하므로 잘라내도 /status?after=, /events/{id}/raw의 동작은 안 바뀐다 -
# 다만 너무 오래된 회차의 카드를 새로고침 없이 계속 띄워둔 브라우저 탭에서
# 뒤늦게 클릭하면 404("event not found")가 날 수 있는데, 프론트가 이미 그
# 경우를 "조회 실패"로 자연스럽게 보여준다.
_MAX_LOG_ENTRIES = 5000
_MAX_EVENTS = 2000
_MAX_RUNS = 500

_HEADER_RE = re.compile(r"^\[(\d+)/(\d+)\] (S\d+) - (.+) \(모듈: (.+)\)$")
_DONE_RE = re.compile(r"^\[(\d+)/(\d+)\] 완료$")
# "=== 실행 시작... ===" / "=== 실행 종료 ===" / "--- 정지 요청 접수... ---" 류 배너 -
# 화면에는 안 뜨고(kind="suppress") 상태 전이 파악용으로만 서버에 남긴다.
_SUPPRESS_RE = re.compile(r"^(===.*===|---.*---)$")
# scenarios.py의 _step/_exec_many가 "라벨 -> OK"/"라벨 -> 실패: ..." 한 줄로 결과를
# 내고, S9는 "라벨: 성공(...)"/"라벨: 차단됨(...)" 형태로 낸다 - 전부 "액션 하나 +
# 결과"가 완결된 한 줄이라 카드 하나에 대응.
_EVENT_RESULT_RE = re.compile(r"(-> OK\b|-> 실패:|: 성공\(|: 차단됨\()")
# waf_actions.py의 _send()가 내는 "METHOD /proxy/path -> status (...)" 한 줄
# (공격/정상 트래픽 요청 전부 이 형태).
_HTTP_LINE_RE = re.compile(r"^(GET|POST|PUT|DELETE|PATCH)\s+/proxy/(\S+)\s+->\s+(\d+)")
# k8s_actions.py가 만드는 모든 리소스 이름은 "dummy-"로 시작(S11만 "system:dummy-")
# - 있으면 이걸로 이 액션이 만든 리소스만 정확히 짚어서 raw_logs를 좁힐 수 있다.
_RESOURCE_NEEDLE_RE = re.compile(r"(system:dummy-[\w-]+|dummy-[\w-]+)")


def _prune_locked() -> None:
    """_lock을 쥔 채로만 호출한다. 세 저장소를 각자 상한선 밑으로 잘라낸다 -
    _log는 리스트라 앞에서부터 슬라이스, _events/_runs는 dict라 가장 작은
    키(가장 오래된 id)부터 하나씩 지운다(매 _append마다 호출되므로 한 번에
    많아야 1개씩만 넘치는 게 보통이라 반복 삭제 비용은 무시할 만하다)."""
    global _log
    if len(_log) > _MAX_LOG_ENTRIES:
        _log = _log[-_MAX_LOG_ENTRIES:]
    while len(_events) > _MAX_EVENTS:
        del _events[min(_events)]
    while len(_runs) > _MAX_RUNS:
        del _runs[min(_runs)]


def _extract_needle(text: str) -> Optional[str]:
    m = _RESOURCE_NEEDLE_RE.search(text)
    if m:
        return m.group(1)
    m = _HTTP_LINE_RE.match(text.strip())
    if m:
        return m.group(2)  # /proxy/ 뒤 경로 - WAF/WAS 원본의 target_endpoint/path와 겹침
    return None


def _append(text: str) -> None:
    global _next_id, _next_run_id, _current_run_id, _next_event_id

    run_id = None
    event_id = None
    kind = "meta"
    stripped = text.strip()

    with _lock:
        header_m = _HEADER_RE.match(text)
        if header_m:
            kind = "header"
            run_id = _next_run_id
            _next_run_id += 1
            _current_run_id = run_id
            _runs[run_id] = {
                "id": run_id,
                "scenario": header_m.group(3),
                "name": header_m.group(4),
                "modules": [mod.strip() for mod in header_m.group(5).split("/")],
                "start_ts": time.time(),
                "end_ts": None,
            }
        elif _DONE_RE.match(text):
            kind = "suppress"
            if _current_run_id is not None and _runs[_current_run_id]["end_ts"] is None:
                _runs[_current_run_id]["end_ts"] = time.time()
            _current_run_id = None
        elif _SUPPRESS_RE.match(text):
            kind = "suppress"
        elif _EVENT_RESULT_RE.search(text) or _HTTP_LINE_RE.match(stripped):
            kind = "event"
            event_id = _next_event_id
            _next_event_id += 1
            _events[event_id] = {
                "id": event_id,
                "run_id": _current_run_id,
                "text": stripped,
                "needle": _extract_needle(text),
                "ts": time.time(),
            }

        _log.append({
            "id": _next_id, "ts": time.time(), "text": text,
            "kind": kind, "run_id": run_id, "event_id": event_id,
        })
        _next_id += 1
        _prune_locked()


def _set_mode(mode: str) -> None:
    global _mode
    with _lock:
        _mode = mode


def _worker_manual(scenario: Optional[str], count: int, normal_per_attack: int) -> None:
    try:
        for line in dummy_generator.generate(scenario, count, normal_per_attack):
            _append(line)
    except Exception as e:
        _append(f"제너레이터가 예외로 중단됨: {e}")
    finally:
        _append("=== 실행 종료 ===")
        _set_mode("idle")


def _worker_auto(scenario: Optional[str], attacks_per_tick: int, interval_seconds: float,
                  normal_per_attack: int, stop_event: threading.Event) -> None:
    try:
        for line in dummy_generator.run_auto(scenario, attacks_per_tick, interval_seconds, normal_per_attack, stop_event):
            _append(line)
    except Exception as e:
        _append(f"자동 실행 중 예외로 중단됨: {e}")
    finally:
        _set_mode("idle")


class TriggerRequest(BaseModel):
    scenario: str = "random"  # "random", "normal"(공격 없이 정상 트래픽만), 또는 "S1".."S25"
    count: int = 1
    normal_per_attack: int = dummy_generator.DEFAULT_NORMAL_PER_ATTACK


class AutoStartRequest(BaseModel):
    scenario: str = "random"
    attacks_per_tick: int = 1
    interval_seconds: float = 10.0
    normal_per_attack: int = dummy_generator.DEFAULT_NORMAL_PER_ATTACK


@app.post("/trigger")
def trigger(body: TriggerRequest):
    global _thread, _mode
    with _lock:
        if _mode != "idle":
            return {"status": "busy", "mode": _mode}
        _mode = "manual"

    _append(f"=== 실행 시작(수동): scenario={body.scenario}, count={body.count}, normal_per_attack={body.normal_per_attack} ===")
    _thread = threading.Thread(
        target=_worker_manual, args=(body.scenario, body.count, body.normal_per_attack), daemon=True
    )
    _thread.start()
    return {"status": "started"}


@app.post("/auto/start")
def auto_start(body: AutoStartRequest):
    global _thread, _stop_event, _mode
    with _lock:
        if _mode != "idle":
            return {"status": "busy", "mode": _mode}
        _mode = "auto"

    _stop_event = threading.Event()
    _append(
        f"=== 자동 실행 시작: {body.interval_seconds}초마다 {body.attacks_per_tick}개씩, "
        f"scenario={body.scenario}, normal_per_attack={body.normal_per_attack} ==="
    )
    _thread = threading.Thread(
        target=_worker_auto,
        args=(body.scenario, body.attacks_per_tick, body.interval_seconds, body.normal_per_attack, _stop_event),
        daemon=True,
    )
    _thread.start()
    return {"status": "started"}


@app.post("/auto/stop")
def auto_stop():
    with _lock:
        if _mode != "auto" or _stop_event is None:
            return {"status": "not_running"}
        _stop_event.set()
    _append("--- 정지 요청 접수, 진행 중인 tick이 끝나면 멈춥니다 ---")
    return {"status": "stopping"}


@app.get("/status")
def status(after: int = 0):
    with _lock:
        entries = [e for e in _log if e["id"] > after]
        mode = _mode
    return {
        "running": mode != "idle",
        "mode": mode,
        "entries": entries,
        "last_id": entries[-1]["id"] if entries else after,
    }


_EVENT_WINDOW_SECONDS = 8  # 이 액션 시각(append 시점) 기준 앞뒤로 여유를 두는 폭


@app.get("/events/{event_id}/raw")
def event_raw_logs(event_id: int):
    """이 액션 카드 하나(개별 공격 요청/정상 트래픽/K8s 액션)의 원본 로그를 지금 막
    (요청이 온 이 시점에) 조회해서 돌려준다 - 미리 캐싱해두지 않고 클릭할 때만
    조회한다. event["needle"](리소스 이름/요청 경로)이 있으면 그걸로 좁혀서 같은
    회차 안 다른 액션과 안 섞이게 하고, 없으면(예: exec 명령 결과처럼 그 줄
    자체엔 식별자가 없는 경우) ±{_EVENT_WINDOW_SECONDS}초 시간창만으로 찾는다.
    sync def라 FastAPI가 자동으로 스레드풀에서 돌려 이벤트 루프를 안 막는다."""
    with _lock:
        event = _events.get(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")

    since_ts = event["ts"] - _EVENT_WINDOW_SECONDS
    until_ts = event["ts"] + _EVENT_WINDOW_SECONDS
    logs = raw_logs.fetch_raw_logs(since_ts, until_ts, extra_needle=event["needle"])
    return {"event": event, "logs": logs}


@app.get("/scenario-list")
def scenario_list():
    return [
        {"id": sid, "name": info["name"], "modules": info["modules"], "story": info["story"]}
        for sid, info in scenarios.SCENARIOS.items()
    ]


@app.get("/")
def index():
    return FileResponse(Path(__file__).resolve().parent / "index.html")


app.mount("/static", StaticFiles(directory=Path(__file__).resolve().parent), name="static")
