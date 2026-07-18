"""
IDS-COLLECTOR 상관분석 시나리오(S1~S59, servers/correlation-engine/app/scenarios/*.yaml)를
바탕으로 실제 공격/정상 트래픽을 만들어내는 더미 생성기.

이 스크립트는 "가짜 로그"를 직접 만들어 넣지 않는다 - 실제 K8s API 호출(scenarios.py,
k8s_actions.py)과 실제 HTTP 요청(waf_actions.py, WAF backend 경유)을 수행해서 진짜
파이프라인(WAF 탐지 로그 / Falco / K8s Audit -> otel-collector -> IDS-COLLECTOR)이
그대로 반응하게 만드는 방식이다.

CLI 사용:
    python dummy_generator.py --scenario random --count 3
    python dummy_generator.py --scenario S4 --count 1 --normal-per-attack 10
    python dummy_generator.py --scenario normal --count 5   # 공격 없이 정상 트래픽만
    python dummy_generator.py --auto --interval 10 --per-tick 2   # Ctrl+C로 정지

프론트엔드(dummy_ui/)는 이 파일의 generate()/run_auto()를 그대로 불러써서 실시간
로그를 스트리밍한다.

환경변수:
    WAF_URL (기본 http://localhost:8000) - WAF backend, 공격/정상 트래픽 둘 다 이 경로로 감
    kubeconfig - 기본 위치(~/.kube/config, 현재 컨텍스트) 그대로 사용

로그 확인은 IDS-COLLECTOR(otel-collector -> normalizer -> OpenSearch -> platform-api)에
왕복 조회하지 않는다 - 두 스택이 별도 네트워크(k3d 클러스터 vs docker-compose)라 그
경로 자체가 안 이어져 있을 수 있고, 이 프론트엔드가 보여줘야 할 "로그"는 이
스크립트 자신이 실제로 보낸 요청/받은 응답이므로 waf_actions.py/scenarios.py가 그
자리에서 바로 yield하는 걸로 충분하다.
"""
import argparse
import random
import threading
import time
from typing import Iterator, Optional

import k8s_actions as k8s
import scenarios
import waf_actions as waf

DEFAULT_NORMAL_PER_ATTACK = 5

# "random"/특정 시나리오 ID와 나란히 고를 수 있는 세 번째 케이스 - 공격이 전혀 없는
# 트래픽만 재현한다(scenarios.SCENARIOS에는 안 넣는다 - SCENARIOS는 "발화시켜야 할
# 공격 시나리오" 목록이고 이건 정반대 개념이라 섞으면 random 선택 시 이것도 뽑힐
# 위험이 있음).
_NORMAL_SCENARIO_ID = "NORMAL"


def run_normal_traffic(n: int) -> Iterator[str]:
    """공격 시나리오 1건당 같이 섞어 보낼 WAF 정상 트래픽(run_normal_only()와 달리
    K8s 활동은 안 섞는다 - 이건 어디까지나 "공격 로그 사이에 섞인 잡음" 역할이라
    기존 동작 그대로 유지)."""
    if n <= 0:
        return
    yield f"  - 정상 트래픽 {n}건 전송"
    for _ in range(n):
        yield f"    {waf.send_normal_request()}"


def _run_normal_k8s_action() -> str:
    label, fn = k8s.random_normal_action()
    try:
        fn()
        return f"  - {label} -> OK"
    except k8s.K8sUnavailable as e:
        return f"  - {label} -> K8s 접근 불가: {e}"
    except Exception as e:
        return f"  - {label} -> 실패: {e}"


def run_normal_only(count: int) -> Iterator[str]:
    """--scenario normal 전용 - 공격 없이 WAF 정상 트래픽 + K8s 정상 조회 활동을
    한 쌍씩 count번 전송한다. run_normal_traffic()(공격 1건에 곁들이는 WAF 전용
    정상 트래픽)과 달리 K8s 쪽 조회 활동도 포함해서 "공격이 하나도 없는 평범한
    하루"를 WAF/K8s 양쪽 모두에서 재현한다."""
    for _ in range(max(1, count)):
        yield f"  - {waf.send_normal_request()}"
        yield _run_normal_k8s_action()


def _pick_scenario(scenario: str) -> Optional[str]:
    if scenario.upper() == "RANDOM":
        # 모듈 채널(was/waf/falco/k8s_audit)을 25:25:25:25로 먼저 고르고 그 안에서
        # 균등 추첨한다 - scenarios.SCENARIO_IDS를 그냥 균등 추첨하면 k8s_audit이
        # 25개 중 20개라 was/waf/falco 로그가 k8s_audit에 묻힌다(scenarios.py의
        # MODULE_SCENARIO_IDS 주석 참고).
        bucket = random.choice(list(scenarios.MODULE_SCENARIO_IDS.values()))
        return random.choice(bucket)
    if scenario.upper() == _NORMAL_SCENARIO_ID:
        return _NORMAL_SCENARIO_ID
    if scenario.upper() in scenarios.SCENARIOS:
        return scenario.upper()
    return None


def generate(
    scenario: Optional[str] = None,
    count: int = 1,
    normal_per_attack: int = DEFAULT_NORMAL_PER_ATTACK,
) -> Iterator[str]:
    """scenario가 None/"random"이면 매 회차 무작위 공격 시나리오, "normal"이면 공격
    없이 WAF+K8s 정상 트래픽 한 쌍만 매 회차 보낸다(count번 반복 = 정상 트래픽
    count쌍, normal_per_attack은 이 모드에 적용되지 않음 - "공격 1건당"이라는 개념
    자체가 없어서다), 특정 ID(예: "S4")면 그 공격 시나리오만 count번 반복한다.
    normal_per_attack은 공격 시나리오에서만 공격 1건당 같이 섞어 보낼 정상 트래픽
    개수(0이면 정상 트래픽 없음)를 조절한다."""
    count = max(1, min(count, 50))
    scenario = scenario or "random"

    for i in range(1, count + 1):
        chosen = _pick_scenario(scenario)
        if chosen is None:
            yield (
                f"[{i}/{count}] 알 수 없는 시나리오: {scenario} "
                f"(사용 가능: {_NORMAL_SCENARIO_ID}, random, {', '.join(scenarios.SCENARIO_IDS)})"
            )
            return

        if chosen == _NORMAL_SCENARIO_ID:
            yield f"[{i}/{count}] {_NORMAL_SCENARIO_ID} - 정상 트래픽만 전송(공격 없음)"
            yield from run_normal_only(1)
            yield f"[{i}/{count}] 완료\n"
            continue

        info = scenarios.SCENARIOS[chosen]
        yield f"[{i}/{count}] {chosen} - {info['name']} (모듈: {'/'.join(info['modules'])})"
        yield f"  스토리: {info['story']}"
        try:
            yield from info["run"]()
        except scenarios.k8s.K8sUnavailable as e:
            yield f"  K8s 접근 불가로 중단: {e}"
        except Exception as e:
            yield f"  예상치 못한 오류: {e}"

        yield from run_normal_traffic(normal_per_attack)
        yield f"[{i}/{count}] 완료\n"


def run_auto(
    scenario: Optional[str],
    attacks_per_tick: int,
    interval_seconds: float,
    normal_per_attack: int,
    stop_event: threading.Event,
) -> Iterator[str]:
    """stop_event가 set될 때까지 interval_seconds마다 attacks_per_tick개의 공격(+정상
    트래픽)을 반복 실행한다. tick 사이 대기는 0.5초 단위로 쪼개서 정지 요청에 바로
    반응하도록 한다(interval이 길어도 정지 버튼이 몇 분씩 안 먹는 일이 없게)."""
    interval_seconds = max(1.0, interval_seconds)
    attacks_per_tick = max(1, min(attacks_per_tick, 20))
    tick = 0

    while not stop_event.is_set():
        tick += 1
        yield f"=== 자동 실행 tick {tick}: {attacks_per_tick}개 공격, {interval_seconds}초 주기 ==="
        yield from generate(scenario, attacks_per_tick, normal_per_attack)

        if stop_event.is_set():
            break
        waited = 0.0
        while waited < interval_seconds and not stop_event.is_set():
            step = min(0.5, interval_seconds - waited)
            time.sleep(step)
            waited += step

    yield f"=== 자동 실행 정지됨 (총 {tick} tick 실행) ==="


def _cli() -> None:
    parser = argparse.ArgumentParser(description="IDS-COLLECTOR 상관분석 시나리오 더미 생성기")
    parser.add_argument(
        "--scenario", default="random",
        help=(
            f"시나리오 ID(예: S4), random(무작위 공격), 또는 {_NORMAL_SCENARIO_ID.lower()}"
            f"(공격 없이 정상 트래픽만). 사용 가능: {', '.join(scenarios.SCENARIO_IDS)}"
        ),
    )
    parser.add_argument("--count", type=int, default=1, help="반복 횟수 (기본 1, --auto와 같이 안 씀)")
    parser.add_argument("--normal-per-attack", type=int, default=DEFAULT_NORMAL_PER_ATTACK, help="공격 1건당 정상 트래픽 개수 (기본 5, 0이면 없음)")
    parser.add_argument("--auto", action="store_true", help="자동 반복 모드 (Ctrl+C로 정지)")
    parser.add_argument("--interval", type=float, default=10.0, help="자동 모드 tick 간격(초, 기본 10)")
    parser.add_argument("--per-tick", type=int, default=1, help="자동 모드 tick당 공격 수 (기본 1)")
    args = parser.parse_args()

    if args.auto:
        stop_event = threading.Event()
        try:
            for line in run_auto(args.scenario, args.per_tick, args.interval, args.normal_per_attack, stop_event):
                print(line)
        except KeyboardInterrupt:
            print("\n정지 요청됨 - 종료합니다.")
    else:
        for line in generate(args.scenario, args.count, args.normal_per_attack):
            print(line)


if __name__ == "__main__":
    _cli()
