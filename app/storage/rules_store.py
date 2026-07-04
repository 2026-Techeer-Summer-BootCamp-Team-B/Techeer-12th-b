"""
담당: 윤재영 (서버·DB 룰) / 심다움 (클라이언트 룰)

DetectionRule 저장소. 초기 뼈대는 인메모리 dict로 구현.
나중에 signatures.py의 하드코딩된 SIGNATURES를 이 저장소 기반으로
동적으로 불러오게 바꿀 수 있음.
"""
from typing import Dict, List, Optional

from app.models.schemas import DetectionRule

_rules: Dict[str, DetectionRule] = {}


def list_rules() -> List[DetectionRule]:
    return list(_rules.values())


def add_rule(rule: DetectionRule) -> None:
    _rules[rule.id] = rule


def get_rule(rule_id: str) -> Optional[DetectionRule]:
    return _rules.get(rule_id)


def remove_rule(rule_id: str) -> bool:
    return _rules.pop(rule_id, None) is not None
