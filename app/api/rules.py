"""
담당: 심다움 / 하지환 / 윤재영
"""
from fastapi import APIRouter

from app.models.schemas import DetectionRule
from app.storage import rules_store

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("")
def list_rules():
    return rules_store.list_rules()


@router.post("")
def create_rule(rule: DetectionRule):
    rules_store.add_rule(rule)
    return {"detail": "created", "id": rule.id}