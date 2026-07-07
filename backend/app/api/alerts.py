from fastapi import APIRouter, Request
from datetime import datetime

# 라우터 생성
router = APIRouter()

@router.post("/", tags=["Falco Webhook"])
async def receive_falco_alert(request: Request):
    try:
        # 1. Falco가 쏴준 JSON 로그 수신
        falco_log = await request.json()
        
        # 2. 요구사항: "agent": "log-analyzer" 태그 동적 주입
        falco_log["agent"] = "log-analyzer"
        
        # (선택) 백엔드 수신 시간 추가
        falco_log["received_at"] = datetime.utcnow().isoformat()
        
        print(f"[🚨 Falco Alert Received] Rule: {falco_log.get('rule', 'Unknown Rule')}")
        
        # 3. Elasticsearch에 저장 (가상의 주석 뼈대 코드)
        # TODO: Elasticsearch 클라이언트 연동 후 주석 해제
        # await es_client.index(
        #     index="attack-logs", 
        #     document=falco_log
        # )
        
        # 4. Falco 측에 성공(200 OK) 응답 반환
        return {"status": "success", "message": "Log successfully tagged and processed"}
        
    except Exception as e:
        # 파싱 에러 방어 로직
        print(f"[에러 발생] 로그 처리 중 문제 발생: {e}")
        return {"status": "error", "message": str(e)}