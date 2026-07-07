FROM python:3.11-slim

WORKDIR /app

# 의존성 먼저 설치 (캐시 활용해서 재빌드 속도 향상)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 코드 복사
COPY . .

EXPOSE 8000

# main.py의 "app" 객체를 uvicorn으로 실행
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
