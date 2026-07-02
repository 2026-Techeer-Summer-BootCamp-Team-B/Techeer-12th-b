# mysite

Django 프로젝트. 카카오/공공데이터 API로 주소 주변 시설(지하철, 버스, 학교, 병원, 마트, 어린이집)을 분석하는 `locations` 앱을 포함합니다.

## 시작하기

### 1. 의존성 설치 (uv 사용)

```bash
uv sync
```

### 2. 환경변수 설정

`.env.example`을 복사해서 `.env`를 만들고, 각자 발급받은 API 키를 입력하세요.

```bash
cp .env.example .env
```

- `KAKAO_REST_API_KEY`: [카카오 개발자](https://developers.kakao.com)에서 발급
- `BUS_STOP_SERVICE_KEY`: [공공데이터포털](https://data.go.kr) '전국버스정류장위치정보' 서비스 키

`.env` 파일은 git에 커밋되지 않습니다 (`.gitignore` 처리됨).

### 3. DB 마이그레이션 및 학교 데이터 적재

```bash
uv run python manage.py migrate
uv run python manage.py load_schools
```

### 4. 서버 실행

```bash
uv run python manage.py runserver
```

- 게시판(pybo 튜토리얼): http://127.0.0.1:8000/pybo/
- 입지 분석: http://127.0.0.1:8000/locations/?address=서울특별시 송파구 송이로 42
- 입지 분석 API (JSON): http://127.0.0.1:8000/locations/api/analyze/?address=서울특별시 송파구 송이로 42

## 앱 구성

- `pybo`: 장고 튜토리얼(점프 투 장고) 게시판 뼈대
- `locations`: 입지 분석 앱
  - `services.py`: 카카오 Local API / 공공데이터포털 버스정류장 API 연동 로직
  - `models.py`: 학교 남녀공학 정보(`School`)
  - `management/commands/load_schools.py`: `locations/data/` 의 CSV를 `School` 테이블로 적재
