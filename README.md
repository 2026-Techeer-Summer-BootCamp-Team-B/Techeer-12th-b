# 🏠 부동산 입지 분석 에이전트

> 주소 하나만 입력하면 AI가 교통·학군·편의시설·안전·실거래가를 종합 분석해 입지 점수와 장단점을 알려주는 지도 기반 입지 분석 에이전트

<br>

## 📌 목차
- [프로젝트 소개](#프로젝트-소개)
- [주요 기능](#주요-기능)
- [기술 스택](#기술-스택)
- [시스템 아키텍처](#시스템-아키텍처)
- [팀원 소개](#팀원-소개)
- [시작하기](#시작하기)

<br>

## 📖 프로젝트 소개
```
자취방을 구하거나 이사할 때 "이 동네 살만한가?"를 판단하는 데는
여러 사이트를 오가며 지하철 거리, 학군, 편의시설, 치안, 시세를
일일이 찾아봐야 하는 번거로움이 있습니다.

부동산 입지 분석 에이전트는 주소 하나만 입력하면 여러 개의 분석
에이전트(MCP)가 병렬로 데이터를 수집해 교통·학군·편의시설·안전·
실거래가 정보를 종합 점수와 지도 시각화로 한 번에 보여주는 서비스입니다.

가상의 시나리오를 시뮬레이션하는 도구가 아니라, 실시간 공공데이터와
지도 API를 기반으로 사실에 근거한 분석 결과를 제공하는 것을
핵심 가치로 합니다.
```

<br>

## ✨ 주요 기능
| 기능 | 설명 |
|------|------|
| 📍 주소 기반 입지 분석 | 주소 입력 시 좌표 변환 후 반경 내 교통·학군·편의시설·안전·시세 데이터를 자동 수집 |
| ⚖️ 우선순위 가중치 설정 | 교통/학군/편의시설/안전 항목별 가중치를 직접 조절해 나에게 맞춘 맞춤형 점수 산출 |
| 🧮 종합 입지 점수 산정 | 수집된 데이터를 종합해 100점 만점의 점수와 등급, 장단점 요약 제공 |
| 🗺️ 지도 시각화 | 카카오맵 기반으로 주변 시설을 카테고리별 핀으로 표시, 반경 오버레이 제공 |
| 🚶 거리뷰(Street View) | 네이버 지도 API 파노라마 기능으로 해당 좌표의 실제 거리 모습을 웹에서 바로 확인 |
| 🚏 대중교통 접근성 분석 | 가장 가까운 지하철역까지 도보 시간, 버스 노선 수, 배차 간격 분석 |
| 🏫 학군 정보 분석 | 인근 초중고 수, 학원가 밀집도 정보 제공 |
| 🚨 안전/환경 분석 | 지역 범죄 통계, 유흥가·소음 요인 등 환경 리스크 분석 |
| 📚 분석 이력 관리 | 과거 분석한 주소 이력 저장 및 2개 매물 비교 기능 |

## 팀 역할 분담(미확정)

| 역할 (담당자) | 담당 범위 | 브랜치 예시 |
|------|-----------|-------------|
| 백엔드 코어 + 프론트엔드 총괄 (이용욱) | 오케스트레이터 에이전트 설계, DRF API 명세, MCP 응답 스키마 정의, 각 MCP의 RAG 결과 통합 관리, 프론트엔드(React/Vite/Tailwind) 리드 | `feature/backend-core`, `feature/frontend` |
| 프론트엔드 서포트 (서동영) | 웹사이트 컴포넌트 단위 작업, UI 퍼블리싱, 화면 연동 | `feature/frontend` |
| 교통·학군 MCP (윤재영) | 공공데이터포털(버스), 학교알리미 API 연동 + 학군 관련 DB 테이블 관리, 교통·학군 도메인 RAG 설계, 분석 이력 DB(`AnalysisHistory`) 모델 필드 구현 | `feature/mcp-transit-school` |
| 안전·환경 MCP (심다움) | 경찰청 KICS(범죄 통계) 연동 + 범죄 통계 DB 테이블 관리, 소음지도 등, 안전·환경 도메인 RAG 설계 | `feature/mcp-safety-env` |
| 지도·시설 MCP (하지환) | Kakao Map/Local(좌표 변환, 주변시설 검색), 지도·시설 도메인 RAG 설계, 종합 점수 계산 로직 구현 | `feature/mcp-map-facility` |

> RAG는 각 MCP 담당자가 자기 도메인 안에서 검색+설명 생성까지 설계

<br>

## 🛠 기술 스택

**Frontend**
```
React
Vite
TailwindCSS
Naver Maps API v3 (Panorama - 거리뷰)
```

**Backend**
```
Python
Django
Django REST Framework
LangChain (RAG 확장 예정)
```

**Database**
```
PostgreSQL / SQLite (개발)
ChromaDB (RAG 확장 예정)
```

**외부 API / MCP**
```
Kakao Map API      - 좌표 변환, 지도 시각화
Naver Maps API v3   - 거리뷰(Panorama) 임베드
Kakao Local API     - 주변 시설(편의점/병원/카페/마트) 검색
공공데이터포털       - 버스 노선, 배차 간격, 학원 정보
학교알리미 API       - 초중고 학교 정보
경찰청 KICS         - 지역별 범죄 통계
국토교통부 실거래가 API - 아파트/빌라/오피스텔 실거래가
```

**협업 도구**
```
Git / GitHub / Notion / Slack / Zoom
```

![Git](https://img.shields.io/badge/Git-F05032?style=for-the-badge&logo=git&logoColor=white)
![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)
![Notion](https://img.shields.io/badge/Notion-000000?style=for-the-badge&logo=notion&logoColor=white)
![Slack](https://img.shields.io/badge/Slack-4A154B?style=for-the-badge&logo=slack&logoColor=white)
![Zoom](https://img.shields.io/badge/Zoom-2D8CFF?style=for-the-badge&logo=zoom&logoColor=white)

<br>

## 🏗 시스템 아키텍처
```
사용자: 주소 입력 + 우선순위(가중치) 설정
        │
        ▼
[오케스트레이터 에이전트]
        │
        ├─────────────── 병렬 실행 ───────────────┐
        │           │           │           │      │
   [지도 MCP]   [교통 MCP]   [학군 MCP]   [범죄 MCP] │
   Kakao Map    공공데이터    학교알리미   경찰청 API │
        │           │           │           │      │
   [시설 MCP]   [환경 MCP]   [실거래 MCP]           │
   Kakao Local  소음지도     국토부 API             │
        └─────────────────────────────────────────┘
                        │
                        ▼
        [종합 점수 계산 에이전트]
        (우선순위 가중치 반영)
                        │
                        ▼
        [결과 출력 + 지도 시각화]
                        │
                        ▼
        [거리뷰 패널] ← Naver Maps API Panorama
        (해당 좌표의 실제 거리 모습 임베드)
```

> 거리뷰는 별도 MCP가 아니라, 프론트엔드에서 분석 결과로 받은 좌표(lat, lng)를
> Naver Maps API v3의 `naver.maps.Panorama` 컴포넌트에 그대로 전달해 렌더링합니다.
> (이미지를 서버로 가져와 저장·분석하는 용도가 아닌, 화면 임베드 전용)

<br>

## 📂 프로젝트 구조

### 앱 구성
- `pybo` : 장고 튜토리얼(점프 투 장고) 게시판 뼈대
- `locations` : 입지 분석 앱
  - `services.py` : 카카오 Local API / 공공데이터포털 버스정류장 API 연동 로직
  - `models.py` : 학교 남녀공학 정보(`School`)
  - `management/commands/load_schools.py` : `locations/data/`의 CSV를 `School` 테이블로 적재

### 최상위 파일

| 파일 | 역할 |
|------|------|
| `manage.py` | Django 명령어 실행 진입점 (`runserver`, `migrate` 등 여기로 실행) |
| `pyproject.toml` | 프로젝트 의존성 정의 (django, requests, python-dotenv) — uv가 관리 |
| `uv.lock` | 의존성 버전 고정 파일 (팀원이 `uv sync` 하면 이 버전 그대로 설치됨) |
| `.python-version` | 사용할 Python 버전 지정 |
| `.env` | 실제 API 키 값 (git에는 안 올라감, 로컬에만 존재) |
| `.env.example` | `.env`에 뭘 채워야 하는지 보여주는 템플릿 (git에 올라감) |
| `.gitignore` | git에 올리지 않을 파일 목록 (`.env`, `db.sqlite3`, `.venv` 등) |
| `db.sqlite3` | 실제 데이터베이스 파일 (마이그레이션/데이터 저장소, git 제외) |
| `README.md` | 팀원용 설치·실행 가이드 |

### `config/` — 프로젝트 전역 설정

| 파일 | 역할 |
|------|------|
| `settings.py` | 전역 설정 (설치된 앱 목록, DB 설정, `.env` 로딩 등) |
| `urls.py` | 최상위 URL 라우팅 — `/pybo/`, `/locations/`를 각 앱으로 분기 |
| `wsgi.py` / `asgi.py` | 배포 시 서버가 Django를 구동하는 진입점 (지금은 안 건드림) |

### `pybo/` — 장고 튜토리얼 게시판 (기존, 손 안 댐)

빈 뼈대 상태. `views.py`에 "Hello world" 하나만 있음. 이후 게시판 기능 만들 때 쓰라고 남겨둠.

### `locations/` — 입지 분석 앱

| 파일 | 역할 |
|------|------|
| `models.py` | `School` 모델 정의 (학교명, 남녀공학 여부) — DB 테이블 스키마 |
| `services.py` | 핵심 로직. 카카오 Local API(주소→좌표, 주변시설 검색), 공공데이터 버스정류장 API 호출 함수들 (`test/location_analyzer.py`를 이식한 부분) |
| `views.py` | HTTP 요청 처리 — `index`(HTML 페이지), `api_analyze`(JSON API) |
| `urls.py` | `locations` 앱 내부 라우팅 (`/`, `/api/analyze/`) |
| `admin.py` | Django 관리자 페이지에 `School` 모델 노출 |
| `templates/locations/index.html` | 주소 입력 폼 + 분석 결과를 보여주는 HTML 화면 |
| `data/학교기본정보_...csv` | 원본 학교 데이터 (`test` 폴더에서 복사) |
| `management/commands/load_schools.py` | CSV를 읽어 `School` 테이블에 적재하는 커맨드 (`test/build_db.py` 대체) |
| `migrations/0001_initial.py` | `School` 모델을 실제 DB 테이블로 만드는 마이그레이션 파일 |
| `apps.py`, `tests.py`, `__init__.py` | Django가 앱을 자동 생성할 때 만드는 기본 뼈대 파일 (거의 안 건드림) |

### 요청 처리 흐름

```
사용자가 /locations/?address=... 접속
        │
        ▼
views.py 가 services.py 의 analyze_location() 호출
        │
        ▼
카카오/공공데이터 API 호출 + models.py 의 School 테이블 조회
        │
        ▼
index.html 로 결과 렌더링
```

<br>

## 👥 팀원 소개
**테커 12기**

| 이름 | 역할 | GitHub |
|------|------|--------|
| 이용욱 | 팀장 | [@yongwook0001-hub](https://github.com/yongwook0001-hub) |
| 서동영 | - | [@](https://github.com/) |
| 심다움 | - | [@](https://github.com/) |
| 윤재영 | - | [@](https://github.com/) |
| 하지환 | - | [@](https://github.com/) |

<br>

## 🚀 시작하기

### 요구사항
```
Python 3.11+
Node.js 18+
uv (Python 패키지 매니저)
Kakao Developers API Key
공공데이터포털 API Key
```

### 설치 및 실행
```bash
# 레포 클론
git clone https://github.com/your-repo.git
cd your-repo

# 백엔드 설정
cd backend
uv sync
cp .env.example .env   # API 키 입력
uv run python manage.py migrate
uv run python manage.py runserver

# 프론트엔드 설정
cd ../frontend
npm install
cp .env.example .env   # VITE_API_BASE_URL 등 입력
npm run dev
```

<br>

## 📋 Git 기본 명령어

### 처음 시작할 때
```bash
# 레포 클론 (처음 한 번만)
git clone https://github.com/your-repo.git

# 클론한 폴더로 이동
cd your-repo
```

### 브랜치
```bash
# 브랜치 목록 확인
git branch

# 새 브랜치 만들기
git branch 브랜치이름

# 브랜치 이동
git checkout 브랜치이름

# 브랜치 만들고 바로 이동 (위 두 개 합친 것)
git checkout -b 브랜치이름

# 브랜치 삭제
git branch -d 브랜치이름
```

### 작업 흐름 (매일 쓰는 것)
```bash
# 1. 원격 저장소 최신 내용 가져오기 (작업 시작 전 항상 먼저)
git pull origin main

# 2. 변경된 파일 확인
git status

# 3. 변경 파일 스테이징 (커밋할 파일 올리기)
git add .                  # 전체 파일
git add 파일이름            # 특정 파일만

# 4. 커밋 (변경 내용 저장)
git commit -m "커밋 메시지"

# 5. 원격 저장소에 올리기
git push origin 브랜치이름
```

### 커밋 메시지 컨벤션
```bash
git commit -m "feat: 로그인 기능 추가"     # 새 기능
git commit -m "fix: 버튼 클릭 오류 수정"   # 버그 수정
git commit -m "style: UI 레이아웃 수정"    # 스타일 변경
git commit -m "refactor: 코드 구조 개선"   # 리팩토링
```

### 기타
```bash
# 커밋 히스토리 확인
git log --oneline

# 변경 내용 확인
git diff

# 작업 내용 임시 저장 (다른 브랜치 이동할 때)
git stash

# 임시 저장한 내용 복원
git stash pop
```

<br>

## 📄 라이센스
```
추가 예정
```
