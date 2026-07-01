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

## 👥 팀원 소개
**테커 12기**

| 이름 | 역할 | GitHub |
|------|------|--------|
| 이용욱 | 팀장 | [@yongwook0001-hub](https://github.com/yongwook0001-hub) |
| 서동영 | 프론트 | [@](https://github.com/) |
| 심다움 | 백엔드 | [@](https://github.com/) |
| 윤재영 | 백엔드 | [@](https://github.com/) |
| 하지환 | 백엔드 | [@](https://github.com/) |

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
git commit -m "docs: README 수정"          # 문서 수정
git commit -m "chore: 패키지 업데이트"     # 기타
```

<br>

## 📄 라이센스
```
추가 예정
```
