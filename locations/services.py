# -*- coding: utf-8 -*-
"""
입지 분석 서비스
- Kakao Local API: 주소 -> 좌표 변환, 반경 내 시설 검색
  (지하철역, 학교, 병원, 대형마트, 어린이집/유치원)
- 공공데이터포털 전국 버스정류장 위치 API: 반경 내 버스정류장 검색
- 학교 남녀공학 정보: School 모델(DB)에서 조회 (load_schools 커맨드로 먼저 적재)

test/location_analyzer.py의 로직을 Django 앱으로 이식한 버전.
API 키는 하드코딩하지 않고 환경변수(.env)에서 읽는다.
"""

import os
from math import radians, sin, cos, sqrt, atan2

import requests

from .models import School

KAKAO_REST_API_KEY = os.environ.get("KAKAO_REST_API_KEY", "")
BUS_STOP_SERVICE_KEY = os.environ.get("BUS_STOP_SERVICE_KEY", "")

# Kakao API 엔드포인트
KAKAO_ADDRESS_URL = "https://dapi.kakao.com/v2/local/search/address.json"   # 주소 → 좌표
KAKAO_CATEGORY_URL = "https://dapi.kakao.com/v2/local/search/category.json"  # 카테고리 검색

# 공공데이터포털 버스정류장 API 엔드포인트
BUS_STOP_URL = "http://apis.data.go.kr/1613000/BusSttnInfoInqireService/getCrdntPrxmtSttnList"

# Kakao 카테고리 코드 목록
# SW8: 지하철역 / SC4: 학교 / HP8: 병원 / MT1: 대형마트 / PS3: 어린이집·유치원
KAKAO_CATEGORIES = {
    "subway": "SW8",
    "school": "SC4",
    "hospital": "HP8",
    "mart": "MT1",
    "kids": "PS3",
}


class LocationAnalyzerError(Exception):
    """입지 분석 중 발생하는 오류 (주소를 찾을 수 없음, API 키 누락 등)"""


def _require_keys():
    if not KAKAO_REST_API_KEY:
        raise LocationAnalyzerError(
            "KAKAO_REST_API_KEY가 설정되지 않았습니다. .env 파일을 확인하세요."
        )


# ============================================================
# 유틸: 두 좌표 간 직선거리 계산 (Haversine 공식), 단위: 미터(m)
# ============================================================
def haversine(lat1, lng1, lat2, lng2):
    R = 6371000  # 지구 평균 반지름 (m)

    dlat = radians(lat2 - lat1)
    dlng = radians(lng2 - lng1)

    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlng / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    return R * c


def _search_kakao_category(category_code: str, lat: float, lng: float, radius: int):
    headers = {"Authorization": f"KakaoAK {KAKAO_REST_API_KEY}"}
    params = {
        "category_group_code": category_code,
        "x": lng,
        "y": lat,
        "radius": radius,
        "sort": "distance",
        "size": 15,
    }

    res = requests.get(KAKAO_CATEGORY_URL, headers=headers, params=params, timeout=5)
    res.raise_for_status()
    data = res.json()

    places = []
    for doc in data["documents"]:
        places.append({
            "name": doc["place_name"],
            "distance_m": int(doc["distance"]),
            "address": doc["road_address_name"] or doc["address_name"],
        })
    return places


def geocode_address(address: str):
    _require_keys()
    headers = {"Authorization": f"KakaoAK {KAKAO_REST_API_KEY}"}
    params = {"query": address}

    res = requests.get(KAKAO_ADDRESS_URL, headers=headers, params=params, timeout=5)
    res.raise_for_status()
    data = res.json()

    if not data["documents"]:
        raise LocationAnalyzerError(f"'{address}' 주소를 찾을 수 없습니다.")

    doc = data["documents"][0]
    lat = float(doc["y"])
    lng = float(doc["x"])
    return lat, lng


def get_nearby_subway_stations(lat: float, lng: float, radius: int = 1000):
    return _search_kakao_category(KAKAO_CATEGORIES["subway"], lat, lng, radius)


def get_nearby_bus_stops(lat: float, lng: float, radius_m: int = 500):
    if not BUS_STOP_SERVICE_KEY:
        return []

    params = {
        "serviceKey": BUS_STOP_SERVICE_KEY,
        "gpsLati": lat,
        "gpsLong": lng,
        "numOfRows": 50,
        "pageNo": 1,
        "_type": "json",
    }

    res = requests.get(BUS_STOP_URL, params=params, timeout=5)
    res.raise_for_status()
    data = res.json()

    try:
        items = data["response"]["body"]["items"]["item"]
    except (KeyError, TypeError):
        return []

    if isinstance(items, dict):
        items = [items]

    stops = []
    for item in items:
        dist = haversine(lat, lng, float(item["gpsLati"]), float(item["gpsLong"]))
        if dist <= radius_m:
            stops.append({
                "name": item.get("nodenm", "이름없음"),
                "distance_m": round(dist),
            })

    stops.sort(key=lambda x: x["distance_m"])
    return stops


def get_nearby_schools(lat: float, lng: float, radius: int = 1000):
    places = _search_kakao_category(KAKAO_CATEGORIES["school"], lat, lng, radius)

    # School 모델(DB)에서 학교명 → 남녀공학 매핑 딕셔너리 생성
    coed_map = dict(School.objects.values_list("school_name", "coed_status"))

    for place in places:
        school_name = place["name"]
        if school_name in coed_map:
            place["coed"] = coed_map[school_name]
        else:
            matched = next(
                (status for name, status in coed_map.items() if school_name in name or name in school_name),
                None
            )
            place["coed"] = matched

    return places


def get_nearby_hospitals(lat: float, lng: float, radius: int = 1000):
    return _search_kakao_category(KAKAO_CATEGORIES["hospital"], lat, lng, radius)


def get_nearby_marts(lat: float, lng: float, radius: int = 2000):
    return _search_kakao_category(KAKAO_CATEGORIES["mart"], lat, lng, radius)


def get_nearby_kids_facilities(lat: float, lng: float, radius: int = 1000):
    return _search_kakao_category(KAKAO_CATEGORIES["kids"], lat, lng, radius)


def analyze_location(address: str):
    lat, lng = geocode_address(address)

    return {
        "address": address,
        "coords": {"lat": lat, "lng": lng},
        "subway": {"list": get_nearby_subway_stations(lat, lng, radius=1000)},
        "bus": {"list": get_nearby_bus_stops(lat, lng, radius_m=500)},
        "school": {"list": get_nearby_schools(lat, lng, radius=1000)},
        "hospital": {"list": get_nearby_hospitals(lat, lng, radius=1000)},
        "mart": {"list": get_nearby_marts(lat, lng, radius=2000)},
        "kids": {"list": get_nearby_kids_facilities(lat, lng, radius=1000)},
    }
