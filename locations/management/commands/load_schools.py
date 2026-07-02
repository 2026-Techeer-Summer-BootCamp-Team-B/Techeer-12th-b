# -*- coding: utf-8 -*-
"""
학교 기본 정보 CSV를 School 모델로 적재하는 management command.
사용법: uv run python manage.py load_schools
"""

import csv
from pathlib import Path

from django.core.management.base import BaseCommand

from locations.models import School

CSV_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "학교기본정보_2026년05월31일기준.csv"


class Command(BaseCommand):
    help = "학교기본정보 CSV를 읽어 School 테이블에 적재합니다 (기존 데이터는 삭제 후 재적재)."

    def handle(self, *args, **options):
        with open(CSV_PATH, encoding="euc-kr", newline="") as f:
            reader = csv.DictReader(f)
            schools = [
                School(
                    school_name=row["학교명"].strip(),
                    coed_status=row["남녀공학구분명"].strip(),
                )
                for row in reader
            ]

        School.objects.all().delete()
        School.objects.bulk_create(schools)

        self.stdout.write(self.style.SUCCESS(f"학교 {len(schools)}개 적재 완료"))
