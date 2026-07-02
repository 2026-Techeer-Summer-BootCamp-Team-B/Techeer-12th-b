from django.db import models


class School(models.Model):
    school_name = models.CharField(max_length=100)
    coed_status = models.CharField(max_length=20)  # 예: 남여공학, 남학교, 여학교

    def __str__(self):
        return f"{self.school_name} ({self.coed_status})"
