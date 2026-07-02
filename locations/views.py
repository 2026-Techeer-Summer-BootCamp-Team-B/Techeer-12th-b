from django.http import JsonResponse
from django.shortcuts import render

from .services import LocationAnalyzerError, analyze_location


def index(request):
    context = {}
    address = request.GET.get("address", "").strip()

    if address:
        context["address"] = address
        try:
            context["result"] = analyze_location(address)
        except LocationAnalyzerError as e:
            context["error"] = str(e)
        except Exception:
            context["error"] = "분석 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요."

    return render(request, "locations/index.html", context)


def api_analyze(request):
    address = request.GET.get("address", "").strip()
    if not address:
        return JsonResponse({"error": "address 파라미터가 필요합니다."}, status=400)

    try:
        result = analyze_location(address)
    except LocationAnalyzerError as e:
        return JsonResponse({"error": str(e)}, status=400)
    except Exception:
        return JsonResponse({"error": "분석 중 오류가 발생했습니다."}, status=502)

    return JsonResponse(result)
