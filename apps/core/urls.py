"""
Core URLs for health checks and basic endpoints.
"""
from django.urls import path
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def health_check(request):
    return JsonResponse({'status': 'healthy', 'service': 'trustscan'})


@csrf_exempt
def readiness_check(request):
    from django.db import connection
    try:
        connection.ensure_connection()
        return JsonResponse({'status': 'ready'})
    except Exception:
        return JsonResponse({'status': 'not ready'}, status=503)


@csrf_exempt
def liveness_check(request):
    return JsonResponse({'status': 'alive'})


urlpatterns = [
    path('health/', health_check, name='health-check'),
    path('ready/', readiness_check, name='readiness-check'),
    path('live/', liveness_check, name='liveness-check'),
]