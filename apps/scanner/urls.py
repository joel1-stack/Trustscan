"""
Scanner app URLs.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.scanner.views import ScanJobViewSet, ScanScheduleViewSet, ScanComparisonViewSet, ScanListView

router = DefaultRouter()
router.register(r'scans', ScanJobViewSet, basename='scan')
router.register(r'schedules', ScanScheduleViewSet, basename='schedule')
router.register(r'comparisons', ScanComparisonViewSet, basename='comparison')

urlpatterns = [
    path('', include(router.urls)),
    path('web/', ScanListView.as_view(), name='scan_list'),
]