"""
Reports app URLs.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.reports.views import TrustReportViewSet, ReportTemplateViewSet, ReportScheduleViewSet, ReportDeliveryViewSet

router = DefaultRouter()
router.register(r'reports', TrustReportViewSet, basename='trustreport')
router.register(r'templates', ReportTemplateViewSet, basename='reporttemplate')
router.register(r'schedules', ReportScheduleViewSet, basename='reportschedule')
router.register(r'deliveries', ReportDeliveryViewSet, basename='reportdelivery')

urlpatterns = [
    path('', include(router.urls)),
]