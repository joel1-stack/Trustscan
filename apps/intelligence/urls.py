"""
Intelligence app URLs.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.intelligence.views import (
    IntelligenceBriefViewSet, BenchmarkViewSet, ThreatIntelViewSet,
    CVEFeedViewSet, ThreatCampaignViewSet, RegulatoryMappingViewSet
)

router = DefaultRouter()
router.register(r'briefs', IntelligenceBriefViewSet, basename='intelligencebrief')
router.register(r'benchmarks', BenchmarkViewSet, basename='benchmark')
router.register(r'threats', ThreatIntelViewSet, basename='threatintel')
router.register(r'cves', CVEFeedViewSet, basename='cvefeed')
router.register(r'campaigns', ThreatCampaignViewSet, basename='threatcampaign')
router.register(r'regulations', RegulatoryMappingViewSet, basename='regulatorymapping')

urlpatterns = [
    path('', include(router.urls)),
]