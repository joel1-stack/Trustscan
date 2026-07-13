"""
Correlation app URLs.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.correlation.views import CorrelationViewSet, CorrelationRuleViewSet, PatternMatchViewSet

router = DefaultRouter()
router.register(r'correlations', CorrelationViewSet, basename='correlation')
router.register(r'rules', CorrelationRuleViewSet, basename='correlationrule')
router.register(r'pattern-matches', PatternMatchViewSet, basename='patternmatch')

urlpatterns = [
    path('', include(router.urls)),
]