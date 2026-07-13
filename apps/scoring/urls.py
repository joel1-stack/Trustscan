"""
Scoring app URLs.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.scoring.views import TrustScoreViewSet, DimensionScoreViewSet, ScoringRuleViewSet, ScoringAlgorithmVersionViewSet

router = DefaultRouter()
router.register(r'scores', TrustScoreViewSet, basename='trustscore')
router.register(r'dimensions', DimensionScoreViewSet, basename='dimensionscore')
router.register(r'rules', ScoringRuleViewSet, basename='scoringrule')
router.register(r'versions', ScoringAlgorithmVersionViewSet, basename='algorithmversion')

urlpatterns = [
    path('', include(router.urls)),
]