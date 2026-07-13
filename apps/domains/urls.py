"""
Domains app URLs.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.domains.views import (
    DomainViewSet,
    DomainPortfolioViewSet,
    BlockedDomainViewSet,
    DomainListView,
    DomainDetailView,
    TriggerScanView,
)

router = DefaultRouter()
router.register(r'domains', DomainViewSet, basename='domain')
router.register(r'portfolios', DomainPortfolioViewSet, basename='portfolio')
router.register(r'blocked', BlockedDomainViewSet, basename='blocked-domain')

urlpatterns = [
    path('', include(router.urls)),
    path('web/', DomainListView.as_view(), name='domain_list'),
    path('web/<uuid:pk>/', DomainDetailView.as_view(), name='domain_detail'),
    path('web/<uuid:pk>/trigger-scan/', TriggerScanView.as_view(), name='trigger_scan'),
]