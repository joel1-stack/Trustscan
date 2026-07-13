"""
Discovery app URLs.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.discovery.views import DiscoveryMapViewSet, AssetViewSet, DNSRecordViewSet, CertificateEntryViewSet, WhoisRecordViewSet

router = DefaultRouter()
router.register(r'maps', DiscoveryMapViewSet, basename='discoverymap')
router.register(r'assets', AssetViewSet, basename='asset')
router.register(r'dns-records', DNSRecordViewSet, basename='dnsrecord')
router.register(r'certificates', CertificateEntryViewSet, basename='certificateentry')
router.register(r'whois', WhoisRecordViewSet, basename='whoisrecord')

urlpatterns = [
    path('', include(router.urls)),
]