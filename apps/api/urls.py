"""
API app URLs.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.api.views import (
    PublicAPIKeyViewSet, WebhookEndpointViewSet, WebhookDeliveryViewSet,
    APIUsageQuotaViewSet, APIRequestLogViewSet, TrustScanPublicAPIViewSet,
    TrustLayerIntegrationViewSet
)

router = DefaultRouter()
router.register(r'keys', PublicAPIKeyViewSet, basename='publicapikey')
router.register(r'webhooks', WebhookEndpointViewSet, basename='webhook')
router.register(r'webhook-deliveries', WebhookDeliveryViewSet, basename='webhookdelivery')
router.register(r'quotas', APIUsageQuotaViewSet, basename='apiusagequota')
router.register(r'logs', APIRequestLogViewSet, basename='apirequestlog')

urlpatterns = [
    path('', include(router.urls)),
    path('trustscan/', include([
        path('score/<str:domain>/', TrustScanPublicAPIViewSet.as_view({'get': 'get_trust_score'}), name='trustscan-score'),
        path('scan/', TrustScanPublicAPIViewSet.as_view({'post': 'trigger_scan'}), name='trustscan-scan'),
        path('scan/<str:scan_id>/', TrustScanPublicAPIViewSet.as_view({'get': 'get_scan_status'}), name='trustscan-scan-status'),
        path('domains/', TrustScanPublicAPIViewSet.as_view({'get': 'list_domains'}), name='trustscan-domains'),
        path('domains/verify/', TrustScanPublicAPIViewSet.as_view({'post': 'verify_domain'}), name='trustscan-verify-domain'),
        path('domains/<str:domain>/verify/', TrustScanPublicAPIViewSet.as_view({'post': 'check_verification'}), name='trustscan-check-verification'),
    ])),
    path('trustlayer/', include([
        path('counterparty/<str:domain>/trust-score/', TrustLayerIntegrationViewSet.as_view({'get': 'counterparty_trust_score'}), name='trustlayer-counterparty-score'),
        path('counterparty/invite/', TrustLayerIntegrationViewSet.as_view({'post': 'invite_counterparty'}), name='trustlayer-invite-counterparty'),
        path('agreement/<str:agreement_id>/trust-check/', TrustLayerIntegrationViewSet.as_view({'get': 'agreement_trust_check'}), name='trustlayer-agreement-check'),
    ])),
]