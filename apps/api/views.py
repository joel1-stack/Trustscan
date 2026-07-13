import hashlib
import hmac
import uuid
import secrets
from django.conf import settings
from django.utils import timezone
from django.db.models import Q
from rest_framework import viewsets, status, generics
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.filters import SearchFilter, OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from apps.api.models import (
    PublicAPIKey, WebhookEndpoint, WebhookDelivery, APIRequestLog, APIUsageQuota
)
from apps.api.serializers import (
    PublicAPIKeySerializer, WebhookEndpointSerializer, WebhookDeliverySerializer,
    APIUsageQuotaSerializer
)
from apps.api.authentication import APIKeyAuthentication
from apps.api.throttling import APIKeyRateThrottle
from apps.scanner.models import ScanJob, ScanSchedule
from apps.scoring.models import TrustScore
from apps.domains.models import Domain
from apps.correlation.models import Correlation
from apps.intelligence.models import IntelligenceBrief
from apps.reports.models import TrustReport
from apps.reconnaissance.models import Finding
from apps.accounts.models import Organization
from apps.core.exceptions import (
    InsufficientPermissionsError, QuotaExceededError, RateLimitError,
    ScanError, DomainNotFoundError
)


class PublicAPIKeyViewSet(viewsets.ModelViewSet):
    serializer_class = PublicAPIKeySerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ['name']
    ordering_fields = ['created_at', 'last_used_at']
    ordering = ['-created_at']
    
    def get_queryset(self):
        return PublicAPIKey.objects.filter(
            organization=self.request.user.organization,
            is_deleted=False
        ).select_related('organization', 'created_by')
    
    def perform_create(self, serializer):
        import secrets
        prefix = f"tsk_{secrets.token_urlsafe(6)}"
        key = f"{prefix}_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        serializer.save(
            organization=self.request.user.organization,
            created_by=self.request.user,
            key_prefix=prefix,
            key_hash=key_hash,
        )
        
        self.created_key = key
    
    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        if hasattr(self, 'created_key'):
            response.data['key'] = self.created_key
        return response
    
    @action(detail=True, methods=['post'])
    def regenerate(self, request, pk=None):
        api_key = self.get_object()
        new_key = f"{api_key.key_prefix}_{secrets.token_urlsafe(32)}"
        api_key.key_hash = hashlib.sha256(new_key.encode()).hexdigest()
        api_key.save(update_fields=['key_hash'])
        
        return Response({
            'key': new_key,
            'message': 'API key regenerated. Update your applications immediately.'
        })
    
    @action(detail=True, methods=['post'])
    def revoke(self, request, pk=None):
        api_key = self.get_object()
        api_key.is_active = False
        api_key.save(update_fields=['is_active'])
        return Response({'message': 'API key revoked'})


class WebhookEndpointViewSet(viewsets.ModelViewSet):
    serializer_class = WebhookEndpointSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ['name', 'url']
    ordering_fields = ['created_at', 'last_triggered_at']
    ordering = ['-created_at']
    
    def get_queryset(self):
        return WebhookEndpoint.objects.filter(
            organization=self.request.user.organization,
            is_deleted=False
        ).select_related('organization')
    
    def perform_create(self, serializer):
        import secrets
        secret = secrets.token_urlsafe(32)
        serializer.save(
            organization=self.request.user.organization,
            secret=secret,
        )
    
    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        webhook = self.get_object()
        from apps.api.tasks import send_test_webhook
        send_test_webhook.delay(str(webhook.id))
        return Response({'message': 'Test webhook sent'})


class WebhookDeliveryViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = WebhookDeliverySerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['status', 'event_type']
    ordering_fields = ['created_at', 'delivered_at']
    ordering = ['-created_at']
    
    def get_queryset(self):
        return WebhookDelivery.objects.filter(
            webhook__organization=self.request.user.organization,
            is_deleted=False
        ).select_related('webhook')


class APIUsageQuotaViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = APIUsageQuotaSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [OrderingFilter]
    ordering_fields = ['period_start', 'requests_count']
    ordering = ['-period_start']
    
    def get_queryset(self):
        return APIUsageQuota.objects.filter(
            organization=self.request.user.organization,
            is_deleted=False
        )


class APIRequestLogViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['response_status', 'method']
    ordering_fields = ['timestamp', 'duration_ms']
    ordering = ['-timestamp']
    
    def get_queryset(self):
        return APIRequestLog.objects.filter(
            organization=self.request.user.organization,
            is_deleted=False
        ).select_related('api_key')


class TrustScanPublicAPIViewSet(viewsets.ViewSet):
    authentication_classes = [APIKeyAuthentication]
    permission_classes = []
    throttle_classes = [APIKeyRateThrottle]
    
    def _check_quota(self, request, scan_type='domain'):
        if not hasattr(request, 'auth') or not request.auth:
            raise InsufficientPermissionsError()
        
        api_key = request.auth
        if not api_key.is_active:
            raise InsufficientPermissionsError('API key is inactive')
        
        if api_key.expires_at and api_key.expires_at < timezone.now():
            raise InsufficientPermissionsError('API key has expired')
        
        quota, _ = APIUsageQuota.objects.get_or_create(
            organization=api_key.organization,
            period_start=timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0),
            defaults={
                'period_end': (timezone.now().replace(day=1) + timezone.timedelta(days=32)).replace(day=1),
                'requests_limit': api_key.rate_limit * 24 * 30,
                'scan_limit': 100,
            }
        )
        
        if quota.requests_count >= quota.requests_limit:
            raise QuotaExceededError('Monthly request quota exceeded')
        
        if scan_type == 'domain' and quota.scan_requests >= quota.scan_limit:
            raise QuotaExceededError('Monthly scan quota exceeded')
        
        quota.requests_count += 1
        if scan_type == 'domain':
            quota.scan_requests += 1
        quota.save(update_fields=['requests_count', 'scan_requests'])
    
    @action(detail=False, methods=['get'], url_path='score/(?P<domain>[^/.]+)')
    def get_trust_score(self, request, domain=None):
        self._check_quota(request, 'domain')
        
        try:
            domain_obj = Domain.objects.get(
                name=domain,
                authorization_status='authorized',
                is_deleted=False
            )
        except Domain.DoesNotExist:
            return Response(
                {'error': {'code': 'domain_not_found', 'message': 'Domain not found or not authorized'}},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if not domain_obj.is_authorized:
            return Response(
                {'error': {'code': 'not_authorized', 'message': 'Domain not authorized for scanning'}},
                status=status.HTTP_403_FORBIDDEN
            )
        
        trust_score = TrustScore.objects.filter(
            domain=domain_obj,
            is_deleted=False
        ).order_by('-calculated_at').first()
        
        if not trust_score:
            return Response(
                {'error': {'code': 'no_score', 'message': 'No trust score available. Run a scan first.'}},
                status=status.HTTP_404_NOT_FOUND
            )
        
        return Response({
            'domain': domain_obj.name,
            'scan_id': str(trust_score.scan_job.id) if trust_score.scan_job else None,
            'status': 'COMPLETED',
            'trust_score': {
                'overall': trust_score.overall,
                'dimensions': trust_score.dimensions,
            },
            'critical_findings': trust_score.critical_count,
            'high_findings': trust_score.high_count,
            'correlations': [
                {'pattern': c.pattern_name, 'risk': c.risk_level, 'narrative': c.narrative}
                for c in trust_score.scan_job.correlations.filter(is_deleted=False)
            ],
            'recommendations': trust_score.top_actions,
            'benchmarks': {
                'industry_average': float(trust_score.intelligence_briefs.first().industry_average) if trust_score.intelligence_briefs.exists() else None,
                'percentile': trust_score.intelligence_briefs.first().industry_percentile if trust_score.intelligence_briefs.exists() else None,
            },
        })
    
    @action(detail=False, methods=['post'], url_path='scan')
    def trigger_scan(self, request):
        self._check_quota(request, 'domain')
        
        domain_name = request.data.get('domain')
        scan_type = request.data.get('scan_type', 'domain_full')
        
        if not domain_name:
            return Response(
                {'error': {'code': 'missing_domain', 'message': 'Domain is required'}},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            domain_obj = Domain.objects.get(
                name__iexact=domain_name,
                is_deleted=False
            )
        except Domain.DoesNotExist:
            return Response(
                {'error': {'code': 'domain_not_found', 'message': 'Domain not found in your portfolio'}},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if not domain_obj.is_authorized:
            return Response(
                {'error': {'code': 'not_authorized', 'message': 'Domain not authorized for scanning'}},
                status=status.HTTP_403_FORBIDDEN
            )
        
        scan_job = ScanJob.objects.create(
            domain=domain_obj,
            scan_type=scan_type,
            trigger_source='api',
            authorization_verified=True,
        )
        
        from apps.scanner.tasks import orchestrate_scan
        orchestrate_scan.delay(str(scan_job.id))
        
        return Response({
            'scan_id': str(scan_job.id),
            'status': 'started',
            'domain': domain_obj.name,
            'estimated_duration_seconds': 120,
        }, status=status.HTTP_202_ACCEPTED)
    
    @action(detail=False, methods=['get'], url_path='scan/(?P<scan_id>[^/.]+)')
    def get_scan_status(self, request, scan_id=None):
        try:
            scan_job = ScanJob.objects.get(
                id=scan_id,
                domain__organization=request.auth.organization,
                is_deleted=False
            )
        except ScanJob.DoesNotExist:
            return Response(
                {'error': {'code': 'scan_not_found', 'message': 'Scan not found'}},
                status=status.HTTP_404_NOT_FOUND
            )
        
        return Response({
            'scan_id': str(scan_job.id),
            'domain': scan_job.domain.name,
            'status': scan_job.status,
            'scan_type': scan_job.scan_type,
            'started_at': scan_job.started_at,
            'completed_at': scan_job.completed_at,
            'duration_seconds': scan_job.duration_seconds,
            'current_phase': scan_job.current_phase,
            'trust_score': scan_job.trust_score,
            'score_status': scan_job.score_status,
        })
    
    @action(detail=False, methods=['get'], url_path='domains')
    def list_domains(self, request):
        domains = Domain.objects.filter(
            organization=request.auth.organization,
            is_deleted=False
        ).order_by('-created_at')
        
        return Response({
            'domains': [
                {
                    'id': str(d.id),
                    'name': d.name,
                    'root_domain': d.root_domain,
                    'tld': d.tld,
                    'industry': d.industry,
                    'is_verified': d.is_verified,
                    'is_authorized': d.is_authorized,
                    'current_trust_score': d.current_trust_score,
                    'current_score_status': d.current_score_status,
                    'last_scanned_at': d.last_scanned_at,
                    'is_monitored': d.is_monitored,
                    'monitoring_frequency': d.monitoring_frequency,
                }
                for d in domains
            ]
        })
    
    @action(detail=False, methods=['post'], url_path='domains/verify')
    def verify_domain(self, request):
        domain_name = request.data.get('domain')
        method = request.data.get('method', 'dns_txt')
        
        if not domain_name:
            return Response(
                {'error': {'code': 'missing_domain', 'message': 'Domain is required'}},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            domain_obj = Domain.objects.get(
                name__iexact=domain_name,
                organization=request.auth.organization,
                is_deleted=False
            )
        except Domain.DoesNotExist:
            return Response(
                {'error': {'code': 'domain_not_found', 'message': 'Domain not found in your portfolio'}},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if domain_obj.is_authorized:
            return Response({'message': 'Domain already verified and authorized'})
        
        import secrets
        token = f"trustscan-verify={secrets.token_urlsafe(32)}"
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        domain_obj.verification_method = method
        domain_obj.verification_token = token
        domain_obj.verification_token_hash = token_hash
        domain_obj.verification_expires_at = timezone.now() + timezone.timedelta(hours=72)
        domain_obj.save(update_fields=[
            'verification_method', 'verification_token', 'verification_token_hash',
            'verification_expires_at'
        ])
        
        instructions = {
            'dns_txt': f'Add TXT record: {token}',
            'html_file': f'Upload file: trustscan_{token}.html with content: {token}',
            'meta_tag': f'Add meta tag: <meta name="trustscan-verification" content="{token}">',
            'email': f'Click verification link sent to admin@{domain_name}',
        }
        
        return Response({
            'domain': domain_obj.name,
            'method': method,
            'token': token,
            'instructions': instructions.get(method, 'Complete verification'),
            'expires_at': domain_obj.verification_expires_at,
        })
    
    @action(detail=False, methods=['post'], url_path='domains/(?P<domain>[^/.]+)/verify')
    def check_verification(self, request, domain=None):
        try:
            domain_obj = Domain.objects.get(
                name__iexact=domain,
                organization=request.auth.organization,
                is_deleted=False
            )
        except Domain.DoesNotExist:
            return Response(
                {'error': {'code': 'domain_not_found', 'message': 'Domain not found'}},
                status=status.HTTP_404_NOT_FOUND
            )
        
        from apps.domains.tasks import check_domain_verification
        check_domain_verification.delay(str(domain_obj.id))
        
        return Response({
            'domain': domain_obj.name,
            'status': 'verification_check_initiated',
            'authorization_status': domain_obj.authorization_status,
        })


class TrustLayerIntegrationViewSet(viewsets.ViewSet):
    authentication_classes = [APIKeyAuthentication]
    permission_classes = []
    throttle_classes = [APIKeyRateThrottle]
    
    def _get_domain(self, domain_name, organization):
        try:
            return Domain.objects.get(
                name__iexact=domain_name,
                organization=organization,
                is_deleted=False
            )
        except Domain.DoesNotExist:
            return None
    
    @action(detail=False, methods=['get'], url_path='counterparty/(?P<domain>[^/.]+)/trust-score')
    def counterparty_trust_score(self, request, domain=None):
        api_key = request.auth
        if not api_key or not api_key.is_active:
            return Response(
                {'error': {'code': 'unauthorized', 'message': 'Invalid API key'}},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        domain_obj = self._get_domain(domain, api_key.organization)
        if not domain_obj:
            return Response(
                {'error': {'code': 'domain_not_found', 'message': 'Counterparty domain not found'}},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if not domain_obj.is_authorized:
            return Response(
                {
                    'error': {
                        'code': 'counterparty_not_verified',
                        'message': 'Counterparty has not verified their domain on TrustScan',
                        'action_required': 'invite_counterparty'
                    }
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        trust_score = TrustScore.objects.filter(
            domain=domain_obj,
            is_deleted=False
        ).order_by('-calculated_at').first()
        
        if not trust_score:
            return Response(
                {'error': {'code': 'no_score', 'message': 'No trust score available'}},
                status=status.HTTP_404_NOT_FOUND
            )
        
        recommendation = 'PROCEED'
        if trust_score.overall >= 70:
            recommendation = 'PROCEED'
        elif trust_score.overall >= 50:
            recommendation = 'HOLD'
        else:
            recommendation = 'REJECT'
        
        critical_correlations = trust_score.scan_job.correlations.filter(
            risk_level='critical',
            is_deleted=False
        ).count()
        
        return Response({
            'counterparty': domain_obj.name,
            'trust_score': trust_score.overall,
            'status': trust_score.status,
            'recommendation': recommendation,
            'critical_risks': critical_correlations,
            'dimensions': trust_score.dimensions,
            'top_risks': trust_score.top_risks[:3],
            'scan_date': trust_score.calculated_at,
            'confidence': trust_score.confidence,
        })
    
    @action(detail=False, methods=['post'], url_path='counterparty/invite')
    def invite_counterparty(self, request):
        api_key = request.auth
        domain_name = request.data.get('domain')
        email = request.data.get('email')
        
        if not domain_name or not email:
            return Response(
                {'error': {'code': 'missing_fields', 'message': 'Domain and email required'}},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        from apps.accounts.tasks import send_counterparty_invitation
        send_counterparty_invitation.delay(
            str(api_key.organization.id),
            domain_name,
            email,
            request.data.get('message', '')
        )
        
        return Response({
            'message': f'Invitation sent to {email} for domain {domain_name}'
        })
    
    @action(detail=False, methods=['get'], url_path='agreement/(?P<agreement_id>[^/.]+)/trust-check')
    def agreement_trust_check(self, request, agreement_id=None):
        api_key = request.auth
        
        trust_threshold = request.query_params.get('threshold', 50)
        
        return Response({
            'agreement_id': agreement_id,
            'trust_check': {
                'required': True,
                'threshold': int(trust_threshold),
                'auto_reject_below': int(trust_threshold),
            }
        })


from apps.core.constants import SeverityChoices