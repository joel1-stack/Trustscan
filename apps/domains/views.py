from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import TemplateView, View
from rest_framework import filters, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.serializers import ModelSerializer

from apps.domains.models import Domain, DomainPortfolio, BlockedDomain
from apps.reconnaissance.models import Finding
from apps.scanner.models import ScanJob


class DomainSerializer(ModelSerializer):
    class Meta:
        model = Domain
        fields = '__all__'


class DomainPortfolioSerializer(ModelSerializer):
    class Meta:
        model = DomainPortfolio
        fields = '__all__'


class BlockedDomainSerializer(ModelSerializer):
    class Meta:
        model = BlockedDomain
        fields = '__all__'


class DomainViewSet(viewsets.ModelViewSet):
    queryset = Domain.objects.all().select_related('organization', 'authorized_by', 'revoked_by')
    serializer_class = DomainSerializer
    permission_classes = [AllowAny]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'root_domain']
    ordering_fields = ['created_at', 'current_trust_score']
    ordering = ['-created_at']


class DomainPortfolioViewSet(viewsets.ModelViewSet):
    queryset = DomainPortfolio.objects.all().select_related('organization')
    serializer_class = DomainPortfolioSerializer
    permission_classes = [AllowAny]


class BlockedDomainViewSet(viewsets.ModelViewSet):
    queryset = BlockedDomain.objects.all()
    serializer_class = BlockedDomainSerializer
    permission_classes = [AllowAny]


class DomainListView(TemplateView):
    template_name = 'domains/domain_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        domains = Domain.objects.order_by('-created_at')
        context['domains'] = domains
        context['authorized_domain_count'] = domains.filter(authorization_status='authorized').count()
        return context


class DomainDetailView(TemplateView):
    template_name = 'domains/domain_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        domain = get_object_or_404(Domain, pk=kwargs['pk'])
        context['domain'] = domain
        context['recent_scans'] = domain.scan_jobs.order_by('-created_at')[:8]
        context['recent_findings'] = Finding.objects.filter(scan_job__domain=domain).order_by('-created_at')[:10]
        return context


class TriggerScanView(View):
    def post(self, request, pk, *args, **kwargs):
        domain = get_object_or_404(Domain, pk=pk)
        scan_job = ScanJob.objects.create(
            domain=domain,
            status='pending',
            scan_type='domain_full',
            trigger_source='web',
            triggered_by=request.user if getattr(request.user, 'is_authenticated', False) else None,
            authorization_status=domain.authorization_status,
            authorization_scope=domain.authorization_scope or [],
        )
        messages.success(request, f"Scan #{scan_job.id} started for {domain.name}.")
        return redirect('domain_detail', pk=domain.pk)
