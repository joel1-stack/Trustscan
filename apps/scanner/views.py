from django.views.generic import TemplateView
from rest_framework import filters, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.serializers import ModelSerializer

from apps.scanner.models import ScanJob, ScanSchedule, ScanComparison


class ScanJobSerializer(ModelSerializer):
    class Meta:
        model = ScanJob
        fields = '__all__'


class ScanScheduleSerializer(ModelSerializer):
    class Meta:
        model = ScanSchedule
        fields = '__all__'


class ScanComparisonSerializer(ModelSerializer):
    class Meta:
        model = ScanComparison
        fields = '__all__'


class ScanJobViewSet(viewsets.ModelViewSet):
    queryset = ScanJob.objects.all().select_related('domain', 'schedule', 'triggered_by')
    serializer_class = ScanJobSerializer
    permission_classes = [AllowAny]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['domain__name', 'status']
    ordering_fields = ['created_at', 'started_at', 'completed_at']
    ordering = ['-created_at']


class ScanScheduleViewSet(viewsets.ModelViewSet):
    queryset = ScanSchedule.objects.all().select_related('domain', 'created_by')
    serializer_class = ScanScheduleSerializer
    permission_classes = [AllowAny]


class ScanComparisonViewSet(viewsets.ModelViewSet):
    queryset = ScanComparison.objects.all().select_related('scan_job', 'previous_scan_job')
    serializer_class = ScanComparisonSerializer
    permission_classes = [AllowAny]


class ScanListView(TemplateView):
    template_name = 'scanner/scan_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        scans = ScanJob.objects.select_related('domain').order_by('-created_at')
        context['scans'] = scans
        context['pending_count'] = scans.filter(status='pending').count()
        context['completed_count'] = scans.filter(status='completed').count()
        return context
