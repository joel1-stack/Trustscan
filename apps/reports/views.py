from rest_framework import viewsets
from rest_framework.permissions import AllowAny
from rest_framework.serializers import ModelSerializer

from apps.reports.models import TrustReport, ReportTemplate, ReportSchedule, ReportDelivery


class TrustReportSerializer(ModelSerializer):
    class Meta:
        model = TrustReport
        fields = '__all__'


class ReportTemplateSerializer(ModelSerializer):
    class Meta:
        model = ReportTemplate
        fields = '__all__'


class ReportScheduleSerializer(ModelSerializer):
    class Meta:
        model = ReportSchedule
        fields = '__all__'


class ReportDeliverySerializer(ModelSerializer):
    class Meta:
        model = ReportDelivery
        fields = '__all__'


class TrustReportViewSet(viewsets.ModelViewSet):
    queryset = TrustReport.objects.all().select_related('scan_job', 'domain', 'trust_score')
    serializer_class = TrustReportSerializer
    permission_classes = [AllowAny]


class ReportTemplateViewSet(viewsets.ModelViewSet):
    queryset = ReportTemplate.objects.all()
    serializer_class = ReportTemplateSerializer
    permission_classes = [AllowAny]


class ReportScheduleViewSet(viewsets.ModelViewSet):
    queryset = ReportSchedule.objects.all().select_related('domain', 'template')
    serializer_class = ReportScheduleSerializer
    permission_classes = [AllowAny]


class ReportDeliveryViewSet(viewsets.ModelViewSet):
    queryset = ReportDelivery.objects.all().select_related('report')
    serializer_class = ReportDeliverySerializer
    permission_classes = [AllowAny]
