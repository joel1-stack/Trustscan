from rest_framework import viewsets
from rest_framework.permissions import AllowAny
from rest_framework.serializers import ModelSerializer

from apps.reconnaissance.models import (
    Finding, InspectorResult, TechnologyFingerprint,
    HTTPResponse, SecurityHeaderFinding, SSLConfiguration,
    EmailSecurityRecord, BreachRecord, ExposedService,
    ReputationFinding, GitHubRepository, APIEndpoint
)


class FindingSerializer(ModelSerializer):
    class Meta:
        model = Finding
        fields = '__all__'


class InspectorResultSerializer(ModelSerializer):
    class Meta:
        model = InspectorResult
        fields = '__all__'


class TechnologyFingerprintSerializer(ModelSerializer):
    class Meta:
        model = TechnologyFingerprint
        fields = '__all__'


class HTTPResponseSerializer(ModelSerializer):
    class Meta:
        model = HTTPResponse
        fields = '__all__'


class SecurityHeaderFindingSerializer(ModelSerializer):
    class Meta:
        model = SecurityHeaderFinding
        fields = '__all__'


class SSLConfigurationSerializer(ModelSerializer):
    class Meta:
        model = SSLConfiguration
        fields = '__all__'


class EmailSecurityRecordSerializer(ModelSerializer):
    class Meta:
        model = EmailSecurityRecord
        fields = '__all__'


class BreachRecordSerializer(ModelSerializer):
    class Meta:
        model = BreachRecord
        fields = '__all__'


class ExposedServiceSerializer(ModelSerializer):
    class Meta:
        model = ExposedService
        fields = '__all__'


class ReputationFindingSerializer(ModelSerializer):
    class Meta:
        model = ReputationFinding
        fields = '__all__'


class GitHubRepositorySerializer(ModelSerializer):
    class Meta:
        model = GitHubRepository
        fields = '__all__'


class APIEndpointSerializer(ModelSerializer):
    class Meta:
        model = APIEndpoint
        fields = '__all__'


class FindingViewSet(viewsets.ModelViewSet):
    queryset = Finding.objects.all().select_related('scan_job', 'asset')
    serializer_class = FindingSerializer
    permission_classes = [AllowAny]


class InspectorResultViewSet(viewsets.ModelViewSet):
    queryset = InspectorResult.objects.all().select_related('scan_job')
    serializer_class = InspectorResultSerializer
    permission_classes = [AllowAny]


class TechnologyFingerprintViewSet(viewsets.ModelViewSet):
    queryset = TechnologyFingerprint.objects.all().select_related('asset', 'scan_job')
    serializer_class = TechnologyFingerprintSerializer
    permission_classes = [AllowAny]


class HTTPResponseViewSet(viewsets.ModelViewSet):
    queryset = HTTPResponse.objects.all().select_related('scan_job')
    serializer_class = HTTPResponseSerializer
    permission_classes = [AllowAny]


class SecurityHeaderFindingViewSet(viewsets.ModelViewSet):
    queryset = SecurityHeaderFinding.objects.all().select_related('asset')
    serializer_class = SecurityHeaderFindingSerializer
    permission_classes = [AllowAny]


class SSLConfigurationViewSet(viewsets.ModelViewSet):
    queryset = SSLConfiguration.objects.all().select_related('asset')
    serializer_class = SSLConfigurationSerializer
    permission_classes = [AllowAny]


class EmailSecurityRecordViewSet(viewsets.ModelViewSet):
    queryset = EmailSecurityRecord.objects.all().select_related('asset')
    serializer_class = EmailSecurityRecordSerializer
    permission_classes = [AllowAny]


class BreachRecordViewSet(viewsets.ModelViewSet):
    queryset = BreachRecord.objects.all().select_related('asset')
    serializer_class = BreachRecordSerializer
    permission_classes = [AllowAny]


class ExposedServiceViewSet(viewsets.ModelViewSet):
    queryset = ExposedService.objects.all().select_related('asset')
    serializer_class = ExposedServiceSerializer
    permission_classes = [AllowAny]


class ReputationFindingViewSet(viewsets.ModelViewSet):
    queryset = ReputationFinding.objects.all().select_related('asset')
    serializer_class = ReputationFindingSerializer
    permission_classes = [AllowAny]


class GitHubRepositoryViewSet(viewsets.ModelViewSet):
    queryset = GitHubRepository.objects.all().select_related('asset')
    serializer_class = GitHubRepositorySerializer
    permission_classes = [AllowAny]


class APIEndpointViewSet(viewsets.ModelViewSet):
    queryset = APIEndpoint.objects.all().select_related('asset')
    serializer_class = APIEndpointSerializer
    permission_classes = [AllowAny]
