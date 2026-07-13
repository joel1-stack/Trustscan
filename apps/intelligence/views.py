from rest_framework import viewsets
from rest_framework.permissions import AllowAny
from rest_framework.serializers import ModelSerializer

from apps.intelligence.models import IntelligenceBrief, Benchmark, ThreatIntel, CVEFeed, ThreatCampaign, RegulatoryMapping


class IntelligenceBriefSerializer(ModelSerializer):
    class Meta:
        model = IntelligenceBrief
        fields = '__all__'


class BenchmarkSerializer(ModelSerializer):
    class Meta:
        model = Benchmark
        fields = '__all__'


class ThreatIntelSerializer(ModelSerializer):
    class Meta:
        model = ThreatIntel
        fields = '__all__'


class CVEFeedSerializer(ModelSerializer):
    class Meta:
        model = CVEFeed
        fields = '__all__'


class ThreatCampaignSerializer(ModelSerializer):
    class Meta:
        model = ThreatCampaign
        fields = '__all__'


class RegulatoryMappingSerializer(ModelSerializer):
    class Meta:
        model = RegulatoryMapping
        fields = '__all__'


class IntelligenceBriefViewSet(viewsets.ModelViewSet):
    queryset = IntelligenceBrief.objects.all().select_related('scan_job', 'domain', 'trust_score')
    serializer_class = IntelligenceBriefSerializer
    permission_classes = [AllowAny]


class BenchmarkViewSet(viewsets.ModelViewSet):
    queryset = Benchmark.objects.all()
    serializer_class = BenchmarkSerializer
    permission_classes = [AllowAny]


class ThreatIntelViewSet(viewsets.ModelViewSet):
    queryset = ThreatIntel.objects.all()
    serializer_class = ThreatIntelSerializer
    permission_classes = [AllowAny]


class CVEFeedViewSet(viewsets.ModelViewSet):
    queryset = CVEFeed.objects.all()
    serializer_class = CVEFeedSerializer
    permission_classes = [AllowAny]


class ThreatCampaignViewSet(viewsets.ModelViewSet):
    queryset = ThreatCampaign.objects.all()
    serializer_class = ThreatCampaignSerializer
    permission_classes = [AllowAny]


class RegulatoryMappingViewSet(viewsets.ModelViewSet):
    queryset = RegulatoryMapping.objects.all()
    serializer_class = RegulatoryMappingSerializer
    permission_classes = [AllowAny]
