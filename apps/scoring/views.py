from rest_framework import viewsets
from rest_framework.permissions import AllowAny
from rest_framework.serializers import ModelSerializer

from apps.scoring.models import TrustScore, DimensionScore, ScoringRule, ScoringAlgorithmVersion


class TrustScoreSerializer(ModelSerializer):
    class Meta:
        model = TrustScore
        fields = '__all__'


class DimensionScoreSerializer(ModelSerializer):
    class Meta:
        model = DimensionScore
        fields = '__all__'


class ScoringRuleSerializer(ModelSerializer):
    class Meta:
        model = ScoringRule
        fields = '__all__'


class ScoringAlgorithmVersionSerializer(ModelSerializer):
    class Meta:
        model = ScoringAlgorithmVersion
        fields = '__all__'


class TrustScoreViewSet(viewsets.ModelViewSet):
    queryset = TrustScore.objects.all().select_related('domain', 'scan_job')
    serializer_class = TrustScoreSerializer
    permission_classes = [AllowAny]


class DimensionScoreViewSet(viewsets.ModelViewSet):
    queryset = DimensionScore.objects.all().select_related('trust_score')
    serializer_class = DimensionScoreSerializer
    permission_classes = [AllowAny]


class ScoringRuleViewSet(viewsets.ModelViewSet):
    queryset = ScoringRule.objects.all()
    serializer_class = ScoringRuleSerializer
    permission_classes = [AllowAny]


class ScoringAlgorithmVersionViewSet(viewsets.ModelViewSet):
    queryset = ScoringAlgorithmVersion.objects.all()
    serializer_class = ScoringAlgorithmVersionSerializer
    permission_classes = [AllowAny]
